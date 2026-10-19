package mtproto

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/pasarguard/node/pkg/logstream"
)

const (
	// telemtCommandTimeout bounds telemt --version so a wedged binary cannot
	// block startup forever.
	telemtCommandTimeout = 30 * time.Second
	// telemtStopTimeout is how long Stop waits after SIGTERM, and again after
	// SIGKILL, for telemt to exit. telemt's graceful shutdown allows 5 s for
	// the middle end and 5 s for the control plane.
	telemtStopTimeout = 15 * time.Second
	// orphanExitTimeout bounds the wait for a killed orphan to go away.
	orphanExitTimeout = 5 * time.Second
	// maxTelemtLogLine caps one line of telemt output; the rest of a longer
	// line is skipped.
	maxTelemtLogLine = 64 * 1024
)

// minTelemtVersion is the oldest telemt the node runs: the release the
// backend is written and tested against. Older releases differ in ways the
// node cannot detect at runtime, such as the per-user octet metric names
// (renamed in 3.5.4), which would make traffic read as zero.
var minTelemtVersion = [3]int{3, 5, 14}

var telemtVersionPattern = regexp.MustCompile(`(?i)\btelemt\s+v?(\d+)\.(\d+)\.(\d+)(\S*)`)

var errProcessManagerClosed = errors.New("telemt process manager is closed")

// telemtRun is one started telemt process.
type telemtRun struct {
	cmd      *exec.Cmd
	pid      int
	waitDone chan struct{} // closed once the process is reaped and its output read
	stopping atomic.Bool   // set by Stop, so the exit is not reported as a crash
}

type processManager struct {
	executablePath string
	workDir        string
	version        string
	logs           *logstream.Buffer
	startupTail    *lineRing

	mu         sync.Mutex
	run        *telemtRun
	generation uint64
	closed     bool
}

// newProcessManager checks the telemt binary and returns a manager that runs
// it with workDir as its working directory. telemt older than 3.5.14 is
// refused.
func newProcessManager(executablePath, workDir string, logBufferSize, startupTailSize int) (*processManager, error) {
	if strings.TrimSpace(executablePath) == "" {
		return nil, errors.New("telemt executable path must not be empty")
	}

	absExecutablePath, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, err
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return nil, err
	}

	version, err := detectTelemtVersion(absExecutablePath)
	if err != nil {
		return nil, err
	}

	return &processManager{
		executablePath: absExecutablePath,
		workDir:        absWorkDir,
		version:        version,
		logs:           logstream.NewBuffer(logBufferSize),
		startupTail:    newLineRing(startupTailSize),
	}, nil
}

func detectTelemtVersion(executablePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), telemtCommandTimeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, executablePath, "--version").CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("telemt --version timed out after %s: %w", telemtCommandTimeout, ctx.Err())
		}
		return "", fmt.Errorf("failed to detect telemt version: %w", err)
	}
	return parseTelemtVersion(string(output))
}

// parseTelemtVersion reads `telemt X.Y.Z` and refuses versions below
// minTelemtVersion. A suffix such as -rc.1 is kept but not compared.
func parseTelemtVersion(output string) (string, error) {
	match := telemtVersionPattern.FindStringSubmatch(output)
	if match == nil {
		return "", fmt.Errorf("failed to parse telemt version from %q", strings.TrimSpace(output))
	}

	var found [3]int
	for i := range found {
		value, err := strconv.Atoi(match[i+1])
		if err != nil {
			return "", fmt.Errorf("failed to parse telemt version from %q: %w", strings.TrimSpace(output), err)
		}
		found[i] = value
	}

	version := fmt.Sprintf("%d.%d.%d%s", found[0], found[1], found[2], match[4])
	if slices.Compare(found[:], minTelemtVersion[:]) < 0 {
		return "", fmt.Errorf("telemt %s is not supported: the node requires telemt %d.%d.%d or newer",
			version, minTelemtVersion[0], minTelemtVersion[1], minTelemtVersion[2])
	}
	return version, nil
}

func (p *processManager) Version() string {
	return p.version
}

func (p *processManager) SubscribeLogs(ctx context.Context) <-chan string {
	return p.logs.Subscribe(ctx)
}

// Start runs `telemt run <configPath>`. Any telemt still running for the same
// config path (left over from a killed node) is killed first.
func (p *processManager) Start(configPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return errProcessManagerClosed
	}
	if p.startedLocked() {
		return errors.New("telemt process is already running")
	}

	cleanupOrphanedTelemt(configPath)

	// No --pid-file: a pid file that survives a hard kill can name a live
	// process later and make telemt refuse to start. The node reloads by
	// signalling its own child instead.
	cmd := exec.Command(p.executablePath, "run", configPath)
	// telemt writes relative-path artifacts (the tls_front cache, for one)
	// into its working directory; keep them in the generated config dir.
	cmd.Dir = p.workDir
	setProcessAttributes(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	p.startupTail.reset()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start telemt: %w", err)
	}

	run := &telemtRun{
		cmd:      cmd,
		pid:      cmd.Process.Pid,
		waitDone: make(chan struct{}),
	}
	p.run = run
	p.generation++

	go p.wait(run, stdout, stderr)
	return nil
}

// wait reads telemt's output to EOF, then reaps the process. os/exec closes
// the pipes in Wait, so calling it while the readers run can lose the last
// lines of a crash.
func (p *processManager) wait(run *telemtRun, stdout, stderr io.Reader) {
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		p.captureLogs(stdout)
	}()
	go func() {
		defer readers.Done()
		p.captureLogs(stderr)
	}()
	readers.Wait()

	err := run.cmd.Wait()
	if !run.stopping.Load() {
		message := "telemt exited unexpectedly"
		if err != nil {
			message = fmt.Sprintf("%s: %v", message, err)
			if strings.Contains(strings.ToLower(err.Error()), "signal: killed") {
				message += " (process was killed externally; check container/system OOM and memory limits)"
			}
		} else {
			message += " with exit status 0"
		}
		log.Println(message)
		p.publish(message)
	}
	close(run.waitDone)
}

func (p *processManager) captureLogs(pipe io.Reader) {
	reader := bufio.NewReaderSize(pipe, maxTelemtLogLine)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			p.publish(string(line) + " [truncated]")
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			if err != nil {
				return
			}
			continue
		}
		if text := strings.TrimRight(string(line), "\r\n"); text != "" || err == nil {
			p.publish(text)
		}
		if err != nil {
			return
		}
	}
}

func (p *processManager) publish(line string) {
	p.startupTail.add(line)
	p.logs.Publish(line)
}

func (p *processManager) Started() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startedLocked()
}

// startedLocked requires p.mu. It checks waitDone, never cmd.ProcessState,
// which Wait writes without the lock.
func (p *processManager) startedLocked() bool {
	if p.run == nil {
		return false
	}
	select {
	case <-p.run.waitDone:
		return false
	default:
		return true
	}
}

// PID returns the running telemt's pid, or 0.
func (p *processManager) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.startedLocked() {
		return 0
	}
	return p.run.pid
}

// Exited returns a channel closed when the current telemt exits, or nil when
// none was started (or it was stopped).
func (p *processManager) Exited() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.run == nil {
		return nil
	}
	return p.run.waitDone
}

// Generation counts successful Starts.
func (p *processManager) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

// StartupTail returns the last n lines (all kept lines when n <= 0) telemt
// wrote since the latest Start, including the exit message after a crash.
func (p *processManager) StartupTail(n int) []string {
	return p.startupTail.tail(n)
}

// Reload asks the running telemt to re-read its config: SIGHUP on Unix. On
// Windows it does nothing, and telemt's config file watcher picks the change
// up.
func (p *processManager) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.startedLocked() {
		return errors.New("telemt process is not running")
	}
	if err := reloadProcess(p.run.cmd); err != nil {
		return fmt.Errorf("failed to signal telemt to reload: %w", err)
	}
	return nil
}

// Notice logs a node message about telemt and adds it to telemt's log
// stream, which the panel shows.
func (p *processManager) Notice(message string) {
	log.Println(message)
	p.logs.Publish(message)
}

// Stop terminates telemt and waits for it to exit, killing it after
// telemtStopTimeout.
func (p *processManager) Stop() {
	p.mu.Lock()
	run := p.run
	p.mu.Unlock()
	if run == nil {
		return
	}

	run.stopping.Store(true)
	select {
	case <-run.waitDone:
	default:
		_ = terminateProcess(run.cmd)
		select {
		case <-run.waitDone:
		case <-time.After(telemtStopTimeout):
			log.Printf("telemt process %d did not exit within %s, killing it", run.pid, telemtStopTimeout)
			_ = killProcess(run.cmd)
			select {
			case <-run.waitDone:
			case <-time.After(telemtStopTimeout):
				log.Printf("warning: telemt process %d is still running after SIGKILL", run.pid)
			}
		}
	}

	p.mu.Lock()
	if p.run == run {
		p.run = nil
	}
	p.mu.Unlock()
}

// Close stops telemt and closes the log buffer. Start fails afterwards.
func (p *processManager) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()

	p.Stop()
	p.logs.Close()
}

// cleanupOrphanedTelemt kills telemt processes still running configPath, for
// example after the node was SIGKILLed. Only a command line that runs exactly
// this config matches, so nothing else is ever killed.
func cleanupOrphanedTelemt(configPath string) {
	processes, err := gopsutilprocess.Processes()
	if err != nil {
		log.Printf("warning: failed to list processes for telemt orphan cleanup: %v", err)
		return
	}

	self := int32(os.Getpid())
	for _, proc := range processes {
		if proc.Pid == self {
			continue
		}
		args, err := proc.CmdlineSlice()
		if err != nil || !runsTelemtConfig(args, configPath) {
			continue
		}

		log.Printf("killing orphaned telemt process %d running %s", proc.Pid, configPath)
		if err := killOrphan(int(proc.Pid)); err != nil {
			log.Printf("warning: failed to kill orphaned telemt process %d: %v", proc.Pid, err)
			continue
		}
		waitProcessGone(proc, orphanExitTimeout)
	}
}

// runsTelemtConfig reports whether args look like `... run <configPath>`.
func runsTelemtConfig(args []string, configPath string) bool {
	if len(args) < 3 || args[len(args)-1] != configPath {
		return false
	}
	return slices.Contains(args[1:len(args)-1], "run")
}

func waitProcessGone(proc *gopsutilprocess.Process, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		running, err := proc.IsRunning()
		if err != nil || !running {
			return
		}
		// A zombie has released its ports; only its parent can reap it.
		if status, err := proc.Status(); err == nil && slices.Contains(status, gopsutilprocess.Zombie) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("warning: orphaned telemt process %d did not exit within %s", proc.Pid, timeout)
}
