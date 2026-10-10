package hysteria

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasarguard/node/backend/proclib"
	nodeLogger "github.com/pasarguard/node/logger"
)

// Core owns the hysteria child process. Like sing-box (and unlike xray, which
// takes its config on stdin) hysteria only accepts a config file path, so the
// config is always written to disk.
type Core struct {
	executablePath string
	configDir      string
	configFilePath string
	version        string
	process        *exec.Cmd
	restarting     bool
	stopping       bool
	waitDone       chan struct{}
	startedAt      time.Time
	logsChan       chan string
	logger         *nodeLogger.Logger
	cancelFunc     context.CancelFunc
	startupMu      sync.RWMutex
	startupPhase   bool
	startupLogs    []string
	startupLogSize int
	startupFailure string
	runtimeMu      sync.RWMutex
	runtimeLogs    []string
	mu             sync.Mutex

	// spawns counts child processes actually launched. Tests assert on it to
	// prove idle cores do not crash-loop (one spawn per real start, zero while
	// idle) — a claim no log grep can make as directly.
	spawns atomic.Int64
}

const defaultStartupLogTailSize = 200

// versionRe matches the version in `hysteria version` output, which reads
// "Version:\tv2.13.0". The banner above it is ASCII art on stdout, so the
// version cannot be taken from the first line of output.
var versionRe = regexp.MustCompile(`(?m)^Version:\s+v([0-9][^\s]*)`)

// NewCore probes the binary so a missing or wrong-arch executable fails here
// with a clear message instead of crash-looping inside the backend.
func NewCore(executablePath, configDir string, logBufferSize, startupLogTailSize int) (*Core, error) {
	if startupLogTailSize <= 0 {
		startupLogTailSize = defaultStartupLogTailSize
	}
	if logBufferSize <= 0 {
		logBufferSize = 1
	}

	core := &Core{
		executablePath: executablePath,
		configDir:      configDir,
		configFilePath: filepath.Join(configDir, "hysteria.json"),
		logsChan:       make(chan string, logBufferSize),
		startupPhase:   true,
		startupLogSize: startupLogTailSize,
	}

	version, err := core.refreshVersion()
	if err != nil {
		return nil, fmt.Errorf("hysteria at %s is unusable: %w", executablePath, err)
	}
	core.version = version
	return core, nil
}

func (c *Core) refreshVersion() (string, error) {
	cmd := exec.Command(c.executablePath, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	m := versionRe.FindStringSubmatch(out.String())
	if len(m) < 2 {
		return "", errors.New("could not parse hysteria version from `hysteria version` output")
	}
	return m[1], nil
}

func (c *Core) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func (c *Core) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.startedLocked()
}

func (c *Core) startedLocked() bool {
	if c.process == nil || c.process.Process == nil {
		return false
	}
	return c.process.ProcessState == nil
}

// ProcessState reports the OS process state, or nil while the core is running.
// Test/diagnostic use only: it is how a caller can tell "the core exited" apart
// from "the core refused the request".
func (c *Core) ProcessState() *os.ProcessState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil {
		return nil
	}
	return c.process.ProcessState
}

func (c *Core) Stopping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopping
}

// Uptime is how long the current child process has been running. Zero when the
// core is stopped or has not been started yet.
func (c *Core) Uptime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.startedLocked() || c.startedAt.IsZero() {
		return 0
	}
	return time.Since(c.startedAt)
}

func (c *Core) Restarting() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restarting
}

// SpawnCount is how many child processes this core has launched. Test/diagnostic
// use only: it is how a test proves an idle core spawns nothing.
func (c *Core) SpawnCount() int64 {
	return c.spawns.Load()
}

// writeConfigFile serializes the config for `hysteria server -c`.
//
// 0600, not 0644: the file carries every user's auth password and the traffic
// stats secret. Hysteria itself reads it as the same user it runs as, so this
// costs nothing and closes the "anyone who can read the config directory" hole
// that sing-box's quota secret already avoids by travelling in the environment.
func (c *Core) writeConfigFile(config *Config) error {
	buf, err := config.ToBytes()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	return os.WriteFile(c.configFilePath, buf, 0o600)
}

func (c *Core) Start(config *Config) error {
	if err := c.writeConfigFile(config); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.startedLocked() {
		return errors.New("hysteria is started already")
	}

	c.runtimeMu.Lock()
	c.runtimeLogs = nil
	c.runtimeMu.Unlock()

	c.startupMu.Lock()
	c.startupPhase = true
	c.startupLogs = nil
	c.startupFailure = ""
	c.startupMu.Unlock()

	if err := c.cleanupOrphanedProcesses(); err != nil {
		log.Printf("warning: failed to cleanup orphaned processes: %v", err)
	}

	if c.process != nil && c.process.Process != nil {
		pid := c.process.Process.Pid
		_ = c.process.Process.Kill()
		_ = proclib.KillProcessTree(pid)
		c.process = nil
	}

	cmd := exec.Command(c.executablePath, "server", "-c", c.configFilePath)
	proclib.SetProcAttributes(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	c.process = cmd
	c.stopping = false
	c.waitDone = make(chan struct{})
	c.startedAt = time.Now()
	c.spawns.Add(1)

	waitDone := c.waitDone
	go func() {
		waitErr := cmd.Wait()
		close(waitDone)
		c.handleProcessExit(cmd, waitErr)
	}()

	ctxCore, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel

	go c.captureProcessLogs(ctxCore, stdout)
	go c.captureProcessLogs(ctxCore, stderr)

	return nil
}

func (c *Core) handleProcessExit(cmd *exec.Cmd, err error) {
	c.mu.Lock()
	expected := c.stopping || c.process != cmd
	c.mu.Unlock()

	if expected {
		return
	}

	message := "hysteria process exited unexpectedly"
	if err != nil {
		message = fmt.Sprintf("%s: %v", message, err)
	}
	log.Println(message)
	c.recordProcessLog(message)
}

func (c *Core) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	started := c.startedLocked()
	if !started && c.process == nil && c.cancelFunc == nil && c.logger == nil {
		return
	}

	if started {
		pid := c.process.Process.Pid
		waitDone := c.waitDone
		c.stopping = true

		_ = c.process.Process.Kill()

		select {
		case <-waitDone:
		case <-time.After(5 * time.Second):
			log.Printf("hysteria process %d did not terminate within timeout, force killing", pid)
			_ = proclib.KillProcessTree(pid)
		}

		if err := proclib.VerifyProcessDead(pid); err != nil {
			log.Printf("warning: hysteria process %d may still be running: %v", pid, err)
			_ = proclib.KillProcessTree(pid)
		}
	}

	c.process = nil
	c.stopping = false
	c.waitDone = nil
	c.startedAt = time.Time{}

	if c.cancelFunc != nil {
		c.cancelFunc()
		c.cancelFunc = nil
	}
	if c.logger != nil {
		c.logger.Close()
		c.logger = nil
	}
	c.SwitchToRuntimeLogPhase()

	log.Println("hysteria core stopped")
}

func (c *Core) Restart(config *Config) error {
	c.mu.Lock()
	if c.restarting {
		c.mu.Unlock()
		return errors.New("hysteria is already restarting")
	}
	c.restarting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.restarting = false
		c.mu.Unlock()
	}()

	log.Println("restarting hysteria core...")
	c.Stop()
	return c.Start(config)
}

func (c *Core) Logs() <-chan string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logsChan
}

// SetLogger attaches the node's log sink. Called once by the backend after New
// has already started the child, so the child's early output reaches the file
// through the same recordProcessLog path either way.
//
// Binding happens HERE rather than in LogLines(): this core's per-core log file
// must be written whether or not anyone ever reads GetLogs. Binding only on the
// stream meant a core whose stream nobody opened wrote no per-core file at all,
// and the gate's disk half found a missing file rather than an empty one.
//
// It binds after the child has started, so any line logged before this call was
// already parked in the previous Logger's bounded backfill ring or dropped —
// which is exactly why that ring exists.
func (c *Core) SetLogger(debug bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logger != nil {
		c.logger.Close()
	}
	c.logger = nodeLogger.New(debug)
	c.logger.BindOnce(c.configDir)
}

func (c *Core) cleanupOrphanedProcesses() error {
	processes, err := proclib.FindProcesses(c.executablePath)
	if err != nil {
		return fmt.Errorf("failed to find hysteria processes: %w", err)
	}

	currentPID := 0
	if c.process != nil && c.process.Process != nil {
		currentPID = c.process.Process.Pid
	}

	nodePID := os.Getpid()

	killedCount := 0
	for _, procInfo := range processes {
		if procInfo.PID == currentPID {
			continue
		}

		kill := false
		reason := ""
		if procInfo.IsZombie && (procInfo.PPID == 0 || procInfo.PPID == 1) {
			kill = true
			reason = "zombie hysteria process without parent"
		} else if procInfo.PPID == nodePID {
			kill = true
			reason = fmt.Sprintf("orphaned hysteria process with node as parent (PPID: %d)", procInfo.PPID)
		}

		if !kill {
			continue
		}

		log.Printf("%s %d (PPID: %d), killing it", reason, procInfo.PID, procInfo.PPID)
		if err := proclib.KillProcessTree(procInfo.PID); err != nil {
			log.Printf("warning: failed to kill orphaned process %d: %v", procInfo.PID, err)
		} else {
			killedCount++
		}
	}

	if killedCount > 0 {
		log.Printf("cleaned up %d orphaned hysteria process(es)", killedCount)
	}
	return nil
}

// --- log capture / startup diagnostics -------------------------------------

func (c *Core) captureProcessLogs(ctx context.Context, pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			c.recordProcessLog(scanner.Text())
		}
	}
}

func (c *Core) recordProcessLog(line string) {
	c.startupMu.Lock()
	phase := c.startupPhase
	if phase {
		c.startupLogs = append(c.startupLogs, line)
		if len(c.startupLogs) > c.startupLogSize {
			c.startupLogs = c.startupLogs[len(c.startupLogs)-c.startupLogSize:]
		}
		if c.startupFailure == "" && isFatalLine(line) {
			c.startupFailure = line
		}
	}
	c.startupMu.Unlock()

	if !phase {
		c.runtimeMu.Lock()
		c.runtimeLogs = append(c.runtimeLogs, line)
		if len(c.runtimeLogs) > 10 {
			c.runtimeLogs = c.runtimeLogs[len(c.runtimeLogs)-10:]
		}
		c.runtimeMu.Unlock()
	}

	// Non-blocking send: never wedge the core on a full log buffer.
	select {
	case c.logsChan <- line:
	default:
	}

	if c.logger != nil {
		c.logger.Log(levelForLine(line), line)
	}
}

// isFatalLine reports whether a hysteria log line means the server refused to
// start. Hysteria logs its startup failure as FATAL (verified against v2.13.0:
// `FATAL  failed to load server config {"error": ...}`).
func isFatalLine(line string) bool {
	return strings.Contains(line, "FATAL")
}

func levelForLine(line string) nodeLogger.LogLevel {
	switch {
	case isFatalLine(line), strings.Contains(line, "ERROR"):
		return nodeLogger.LogError
	case strings.Contains(line, "WARN"):
		return nodeLogger.LogWarning
	default:
		return nodeLogger.LogInfo
	}
}

func (c *Core) isStartupLogPhase() bool {
	c.startupMu.RLock()
	defer c.startupMu.RUnlock()
	return c.startupPhase
}

func (c *Core) setStartupLogPhase() {
	c.startupMu.Lock()
	c.startupPhase = true
	c.startupMu.Unlock()
}

// SwitchToRuntimeLogPhase ends the startup tail: from here on a core that dies
// is a runtime problem, and only the last few lines are worth keeping.
func (c *Core) SwitchToRuntimeLogPhase() {
	c.startupMu.Lock()
	c.startupPhase = false
	c.startupMu.Unlock()
}

func (c *Core) LatestStartupFailure() string {
	c.startupMu.RLock()
	defer c.startupMu.RUnlock()
	return c.startupFailure
}

func (c *Core) StartupLogTail(n int) []string {
	c.startupMu.RLock()
	defer c.startupMu.RUnlock()
	return tailLines(c.startupLogs, n)
}

func (c *Core) RuntimeLogTail(n int) []string {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	return tailLines(c.runtimeLogs, n)
}

func tailLines(lines []string, n int) []string {
	if len(lines) == 0 {
		return nil
	}
	if n <= 0 || n > len(lines) {
		n = len(lines)
	}
	out := make([]string, n)
	copy(out, lines[len(lines)-n:])
	return out
}
