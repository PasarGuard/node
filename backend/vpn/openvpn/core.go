package openvpn

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

// logf is the package's one line to the node's own log. Nothing that reaches
// it may contain a password — see the secret-hygiene test.
func logf(format string, args ...any) {
	log.Printf(format, args...)
}

// Core owns the openvpn child process. Same shape as hysteria's
// (backend/hysteria/core.go): config file on disk, stdout/stderr captured,
// startup tail kept for the error the panel shows when the child refuses to
// start.
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

	// spawns counts child processes actually launched, so a test can prove an
	// idle core starts nothing rather than inferring it from a log.
	spawns atomic.Int64

	// env is appended to the child's environment. The auth executable reads its
	// credential file path from here; openvpn passes its environment on to
	// scripts and executables it runs.
	env []string
}

const defaultStartupLogTailSize = 200

// versionRe matches the first line of `openvpn --version`, which reads
// "OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] …".
var versionRe = regexp.MustCompile(`(?m)^OpenVPN\s+(\S+)`)

// NewCore probes the binary so a missing or wrong-arch executable fails here
// with a clear message instead of crash-looping inside the backend.
func NewCore(executablePath, configDir string, logBufferSize, startupLogTailSize int) (*Core, error) {
	if startupLogTailSize <= 0 {
		startupLogTailSize = defaultStartupLogTailSize
	}
	if logBufferSize <= 0 {
		logBufferSize = 1
	}
	c := &Core{
		executablePath: executablePath,
		configDir:      configDir,
		configFilePath: filepath.Join(configDir, "server.conf"),
		logsChan:       make(chan string, logBufferSize),
		startupPhase:   true,
		startupLogSize: startupLogTailSize,
	}
	version, err := c.refreshVersion()
	if err != nil {
		return nil, fmt.Errorf("openvpn at %s is unusable: %w", executablePath, err)
	}
	c.version = version
	return c, nil
}

func (c *Core) refreshVersion() (string, error) {
	cmd := exec.Command(c.executablePath, "--version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	m := versionRe.FindStringSubmatch(out.String())
	if len(m) < 2 {
		return "", errors.New("could not parse the OpenVPN version from `openvpn --version` output")
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

// Uptime is how long the current child process has been running.
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

// SpawnCount is how many children this core has launched. Test/diagnostic use.
func (c *Core) SpawnCount() int64 {
	return c.spawns.Load()
}

// Start launches the child. The config file, the PKI and the roster must
// already be on disk — Start only runs the binary.
func (c *Core) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.startedLocked() {
		return errors.New("openvpn is started already")
	}
	if _, err := os.Stat(c.configFilePath); err != nil {
		return fmt.Errorf("openvpn: %s is missing: %w", filepath.Base(c.configFilePath), err)
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
		logf("warning: failed to cleanup orphaned openvpn processes: %v", err)
	}

	if c.process != nil && c.process.Process != nil {
		pid := c.process.Process.Pid
		_ = c.process.Process.Kill()
		_ = proclib.KillProcessTree(pid)
		c.process = nil
	}

	// A socket left by a killed child would make openvpn refuse to start
	// ("Unix socket already exists"). The old owner is gone; remove it.
	stale := filepath.Join(c.configDir, mgmtSocketFile)
	if err := os.Remove(stale); err != nil && !os.IsNotExist(err) {
		logf("openvpn: could not remove the stale management socket: %v", err)
	}

	// --cd first: every relative path in server.conf (ca.crt, ccd, mgmt.sock)
	// resolves against it.
	cmd := exec.Command(c.executablePath, "--cd", c.configDir, "--config", "server.conf")
	proclib.SetProcAttributes(cmd)
	cmd.Env = append(os.Environ(), c.env...)

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
	message := "openvpn process exited unexpectedly"
	if err != nil {
		message = fmt.Sprintf("%s: %v", message, err)
	}
	logf("%s", message)
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
			logf("openvpn process %d did not terminate within timeout, force killing", pid)
			_ = proclib.KillProcessTree(pid)
		}
		if err := proclib.VerifyProcessDead(pid); err != nil {
			logf("warning: openvpn process %d may still be running: %v", pid, err)
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
	logf("openvpn core stopped")
}

func (c *Core) Restart() error {
	c.mu.Lock()
	if c.restarting {
		c.mu.Unlock()
		return errors.New("openvpn is already restarting")
	}
	c.restarting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.restarting = false
		c.mu.Unlock()
	}()

	logf("restarting openvpn core...")
	c.Stop()
	return c.Start()
}

func (c *Core) Logs() <-chan string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logsChan
}

// SetLogger attaches the node's log sink and binds it to this core's directory
// on the way past, so core-<id>.log is written whether or not anyone ever
// opens GetLogs (the same lesson backend/hysteria/core.go:341-361 records).
func (c *Core) SetLogger(debug bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logger != nil {
		c.logger.Close()
	}
	c.logger = nodeLogger.New(debug)
	c.logger.BindOnce(c.configDir)
}

// LogLines is the classified stream, alongside the unchanged Logs() string
// channel. Binding here as well as in SetLogger is deliberate: a consumer that
// attaches before the first line still gets a live channel rather than nil.
func (c *Core) LogLines() <-chan nodeLogger.LogLine {
	if c.logger == nil {
		return nil
	}
	c.logger.BindOnce(c.configDir)
	return c.logger.LogLines()
}

func (c *Core) cleanupOrphanedProcesses() error {
	processes, err := proclib.FindProcesses(c.executablePath)
	if err != nil {
		return fmt.Errorf("failed to find openvpn processes: %w", err)
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
			reason = "zombie openvpn process without parent"
		} else if procInfo.PPID == nodePID {
			kill = true
			reason = fmt.Sprintf("orphaned openvpn process with node as parent (PPID: %d)", procInfo.PPID)
		}
		if !kill {
			continue
		}
		logf("%s %d (PPID: %d), killing it", reason, procInfo.PID, procInfo.PPID)
		if err := proclib.KillProcessTree(procInfo.PID); err != nil {
			logf("warning: failed to kill orphaned process %d: %v", procInfo.PID, err)
		} else {
			killedCount++
		}
	}
	if killedCount > 0 {
		logf("cleaned up %d orphaned openvpn process(es)", killedCount)
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

// isFatalLine reports whether a line means the server refused to start.
// openvpn prints "Options error: …" for a bad config and "ERROR: …" for the
// runtime class of failure; both are what the panel needs to see verbatim.
func isFatalLine(line string) bool {
	return strings.Contains(line, "Options error") ||
		strings.Contains(line, "ERROR:") ||
		strings.Contains(line, "FATAL")
}

func levelForLine(line string) nodeLogger.LogLevel {
	switch {
	case isFatalLine(line):
		return nodeLogger.LogError
	case strings.Contains(line, "WARNING"), strings.Contains(line, "WARN"):
		return nodeLogger.LogWarning
	default:
		return nodeLogger.LogInfo
	}
}

func (c *Core) SwitchToRuntimeLogPhase() {
	c.startupMu.Lock()
	c.startupPhase = false
	c.startupMu.Unlock()
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
