package singbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"time"

	"github.com/pasarguard/node/backend/proclib"
	nodeLogger "github.com/pasarguard/node/logger"
)

// Core owns the sing-box child process. Unlike xray (config on stdin), sing-box
// only accepts a config file path, so the config is always written to disk.
type Core struct {
	executablePath string
	configDir      string
	configFilePath string
	version        string
	hasV2rayAPI    bool
	process        *exec.Cmd
	restarting     bool
	stopping       bool
	waitDone       chan struct{}
	quotaSecret    string
	hasQuotaPatch  bool
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
}

// quotaSecretEnv is the variable the sing-box child reads to authenticate its
// quota control endpoint. The constant is declared here rather than imported so
// the node and the core patch cannot drift apart silently: the test below
// asserts both agree on the spelling.
const quotaSecretEnv = "SINGBOX_QUOTA_SECRET"

// NewSingBoxCore probes the binary and, unless allowMissing is set
// (SINGBOX_ALLOW_MISSING_V2RAY_API=1), refuses a build without the
// v2ray_api tag — running it would silently lose per-user stats.
func NewSingBoxCore(executablePath, configDir string, logBufferSize, startupLogTailSize int, allowMissing bool, quotaSecret ...string) (*Core, error) {
	if startupLogTailSize <= 0 {
		startupLogTailSize = 200
	}
	if logBufferSize <= 0 {
		logBufferSize = 1
	}

	secret := ""
	for _, candidate := range quotaSecret {
		if candidate != "" {
			secret = candidate
			break
		}
	}
	if secret == "" {
		// Generated here when not supplied, so a caller cannot accidentally
		// start a core whose control endpoint is unauthenticated.
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err == nil {
			secret = hex.EncodeToString(buf)
		}
	}

	core := &Core{
		quotaSecret:    secret,
		executablePath: executablePath,
		configDir:      configDir,
		configFilePath: filepath.Join(configDir, "singbox.json"),
		logsChan:       make(chan string, logBufferSize),
		startupPhase:   true,
		startupLogSize: startupLogTailSize,
	}

	version, hasV2rayAPI, err := core.refreshVersion()
	if err != nil {
		return nil, err
	}
	core.version = version
	core.hasQuotaPatch = isQuotaPatchedOutput(version)
	if !core.hasQuotaPatch {
		log.Printf("WARNING: sing-box at %s has no quota patch (version %q): in-core byte-exact limits are unavailable and the panel will use adaptive polling",
			executablePath, version)
	}
	if !hasV2rayAPI && !allowMissing {
		return nil, fmt.Errorf(
			"sing-box at %s was built WITHOUT -tags with_v2ray_api: per-user traffic stats would silently stay at zero. "+
				"Install a stats-capable build (make build_singbox_v2api / Dockerfile.singbox) or set SINGBOX_ALLOW_MISSING_V2RAY_API=1 to run without usage accounting",
			executablePath,
		)
	}
	if !hasV2rayAPI {
		log.Printf("WARNING: sing-box at %s runs without -tags with_v2ray_api (SINGBOX_ALLOW_MISSING_V2RAY_API=1); per-user usage will NOT be recorded", executablePath)
	}

	return core, nil
}

func (c *Core) refreshVersion() (string, bool, error) {
	cmd := exec.Command(c.executablePath, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", false, err
	}

	text := out.String()
	// A binary built straight from source (no ldflags version metadata) reports
	// "sing-box version unknown"; keep the string so the panel can show it.
	m := regexp.MustCompile(`sing-box version (\S+)`).FindStringSubmatch(text)
	if len(m) < 2 {
		return "", false, errors.New("could not parse sing-box version")
	}
	return m[1], strings.Contains(text, "with_v2ray_api"), nil
}

// quotaPatchMarker is the version suffix Dockerfile.singbox stamps onto a binary
// built from the quota patch. Reading it is how "auto" mode decides whether
// byte-exact limits are available, without having to run the core.
const quotaPatchMarker = "quota-v1"

// isQuotaPatchedOutput reports whether a `sing-box version` string carries the
// patch marker. The marker is deliberately a version suffix rather than a
// separate probe: it is already printed by every build, so there is nothing
// extra to keep in sync.
func isQuotaPatchedOutput(version string) bool {
	return strings.Contains(version, quotaPatchMarker)
}

// isQuotaPatched runs `sing-box version` for a path. Separate from
// isQuotaPatchedOutput so a caller that already has the string does not pay
// for a subprocess.
func isQuotaPatched(executablePath string) bool {
	cmd := exec.Command(executablePath, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return false
	}
	return isQuotaPatchedOutput(out.String())
}

// HasQuotaPatch reports whether the running binary carries the in-core quota
// enforcement patch.
func (c *Core) HasQuotaPatch() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hasQuotaPatch
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
	if c.process.ProcessState == nil {
		return true
	}
	return false
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

func (c *Core) Restarting() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.restarting
}

// writeConfigFile serializes the config for sing-box -c.
func (c *Core) writeConfigFile(config *Config) error {
	buf, err := json.MarshalIndent(config.raw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	return os.WriteFile(c.configFilePath, buf, 0o644)
}

// checkConfig runs `sing-box check -c` on the written config.
func (c *Core) checkConfig() error {
	cmd := exec.Command(c.executablePath, "check", "-c", c.configFilePath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("sing-box config check failed: %s", detail)
}

func (c *Core) Start(config *Config, debugMode bool) error {
	if err := c.writeConfigFile(config); err != nil {
		return err
	}

	// Validate the exact config (post user-injection) before spawning; a bad
	// config must surface as a clean API error, not a crash-looping process.
	if err := c.checkConfig(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.startedLocked() {
		return errors.New("sing-box is started already")
	}

	c.runtimeMu.Lock()
	c.runtimeLogs = nil
	c.runtimeMu.Unlock()

	c.startupMu.Lock()
	c.startupPhase = true
	c.startupLogs = nil
	c.startupFailure = ""
	c.startupMu.Unlock()

	// Clean up any orphaned sing-box processes before starting a new one
	if err := c.cleanupOrphanedProcesses(); err != nil {
		log.Printf("warning: failed to cleanup orphaned processes: %v", err)
	}

	// Force kill any orphaned process from a previous run of this Core
	if c.process != nil && c.process.Process != nil {
		pid := c.process.Process.Pid
		_ = c.process.Process.Kill()
		_ = proclib.KillProcessTree(pid)
		c.process = nil
	}

	cmd := exec.Command(c.executablePath, "run", "-c", c.configFilePath)
	// The secret reaches the child through its environment and nowhere else:
	// not the config file (which is copied into images and crash dumps), not
	// the logs, not any RPC response.
	env := os.Environ()
	if c.quotaSecret != "" {
		env = append(env, quotaSecretEnv+"="+c.quotaSecret)
	}
	cmd.Env = env
	proclib.SetProcAttributes(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	c.logger = nodeLogger.New(debugMode)

	if err := cmd.Start(); err != nil {
		return err
	}
	c.process = cmd
	c.stopping = false
	c.waitDone = make(chan struct{})

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

	message := "sing-box process exited unexpectedly"
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
			log.Printf("sing-box process %d did not terminate within timeout, force killing", pid)
			_ = proclib.KillProcessTree(pid)
		}

		if err := proclib.VerifyProcessDead(pid); err != nil {
			log.Printf("warning: sing-box process %d may still be running: %v", pid, err)
			_ = proclib.KillProcessTree(pid)
		}
	}

	c.process = nil
	c.stopping = false
	c.waitDone = nil

	if c.cancelFunc != nil {
		c.cancelFunc()
		c.cancelFunc = nil
	}
	if c.logger != nil {
		c.logger.Close()
		c.logger = nil
	}
	c.SwitchToRuntimeLogPhase()

	log.Println("sing-box core stopped")
}

func (c *Core) Restart(config *Config, debugMode bool) error {
	c.mu.Lock()
	if c.restarting {
		c.mu.Unlock()
		return errors.New("sing-box is already restarting")
	}
	c.restarting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.restarting = false
		c.mu.Unlock()
	}()

	log.Println("restarting sing-box core...")
	c.Stop()
	return c.Start(config, debugMode)
}

func (c *Core) Logs() <-chan string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logsChan
}

// ProcessInfo holds information about a process
type ProcessInfo = proclib.ProcessInfo

func (c *Core) cleanupOrphanedProcesses() error {
	processes, err := proclib.FindProcesses(c.executablePath)
	if err != nil {
		return fmt.Errorf("failed to find sing-box processes: %w", err)
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
			reason = "zombie sing-box process without parent"
		} else if procInfo.PPID == nodePID {
			kill = true
			reason = fmt.Sprintf("orphaned sing-box process with node as parent (PPID: %d)", procInfo.PPID)
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
		log.Printf("cleaned up %d orphaned sing-box process(es)", killedCount)
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
		if c.startupFailure == "" && strings.Contains(line, "FATAL") {
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

	// Non-blocking send: never wedge the core on a full log buffer
	select {
	case c.logsChan <- line:
	default:
	}

	if c.logger != nil {
		level := nodeLogger.LogInfo
		if strings.Contains(line, "ERR[") || strings.Contains(line, "FATAL") {
			level = nodeLogger.LogError
		}
		c.logger.Log(level, line)
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
