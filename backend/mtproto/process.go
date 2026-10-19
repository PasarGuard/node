package mtproto

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/pkg/logstream"
)

// telemtCommandTimeout bounds the short-lived telemt invocations (--version,
// reload) so a wedged binary cannot block startup or a live reload forever.
const telemtCommandTimeout = 30 * time.Second

type commandFactory func(executable string, args ...string) *exec.Cmd

type processManager struct {
	executablePath string
	configPath     string
	pidFilePath    string
	logs           *logstream.Buffer
	version        string
	commandFactory commandFactory

	mu     sync.RWMutex
	cmd    *exec.Cmd
	waitCh chan error
}

func newProcessManager(executablePath, configPath, pidFilePath string, logBufferSize int) (*processManager, error) {
	if strings.TrimSpace(executablePath) == "" {
		return nil, fmt.Errorf("telemt executable path must not be empty")
	}

	absExecutablePath, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, err
	}
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	absPIDFilePath, err := filepath.Abs(pidFilePath)
	if err != nil {
		return nil, err
	}

	manager := &processManager{
		executablePath: absExecutablePath,
		configPath:     absConfigPath,
		pidFilePath:    absPIDFilePath,
		logs:           logstream.NewBuffer(logBufferSize),
		commandFactory: func(executable string, args ...string) *exec.Cmd {
			return exec.Command(executable, args...)
		},
	}

	manager.version, err = manager.detectVersion()
	if err != nil {
		return nil, err
	}

	return manager, nil
}

func (p *processManager) detectVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), telemtCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.executablePath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("telemt --version timed out after %s: %w", telemtCommandTimeout, ctx.Err())
		}
		return "", fmt.Errorf("failed to detect telemt version: %w", err)
	}

	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "telemt") {
		return fields[1], nil
	}
	if line == "" {
		return "", fmt.Errorf("failed to detect telemt version: empty output")
	}
	return line, nil
}

func (p *processManager) Version() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

func (p *processManager) SubscribeLogs(ctx context.Context) <-chan string {
	return p.logs.Subscribe(ctx)
}

func (p *processManager) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.startedLocked() {
		return fmt.Errorf("telemt process is already running")
	}

	if err := os.MkdirAll(filepath.Dir(p.configPath), 0o755); err != nil {
		return fmt.Errorf("failed to create telemt config directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(p.pidFilePath), 0o755); err != nil {
		return fmt.Errorf("failed to create telemt pid directory: %w", err)
	}

	cmd := p.commandFactory(p.executablePath, "run", "--pid-file", p.pidFilePath, p.configPath)
	// Pin telemt's working directory to the generated-config dir so its
	// relative-path artifacts (e.g. the tls_front cache) stay contained there
	// instead of littering the node's working directory.
	cmd.Dir = filepath.Dir(p.configPath)
	setProcessAttributes(cmd)

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

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	go p.captureLogs(stdout)
	go p.captureLogs(stderr)

	p.cmd = cmd
	p.waitCh = waitCh
	return nil
}

func (p *processManager) WaitChan() <-chan error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.waitCh
}

func (p *processManager) PID() int32 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return int32(p.cmd.Process.Pid)
}

func (p *processManager) Started() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.startedLocked()
}

func (p *processManager) startedLocked() bool {
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

func (p *processManager) Reload() error {
	ctx, cancel := context.WithTimeout(context.Background(), telemtCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.executablePath, "reload", "--pid-file", p.pidFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("telemt reload timed out after %s: %w", telemtCommandTimeout, ctx.Err())
		}
		return fmt.Errorf("failed to reload telemt: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (p *processManager) Shutdown() {
	p.mu.Lock()
	cmd := p.cmd
	waitCh := p.waitCh
	p.cmd = nil
	p.waitCh = nil
	p.mu.Unlock()

	if cmd == nil {
		return
	}

	_ = terminateProcess(cmd)
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-time.After(5 * time.Second):
			_ = killProcess(cmd)
			<-waitCh
		}
	}
}

func (p *processManager) Restart() error {
	p.Shutdown()
	return p.Start()
}

func (p *processManager) captureLogs(pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		p.logs.Publish(scanner.Text())
	}
}
