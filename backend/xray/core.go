package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/pasarguard/node/config"
	nodeLogger "github.com/pasarguard/node/logger"
)

type Core struct {
	executablePath string
	assetsPath     string
	configPath     string
	version        string
	process        *exec.Cmd
	restarting     bool
	logsChan       chan string
	cancelFunc     context.CancelFunc
	mu             sync.Mutex
}

func NewXRayCore(executablePath, assetsPath, configPath string) (*Core, error) {
	core := &Core{
		executablePath: executablePath,
		assetsPath:     assetsPath,
		configPath:     configPath,
		logsChan:       make(chan string, config.LogBufferSize),
	}

	version, err := core.refreshVersion()
	if err != nil {
		return nil, err
	}
	core.version = version

	return core, nil
}

func (c *Core) GenerateConfigFile(config []byte) error {
	var prettyJSON bytes.Buffer

	if err := json.Indent(&prettyJSON, config, "", "    "); err != nil {
		return err
	}

	// Ensure the directory exists
	if err := os.MkdirAll(c.configPath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	jsonFile, err := os.Create(filepath.Join(c.configPath, "xray.json"))
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	_, err = jsonFile.Write(prettyJSON.Bytes())
	return err
}

func (c *Core) refreshVersion() (string, error) {
	cmd := exec.Command(c.executablePath, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	r := regexp.MustCompile(`^Xray (\d+\.\d+\.\d+)`)
	matches := r.FindStringSubmatch(out.String())
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", errors.New("could not parse Xray version")
}

func (c *Core) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func (c *Core) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.process == nil || c.process.Process == nil {
		return false
	}
	if c.process.ProcessState == nil {
		return true
	}
	return false
}

func (c *Core) Start(xConfig *Config) error {
	logConfig := xConfig.LogConfig
	if logConfig == nil {
		return errors.New("log config is empty")
	}

	logLevel := logConfig.LogLevel
	if logLevel == "none" || logLevel == "error" {
		xConfig.LogConfig.LogLevel = "warning"
	}

	accessFile, errorFile := xConfig.RemoveLogFiles()

	bytesConfig, err := xConfig.ToBytes()
	if config.Debug {
		if err = c.GenerateConfigFile(bytesConfig); err != nil {
			return err
		}
	}

	if c.Started() {
		return errors.New("xray is started already")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := exec.Command(c.executablePath, "-c", "stdin:")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+c.assetsPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err = nodeLogger.SetLogFile(accessFile, errorFile); err != nil {
		return err
	}

	cmd.Stdin = bytes.NewBuffer(bytesConfig)
	if err = cmd.Start(); err != nil {
		return err
	}
	c.process = cmd

	// Wait for the process to exit to prevent zombie processes
	go func() {
		_ = cmd.Wait()
	}()

	ctxCore, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel

	// Start capturing process logs
	go c.captureProcessLogs(ctxCore, stdout)
	go c.captureProcessLogs(ctxCore, stderr)

	return nil
}

func (c *Core) Stop() {
	if !c.Started() {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.process != nil && c.process.Process != nil {
		_ = c.process.Process.Kill()
	}
	c.process = nil

	if c.cancelFunc != nil {
		c.cancelFunc()
	}

	log.Println("xray core stopped")
}

func (c *Core) Restart(config *Config) error {
	if c.restarting {
		return errors.New("xray is already restarted")
	}

	c.mu.Lock()
	c.restarting = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.restarting = false
		c.mu.Unlock()
	}()

	log.Println("restarting Xray core...")
	c.Stop()
	if err := c.Start(config); err != nil {
		return err
	}
	return nil
}

func (c *Core) Logs() chan string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.logsChan
}
