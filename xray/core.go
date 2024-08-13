package xray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"

	cnf "marzban-node/config"
	log "marzban-node/logger"
)

type Core struct {
	executablePath string
	assetsPath     string
	version        string
	process        *exec.Cmd
	restarting     bool
	logsChan       chan string
	tempLogBuffers []string
	cancelFunc     context.CancelFunc
	mu             sync.Mutex
}

func NewXRayCore() (*Core, error) {
	var tempLog []string
	core := &Core{
		executablePath: cnf.XrayExecutablePath,
		assetsPath:     cnf.XrayAssetsPath,
		logsChan:       make(chan string, 100),
		tempLogBuffers: tempLog,
	}

	version, err := core.RefreshVersion()
	if err != nil {
		return nil, err
	}
	core.setVersion(version)

	return core, nil
}

func (x *Core) RefreshVersion() (string, error) {
	cmd := exec.Command(x.executablePath, "version")
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

func (x *Core) setVersion(version string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.version = version
}

func (x *Core) GetVersion() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.version
}

func (x *Core) Started() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.process == nil || x.process.Process == nil {
		return false
	}
	if x.process.ProcessState == nil {
		return true
	}
	return false
}

func (x *Core) Start(config *Config) error {
	if x.Started() {
		return errors.New("Xray is started already")
	}

	logLevel := config.Log.LogLevel
	if logLevel == "none" || logLevel == "error" {
		config.Log.LogLevel = "warning"
	}

	cmd := exec.Command(x.executablePath, "run", "-config", "stdin:")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+x.assetsPath)

	xrayJson, err := config.ToJSON()
	if err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	cmd.Stdin = bytes.NewBufferString(xrayJson)

	err = cmd.Start()
	if err != nil {
		return err
	}

	ctx := x.makeContext()

	x.process = cmd

	// Start capturing process logs
	go x.captureProcessLogs(ctx, stdout)
	go x.captureProcessLogs(ctx, stderr)
	go x.fillChannel(ctx)

	if cnf.Debug {
		var prettyJSON bytes.Buffer
		var jsonFile *os.File
		err = json.Indent(&prettyJSON, []byte(xrayJson), "", "    ")
		if err != nil {
			log.Error("Problem in formatting JSON: ", err)
		} else {
			jsonFile, err = os.Create(cnf.GeneratedConfigPath)
			if err != nil {
				log.Error("Can't create generated config json file", err)
			} else {
				_, err = jsonFile.WriteString(prettyJSON.String())
				if err != nil {
					log.Error("Problem in writing generated config json File: ", err)
				}
			}
		}
	}

	return nil
}

func (x *Core) Stop() {
	if !x.Started() {
		return
	}

	_ = x.process.Process.Kill()
	x.mu.Lock()
	defer x.mu.Unlock()
	x.process = nil

	x.cancelFunc()

	log.Warning("Xray core stopped")
}

func (x *Core) Restart(config *Config) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.restarting {
		return errors.New("Xray is already restarted")
	}

	x.restarting = true
	defer func() { x.restarting = false }()

	log.Warning("restarting Xray core...")
	x.Stop()
	err := x.Start(config)
	if err != nil {
		return err
	}
	return nil
}

func (x *Core) captureProcessLogs(ctx context.Context, pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			output := scanner.Text()
			if cnf.Debug {
				log.DetectLogType(output)
			}
			x.mu.Lock()
			x.tempLogBuffers = append(x.tempLogBuffers, output)
			x.mu.Unlock()
		}
	}
}

func (x *Core) tempLogPop(n int) []string {
	if n <= 0 {
		return nil
	}

	x.mu.Lock()
	defer x.mu.Unlock()

	if len(x.tempLogBuffers) == 0 {
		return nil
	}

	if n > len(x.tempLogBuffers) {
		n = len(x.tempLogBuffers)
	}

	logList := x.tempLogBuffers[:n]
	x.tempLogBuffers = x.tempLogBuffers[n:]
	return logList
}

func (x *Core) fillChannel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			chanLen := len(x.logsChan)
			if chanLen < 100 {
				logList := x.tempLogPop(100 - chanLen)
				if logList != nil {
					x.mu.Lock()
					for _, lastLog := range logList {
						x.logsChan <- lastLog
					}
					x.mu.Unlock()
				}
			}
		}
		time.Sleep(time.Millisecond * 100)
	}
}

func (x *Core) GetLogs() chan string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.logsChan
}

func (x *Core) makeContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	x.mu.Lock()
	defer x.mu.Unlock()
	x.cancelFunc = cancel
	return ctx
}
