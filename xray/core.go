package xray

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	cnf "marzban-node/config"
	log "marzban-node/logger"
	"os"
	"os/exec"
	"regexp"
	"sync"
)

type Core struct {
	executablePath string
	assetsPath     string
	version        string
	process        *exec.Cmd
	restarting     bool
	logsChan       chan string
	cancelFunc     context.CancelFunc
	mu             sync.Mutex
}

func NewXRayCore() (*Core, error) {
	core := &Core{
		executablePath: cnf.XrayExecutablePath,
		assetsPath:     cnf.XrayAssetsPath,
		logsChan:       make(chan string),
	}

	version, err := core.refreshVersion()
	if err != nil {
		return nil, err
	}
	core.setVersion(version)

	return core, nil
}

func (x *Core) refreshVersion() (string, error) {
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

	accessFile, errorFile := config.RemoveLogFiles()

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

	log.SetLogFile(accessFile, errorFile)

	ctx := x.makeContext()

	x.process = cmd

	// Start capturing process logs
	go x.captureProcessLogs(ctx, stdout)
	go x.captureProcessLogs(ctx, stderr)

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
			log.DetectLogType(output)
			x.logsChan <- output
		}
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
