package xray

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"marzban-node/config"
	log "marzban-node/logger"
	"os"
	"os/exec"
	"regexp"
)

type XRayCore struct {
	ExecutablePath string
	AssetsPath     string
	Version        string
	Process        *exec.Cmd
	Restarting     bool
	LogsBuffer     []string
	TempLogBuffers map[int][]string
	OnStartFuncs   []func()
	OnStopFuncs    []func()
	Env            map[string]string
}

func NewXRayCore() (*XRayCore, error) {
	core := &XRayCore{
		ExecutablePath: config.XrayExecutablePath,
		AssetsPath:     config.XrayAssetsPath,
		LogsBuffer:     make([]string, 0, 100),
		TempLogBuffers: make(map[int][]string),
		OnStartFuncs:   make([]func(), 0),
		OnStopFuncs:    make([]func(), 0),
		Env: map[string]string{
			"XRAY_LOCATION_ASSET": config.XrayAssetsPath,
		},
	}

	version, err := core.GetVersion()
	if err != nil {
		return nil, err
	}
	core.Version = version

	return core, nil
}

func (x *XRayCore) GetVersion() (string, error) {
	cmd := exec.Command(x.ExecutablePath, "version")
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

func (x *XRayCore) CaptureProcessLogs() {
	if config.Debug {
		go func() {
			reader, writer := io.Pipe()
			x.Process.Stdout = writer
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				output := scanner.Text()
				x.LogsBuffer = append(x.LogsBuffer, output)
				for i := range x.TempLogBuffers {
					x.TempLogBuffers[i] = append(x.TempLogBuffers[i], output)
				}
				log.DebugLog(output)
			}
		}()
	} else {
		go func() {
			reader, writer := io.Pipe()
			x.Process.Stdout = writer
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				output := scanner.Text()
				x.LogsBuffer = append(x.LogsBuffer, output)
				for i := range x.TempLogBuffers {
					x.TempLogBuffers[i] = append(x.TempLogBuffers[i], output)
				}
			}
		}()
	}
}

func (x *XRayCore) GetLogs() []string {
	return x.LogsBuffer
}

func (x *XRayCore) Started() bool {
	if x.Process == nil {
		return false
	}

	err := x.Process.Process.Signal(os.Interrupt)
	if err != nil {
		return false
	}

	return true
}

func (x *XRayCore) Start(config XRayConfig) error {
	if x.Started() {
		return errors.New("Xray is started already")
	}

	logLevel := config.Log.LogLevel
	if logLevel == "none" || logLevel == "error" {
		config.Log.LogLevel = "warning"
	}

	cmd := exec.Command(x.ExecutablePath, "run", "-config", "stdin:")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+x.AssetsPath)
	xrayJson, err := config.ToJSON()
	if err != nil {
		return err
	}
	cmd.Stdin = bytes.NewBufferString(xrayJson)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return err
	}

	x.Process = cmd
	x.CaptureProcessLogs()

	// execute on start functions
	for _, f := range x.OnStartFuncs {
		go f()
	}

	return nil
}

func (x *XRayCore) Stop() {
	if !x.Started() {
		return
	}

	_ = x.Process.Process.Kill()
	x.Process = nil
	log.WarningLog("Xray core stopped")

	// execute on stop functions
	for _, f := range x.OnStopFuncs {
		go f()
	}
}

func (x *XRayCore) Restart(config XRayConfig) {
	if x.Restarting {
		return
	}

	x.Restarting = true
	defer func() { x.Restarting = false }()

	log.WarningLog("Restarting Xray core...")
	x.Stop()
	err := x.Start(config)
	if err != nil {
		log.ErrorLog("Failed to start core: ", err)
	}
}

func (x *XRayCore) OnStart(f func()) {
	x.OnStartFuncs = append(x.OnStartFuncs, f)
}

func (x *XRayCore) OnStop(f func()) {
	x.OnStopFuncs = append(x.OnStopFuncs, f)
}
