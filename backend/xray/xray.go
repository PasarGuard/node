package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/m03ed/marzban-node-go/backend"
	"github.com/m03ed/marzban-node-go/backend/xray/api"
	"github.com/m03ed/marzban-node-go/common"
	nodeLogger "github.com/m03ed/marzban-node-go/logger"
)

type Xray struct {
	config     *Config
	core       *Core
	handler    *api.XrayHandler
	configPath string
	ctx        context.Context
	cancelFunc context.CancelFunc
	mu         sync.Mutex
}

func NewXray(ctx context.Context, port int, executablePath, assetsPath, configPath string) (*Xray, error) {
	executableAbsolutePath, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, err
	}

	assetsAbsolutePath, err := filepath.Abs(assetsPath)
	if err != nil {
		return nil, err
	}

	configAbsolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	xCtx, xCancel := context.WithCancel(context.Background())

	xray := &Xray{configPath: configAbsolutePath, ctx: xCtx, cancelFunc: xCancel}

	start := time.Now()

	config, ok := ctx.Value(backend.ConfigKey{}).(*Config)
	if !ok {
		return nil, errors.New("xray config has not been initialized")
	}

	if err = config.ApplyAPI(port); err != nil {
		return nil, err
	}

	users := ctx.Value(backend.UsersKey{}).([]*common.User)
	config.syncUsers(users)

	xray.setConfig(config)

	if err = xray.GenerateConfigFile(); err != nil {
		return nil, err
	}

	log.Println("config generated in", time.Since(start).Seconds(), "second.")

	core, err := NewXRayCore(executableAbsolutePath, assetsAbsolutePath, configAbsolutePath)
	if err != nil {
		return nil, err
	}

	if err = core.Start(config); err != nil {
		return nil, err
	}

	xray.setCore(core)

	if err = xray.checkXrayStatus(); err != nil {
		xray.Shutdown()
		return nil, err
	}

	handler, err := api.NewXrayAPI(port)
	if err != nil {
		xray.Shutdown()
		return nil, err
	}
	xray.setHandler(handler)
	go xray.checkXrayHealth()

	return xray, nil
}

func (x *Xray) setConfig(config *Config) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.config = config
}

func (x *Xray) getConfig() *Config {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.config
}

func (x *Xray) setCore(core *Core) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.core = core
}

func (x *Xray) getCore() *Core {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.core
}

func (x *Xray) GetCore() backend.Core {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.core
}

func (x *Xray) GetLogs() chan string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.core.GetLogs()
}

func (x *Xray) GetVersion() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.core.GetVersion()
}

func (x *Xray) setHandler(handler *api.XrayHandler) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.handler = handler
}

func (x *Xray) getHandler() *api.XrayHandler {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.handler
}

func (x *Xray) Started() bool {
	return x.core.Started()
}

func (x *Xray) Restart() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.core.Restart(x.config); err != nil {
		return err
	}
	return nil
}

func (x *Xray) Shutdown() {
	x.mu.Lock()
	defer x.mu.Unlock()

	x.cancelFunc()

	if x.core != nil {
		x.core.Stop()
	}
	if x.handler != nil {
		x.handler.Close()
	}
}

func (x *Xray) GetSysStats(ctx context.Context) (*common.BackendStatsResponse, error) {
	return x.handler.GetSysStats(ctx)
}

func (x *Xray) GetUsersStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	return x.handler.GetUsersStats(ctx, reset)
}

func (x *Xray) GetUserStats(ctx context.Context, email string, reset bool) (*common.StatResponse, error) {
	return x.handler.GetUserStats(ctx, email, reset)
}

func (x *Xray) GetStatOnline(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	return x.handler.GetStatOnline(ctx, email)
}

func (x *Xray) GetOutboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	return x.handler.GetOutboundsStats(ctx, reset)
}

func (x *Xray) GetOutboundStats(ctx context.Context, tag string, reset bool) (*common.StatResponse, error) {
	return x.handler.GetOutboundStats(ctx, tag, reset)
}

func (x *Xray) GetInboundsStats(ctx context.Context, reset bool) (*common.StatResponse, error) {
	return x.handler.GetInboundsStats(ctx, reset)
}

func (x *Xray) GetInboundStats(ctx context.Context, tag string, reset bool) (*common.StatResponse, error) {
	return x.handler.GetInboundStats(ctx, tag, reset)
}

func (x *Xray) GenerateConfigFile() error {
	x.mu.Lock()
	defer x.mu.Unlock()

	var prettyJSON bytes.Buffer

	config, err := x.config.ToJSON()
	if err != nil {
		return err
	}

	if err = json.Indent(&prettyJSON, []byte(config), "", "    "); err != nil {
		return err
	}

	// Ensure the directory exists
	if err = os.MkdirAll(x.configPath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	jsonFile, err := os.Create(filepath.Join(x.configPath, "xray.json"))
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	_, err = jsonFile.WriteString(prettyJSON.String())
	return err
}

func (x *Xray) checkXrayStatus() error {
	core := x.getCore()

	logChan := core.GetLogs()
	version := core.GetVersion()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

Loop:
	for {
		select {
		case lastLog := <-logChan:
			if strings.Contains(lastLog, "Xray "+version+" started") {
				break Loop
			} else {
				regex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^]]+)\] (.+)$`)
				matches := regex.FindStringSubmatch(lastLog)
				if len(matches) > 3 && matches[2] == "Error" {
					return errors.New("Failed to start xray: " + matches[3])
				}
			}
		case <-ctx.Done():
			return errors.New("failed to start xray: context done")
		}
	}
	return nil
}

func (x *Xray) checkXrayHealth() {
	for {
		select {
		case <-x.ctx.Done():
			return
		default:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
			if _, err := x.GetSysStats(ctx); err != nil {
				if err = x.Restart(); err != nil {
					nodeLogger.Log(nodeLogger.LogError, err.Error())
				} else {
					nodeLogger.Log(nodeLogger.LogInfo, "xray restarted")
				}
			}
			cancel()
		}
		time.Sleep(time.Second * 2)
	}
}
