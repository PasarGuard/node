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

	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray/api"
	"github.com/m03ed/gozargah-node/common"
	nodeLogger "github.com/m03ed/gozargah-node/logger"
)

type Xray struct {
	config     *Config
	core       *Core
	handler    *api.XrayHandler
	configPath string
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
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

	xray := &Xray{configPath: configAbsolutePath, cancelFunc: xCancel}

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
	go xray.checkXrayHealth(xCtx)

	return xray, nil
}

func (x *Xray) setConfig(config *Config) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.config = config
}

func (x *Xray) getConfig() *Config {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.config
}

func (x *Xray) setCore(core *Core) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.core = core
}

func (x *Xray) getCore() *Core {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core
}

func (x *Xray) GetCore() backend.Core {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core
}

func (x *Xray) GetLogs() chan string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core.GetLogs()
}

func (x *Xray) GetVersion() string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core.GetVersion()
}

func (x *Xray) setHandler(handler *api.XrayHandler) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.handler = handler
}

func (x *Xray) getHandler() *api.XrayHandler {
	x.mu.RLock()
	defer x.mu.RUnlock()
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

func (x *Xray) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	return x.handler.GetUserOnlineStats(ctx, email)
}

func (x *Xray) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	return x.handler.GetUserOnlineIpListStats(ctx, email)
}

func (x *Xray) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	switch request.GetType() {

	case common.StatType_Outbounds:
		return x.handler.GetOutboundsStats(ctx, request.GetReset_())
	case common.StatType_Outbound:
		return x.handler.GetOutboundStats(ctx, request.GetName(), request.GetReset_())

	case common.StatType_Inbounds:
		return x.handler.GetInboundsStats(ctx, request.GetReset_())
	case common.StatType_Inbound:
		return x.handler.GetInboundStats(ctx, request.GetName(), request.GetReset_())

	case common.StatType_UsersStat:
		return x.handler.GetUsersStats(ctx, request.GetReset_())
	case common.StatType_UserStat:
		return x.handler.GetUserStats(ctx, request.GetName(), request.GetReset_())

	default:
		return nil, errors.New("not implemented stat type")
	}
}

func (x *Xray) GenerateConfigFile() error {
	x.mu.RLock()
	defer x.mu.RUnlock()

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

	// Precompile regex for better performance
	logRegex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^]]+)\] (.+)$`)

	for {
		select {
		case lastLog := <-logChan:
			if strings.Contains(lastLog, "Xray "+version+" started") {
				return nil
			}

			// Check for failure patterns
			matches := logRegex.FindStringSubmatch(lastLog)
			if len(matches) > 3 {
				// Check both error level and message content
				if matches[2] == "Error" || strings.Contains(matches[3], "Failed to start") {
					return fmt.Errorf("failed to start xray: %s", matches[3])
				}
			} else {
				// Fallback check if log format doesn't match
				if strings.Contains(lastLog, "Failed to start") {
					return fmt.Errorf("failed to start xray: %s", lastLog)
				}
			}

		case <-ctx.Done():
			return errors.New("failed to start xray: context timeout")
		}
	}
}

func (x *Xray) checkXrayHealth(baseCtx context.Context) {
	for {
		select {
		case <-baseCtx.Done():
			return
		default:
			ctx, cancel := context.WithTimeout(baseCtx, time.Second*3)
			_, err := x.GetSysStats(ctx)
			cancel() // Always call cancel to avoid context leak

			if err != nil {
				if errors.Is(err, context.Canceled) {
					// Context was canceled due to x.ctx cancellation
					return // Exit gracefully
				}

				// Handle other errors by attempting restart
				if err = x.Restart(); err != nil {
					nodeLogger.Log(nodeLogger.LogError, err.Error())
				} else {
					nodeLogger.Log(nodeLogger.LogInfo, "xray restarted")
				}
			}
		}
		time.Sleep(time.Second * 5)
	}
}
