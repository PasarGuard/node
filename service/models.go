package service

import (
	"context"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	log "marzban-node/logger"
	"marzban-node/tools"
	"marzban-node/xray"
	"marzban-node/xray_api"
)

type Service struct {
	Router     chi.Router
	connected  bool
	clientIP   string
	sessionID  uuid.UUID
	core       *xray.Core
	config     *xray.Config
	apiPort    int
	xrayAPI    *xray_api.XrayAPI
	stats      tools.SystemStats
	cancelFunc context.CancelFunc
	mu         sync.Mutex
}

type session struct {
	SessionId string `json:"session_id"`
}

func (s *Service) Init() error {
	s.SetRouter()
	s.ResetAPIPort()
	err := s.ResetCore()
	if err != nil {
		return err
	}
	err = s.ResetXrayAPI()
	if err != nil {

	}
	return nil
}

func (s *Service) SetRouter() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Router = chi.NewRouter()
}

func (s *Service) GetRouter() chi.Router {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Router
}

func (s *Service) SetConnected(connected bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connected = connected
}

func (s *Service) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

func (s *Service) SetIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientIP = ip
}

func (s *Service) GetIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientIP
}

func (s *Service) SetSessionID(id uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = id
}

func (s *Service) GetSessionID() uuid.UUID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

func (s *Service) ResetCore() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	core, err := xray.NewXRayCore()
	if err != nil {
		return err
	}
	s.core = core
	return nil
}

func (s *Service) GetCore() *xray.Core {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core
}

func (s *Service) SetConfig(config *xray.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = config
}

func (s *Service) GetConfig() *xray.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *Service) ResetAPIPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiPort := tools.FindFreePort()
	s.apiPort = apiPort
	return apiPort
}

func (s *Service) GetAPIPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.apiPort
}

func (s *Service) ResetXrayAPI() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	api, err := xray_api.NewXrayAPI(s.apiPort)
	if err != nil {
		log.Error("Failed to create new xray client: ", err)
		return nil
	}
	s.xrayAPI = api
	return nil
}

func (s *Service) GetXrayAPI() *xray_api.XrayAPI {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.xrayAPI
}

func (s *Service) startJobs() {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelFunc = cancel
	go s.getSystemStats(ctx)
}

func (s *Service) StopJobs() {
	s.GetCore().Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelFunc()
}

func (s *Service) getSystemStats(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			break
		default:
			stats, err := tools.GetSystemStats()
			if err != nil {
				log.Error("Failed to get system stats: ", err)
			} else {
				s.mu.Lock()
				s.stats = stats
				s.mu.Unlock()
			}
			time.Sleep(1 * time.Second)
		}
	}
}

type UserData struct {
	User xray.User `json:"user"`
}
