package rpc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/common"
)

// Tunnels is this node's tunnel manager: one instance per (tunnel_id, side),
// its own port allocator, its own per-tunnel log rings, and one JSON file per
// side under <GeneratedConfigPath>/tunnels so a tunnel comes back from config
// alone after the node process restarts.
//
// Created on first use so a proxy node that never hears a tunnel RPC pays
// nothing for the manager.
func (s *Service) Tunnels() *tunnel.Manager {
	s.tunnelOnce.Do(func() {
		cfg := s.Config()
		opts := tunnel.ManagerOptions{}
		if cfg != nil {
			opts.Dir = filepath.Join(cfg.GeneratedConfigPath, "tunnels")
			opts.BundleDir = cfg.TunnelBundleDir
		}
		s.tunnelMgr = tunnel.NewManager(opts)
	})
	return s.tunnelMgr
}

// Disconnect stops the tunnels first, then every core. Shadows the embedded
// Controller.Disconnect so a shutting-down node does not leave in-process
// relays and child processes behind.
func (s *Service) Disconnect() {
	if s.tunnelMgr != nil {
		s.tunnelMgr.Shutdown()
	}
	s.Controller.Disconnect()
}

// specFromProto maps the wire shape onto the adapter's Spec (CONTRACT §2.1).
// Secret NAMES travel; each becomes a Secrets entry with an empty value that
// the Manager resolves from the environment just before Start, so no value is
// ever carried on the wire in either direction.
func specFromProto(in *common.TunnelSpec) (tunnel.Spec, error) {
	side, err := tunnel.ParseSide(in.GetSide())
	if err != nil {
		return tunnel.Spec{}, err
	}
	spec := tunnel.Spec{
		TunnelID:    in.GetTunnelId(),
		Tool:        in.GetTool(),
		ToolVersion: in.GetToolVersion(),
		Side:        side,
		Mode:        in.GetMode(),
		Params:      map[string]string{},
		Secrets:     map[string]string{},
		Enabled:     in.GetEnabled(),
	}
	for k, v := range in.GetParams() {
		spec.Params[k] = v
	}
	for _, name := range in.GetSecretNames() {
		spec.Secrets[name] = ""
	}
	if err := spec.Validate(); err != nil {
		return tunnel.Spec{}, err
	}
	return spec, nil
}

// startCode maps a framework refusal onto the gRPC code the panel can act on.
// Spec problems are the caller's fault; a missing or mismatched binary is the
// node's environment; everything else from a Start is a failed start.
func startCode(err error) codes.Code {
	switch {
	case errors.Is(err, tunnel.ErrInvalidSpec),
		errors.Is(err, tunnel.ErrUnknownSide):
		return codes.InvalidArgument
	case errors.Is(err, tunnel.ErrSecretUnresolved),
		errors.Is(err, tunnel.ErrModeUnsupported),
		errors.Is(err, tunnel.ErrRoleRefused):
		return codes.FailedPrecondition
	case errors.Is(err, tunnel.ErrUnknownTool):
		return codes.Unimplemented
	case errors.Is(err, tunnel.ErrBinaryNotFound),
		errors.Is(err, tunnel.ErrBinaryMismatch):
		return codes.FailedPrecondition
	}
	return codes.Internal
}

// StartTunnel brings up one side of one tunnel and returns its status.
//
// Ports come from Params[listen_port] when the panel pinned one — it has to,
// because the other side's `peer` is written from the same number and
// TunnelStatus carries no port to read one back — and otherwise from the
// manager's allocator.
func (s *Service) StartTunnel(ctx context.Context, in *common.TunnelSpec) (*common.TunnelStatus, error) {
	spec, err := specFromProto(in)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	m := s.Tunnels()
	ports, err := portsForTunnel(m, spec)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := m.Start(ctx, spec, ports); err != nil {
		// The manager never took the instance, so the pair is still ours.
		m.Alloc().Release(ports)
		return nil, status.Errorf(startCode(err), "%v", err)
	}

	st, ok := m.Status(spec.TunnelID)
	if !ok {
		return nil, status.Errorf(codes.Internal, "tunnel %s did not survive its own start", spec.TunnelID)
	}
	return statusToProto(st), nil
}

// portsForTunnel honours a panel-pinned listen port, else allocates a pair.
func portsForTunnel(m *tunnel.Manager, spec tunnel.Spec) (tunnel.Ports, error) {
	raw := spec.Params[tunnel.ParamListenPort]
	if raw == "" {
		return m.Alloc().AllocPair(), nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65534 {
		return tunnel.Ports{}, fmt.Errorf("%s must be a port number 1-65534, got %q", tunnel.ParamListenPort, raw)
	}
	// Control is port+1 and is reserved with it, the same pair rule §1.4
	// gives every allocated port.
	return tunnel.Ports{Listen: port, Control: port + 1}, nil
}

// StopTunnel takes the tunnel down and forgets it, so a process restart does
// not bring it back: Stop is the panel saying "no longer", not a pause.
func (s *Service) StopTunnel(_ context.Context, in *common.TunnelId) (*common.Empty, error) {
	if err := s.Tunnels().Stop(in.GetTunnelId()); err != nil {
		if errors.Is(err, tunnel.ErrNotRunning) {
			return nil, status.Errorf(codes.NotFound, "%v", err)
		}
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &common.Empty{}, nil
}

// ListTunnels reports every side this node runs. One node normally runs one
// side per tunnel_id, so one row per tunnel in practice.
func (s *Service) ListTunnels(_ context.Context, _ *common.Empty) (*common.TunnelStatusList, error) {
	listed := s.Tunnels().List()
	out := &common.TunnelStatusList{Tunnels: make([]*common.TunnelStatus, 0, len(listed))}
	for _, st := range listed {
		out.Tunnels = append(out.Tunnels, statusToProto(st))
	}
	return out, nil
}

// GetTunnelSchemas publishes every adapter's params schema (glue-2): the
// dialog generates its field inputs from this reply instead of a hand-written
// form per tool. Render stays the authority on what a Spec accepts — a wrong
// entry here is a wrong form field, never a wrong config.
func (s *Service) GetTunnelSchemas(_ context.Context, _ *common.Empty) (*common.TunnelSchemas, error) {
	out := &common.TunnelSchemas{}
	for _, ts := range tunnel.Schemas() {
		tool := &common.ToolSchema{Tool: ts.Tool}
		for _, f := range ts.Params {
			tool.Params = append(tool.Params, &common.TunnelParamField{
				Key:         f.Key,
				RequiredFor: append([]string(nil), f.RequiredFor...),
				Help:        f.Help,
			})
		}
		out.Tools = append(out.Tools, tool)
	}
	return out, nil
}

// GetTunnelLogs is the live, multiplexed log stream: every record from every
// tunnel this node runs, each carrying its tunnel_id (CONTRACT §3.1 — same
// shape as GetLogs with core_id, filter client-side, no filter RPC).
func (s *Service) GetTunnelLogs(_ *common.Empty, stream common.NodeService_GetTunnelLogsServer) error {
	replay, ch, cancel := s.Tunnels().ReplayAndSubscribe(256)
	defer cancel()

	send := func(rec tunnel.Record) error {
		return stream.Send(&common.TunnelLog{
			TunnelId:  rec.TunnelID,
			Level:     rec.Level,
			TsUnixMs:  rec.TsUnixMs,
			Detail:    rec.Detail,
		})
	}

	// What the rings already hold first — a read path that only reported
	// records emitted after it opened would answer an operator's "show me the
	// logs" with nothing — then whatever arrives live. A record that was in a
	// ring *and* fanned out to this subscriber is sent once: the ring append
	// and the fan-out are not one critical section, so that overlap is real.
	pending := map[tunnel.Record]int{}
	for _, rec := range replay {
		pending[rec]++
		if err := send(rec); err != nil {
			return err
		}
	}
	for {
		select {
		case rec, ok := <-ch:
			if !ok {
				return nil
			}
			if pending[rec] > 0 {
				pending[rec]--
				continue
			}
			if err := send(rec); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func statusToProto(st tunnel.Status) *common.TunnelStatus {
	return &common.TunnelStatus{
		TunnelId:      st.TunnelID,
		State:         st.State,
		LastError:     st.LastError,
		Version:       st.Version,
		UptimeSeconds: st.UptimeSeconds,
		BytesUp:       st.BytesUp,
		BytesDown:     st.BytesDown,
		ListenPort:    st.ListenPort,
	}
}
