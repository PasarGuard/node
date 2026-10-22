package xray

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// No "log" section on purpose: the node adds one at start, and a live update
// must not take that for a change.
const liveSessionConfig = `{
	"inbounds": [{
		"tag": "VLESS TCP SESSION",
		"listen": "127.0.0.1",
		"port": %d,
		"protocol": "vless",
		"settings": {"clients": [], "decryption": "none"}
	}],
	"outbounds": [%s],
	"routing": {"rules": [%s]}
}`

const (
	liveDirect      = `{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}}`
	liveDirectAsIs  = `{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs", "finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}}`
	liveBlock       = `{"tag": "block", "protocol": "blackhole"}`
	liveBlockHTTP   = `{"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}`
	liveRuleToBlock = `{"type": "field", "ruleTag": "pg-live", "domain": ["example.com"], "outboundTag": "block"}`
)

func corePID(back *Xray) int {
	back.core.mu.Lock()
	defer back.core.mu.Unlock()
	return back.core.processPID
}

func TestApplyConfigLiveKeepsOpenConnections(t *testing.T) {
	source := startByteSource(t)
	inboundPort := netutil.FindFreePort()
	configWith := func(outbounds, rules string) string {
		return fmt.Sprintf(liveSessionConfig, inboundPort, outbounds, rules)
	}

	xrayConfig, err := NewConfig(configWith(liveDirect, ""), nil)
	if err != nil {
		t.Fatal(err)
	}

	aliceID := uuid.New()
	back, err := New(
		context.Background(),
		xrayConfig,
		[]*common.User{sessionUser("1.alice", aliceID, sessionTestInbound)},
		netutil.FindFreePort(),
		netutil.FindFreePort(),
		&config.Config{
			XrayExecutablePath:  executablePath,
			XrayAssetsPath:      assetsPath,
			GeneratedConfigPath: configPath,
			LogBufferSize:       1000,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pid := corePID(back)
	stream := openVlessStream(t, inboundPort, aliceID, source)
	requireFlowing(t, stream, "before any live update")

	updates := []struct {
		name   string
		config string
	}{
		{"same config again", configWith(liveDirect, "")},
		{"new outbound and rule", configWith(liveDirect+", "+liveBlock, liveRuleToBlock)},
		{"edited outbound", configWith(liveDirect+", "+liveBlockHTTP, liveRuleToBlock)},
		{"edited default outbound", configWith(liveDirectAsIs+", "+liveBlockHTTP, liveRuleToBlock)},
	}
	for _, update := range updates {
		applied, err := back.ApplyConfigLive(ctx, update.config, nil)
		if err != nil || !applied {
			t.Fatalf("%s: ApplyConfigLive = %v, %v; want applied", update.name, applied, err)
		}
		requireFlowing(t, stream, "after a live update: "+update.name)
	}

	rules, err := back.ListRoutingRules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rule := range rules.GetRules() {
		found = found || rule.GetRuleTag() == "pg-live"
	}
	if !found {
		t.Fatal("the rule added by the live update is not in xray")
	}

	requireFlowing(t, openVlessStream(t, inboundPort, aliceID, source), "on a new connection after the live updates")

	if got := corePID(back); got != pid {
		t.Fatalf("xray restarted during the live updates: pid %d, then %d", pid, got)
	}

	moved := fmt.Sprintf(liveSessionConfig, netutil.FindFreePort(), liveDirectAsIs+", "+liveBlockHTTP, liveRuleToBlock)
	if applied, err := back.ApplyConfigLive(ctx, moved, nil); err != nil || applied {
		t.Fatalf("inbound change: ApplyConfigLive = %v, %v; want a restart request", applied, err)
	}
}
