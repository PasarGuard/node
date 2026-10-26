package mtproto

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
)

const testSecret = "00112233445566778899aabbccddeeff"

func mtUser(email, tag, secret string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: []string{tag},
		Proxies:  &common.Proxy{Mtproto: &common.Mtproto{Secret: secret}},
	}
}

func TestGetOutboundsLatency_Empty(t *testing.T) {
	m := &MTProto{}
	resp, err := m.GetOutboundsLatency(context.Background(), &common.LatencyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || len(resp.GetLatencies()) != 0 {
		t.Errorf("expected empty latency response, got %+v", resp)
	}
}

func TestBuildPatchUserRequest_ClearsOptionalFields(t *testing.T) {
	payload, err := buildPatchUserRequest(&runtimeUser{
		Username: "alice",
		Secret:   testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got := string(encoded)
	for _, want := range []string{
		`"secret":"` + testSecret + `"`,
		`"user_ad_tag":null`,
		`"max_tcp_conns":null`,
		`"max_unique_ips":null`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patch JSON missing %s: %s", want, got)
		}
	}

	// No secret: the patch leaves telemt's secret as it is.
	noSecret, err := buildPatchUserRequest(&runtimeUser{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := json.Marshal(noSecret); strings.Contains(string(encoded), "secret") {
		t.Errorf("patch JSON without a secret sends one: %s", encoded)
	}

	tag := "aabbccddeeff00112233445566778899"
	setPayload, err := buildPatchUserRequest(&runtimeUser{
		Username:     "alice",
		Secret:       testSecret,
		UserAdTag:    tag,
		MaxTCPConns:  4,
		MaxUniqueIPs: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if setPayload.UserAdTag == nil || *setPayload.UserAdTag != tag {
		t.Errorf("user_ad_tag = %v, want %s", setPayload.UserAdTag, tag)
	}
	if setPayload.MaxTCPConns == nil || *setPayload.MaxTCPConns != 4 {
		t.Errorf("max_tcp_conns = %v, want 4", setPayload.MaxTCPConns)
	}
	if setPayload.MaxUniqueIPs == nil || *setPayload.MaxUniqueIPs != 2 {
		t.Errorf("max_unique_ips = %v, want 2", setPayload.MaxUniqueIPs)
	}
}

func TestBuildCreateUserRequest_OmitsUnsetFields(t *testing.T) {
	encoded, err := json.Marshal(buildCreateUserRequest(&runtimeUser{Username: "alice", Secret: testSecret}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"username":"alice","secret":"`+testSecret+`"}`; got != want {
		t.Errorf("create JSON = %s, want %s", got, want)
	}
	encoded, err = json.Marshal(buildCreateUserRequest(&runtimeUser{Username: "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"username":"alice"}`; got != want {
		t.Errorf("create JSON without a secret = %s, want %s", got, want)
	}

	tag := "aabbccddeeff00112233445566778899"
	encoded, err = json.Marshal(buildCreateUserRequest(&runtimeUser{
		Username:     "alice",
		Secret:       testSecret,
		UserAdTag:    tag,
		MaxTCPConns:  4,
		MaxUniqueIPs: 2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"user_ad_tag":"` + tag + `"`, `"max_tcp_conns":4`, `"max_unique_ips":2`} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("create JSON missing %s: %s", want, encoded)
		}
	}
}
