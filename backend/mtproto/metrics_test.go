package mtproto

import (
	"strings"
	"testing"
)

// telemt3514Metrics is the per-user part of telemt 3.5.14's /metrics output
// (src/metrics/render/users.rs), plus the pre-3.5.4 octet names, which must
// be ignored.
const telemt3514Metrics = `# HELP telemt_user_connections_total Per-user total connections
# TYPE telemt_user_connections_total counter
# HELP telemt_user_connections_current Per-user active connections
# TYPE telemt_user_connections_current gauge
# HELP telemt_user_octets_from_client_total Per-user total bytes received
# TYPE telemt_user_octets_from_client_total counter
# HELP telemt_user_octets_to_client_total Per-user total bytes sent
# TYPE telemt_user_octets_to_client_total counter
telemt_ip_reservation_rollback_total{reason="tcp_limit"} 0
telemt_ip_tracker_users{scope="active"} 2
telemt_user_connections_total{user="alice"} 9
telemt_user_connections_current{user="alice"} 3
telemt_user_octets_from_client_total{user="alice"} 1024
telemt_user_octets_to_client_total{user="alice"} 2048
telemt_user_msgs_from_client_total{user="alice"} 11
telemt_user_msgs_to_client_total{user="alice"} 12
telemt_user_connections_total{user="bob"} 1
telemt_user_connections_current{user="bob"} 0
telemt_user_octets_from_client_total{user="bob"} 7
telemt_user_octets_to_client_total{user="bob"} 0
telemt_user_octets_from_client{user="alice"} 999999
telemt_user_octets_to_client{user="alice"} 999999
# HELP telemt_user_unique_ips_current Per-user current number of unique active IPs
# TYPE telemt_user_unique_ips_current gauge
telemt_user_unique_ips_current{user="alice"} 2
telemt_user_unique_ips_recent_window{user="alice"} 4
telemt_user_unique_ips_limit{user="alice"} 0
telemt_user_unique_ips_utilization{user="alice"} 0.000000
telemt_user_unique_ips_current{user="bob"} 0
telemt_user_unique_ips_current{user="carol"} 1
# HELP telemt_telemetry_user_series_suppressed User-labeled metric series suppression flag
# TYPE telemt_telemetry_user_series_suppressed gauge
telemt_telemetry_user_series_suppressed 0
telemt_telemetry_user_series_users{family="stats",status="emitted"} 2
telemt_telemetry_user_series_users{family="stats",status="suppressed"} 0
`

func TestParseMetricsNewNames(t *testing.T) {
	users, suppressed, err := parseMetrics(strings.NewReader(telemt3514Metrics))
	if err != nil {
		t.Fatal(err)
	}
	if suppressed != 0 {
		t.Errorf("suppressed = %d, want 0", suppressed)
	}
	want := map[string]userMetrics{
		"alice": {Uplink: 1024, Downlink: 2048, ConnectionsCurrent: 3, UniqueIPsCurrent: 2},
		"bob":   {Uplink: 7},
		"carol": {UniqueIPsCurrent: 1},
	}
	if len(users) != len(want) {
		t.Errorf("users = %+v, want %+v", users, want)
	}
	for name, metrics := range want {
		if users[name] != metrics {
			t.Errorf("%s = %+v, want %+v", name, users[name], metrics)
		}
	}

	_, suppressed, err = parseMetrics(strings.NewReader("telemt_telemetry_user_series_suppressed 1\n"))
	if err != nil || suppressed != 1 {
		t.Errorf("suppressed = %d, %v; want 1", suppressed, err)
	}
}

func TestParseMetricsIgnoresBadLabelsOnOtherMetrics(t *testing.T) {
	body := `telemt_tls_front_profile{domain="bad\q.example"} 1
telemt_other{broken} 1
telemt_unterminated{a="b" 1
telemt_user_octets_from_client_total{user="alice"} 10
telemt_user_octets_to_client_total{user="alice"} 20
`
	users, _, err := parseMetrics(strings.NewReader(body))
	if err != nil {
		t.Fatalf("a bad label on an unrelated metric failed the scrape: %v", err)
	}
	if got := users["alice"]; got != (userMetrics{Uplink: 10, Downlink: 20}) {
		t.Errorf("alice = %+v, want uplink 10, downlink 20", got)
	}
}

// TestParseMetricsRejectsBadUserSeries: a per-user series the node cannot
// read fails the whole scrape. Skipping it would read as a counter reset.
func TestParseMetricsRejectsBadUserSeries(t *testing.T) {
	for _, line := range []string{
		`telemt_user_octets_to_client_total{user="alice"} many`,
		`telemt_user_octets_to_client_total{user="alice} 1`,
		`telemt_user_octets_to_client_total{user="alice"}`,
		`telemt_telemetry_user_series_suppressed yes`,
	} {
		if _, _, err := parseMetrics(strings.NewReader(line + "\n")); err == nil {
			t.Errorf("parseMetrics(%q) succeeded, want an error", line)
		}
	}
}

func TestParseMetricsLabelValueWithSpaces(t *testing.T) {
	body := `telemt_user_octets_from_client_total{user="alice",note="a b"} 5 1700000000000` + "\n"
	users, _, err := parseMetrics(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if users["alice"].Uplink != 5 {
		t.Errorf("alice uplink = %d, want 5", users["alice"].Uplink)
	}
}
