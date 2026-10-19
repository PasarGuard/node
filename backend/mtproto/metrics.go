package mtproto

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// telemt 3.5.14 metric names (src/metrics/render/users.rs). The octet
// counters were renamed with a _total suffix in 3.5.4.
const (
	// metricOctetsFromClient counts bytes received from the client: uplink.
	metricOctetsFromClient = "telemt_user_octets_from_client_total"
	// metricOctetsToClient counts bytes sent to the client: downlink.
	metricOctetsToClient     = "telemt_user_octets_to_client_total"
	metricConnectionsCurrent = "telemt_user_connections_current"
	metricUniqueIPsCurrent   = "telemt_user_unique_ips_current"
	// metricUserSeriesSuppressed is above 0 when telemt left users out of
	// the per-user series: it exports them for at most 4096 users.
	metricUserSeriesSuppressed = "telemt_telemetry_user_series_suppressed"
)

// maxMetricsLine bounds one line of telemt's metrics output.
const maxMetricsLine = 1 << 20

// userMetrics holds one user's telemt counters and gauges. Octets are
// cumulative counters (the tracker turns them into deltas); connections and
// unique IPs are point-in-time gauges.
type userMetrics struct {
	Uplink             int64
	Downlink           int64
	ConnectionsCurrent int64
	UniqueIPsCurrent   int64
}

type metricsScraper struct {
	url        string
	httpClient *http.Client
}

func newMetricsScraper(url string) *metricsScraper {
	return &metricsScraper{
		url: url,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Scrape reads telemt's metrics endpoint; see parseMetrics.
func (s *metricsScraper) Scrape(ctx context.Context) (map[string]userMetrics, int64, error) {
	if s == nil {
		return nil, 0, errors.New("mtproto metrics scraper is nil")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, 0, err
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, 0, fmt.Errorf("mtproto metrics scrape failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}

	return parseMetrics(response.Body)
}

// parseMetrics reads telemt's Prometheus text output and returns the
// per-user metrics by username and the value of the series suppression
// gauge. Other metrics are skipped before their labels are read, so an odd
// label elsewhere cannot fail the scrape. A per-user line it cannot read
// fails the whole parse: skipping it would read as a counter reset.
func parseMetrics(reader io.Reader) (map[string]userMetrics, int64, error) {
	users := make(map[string]userMetrics)
	var suppressed int64
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxMetricsLine)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, rest := splitMetricName(line)
		switch name {
		case metricOctetsFromClient, metricOctetsToClient, metricConnectionsCurrent, metricUniqueIPsCurrent:
		case metricUserSeriesSuppressed:
			_, value, err := parseSample(rest)
			if err != nil {
				return nil, 0, fmt.Errorf("invalid prometheus line %q: %w", line, err)
			}
			suppressed = value
			continue
		default:
			continue
		}

		labels, value, err := parseSample(rest)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid prometheus line %q: %w", line, err)
		}
		username := labels["user"]
		if username == "" {
			continue
		}

		entry := users[username]
		switch name {
		case metricOctetsFromClient:
			entry.Uplink = value
		case metricOctetsToClient:
			entry.Downlink = value
		case metricConnectionsCurrent:
			entry.ConnectionsCurrent = value
		case metricUniqueIPsCurrent:
			entry.UniqueIPsCurrent = value
		}
		users[username] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	return users, suppressed, nil
}

// splitMetricName splits a sample line into the metric name and the rest:
// labels, if any, then the value.
func splitMetricName(line string) (name, rest string) {
	end := strings.IndexAny(line, "{ \t")
	if end < 0 {
		return line, ""
	}
	return line[:end], line[end:]
}

// parseSample reads `{labels} value [timestamp]` or `value [timestamp]`.
func parseSample(rest string) (map[string]string, int64, error) {
	labels := map[string]string{}
	if strings.HasPrefix(rest, "{") {
		end := labelsEnd(rest)
		if end < 0 {
			return nil, 0, errors.New("unterminated label set")
		}
		parsed, err := parsePrometheusLabels(rest[1:end])
		if err != nil {
			return nil, 0, err
		}
		labels = parsed
		rest = rest[end+1:]
	}

	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return nil, 0, errors.New("missing value")
	}
	value, err := parseMetricValue(fields[0])
	if err != nil {
		return nil, 0, err
	}
	return labels, value, nil
}

// labelsEnd returns the index of the brace closing the label set that s
// starts with, or -1.
func labelsEnd(s string) int {
	inQuotes := false
	escapeNext := false
	for index := 1; index < len(s); index++ {
		switch c := s[index]; {
		case escapeNext:
			escapeNext = false
		case c == '\\':
			escapeNext = true
		case c == '"':
			inQuotes = !inQuotes
		case c == '}' && !inQuotes:
			return index
		}
	}
	return -1
}

// parseMetricValue reads a sample value as an integer. telemt writes
// counters and gauges as integers; a float form is accepted too.
func parseMetricValue(text string) (int64, error) {
	if value, err := strconv.ParseInt(text, 10, 64); err == nil {
		return value, nil
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsNaN(value) || math.Abs(value) >= math.MaxInt64 {
		return 0, fmt.Errorf("invalid prometheus metric value %q", text)
	}
	return int64(value), nil
}

func parsePrometheusLabels(raw string) (map[string]string, error) {
	result := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}

	parts := splitLabelPairs(raw)
	for _, part := range parts {
		if part == "" {
			// A trailing comma is valid.
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			return nil, fmt.Errorf("invalid prometheus label pair %q", part)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("invalid prometheus label value %q: %w", value, err)
		}
		result[key] = decoded
	}

	return result, nil
}

func splitLabelPairs(raw string) []string {
	parts := make([]string, 0)
	start := 0
	inQuotes := false
	escapeNext := false

	for index, r := range raw {
		switch {
		case escapeNext:
			escapeNext = false
		case r == '\\':
			escapeNext = true
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			parts = append(parts, strings.TrimSpace(raw[start:index]))
			start = index + 1
		}
	}

	parts = append(parts, strings.TrimSpace(raw[start:]))
	return parts
}
