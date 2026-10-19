package mtproto

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	telemtMetricFromClient        = "telemt_user_octets_from_client"
	telemtMetricToClient          = "telemt_user_octets_to_client"
	telemtMetricConnectionsCurrnt = "telemt_user_connections_current"
	telemtMetricUniqueIPsCurrent  = "telemt_user_unique_ips_current"
)

// userMetrics holds the per-user counters/gauges scraped from telemt's
// Prometheus endpoint. Octets are monotonic counters (delta-tracked by
// trafficTracker); connections/unique-ips are point-in-time gauges.
type userMetrics struct {
	Uplink             int64
	Downlink           int64
	ConnectionsCurrent int64
	UniqueIPsCurrent   int64
}

var perUserMetricNames = map[string]struct{}{
	telemtMetricFromClient:        {},
	telemtMetricToClient:          {},
	telemtMetricConnectionsCurrnt: {},
	telemtMetricUniqueIPsCurrent:  {},
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

func (s *metricsScraper) Scrape(ctx context.Context) (map[string]userMetrics, error) {
	if s == nil {
		return nil, fmt.Errorf("mtproto metrics scraper is nil")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("mtproto metrics scrape failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}

	return parseMetrics(response.Body)
}

func parseMetrics(reader io.Reader) (map[string]userMetrics, error) {
	counters := make(map[string]userMetrics)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		metricName, labels, value, ok, err := parseMetricLine(line)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		username, exists := labels["user"]
		if !exists || username == "" {
			continue
		}

		entry := counters[username]
		switch metricName {
		case telemtMetricFromClient:
			entry.Uplink = value
		case telemtMetricToClient:
			entry.Downlink = value
		case telemtMetricConnectionsCurrnt:
			entry.ConnectionsCurrent = value
		case telemtMetricUniqueIPsCurrent:
			entry.UniqueIPsCurrent = value
		default:
			continue
		}
		counters[username] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return counters, nil
}

func parseMetricLine(line string) (string, map[string]string, int64, bool, error) {
	splitIndex := strings.IndexAny(line, " \t")
	if splitIndex <= 0 {
		return "", nil, 0, false, nil
	}

	metricWithLabels := strings.TrimSpace(line[:splitIndex])
	valueText := strings.TrimSpace(line[splitIndex+1:])
	if valueText == "" {
		return "", nil, 0, false, nil
	}

	metricName := metricWithLabels
	labels := make(map[string]string)

	if braceIndex := strings.IndexByte(metricWithLabels, '{'); braceIndex >= 0 {
		if !strings.HasSuffix(metricWithLabels, "}") {
			return "", nil, 0, false, fmt.Errorf("invalid prometheus metric line %q", line)
		}

		metricName = metricWithLabels[:braceIndex]
		parsedLabels, err := parsePrometheusLabels(metricWithLabels[braceIndex+1 : len(metricWithLabels)-1])
		if err != nil {
			return "", nil, 0, false, err
		}
		labels = parsedLabels
	}

	if _, tracked := perUserMetricNames[metricName]; !tracked {
		return "", nil, 0, false, nil
	}

	metricValue, err := strconv.ParseFloat(strings.Fields(valueText)[0], 64)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("invalid prometheus metric value %q: %w", valueText, err)
	}

	return metricName, labels, int64(metricValue), true, nil
}

func parsePrometheusLabels(raw string) (map[string]string, error) {
	result := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}

	parts := splitLabelPairs(raw)
	for _, part := range parts {
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
