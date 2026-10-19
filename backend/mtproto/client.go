package mtproto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type apiClient struct {
	baseURL    string
	authHeader string
	httpClient *http.Client
}

type apiSuccessResponse[T any] struct {
	OK    bool          `json:"ok"`
	Data  T             `json:"data"`
	Error *apiErrorBody `json:"error,omitempty"`
}

type apiErrorResponse struct {
	Error *apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// telemtUserInfo is the part of telemt's user record the node reads.
type telemtUserInfo struct {
	Username           string `json:"username"`
	InRuntime          bool   `json:"in_runtime"`
	CurrentConnections uint64 `json:"current_connections"`
	ActiveUniqueIPs    int    `json:"active_unique_ips"`
	TotalOctets        uint64 `json:"total_octets"`
}

type telemtUserActiveIPs struct {
	Username  string   `json:"username"`
	ActiveIPs []string `json:"active_ips"`
}

type telemtDeleteUserResponse struct {
	Username  string `json:"username"`
	InRuntime bool   `json:"in_runtime"`
}

type telemtHealth struct {
	Status   string `json:"status"`
	ReadOnly bool   `json:"read_only"`
}

type telemtHealthReady struct {
	Ready  bool   `json:"ready"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type telemtCreateUserRequest struct {
	Username     string `json:"username"`
	Secret       string `json:"secret,omitempty"`
	UserAdTag    string `json:"user_ad_tag,omitempty"`
	MaxTCPConns  *int   `json:"max_tcp_conns,omitempty"`
	MaxUniqueIPs *int   `json:"max_unique_ips,omitempty"`
}

// telemtPatchUserRequest uses JSON Merge Patch: omitted fields are unchanged,
// JSON null removes the per-user override, and a value sets it. omitempty is
// therefore not used on the clearable fields.
type telemtPatchUserRequest struct {
	Secret       string  `json:"secret,omitempty"`
	UserAdTag    *string `json:"user_ad_tag"`
	MaxTCPConns  *int    `json:"max_tcp_conns"`
	MaxUniqueIPs *int    `json:"max_unique_ips"`
}

type apiStatusError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *apiStatusError) Error() string {
	message := strings.TrimSpace(e.Message)
	if message != "" {
		return message
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("telemt API request failed with status %d", e.StatusCode)
}

func (e *apiStatusError) NotFound() bool {
	return e.StatusCode == http.StatusNotFound || e.Code == "not_found"
}

func (e *apiStatusError) UserExists() bool {
	return e.StatusCode == http.StatusConflict && e.Code == "user_exists"
}

func newAPIClient(baseURL, authHeader string) *apiClient {
	return &apiClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authHeader: authHeader,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *apiClient) Health(ctx context.Context) error {
	_, err := doAPIRequest[telemtHealth](ctx, c, http.MethodGet, "/v1/health", nil)
	return err
}

// Ready returns nil when /v1/health/ready answers 200: telemt admits clients
// and has a healthy Telegram upstream. On 503 the error carries telemt's
// reason, such as no_healthy_upstreams.
func (c *apiClient) Ready(ctx context.Context) error {
	_, err := doAPIRequest[telemtHealthReady](ctx, c, http.MethodGet, "/v1/health/ready", nil)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusServiceUnavailable {
		var body apiSuccessResponse[telemtHealthReady]
		if json.Unmarshal([]byte(apiErr.Message), &body) == nil && body.Data.Reason != "" {
			return fmt.Errorf("telemt is not ready: %s", body.Data.Reason)
		}
	}
	return err
}

// ListUsers returns the users of telemt's config file; InRuntime tells
// whether the running config has each one too. telemt loads the whole config
// for any user read, so one list beats a read per user.
func (c *apiClient) ListUsers(ctx context.Context) ([]telemtUserInfo, error) {
	users, err := doAPIRequest[[]telemtUserInfo](ctx, c, http.MethodGet, "/v1/users", nil)
	if err != nil {
		return nil, err
	}
	return *users, nil
}

// ActiveIPs returns the active client IPs per username, for the users that
// have any.
func (c *apiClient) ActiveIPs(ctx context.Context) (map[string][]string, error) {
	entries, err := doAPIRequest[[]telemtUserActiveIPs](ctx, c, http.MethodGet, "/v1/stats/users/active-ips", nil)
	if err != nil {
		return nil, err
	}
	activeIPs := make(map[string][]string, len(*entries))
	for _, entry := range *entries {
		activeIPs[entry.Username] = entry.ActiveIPs
	}
	return activeIPs, nil
}

func (c *apiClient) CreateUser(ctx context.Context, user *runtimeUser) error {
	request, err := buildCreateUserRequest(user)
	if err != nil {
		return err
	}
	_, err = doAPIRequest[telemtUserInfo](ctx, c, http.MethodPost, "/v1/users", request)
	return err
}

func (c *apiClient) PatchUser(ctx context.Context, username string, user *runtimeUser) error {
	request, err := buildPatchUserRequest(user)
	if err != nil {
		return err
	}
	_, err = doAPIRequest[telemtUserInfo](ctx, c, http.MethodPatch, "/v1/users/"+url.PathEscape(username), request)
	return err
}

// DeleteUser removes the user. telemt answers with the username and whether
// its running config still has the user (status 202 then, else 200).
func (c *apiClient) DeleteUser(ctx context.Context, username string) error {
	_, err := doAPIRequest[telemtDeleteUserResponse](ctx, c, http.MethodDelete, "/v1/users/"+url.PathEscape(username), nil)
	return err
}

func buildCreateUserRequest(user *runtimeUser) (*telemtCreateUserRequest, error) {
	maxTCPConns, err := optionalPositiveInt(user.MaxTCPConns, "max_tcp_conns")
	if err != nil {
		return nil, err
	}
	maxUniqueIPs, err := optionalPositiveInt(user.MaxUniqueIPs, "max_unique_ips")
	if err != nil {
		return nil, err
	}

	request := &telemtCreateUserRequest{
		Username:     user.Username,
		Secret:       user.Secret,
		UserAdTag:    user.UserAdTag,
		MaxTCPConns:  maxTCPConns,
		MaxUniqueIPs: maxUniqueIPs,
	}
	return request, nil
}

func buildPatchUserRequest(user *runtimeUser) (*telemtPatchUserRequest, error) {
	if user == nil {
		return nil, errors.New("mtproto user is nil")
	}

	maxTCPConns, err := optionalPositiveInt(user.MaxTCPConns, "max_tcp_conns")
	if err != nil {
		return nil, err
	}
	maxUniqueIPs, err := optionalPositiveInt(user.MaxUniqueIPs, "max_unique_ips")
	if err != nil {
		return nil, err
	}

	request := &telemtPatchUserRequest{
		Secret:       user.Secret,
		MaxTCPConns:  maxTCPConns,
		MaxUniqueIPs: maxUniqueIPs,
	}
	if user.UserAdTag != "" {
		tag := user.UserAdTag
		request.UserAdTag = &tag
	}
	return request, nil
}

func optionalPositiveInt(value uint32, field string) (*int, error) {
	if value == 0 {
		return nil, nil
	}
	maxInt := int(^uint(0) >> 1)
	if uint64(value) > uint64(maxInt) {
		return nil, fmt.Errorf("mtproto field %s exceeds native int range", field)
	}
	converted := int(value)
	return &converted, nil
}

func doAPIRequest[T any](ctx context.Context, client *apiClient, method, path string, body any) (*T, error) {
	if client == nil {
		return nil, errors.New("mtproto api client is nil")
	}

	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode mtproto api request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, requestBody)
	if err != nil {
		return nil, err
	}

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if client.authHeader != "" {
		request.Header.Set("Authorization", client.authHeader)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		var failure apiErrorResponse
		if json.Unmarshal(payload, &failure) == nil && failure.Error != nil {
			return nil, &apiStatusError{
				StatusCode: response.StatusCode,
				Code:       failure.Error.Code,
				Message:    failure.Error.Message,
			}
		}
		return nil, &apiStatusError{
			StatusCode: response.StatusCode,
			Message:    strings.TrimSpace(string(payload)),
		}
	}

	var success apiSuccessResponse[T]
	if err := json.Unmarshal(payload, &success); err != nil {
		return nil, fmt.Errorf("failed to decode mtproto api response: %w", err)
	}
	if !success.OK {
		if success.Error != nil {
			return nil, &apiStatusError{
				StatusCode: response.StatusCode,
				Code:       success.Error.Code,
				Message:    success.Error.Message,
			}
		}
		return nil, &apiStatusError{
			StatusCode: response.StatusCode,
			Message:    "telemt api returned ok=false",
		}
	}

	return &success.Data, nil
}
