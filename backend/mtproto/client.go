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
	OK       bool          `json:"ok"`
	Data     T             `json:"data"`
	Revision string        `json:"revision"`
	Error    *apiErrorBody `json:"error,omitempty"`
}

type apiErrorResponse struct {
	OK       bool          `json:"ok"`
	Error    *apiErrorBody `json:"error"`
	Request  uint64        `json:"request_id"`
	Revision string        `json:"revision"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type telemtUserInfo struct {
	Username            string   `json:"username"`
	InRuntime           bool     `json:"in_runtime"`
	CurrentConnections  uint64   `json:"current_connections"`
	ActiveUniqueIPsList []string `json:"active_unique_ips_list"`
	RecentUniqueIPsList []string `json:"recent_unique_ips_list"`
	ActiveUniqueIPs     int      `json:"active_unique_ips"`
	RecentUniqueIPs     int      `json:"recent_unique_ips"`
	UserAdTag           string   `json:"user_ad_tag"`
	ExpirationRFC3339   string   `json:"expiration_rfc3339"`
	DataQuotaBytes      uint64   `json:"data_quota_bytes"`
	MaxTCPConns         int      `json:"max_tcp_conns"`
	MaxUniqueIPs        int      `json:"max_unique_ips"`
	TotalOctets         uint64   `json:"total_octets"`
}

type telemtHealth struct {
	Status   string `json:"status"`
	ReadOnly bool   `json:"read_only"`
}

type telemtCreateUserRequest struct {
	Username          string  `json:"username"`
	Secret            string  `json:"secret,omitempty"`
	UserAdTag         string  `json:"user_ad_tag,omitempty"`
	MaxTCPConns       *int    `json:"max_tcp_conns,omitempty"`
	ExpirationRFC3339 string  `json:"expiration_rfc3339,omitempty"`
	DataQuotaBytes    *uint64 `json:"data_quota_bytes,omitempty"`
	MaxUniqueIPs      *int    `json:"max_unique_ips,omitempty"`
}

type telemtPatchUserRequest struct {
	Secret            string  `json:"secret,omitempty"`
	UserAdTag         string  `json:"user_ad_tag,omitempty"`
	MaxTCPConns       *int    `json:"max_tcp_conns,omitempty"`
	ExpirationRFC3339 string  `json:"expiration_rfc3339,omitempty"`
	DataQuotaBytes    *uint64 `json:"data_quota_bytes,omitempty"`
	MaxUniqueIPs      *int    `json:"max_unique_ips,omitempty"`
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

func (c *apiClient) GetUser(ctx context.Context, username string) (*telemtUserInfo, error) {
	escapedUsername := url.PathEscape(username)
	user, err := doAPIRequest[telemtUserInfo](ctx, c, http.MethodGet, "/v1/users/"+escapedUsername, nil)
	if err != nil {
		return nil, err
	}
	return user, nil
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

func (c *apiClient) DeleteUser(ctx context.Context, username string) error {
	_, err := doAPIRequest[map[string]any](ctx, c, http.MethodDelete, "/v1/users/"+url.PathEscape(username), nil)
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
		Username:          user.Username,
		Secret:            user.Secret,
		UserAdTag:         user.UserAdTag,
		MaxTCPConns:       maxTCPConns,
		ExpirationRFC3339: user.ExpirationRFC3339,
		DataQuotaBytes:    optionalPositiveUint64(user.DataQuotaBytes),
		MaxUniqueIPs:      maxUniqueIPs,
	}
	return request, nil
}

func buildPatchUserRequest(user *runtimeUser) (*telemtPatchUserRequest, error) {
	maxTCPConns, err := optionalPositiveInt(user.MaxTCPConns, "max_tcp_conns")
	if err != nil {
		return nil, err
	}
	maxUniqueIPs, err := optionalPositiveInt(user.MaxUniqueIPs, "max_unique_ips")
	if err != nil {
		return nil, err
	}

	request := &telemtPatchUserRequest{
		Secret:            user.Secret,
		UserAdTag:         user.UserAdTag,
		MaxTCPConns:       maxTCPConns,
		ExpirationRFC3339: user.ExpirationRFC3339,
		DataQuotaBytes:    optionalPositiveUint64(user.DataQuotaBytes),
		MaxUniqueIPs:      maxUniqueIPs,
	}
	return request, nil
}

func optionalPositiveUint64(value uint64) *uint64 {
	if value == 0 {
		return nil
	}
	copyValue := value
	return &copyValue
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
