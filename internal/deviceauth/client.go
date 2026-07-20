package deviceauth

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
)

const (
	startPath    = "/api/machines/device-authorizations/start"
	pollPath     = "/api/machines/device-authorizations/poll"
	completePath = "/api/machines/device-authorizations/complete"
)

type Status string

const (
	StatusAuthorizationPending Status = "authorization_pending"
	StatusSlowDown             Status = "slow_down"
	StatusExpiredToken         Status = "expired_token"
	StatusAccessDenied         Status = "access_denied"
	StatusAuthorized           Status = "authorized"
	StatusEnrolled             Status = "enrolled"
)

type Preflight struct {
	ConfigWritable     bool   `json:"configWritable"`
	CredentialWritable bool   `json:"credentialWritable"`
	JournalWritable    bool   `json:"journalWritable"`
	Platform           string `json:"platform"`
}
type Machine struct {
	DisplayName string `json:"displayName"`
	LocalUUID   string `json:"localUuid"`
	OS          string `json:"os"`
}
type StartRequest struct {
	PublicKey string    `json:"publicKey"`
	Preflight Preflight `json:"preflight"`
	Machine   Machine   `json:"machine"`
}
type StartResponse struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
	ExpiresIn  int    `json:"expiresIn"`
	Interval   int    `json:"interval"`
}
type PollRequest struct {
	DeviceCode       string `json:"deviceCode"`
	CollectorVersion string `json:"collectorVersion,omitempty"`
}
type PollResponse struct {
	Status   Status    `json:"status"`
	Envelope *Envelope `json:"envelope,omitempty"`
	Interval int       `json:"interval,omitempty"`
}
type CompleteRequest struct {
	DeviceCode string `json:"deviceCode"`
}
type CompleteResponse struct {
	Status string `json:"status"`
}
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
type Client struct {
	BaseURL    string
	HTTPClient HTTPClient
}

func (client Client) Start(ctx context.Context, request StartRequest) (StartResponse, error) {
	if request.PublicKey == "" || request.Machine.DisplayName == "" || request.Machine.LocalUUID == "" ||
		!request.Preflight.ConfigWritable || !request.Preflight.CredentialWritable || !request.Preflight.JournalWritable ||
		(request.Preflight.Platform != "macos" && request.Preflight.Platform != "linux") || request.Machine.OS != request.Preflight.Platform {
		return StartResponse{}, errors.New("invalid device authorization start request")
	}
	var response StartResponse
	if err := client.post(ctx, startPath, request, &response); err != nil {
		return StartResponse{}, err
	}
	if response.DeviceCode == "" || response.UserCode == "" || response.ExpiresIn <= 0 || response.Interval <= 0 {
		return StartResponse{}, errors.New("invalid device authorization start response")
	}
	return response, nil
}
func (client Client) Poll(ctx context.Context, request PollRequest) (PollResponse, error) {
	if request.DeviceCode == "" {
		return PollResponse{}, errors.New("invalid device authorization poll request")
	}
	var response PollResponse
	if err := client.post(ctx, pollPath, request, &response); err != nil {
		return PollResponse{}, err
	}
	if !validPollResponse(response) {
		return PollResponse{}, errors.New("invalid device authorization poll response")
	}
	return response, nil
}
func (client Client) Complete(ctx context.Context, request CompleteRequest) (CompleteResponse, error) {
	if request.DeviceCode == "" {
		return CompleteResponse{}, errors.New("invalid device authorization complete request")
	}
	var response CompleteResponse
	if err := client.post(ctx, completePath, request, &response); err != nil {
		return CompleteResponse{}, err
	}
	if response.Status != "enrolled" {
		return CompleteResponse{}, errors.New("invalid device authorization complete response")
	}
	return response, nil
}
func validStatus(status Status) bool {
	return status == StatusAuthorizationPending || status == StatusSlowDown || status == StatusExpiredToken || status == StatusAccessDenied || status == StatusAuthorized || status == StatusEnrolled
}
func validPollResponse(response PollResponse) bool {
	if !validStatus(response.Status) {
		return false
	}
	if response.Status == StatusAuthorizationPending || response.Status == StatusSlowDown {
		return response.Interval > 0 && response.Envelope == nil
	}
	if response.Status == StatusAuthorized {
		return response.Envelope != nil && response.Interval == 0
	}
	return response.Envelope == nil && response.Interval == 0
}
func (client Client) post(ctx context.Context, path string, input, output interface{}) error {
	base, err := url.Parse(client.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("invalid device authorization API URL")
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	body, err := json.Marshal(input)
	if err != nil {
		return errors.New("invalid device authorization request")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid device authorization request")
	}
	request.Header.Set("content-type", "application/json")
	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if standardClient, ok := httpClient.(*http.Client); ok {
		redirectRejectingClient := *standardClient
		redirectRejectingClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &redirectRejectingClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return errors.New("device authorization request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("device authorization request failed: status=%d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
		return errors.New("invalid device authorization response")
	}
	return nil
}
