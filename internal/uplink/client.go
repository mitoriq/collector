package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/queue"
)

var ErrEnrollmentRejected = errors.New("enrollment rejected")

const HeartbeatInterval = time.Minute

const EnrollmentRejectedUserMessage = "登録が無効になりました。再度 enroll を実行してください。未送信イベントは queue に保持されています。"

type EnrollmentRejectedError struct {
	StatusCode int
}

func (err EnrollmentRejectedError) Error() string {
	return fmt.Sprintf("%s: status=%d", ErrEnrollmentRejected, err.StatusCode)
}

func (err EnrollmentRejectedError) Unwrap() error {
	return ErrEnrollmentRejected
}

func (err EnrollmentRejectedError) UserMessage() string {
	return EnrollmentRejectedUserMessage
}

type Config struct {
	APIURL            string
	AllowInsecureHTTP bool
	AuditLog          *localaudit.Store
	HTTPClient        *http.Client
	Now               func() time.Time
	Token             string
}

type Client struct {
	allowInsecureHTTP bool
	apiURL            string
	auditLog          *localaudit.Store
	httpClient        *http.Client
	now               func() time.Time
	token             string
}

type DrainOptions struct {
	BatchSize int
	Now       func() time.Time
}

func NewClient(config Config) Client {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}

	return Client{
		allowInsecureHTTP: config.AllowInsecureHTTP,
		apiURL:            strings.TrimRight(config.APIURL, "/"),
		auditLog:          config.AuditLog,
		httpClient:        httpClient,
		now:               now,
		token:             config.Token,
	}
}

func (client Client) SendEvents(
	ctx context.Context,
	events []contracts.AgentEvent,
) (contracts.CollectorCounts, error) {
	var counts contracts.CollectorCounts
	if len(events) == 0 {
		return counts, nil
	}
	audit := eventAuditEntry(events)
	if err := client.appendAudit(ctx, audit); err != nil {
		return counts, err
	}
	err := client.postJSON(ctx, "/api/collector/events", contracts.CollectorBatch{
		Events: events,
		SentAt: client.now().UTC().Format(time.RFC3339Nano),
	}, &counts)
	if err != nil {
		return counts, client.recordFailure(ctx, audit, err)
	}
	if err := client.recordAccepted(ctx, audit, counts); err != nil {
		return counts, err
	}

	return counts, nil
}

func (client Client) SendUsage(
	ctx context.Context,
	metrics []contracts.UsageMetric,
) (contracts.CollectorCounts, error) {
	var counts contracts.CollectorCounts
	if len(metrics) == 0 {
		return counts, nil
	}
	audit := usageAuditEntry(metrics)
	if err := client.appendAudit(ctx, audit); err != nil {
		return counts, err
	}
	err := client.postJSON(ctx, "/api/collector/usage", contracts.CollectorUsageBatch{
		Metrics: metrics,
		SentAt:  client.now().UTC().Format(time.RFC3339Nano),
	}, &counts)
	if err != nil {
		return counts, client.recordFailure(ctx, audit, err)
	}
	if err := client.recordAccepted(ctx, audit, counts); err != nil {
		return counts, err
	}

	return counts, nil
}

func (client Client) SendHeartbeat(
	ctx context.Context,
	heartbeat contracts.HeartbeatRequest,
) (contracts.HeartbeatResponse, error) {
	var response contracts.HeartbeatResponse
	audit := localaudit.Entry{
		Category:      "heartbeat",
		Phase:         "attempted",
		Count:         1,
		PrivacyLevels: map[string]int{"L0": 1},
	}
	if err := client.appendAudit(ctx, audit); err != nil {
		return response, err
	}
	err := client.postJSON(ctx, "/api/collector/heartbeat", heartbeat, &response)
	if err != nil {
		return response, client.recordFailure(ctx, audit, err)
	}
	if err := client.recordAccepted(ctx, audit, contracts.CollectorCounts{Accepted: 1}); err != nil {
		return response, err
	}

	return response, nil
}

func eventAuditEntry(events []contracts.AgentEvent) localaudit.Entry {
	privacyLevels := make(map[string]int)
	eventTypes := make(map[string]int)
	sources := make(map[string]int)
	for _, event := range events {
		privacyLevels[event.PrivacyLevel]++
		eventTypes[string(event.Type)]++
		if event.Source != "" {
			sources[event.Source]++
		}
	}

	return localaudit.Entry{
		Category:      "events",
		Phase:         "attempted",
		Count:         len(events),
		PrivacyLevels: privacyLevels,
		EventTypes:    eventTypes,
		Sources:       sources,
	}
}

func usageAuditEntry(metrics []contracts.UsageMetric) localaudit.Entry {
	sources := make(map[string]int)
	for _, metric := range metrics {
		if metric.Source != "" {
			sources[metric.Source]++
		}
	}

	return localaudit.Entry{
		Category:      "usage",
		Phase:         "attempted",
		Count:         len(metrics),
		PrivacyLevels: map[string]int{"L1": len(metrics)},
		Sources:       sources,
	}
}

func (client Client) appendAudit(ctx context.Context, entry localaudit.Entry) error {
	if client.auditLog == nil {
		return nil
	}
	if err := client.auditLog.AppendContext(ctx, entry); err != nil {
		return fmt.Errorf("write collector audit log: %w", err)
	}

	return nil
}

func (client Client) recordAccepted(
	ctx context.Context,
	attempt localaudit.Entry,
	counts contracts.CollectorCounts,
) error {
	accepted := localaudit.Entry{
		Category: attempt.Category,
		Phase:    "accepted",
		Count:    attempt.Count,
		Result: &localaudit.Result{
			Accepted:   counts.Accepted,
			Duplicated: counts.Duplicated,
			Rejected:   counts.Rejected,
		},
	}

	return client.appendAudit(ctx, accepted)
}

func (client Client) recordFailure(ctx context.Context, attempt localaudit.Entry, requestErr error) error {
	failed := localaudit.Entry{
		Category:    attempt.Category,
		Phase:       "failed",
		Count:       attempt.Count,
		FailureCode: auditFailureCode(requestErr),
	}
	if auditErr := client.appendAudit(ctx, failed); auditErr != nil {
		return errors.Join(requestErr, auditErr)
	}

	return requestErr
}

func auditFailureCode(err error) string {
	if errors.Is(err, ErrEnrollmentRejected) {
		return "enrollment_rejected"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}

	return "request_failed"
}

func DrainQueue(ctx context.Context, store *queue.Store, client Client, options DrainOptions) error {
	now := drainNow(options)
	batchSize := options.BatchSize
	if batchSize < 1 {
		batchSize = 100
	}
	records, err := store.Due(ctx, batchSize, now)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}

	events := make([]contracts.AgentEvent, 0, len(records))
	ids := make([]int64, 0, len(records))
	for _, record := range records {
		events = append(events, record.Event)
		ids = append(ids, record.ID)
	}

	counts, err := client.SendEvents(ctx, events)
	if err != nil {
		if errors.Is(err, ErrEnrollmentRejected) {
			return err
		}
		for _, record := range records {
			if retryErr := store.MarkRetry(ctx, record.ID, now.Add(retryDelay(record.Attempts))); retryErr != nil {
				return retryErr
			}
		}
		return err
	}
	if counts.Accepted+counts.Duplicated != len(records) || counts.Rejected > 0 {
		for _, record := range records {
			if retryErr := store.MarkRetry(ctx, record.ID, now.Add(retryDelay(record.Attempts))); retryErr != nil {
				return retryErr
			}
		}
		return fmt.Errorf("collector batch not fully accepted: accepted=%d duplicated=%d rejected=%d",
			counts.Accepted,
			counts.Duplicated,
			counts.Rejected,
		)
	}

	return store.MarkDelivered(ctx, ids)
}

func (client Client) postJSON(
	ctx context.Context,
	path string,
	body any,
	output any,
) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint, err := client.endpoint(path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	request.Header.Set("content-type", "application/json")
	if client.token != "" {
		request.Header.Set("authorization", "Bearer "+client.token)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return EnrollmentRejectedError{StatusCode: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("collector request failed: status=%d", response.StatusCode)
	}
	if output == nil {
		return nil
	}

	return json.NewDecoder(response.Body).Decode(output)
}

func drainNow(options DrainOptions) time.Time {
	if options.Now == nil {
		return time.Now().UTC()
	}

	return options.Now().UTC()
}

func retryDelay(attempts int) time.Duration {
	delay := time.Second
	for range attempts {
		delay *= 2
		if delay >= time.Minute {
			return time.Minute
		}
	}

	return delay
}

func (client Client) endpoint(path string) (string, error) {
	parsed, err := url.Parse(client.apiURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "https" {
		return client.apiURL + path, nil
	}
	if parsed.Scheme == "http" && client.allowInsecureHTTP && isLoopbackHost(parsed.Hostname()) {
		return client.apiURL + path, nil
	}

	return "", fmt.Errorf("collector api url must use https")
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
