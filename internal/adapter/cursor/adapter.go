package cursor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mitoriq/collector/internal/adapter/sessionkey"
	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/normalize"
	_ "modernc.org/sqlite"
)

const Source = "cursor"

const defaultAPIBaseURL = "https://api.cursor.com"

var defaultAnalyticsEndpoints = []string{
	"/analytics/team/agent-edits",
	"/analytics/team/models",
}

type Identity struct {
	MachineEnrollmentID string
	MachineID           string
	MemberID            string
	OrganizationID      string
	ProjectID           *string
}

type Options struct {
	APIBaseURL         string
	APIKey             string
	AnalyticsEndDate   string
	AnalyticsStartDate string
	EnableHooksBeta    bool
	HTTPClient         *http.Client
	Identity           Identity
	LocalStateDBPath   string
	Now                func() time.Time
	Redaction          normalize.RedactionOptions
	SessionStartedAt   time.Time
}

type Collection struct {
	Events       []contracts.AgentEvent
	UsageMetrics []contracts.UsageMetric
}

type hookInput struct {
	ConversationID string `json:"conversation_id"`
	CWD            string `json:"cwd"`
	Event          string `json:"event"`
	GenerationID   string `json:"generation_id"`
	HookEventName  string `json:"hook_event_name"`
	Model          string `json:"model"`
	SessionID      string `json:"session_id"`
	SessionIDCamel string `json:"sessionId"`
	Timestamp      string `json:"timestamp"`
	ToolName       string `json:"tool_name"`
	ToolUseID      string `json:"tool_use_id"`
	Workspace      string `json:"workspace"`
}

type usageCounter struct {
	Date       string
	Field      string
	Model      string
	SourceName string
	Value      int
}

type cursorStateRow struct {
	Key   string
	Value string
}

func CollectLocalState(ctx context.Context, options Options) (Collection, error) {
	if strings.TrimSpace(options.LocalStateDBPath) == "" {
		return Collection{}, nil
	}
	if _, err := os.Stat(options.LocalStateDBPath); err != nil {
		if os.IsNotExist(err) {
			return Collection{}, nil
		}
		return Collection{}, err
	}
	db, err := sql.Open("sqlite", options.LocalStateDBPath)
	if err != nil {
		return Collection{}, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, `select key, value from ItemTable where key like 'aiCodeTracking.%' order by key asc`)
	if err != nil {
		return Collection{}, err
	}
	defer rows.Close()

	var counters []usageCounter
	for rows.Next() {
		var row cursorStateRow
		if err := rows.Scan(&row.Key, &row.Value); err != nil {
			return Collection{}, err
		}
		counters = append(counters, countersFromLocalStateRow(row)...)
	}
	if err := rows.Err(); err != nil {
		return Collection{}, err
	}

	return collectionFromCounters(counters, options)
}

func FetchAnalytics(ctx context.Context, options Options) (Collection, error) {
	if strings.TrimSpace(options.APIKey) == "" {
		return Collection{}, nil
	}
	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var counters []usageCounter
	for _, endpoint := range defaultAnalyticsEndpoints {
		payload, err := fetchAnalyticsEndpoint(ctx, client, endpoint, options)
		if err != nil {
			return Collection{}, err
		}
		counters = append(counters, countersFromAnalyticsPayload(endpoint, payload)...)
	}

	return collectionFromCounters(counters, options)
}

func NormalizeHookJSON(body []byte, options Options) (Collection, error) {
	if !options.EnableHooksBeta {
		return Collection{}, fmt.Errorf("cursor hooks beta is disabled")
	}

	var input hookInput
	if err := json.Unmarshal(body, &input); err != nil {
		return Collection{}, err
	}
	input = input.withCanonicalSessionID()
	eventType, payload, ok := hookEvent(input)
	if !ok {
		return Collection{}, nil
	}
	event, err := normalizeEvent(input, eventType, payload, options)
	if err != nil {
		return Collection{}, err
	}

	return Collection{Events: []contracts.AgentEvent{event}}, nil
}

func (input hookInput) withCanonicalSessionID() hookInput {
	if strings.TrimSpace(input.ConversationID) != "" {
		input.SessionID = input.ConversationID
		return input
	}
	if strings.TrimSpace(input.SessionID) != "" {
		return input
	}
	if strings.TrimSpace(input.SessionIDCamel) != "" {
		input.SessionID = input.SessionIDCamel
	}

	return input
}

func hookEvent(input hookInput) (contracts.EventType, map[string]any, bool) {
	name := canonicalHookName(input.HookEventName)
	if name == "" {
		name = canonicalHookName(input.Event)
	}
	switch name {
	case "session", "sessionstart":
		payload := map[string]any{"repo": nil}
		if model := metadataName(input.Model, ""); model != "" {
			payload["model"] = model
		}
		return contracts.EventTypeSessionStarted, payload, true
	case "beforesubmitprompt", "prompt", "promptsubmitted":
		return contracts.EventTypePromptSubmitted, map[string]any{}, true
	case "pretooluse":
		return contracts.EventTypeToolStarted, map[string]any{
			"toolName": metadataName(input.ToolName, "cursor"),
		}, true
	case "posttooluse":
		return contracts.EventTypeToolCompleted, map[string]any{
			"durationMs": 0,
			"toolName":   metadataName(input.ToolName, "cursor"),
		}, true
	case "posttoolusefailure":
		return contracts.EventTypeToolFailed, map[string]any{
			"toolName": metadataName(input.ToolName, "cursor"),
		}, true
	case "sessionend":
		return contracts.EventTypeSessionStopped, map[string]any{
			"durationMs": 0,
			"reason":     "normal",
		}, true
	default:
		return "", nil, false
	}
}

func canonicalHookName(value string) string {
	return strings.Map(func(char rune) rune {
		switch char {
		case '-', '.', '_', ' ':
			return -1
		default:
			return char
		}
	}, strings.ToLower(strings.TrimSpace(value)))
}

func metadataName(value string, fallback string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return fallback
	}
	runes := []rune(normalized)
	if len(runes) > 128 {
		return string(runes[:128])
	}

	return normalized
}

func fetchAnalyticsEndpoint(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	options Options,
) (any, error) {
	baseURL := strings.TrimRight(options.APIBaseURL, "/")
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}
	requestURL, err := url.Parse(baseURL + endpoint)
	if err != nil {
		return nil, err
	}
	query := requestURL.Query()
	if options.AnalyticsStartDate != "" {
		query.Set("startDate", options.AnalyticsStartDate)
	}
	if options.AnalyticsEndDate != "" {
		query.Set("endDate", options.AnalyticsEndDate)
	}
	requestURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("authorization", basicAuth(options.APIKey))
	request.Header.Set("accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("cursor analytics %s returned %d", endpoint, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func basicAuth(apiKey string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(apiKey+":"))
}

func countersFromLocalStateRow(row cursorStateRow) []usageCounter {
	date := dateFromText(row.Key)
	if date == "" {
		return nil
	}
	sourceName := sanitizeModel("cursor-local." + keySuffix(row.Key))
	counts := countsFromJSON(row.Value)
	counters := make([]usageCounter, 0, len(counts))
	for field, value := range counts {
		counters = append(counters, usageCounter{
			Date:       date,
			Field:      field,
			Model:      sourceName + "." + field,
			SourceName: sourceName,
			Value:      value,
		})
	}
	sortCounters(counters)

	return counters
}

func countersFromAnalyticsPayload(endpoint string, payload any) []usageCounter {
	records := collectRecords(payload)
	counters := make([]usageCounter, 0, len(records))
	for _, record := range records {
		date := stringField(record, "event_date")
		if date == "" {
			date = stringField(record, "date")
		}
		if date == "" {
			continue
		}
		switch endpoint {
		case "/analytics/team/agent-edits":
			counters = append(counters, counterFromRecord(record, date, "total_accepts", "cursor-agent-edits.accepts")...)
			counters = append(counters, counterFromRecord(record, date, "total_lines_accepted", "cursor-agent-edits.lines-accepted")...)
		case "/analytics/team/models":
			model := sanitizeModel(stringField(record, "model"))
			if model == "" {
				model = "cursor-model-usage"
			}
			counters = append(counters, counterFromRecord(record, date, "usage", model)...)
		}
	}
	sortCounters(counters)

	return counters
}

func counterFromRecord(
	record map[string]any,
	date string,
	field string,
	model string,
) []usageCounter {
	value, ok := intField(record, field)
	if !ok || value < 1 {
		return nil
	}

	return []usageCounter{{
		Date:       date,
		Field:      field,
		Model:      model,
		SourceName: model,
		Value:      value,
	}}
}

func collectionFromCounters(counters []usageCounter, options Options) (Collection, error) {
	metrics := make([]contracts.UsageMetric, 0, len(counters))
	for _, counter := range counters {
		if counter.Value < 1 {
			continue
		}
		occurredAt, ok := occurredAtFromDate(counter.Date)
		if !ok {
			continue
		}
		sessionID := StableSessionKey(cursorAggregateSessionKey(counter, options.Identity), occurredAt)
		metric := contracts.UsageMetric{
			ID:                  "met_" + shortHash(strings.Join([]string{sessionID, counter.Model, counter.Field, occurredAt.Format(time.RFC3339Nano)}, "\x00")),
			SchemaVersion:       1,
			OrganizationID:      options.Identity.OrganizationID,
			MachineEnrollmentID: options.Identity.MachineEnrollmentID,
			SessionID:           sessionID,
			Source:              Source,
			Model:               counter.Model,
			OccurredAt:          occurredAt.Format(time.RFC3339Nano),
			UsageCount:          counter.Value,
			Cost:                contracts.Cost{Accuracy: contracts.CostAccuracyUnknown},
			IdempotencyKey:      "cursor:" + shortHash(strings.Join([]string{sessionID, counter.Model, counter.Field}, "\x00")),
		}
		metrics = append(metrics, metric)
	}

	return Collection{UsageMetrics: metrics}, nil
}

func normalizeEvent(
	input hookInput,
	eventType contracts.EventType,
	payload map[string]any,
	options Options,
) (contracts.AgentEvent, error) {
	occurredAt := occurredAt(input.Timestamp, options)
	cwd := input.CWD
	if cwd == "" {
		cwd = input.Workspace
	}
	sourceSessionID := strings.Join([]string{
		strings.TrimSpace(options.Identity.OrganizationID),
		strings.TrimSpace(options.Identity.MachineEnrollmentID),
		strings.TrimSpace(input.SessionID),
	}, "\x00")
	sessionScope := cwd
	if strings.TrimSpace(input.SessionID) != "" {
		sessionScope = ""
	}
	sessionID := sessionkey.Stable(sourceSessionID, Source, sessionScope, stableStartedAt(options))
	eventIdentity := occurredAt.Format(time.RFC3339Nano)
	if invocationID := stableInvocationID(input); invocationID != "" {
		eventIdentity = invocationID
	}
	eventKey := strings.Join([]string{sessionID, string(eventType), eventIdentity}, "\x00")
	raw := normalize.RawEvent{
		ID:             "evt_" + shortHash(eventKey),
		OccurredAt:     occurredAt.Format(time.RFC3339Nano),
		Payload:        payload,
		ProjectID:      options.Identity.ProjectID,
		SessionID:      sessionID,
		Source:         Source,
		Type:           string(eventType),
		IdempotencyKey: "cursor:" + shortHash(eventKey),
	}

	return normalize.NormalizeRawEvent(raw, normalize.NormalizeOptions{
		MachineEnrollmentID: options.Identity.MachineEnrollmentID,
		MachineID:           options.Identity.MachineID,
		MemberID:            options.Identity.MemberID,
		OrganizationID:      options.Identity.OrganizationID,
		PrivacyLevel:        "L1",
		Redaction:           options.Redaction,
	})
}

func stableInvocationID(input hookInput) string {
	if toolUseID := strings.TrimSpace(input.ToolUseID); toolUseID != "" {
		return "tool:" + toolUseID
	}
	if generationID := strings.TrimSpace(input.GenerationID); generationID != "" {
		return "generation:" + generationID
	}

	return ""
}

func countsFromJSON(value string) map[string]int {
	var decoded any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(value))
		if parseErr != nil || parsed < 1 {
			return nil
		}

		return map[string]int{"usage": parsed}
	}
	counts := map[string]int{}
	collectNumericCounters(decoded, counts)

	return counts
}

func collectNumericCounters(value any, counts map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		for key, entry := range typed {
			normalized := normalizedCounterField(key)
			if normalized != "" {
				if value, ok := numericValue(entry); ok && value >= 1 {
					counts[normalized] += value
				}
				continue
			}
			collectNumericCounters(entry, counts)
		}
	case []any:
		for _, entry := range typed {
			collectNumericCounters(entry, counts)
		}
	}
}

func normalizedCounterField(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "usage", "count", "total":
		return "usage"
	case "total_accepts", "accepts", "accepted":
		return "accepts"
	case "total_lines_accepted", "linesaccepted", "lines_accepted":
		return "lines-accepted"
	case "total_lines_suggested", "linessuggested", "lines_suggested":
		return "lines-suggested"
	default:
		return ""
	}
}

func numericValue(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		if typed <= 0 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int(typed), true
	case int:
		return typed, typed > 0
	case json.Number:
		parsed, err := typed.Int64()
		return int(parsed), err == nil && parsed > 0
	default:
		return 0, false
	}
}

func collectRecords(value any) []map[string]any {
	switch typed := value.(type) {
	case []any:
		records := make([]map[string]any, 0, len(typed))
		for _, entry := range typed {
			records = append(records, collectRecords(entry)...)
		}
		return records
	case map[string]any:
		if looksLikeRecord(typed) {
			return []map[string]any{typed}
		}
		var records []map[string]any
		for _, entry := range typed {
			records = append(records, collectRecords(entry)...)
		}
		return records
	default:
		return nil
	}
}

func looksLikeRecord(record map[string]any) bool {
	for _, key := range []string{"usage", "total_accepts", "total_lines_accepted"} {
		if _, ok := record[key]; ok {
			return true
		}
	}

	return false
}

func intField(record map[string]any, key string) (int, bool) {
	return numericValue(record[key])
}

func stringField(record map[string]any, key string) string {
	value, ok := record[key].(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func keySuffix(key string) string {
	parts := strings.Split(strings.TrimSpace(key), ".")
	if len(parts) < 2 {
		return "ai-code-tracking"
	}
	start := len(parts) - 2
	if start < 1 {
		start = 1
	}

	return strings.Join(parts[start:], ".")
}

func sanitizeModel(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return ""
	}
	var builder strings.Builder
	lastDash := false
	for _, char := range normalized {
		allowed := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-'
		if allowed {
			builder.WriteRune(char)
			lastDash = char == '-'
			continue
		}
		if !lastDash {
			builder.WriteRune('-')
			lastDash = true
		}
	}

	return strings.Trim(builder.String(), "-.")
}

func dateFromText(value string) string {
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '.' || r == '/' || r == '_' || r == ':' || r == ' '
	}) {
		if len(part) == 10 && part[4] == '-' && part[7] == '-' && isValidDate(part) {
			return part
		}
	}

	return ""
}

func occurredAtFromDate(date string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02", date)
	if err != nil {
		return time.Time{}, false
	}

	return parsed.UTC(), true
}

func isValidDate(date string) bool {
	_, err := time.Parse("2006-01-02", date)
	return err == nil
}

func occurredAt(timestamp string, options Options) time.Time {
	if timestamp != "" {
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err == nil {
			return parsed.UTC()
		}
	}

	return now(options)
}

func now(options Options) time.Time {
	if options.Now != nil {
		return options.Now().UTC()
	}

	return time.Now().UTC()
}

func stableStartedAt(options Options) time.Time {
	if !options.SessionStartedAt.IsZero() {
		return options.SessionStartedAt.UTC()
	}

	return time.Unix(0, 0).UTC()
}

func StableSessionKey(sourceSessionID string, occurredAt time.Time) string {
	return sessionkey.Stable(sourceSessionID, Source, "", occurredAt)
}

func cursorAggregateSessionKey(counter usageCounter, identity Identity) string {
	return strings.Join([]string{
		Source,
		strings.TrimSpace(identity.OrganizationID),
		strings.TrimSpace(identity.MachineEnrollmentID),
		counter.Model,
		counter.Date,
	}, "\x00")
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:24]
}

func sortCounters(counters []usageCounter) {
	sort.Slice(counters, func(left, right int) bool {
		if counters[left].Model != counters[right].Model {
			return counters[left].Model < counters[right].Model
		}
		if counters[left].Date != counters[right].Date {
			return counters[left].Date < counters[right].Date
		}

		return counters[left].Field < counters[right].Field
	})
}
