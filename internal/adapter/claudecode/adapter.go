package claudecode

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mitoriq/collector/internal/adapter/gitcontext"
	"github.com/mitoriq/collector/internal/adapter/sessionkey"
	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/normalize"
)

const Source = "claude-code"

type Identity struct {
	MachineEnrollmentID string
	MachineID           string
	MemberID            string
	OrganizationID      string
	ProjectID           *string
}

type Options struct {
	Identity         Identity
	Now              func() time.Time
	Redaction        normalize.RedactionOptions
	RepoResolver     func(cwd string) (gitcontext.Snapshot, error)
	SessionStartedAt time.Time
}

type Collection struct {
	Events       []contracts.AgentEvent
	UsageMetrics []contracts.UsageMetric
}

type HookInput struct {
	CWD              string      `json:"cwd"`
	DurationMs       *float64    `json:"duration_ms"`
	HookEventName    string      `json:"hook_event_name"`
	Model            string      `json:"model"`
	NotificationType string      `json:"notification_type"`
	Prompt           string      `json:"prompt"`
	Reason           string      `json:"reason"`
	SessionID        string      `json:"session_id"`
	SessionIDCamel   string      `json:"sessionId"`
	Timestamp        string      `json:"timestamp"`
	ToolName         string      `json:"tool_name"`
	ToolUseID        string      `json:"tool_use_id"`
	Type             string      `json:"type"`
	Usage            *TokenUsage `json:"usage"`
}

type TokenUsage struct {
	InputTokens       *int `json:"input_tokens"`
	InputTokensCamel  *int `json:"inputTokens"`
	OutputTokens      *int `json:"output_tokens"`
	OutputTokensCamel *int `json:"outputTokens"`
}

type jsonlRow struct {
	HookInput
	Message *messageRow `json:"message"`
}

type messageRow struct {
	Content json.RawMessage `json:"content"`
	Model   string          `json:"model"`
	Role    string          `json:"role"`
	Usage   *TokenUsage     `json:"usage"`
}

func NormalizeHookJSON(body []byte, options Options) (Collection, error) {
	var input HookInput
	if err := json.Unmarshal(body, &input); err != nil {
		return Collection{}, err
	}

	return NormalizeHook(input, options)
}

func NormalizeHook(input HookInput, options Options) (Collection, error) {
	input = input.withCanonicalSessionID()
	eventType, payload, ok, err := hookEvent(input, options)
	if err != nil {
		return Collection{}, err
	}
	if !ok {
		return Collection{}, nil
	}
	event, err := normalizeEvent(input, eventType, payload, options)
	if err != nil {
		return Collection{}, err
	}

	return Collection{Events: []contracts.AgentEvent{event}}, nil
}

func ParseJSONLFallback(reader io.Reader, options Options) (Collection, error) {
	var collection Collection
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		next, err := parseJSONLLine([]byte(line), options)
		if err != nil {
			return Collection{}, err
		}
		collection = mergeCollection(collection, next)
	}
	if err := scanner.Err(); err != nil {
		return Collection{}, err
	}

	return collection, nil
}

func ParseOTelJSON(body []byte, options Options) (Collection, error) {
	var payload otelPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return Collection{}, err
	}
	var collection Collection
	for _, resourceLog := range payload.ResourceLogs {
		for _, scopeLog := range resourceLog.ScopeLogs {
			for _, record := range scopeLog.LogRecords {
				metric, ok, err := usageMetricFromOTelRecord(record, options)
				if err != nil {
					return Collection{}, err
				}
				if ok {
					collection.UsageMetrics = append(collection.UsageMetrics, metric)
				}
			}
		}
	}

	return collection, nil
}

func StableSessionKey(sourceSessionID string, tool string, cwd string, startedAt time.Time) string {
	return sessionkey.Stable(sourceSessionID, tool, cwd, startedAt)
}

func parseJSONLLine(line []byte, options Options) (Collection, error) {
	var row jsonlRow
	if err := json.Unmarshal(line, &row); err != nil {
		return Collection{}, err
	}
	if row.Message != nil && row.Message.Model != "" && row.Message.Usage != nil {
		return usageCollection(row, options)
	}
	if row.Message != nil && row.Message.Role == "user" {
		return promptSubmittedCollection(row, options)
	}
	if row.HookEventName == "" && isClaudeHookName(row.Type) {
		row.HookEventName = row.Type
	}

	return NormalizeHook(row.HookInput, options)
}

func hookEvent(input HookInput, options Options) (contracts.EventType, map[string]any, bool, error) {
	switch input.HookEventName {
	case "SessionStart":
		payload, err := sessionStartedPayload(input, options)
		return contracts.EventTypeSessionStarted, payload, true, err
	case "SessionEnd":
		payload, err := sessionStoppedPayload(input, options)
		return contracts.EventTypeSessionStopped, payload, true, err
	case "PreToolUse":
		return contracts.EventTypeToolStarted, map[string]any{"toolName": toolName(input)}, true, nil
	case "PostToolUse":
		payload, err := toolCompletedPayload(input, options)
		return contracts.EventTypeToolCompleted, payload, true, err
	case "PostToolUseFailure":
		return contracts.EventTypeToolFailed, map[string]any{"toolName": toolName(input)}, true, nil
	case "UserPromptSubmit", "PromptSubmit":
		return contracts.EventTypePromptSubmitted, promptSubmittedPayload(input, options), true, nil
	case "PermissionRequest":
		return contracts.EventTypePermissionRequested, permissionPayload(input, "permission_request"), true, nil
	case "Notification":
		eventType, payload, ok := notificationEvent(input)
		return eventType, payload, ok, nil
	case "Elicitation", "AskUserQuestion":
		return contracts.EventTypeUserInputRequested, userInputPayload("elicitation"), true, nil
	default:
		return "", nil, false, nil
	}
}

func promptSubmittedCollection(row jsonlRow, options Options) (Collection, error) {
	if row.Message == nil {
		return Collection{}, nil
	}
	prompt := strings.TrimSpace(messageContentText(row.Message.Content))
	if prompt == "" {
		return Collection{}, nil
	}
	row.HookInput = row.HookInput.withCanonicalSessionID()
	if row.HookEventName == "" {
		row.HookEventName = "UserPromptSubmit"
	}
	row.Prompt = prompt
	event, err := normalizeEvent(
		row.HookInput,
		contracts.EventTypePromptSubmitted,
		promptSubmittedPayload(row.HookInput, options),
		options,
	)
	if err != nil {
		return Collection{}, err
	}

	return Collection{Events: []contracts.AgentEvent{event}}, nil
}

func messageContentText(content json.RawMessage) string {
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		return text
	}

	var parts []struct {
		Text string `json:"text"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(content, &parts); err != nil {
		return ""
	}
	textParts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part.Type == "" || part.Type == "text" {
			textParts = append(textParts, part.Text)
		}
	}

	return strings.Join(textParts, " ")
}

func notificationEvent(input HookInput) (contracts.EventType, map[string]any, bool) {
	switch input.NotificationType {
	case "permission_prompt":
		return contracts.EventTypePermissionRequested, permissionPayload(input, "notification.permission_prompt"), true
	case "elicitation_dialog", "idle_prompt":
		return contracts.EventTypeUserInputRequested, userInputPayload("notification"), true
	default:
		return "", nil, false
	}
}

func normalizeEvent(
	input HookInput,
	eventType contracts.EventType,
	payload map[string]any,
	options Options,
) (contracts.AgentEvent, error) {
	input = input.withCanonicalSessionID()
	occurredAt := occurredAt(input, options)
	sessionID := StableSessionKey(input.SessionID, Source, input.CWD, startedAt(input, options, occurredAt))
	snapshot, _ := payload["_localSnapshot"].(gitcontext.Snapshot)
	delete(payload, "_localSnapshot")
	raw := normalize.RawEvent{
		ID:             eventID(sessionID, input, eventType, occurredAt),
		LocalDenyPaths: localDenyPaths(snapshot),
		OccurredAt:     occurredAt.Format(time.RFC3339Nano),
		Payload:        payload,
		ProjectID:      options.Identity.ProjectID,
		SessionID:      sessionID,
		Source:         Source,
		Type:           string(eventType),
		IdempotencyKey: idempotencyKey(sessionID, input, eventType, occurredAt),
	}

	event, err := normalize.NormalizeRawEvent(raw, normalizeOptions(options, eventType, payload))
	if err != nil {
		return contracts.AgentEvent{}, err
	}
	event.LocalRepoRemoteURLHash = repoRemoteURLHash(snapshot)

	return event, nil
}

func usageCollection(row jsonlRow, options Options) (Collection, error) {
	row.HookInput = row.HookInput.withCanonicalSessionID()
	metric, err := usageMetric(
		row.SessionID,
		row.CWD,
		occurredAt(row.HookInput, options),
		row.Message.Model,
		row.Message.Usage,
		contracts.Cost{Accuracy: contracts.CostAccuracyUnknown},
		options,
	)
	if err != nil {
		return Collection{}, err
	}

	return Collection{UsageMetrics: []contracts.UsageMetric{metric}}, nil
}

func usageMetric(
	sourceSessionID string,
	cwd string,
	occurredAt time.Time,
	model string,
	usage *TokenUsage,
	cost contracts.Cost,
	options Options,
) (contracts.UsageMetric, error) {
	if strings.TrimSpace(sourceSessionID) == "" {
		return contracts.UsageMetric{}, fmt.Errorf("session id is required")
	}
	if strings.TrimSpace(cwd) == "" {
		return contracts.UsageMetric{}, fmt.Errorf("cwd is required")
	}
	if strings.TrimSpace(model) == "" {
		return contracts.UsageMetric{}, fmt.Errorf("model is required")
	}
	sessionID := StableSessionKey(sourceSessionID, Source, cwd, startedAtForMetric(options, occurredAt))
	id := "met_" + shortHash(strings.Join([]string{sessionID, model, occurredAt.Format(time.RFC3339Nano)}, "\x00"))
	return contracts.UsageMetric{
		ID:                  id,
		SchemaVersion:       1,
		OrganizationID:      options.Identity.OrganizationID,
		MachineEnrollmentID: options.Identity.MachineEnrollmentID,
		SessionID:           sessionID,
		Model:               strings.TrimSpace(model),
		OccurredAt:          occurredAt.Format(time.RFC3339Nano),
		InputTokens:         usage.inputTokens(),
		OutputTokens:        usage.outputTokens(),
		Cost:                cost,
		IdempotencyKey:      id + ":claude-code",
	}, nil
}

func normalizeOptions(options Options, eventType contracts.EventType, payload map[string]any) normalize.NormalizeOptions {
	return normalize.NormalizeOptions{
		MachineEnrollmentID: options.Identity.MachineEnrollmentID,
		MachineID:           options.Identity.MachineID,
		MemberID:            options.Identity.MemberID,
		OrganizationID:      options.Identity.OrganizationID,
		PrivacyLevel:        privacyLevelForPayload(eventType, payload),
		Redaction:           options.Redaction,
	}
}

func occurredAt(input HookInput, options Options) time.Time {
	if input.Timestamp != "" {
		parsed, err := time.Parse(time.RFC3339Nano, input.Timestamp)
		if err == nil {
			return parsed.UTC()
		}
	}
	if options.Now != nil {
		return options.Now().UTC()
	}

	return time.Now().UTC()
}

func startedAt(input HookInput, options Options, fallback time.Time) time.Time {
	if !options.SessionStartedAt.IsZero() {
		return options.SessionStartedAt.UTC()
	}
	if input.HookEventName == "SessionStart" {
		return fallback.UTC()
	}

	return time.Unix(0, 0).UTC()
}

func startedAtForMetric(options Options, fallback time.Time) time.Time {
	if !options.SessionStartedAt.IsZero() {
		return options.SessionStartedAt.UTC()
	}

	return fallback.UTC()
}

func sessionStartedPayload(input HookInput, options Options) (map[string]any, error) {
	snapshot, err := resolveRepo(input.CWD, options)
	if err != nil {
		return nil, err
	}
	var repo any
	if snapshot.Repo != nil {
		repo = snapshot.Repo
	}
	payload := map[string]any{"_localSnapshot": snapshot, "repo": repo}
	if strings.TrimSpace(input.Model) != "" {
		payload["model"] = strings.TrimSpace(input.Model)
	}

	return payload, nil
}

func sessionStoppedPayload(input HookInput, options Options) (map[string]any, error) {
	payload := map[string]any{
		"reason":     stopReason(input.Reason),
		"durationMs": durationMs(input),
	}
	snapshot, err := resolveRepo(input.CWD, options)
	if err != nil {
		return nil, err
	}
	if snapshot.DiffStat.FilesChanged > 0 {
		payload["_localSnapshot"] = snapshot
		payload["filesChanged"] = snapshot.DiffStat.FilesChanged
	}

	return payload, nil
}

func toolCompletedPayload(input HookInput, options Options) (map[string]any, error) {
	payload := map[string]any{
		"toolName":   toolName(input),
		"durationMs": durationMs(input),
	}
	snapshot, err := resolveRepo(input.CWD, options)
	if err != nil {
		return nil, err
	}
	if snapshot.DiffStat.FilesChanged > 0 {
		payload["_localSnapshot"] = snapshot
		payload["filesChanged"] = snapshot.DiffStat.FilesChanged
	}

	return payload, nil
}

func permissionPayload(input HookInput, action string) map[string]any {
	return map[string]any{
		"toolName": toolName(input),
		"action":   action,
	}
}

func userInputPayload(reason string) map[string]any {
	return map[string]any{"reason": reason}
}

func promptSubmittedPayload(input HookInput, options Options) map[string]any {
	prompt := strings.TrimSpace(input.Prompt)
	payload := map[string]any{"charCount": len([]rune(prompt))}
	if summary := normalize.PromptSummary(prompt, options.Redaction); summary != "" {
		payload["promptSummary"] = summary
	}

	return payload
}

func durationMs(input HookInput) float64 {
	if input.DurationMs == nil || *input.DurationMs < 0 {
		return 0
	}

	return *input.DurationMs
}

func toolName(input HookInput) string {
	name := strings.TrimSpace(input.ToolName)
	if name == "" {
		return "Claude Code"
	}

	return name
}

func stopReason(reason string) string {
	switch reason {
	case "prompt_input_exit":
		return "user_cancelled"
	case "StopFailure":
		return "error"
	default:
		return "normal"
	}
}

func resolveRepo(cwd string, options Options) (gitcontext.Snapshot, error) {
	if options.RepoResolver == nil || strings.TrimSpace(cwd) == "" {
		return gitcontext.Snapshot{}, nil
	}

	return options.RepoResolver(cwd)
}

func repoRemoteURLHash(snapshot gitcontext.Snapshot) string {
	if snapshot.Repo == nil || strings.TrimSpace(snapshot.Repo.RemoteURLHash) == "" {
		return ""
	}

	return snapshot.Repo.RemoteURLHash
}

func privacyLevelForPayload(eventType contracts.EventType, payload map[string]any) string {
	switch eventType {
	case contracts.EventTypePromptSubmitted:
		if payload["promptSummary"] != nil {
			return "L3"
		}
	case contracts.EventTypeSessionStarted:
		if payload["repo"] != nil {
			return "L2"
		}
	case contracts.EventTypeToolCompleted, contracts.EventTypeSessionStopped:
		if payload["filesChanged"] != nil {
			return "L2"
		}
	}

	return ""
}

func localDenyPaths(snapshot gitcontext.Snapshot) []string {
	paths := append([]string(nil), snapshot.DiffStat.ChangedPaths...)
	if snapshot.Repo != nil && snapshot.Repo.WorktreeRelativePath != nil {
		paths = append(paths, *snapshot.Repo.WorktreeRelativePath)
	}

	return paths
}

func eventID(sessionID string, input HookInput, eventType contracts.EventType, occurredAt time.Time) string {
	return "evt_" + shortHash(strings.Join([]string{
		sessionID,
		string(eventType),
		input.ToolUseID,
		occurredAt.Format(time.RFC3339Nano),
	}, "\x00"))
}

func idempotencyKey(sessionID string, input HookInput, eventType contracts.EventType, occurredAt time.Time) string {
	return strings.Join([]string{
		optionsKeyPrefix(Source),
		sessionID,
		string(eventType),
		input.ToolUseID,
		occurredAt.Format(time.RFC3339Nano),
	}, ":")
}

func optionsKeyPrefix(source string) string {
	return "collector:" + source
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:])[:32]
}

func mergeCollection(left Collection, right Collection) Collection {
	return Collection{
		Events:       append(left.Events, right.Events...),
		UsageMetrics: append(left.UsageMetrics, right.UsageMetrics...),
	}
}

func isClaudeHookName(value string) bool {
	switch value {
	case "SessionStart", "SessionEnd", "PreToolUse", "PostToolUse", "PostToolUseFailure",
		"UserPromptSubmit", "PromptSubmit", "PermissionRequest", "Notification", "Elicitation",
		"AskUserQuestion":
		return true
	default:
		return false
	}
}

func (input HookInput) withCanonicalSessionID() HookInput {
	if input.SessionID != "" || input.SessionIDCamel == "" {
		return input
	}
	input.SessionID = input.SessionIDCamel

	return input
}

func (usage *TokenUsage) inputTokens() *int {
	if usage == nil {
		return nil
	}
	if usage.InputTokens != nil {
		return usage.InputTokens
	}

	return usage.InputTokensCamel
}

func (usage *TokenUsage) outputTokens() *int {
	if usage == nil {
		return nil
	}
	if usage.OutputTokens != nil {
		return usage.OutputTokens
	}

	return usage.OutputTokensCamel
}

type otelPayload struct {
	ResourceLogs []otelResourceLog `json:"resourceLogs"`
}

type otelResourceLog struct {
	ScopeLogs []otelScopeLog `json:"scopeLogs"`
}

type otelScopeLog struct {
	LogRecords []otelLogRecord `json:"logRecords"`
}

type otelLogRecord struct {
	Attributes   []otelAttribute `json:"attributes"`
	TimeUnixNano string          `json:"timeUnixNano"`
}

type otelAttribute struct {
	Key   string         `json:"key"`
	Value otelValueUnion `json:"value"`
}

type otelValueUnion struct {
	DoubleValue *float64 `json:"doubleValue"`
	IntValue    *string  `json:"intValue"`
	StringValue *string  `json:"stringValue"`
}

func usageMetricFromOTelRecord(
	record otelLogRecord,
	options Options,
) (contracts.UsageMetric, bool, error) {
	attributes := otelAttributes(record.Attributes)
	if attributes["event.name"] != "api_request" {
		return contracts.UsageMetric{}, false, nil
	}
	occurredAt := otelOccurredAt(record, options)
	usage := &TokenUsage{
		InputTokens:  intPointerFromString(attributes["input_tokens"]),
		OutputTokens: intPointerFromString(attributes["output_tokens"]),
	}
	amountUSD := floatPointerFromString(attributes["cost_usd"])
	cost := contracts.Cost{Accuracy: contracts.CostAccuracyUnknown}
	if amountUSD != nil && usage.inputTokens() != nil && usage.outputTokens() != nil {
		cost = contracts.Cost{
			Accuracy:     contracts.CostAccuracyActual,
			AmountUSD:    amountUSD,
			InputTokens:  usage.inputTokens(),
			OutputTokens: usage.outputTokens(),
		}
	}
	metric, err := usageMetric(
		attributes["session.id"],
		attributes["cwd"],
		occurredAt,
		attributes["model"],
		usage,
		cost,
		options,
	)
	if err != nil {
		return contracts.UsageMetric{}, false, err
	}

	return metric, true, nil
}

func otelAttributes(attributes []otelAttribute) map[string]string {
	values := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		if attribute.Value.StringValue != nil {
			values[attribute.Key] = *attribute.Value.StringValue
		}
		if attribute.Value.IntValue != nil {
			values[attribute.Key] = *attribute.Value.IntValue
		}
		if attribute.Value.DoubleValue != nil {
			values[attribute.Key] = strconv.FormatFloat(*attribute.Value.DoubleValue, 'f', -1, 64)
		}
	}

	return values
}

func otelOccurredAt(record otelLogRecord, options Options) time.Time {
	if record.TimeUnixNano != "" {
		nanos, err := strconv.ParseInt(record.TimeUnixNano, 10, 64)
		if err == nil {
			return time.Unix(0, nanos).UTC()
		}
	}
	if options.Now != nil {
		return options.Now().UTC()
	}

	return time.Now().UTC()
}

func intPointerFromString(value string) *int {
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return nil
	}

	return &parsed
}

func floatPointerFromString(value string) *float64 {
	if value == "" {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 {
		return nil
	}

	return &parsed
}
