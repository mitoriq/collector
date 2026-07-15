package codexcli

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

const Source = "codex"

const unpricedEstimatedAmountUSD = 0

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
	CWD              string          `json:"cwd"`
	DurationMs       *float64        `json:"duration_ms"`
	HookEventName    string          `json:"hook_event_name"`
	Model            string          `json:"model"`
	SessionID        string          `json:"session_id"`
	SessionIDCamel   string          `json:"sessionId"`
	Timestamp        string          `json:"timestamp"`
	ToolInput        json.RawMessage `json:"tool_input"`
	ToolName         string          `json:"tool_name"`
	ToolResponse     json.RawMessage `json:"tool_response"`
	ToolUseID        string          `json:"tool_use_id"`
	NotificationType string          `json:"notification_type"`
	Prompt           string          `json:"prompt"`
	TranscriptPath   *string         `json:"transcript_path"`
	TurnID           string          `json:"turn_id"`
}

type TokenUsage struct {
	InputTokens       *int `json:"input_tokens"`
	InputTokensCamel  *int `json:"inputTokens"`
	OutputTokens      *int `json:"output_tokens"`
	OutputTokensCamel *int `json:"outputTokens"`
}

type sessionRow struct {
	Payload   sessionPayload `json:"payload"`
	Timestamp string         `json:"timestamp"`
	Type      string         `json:"type"`
}

type sessionPayload struct {
	CWD       string      `json:"cwd"`
	Event     string      `json:"event"`
	ID        string      `json:"id"`
	Item      itemPayload `json:"item"`
	Model     string      `json:"model"`
	Sandbox   string      `json:"sandbox"`
	SessionID string      `json:"session_id"`
	Tool      string      `json:"tool"`
	TurnID    string      `json:"turn_id"`
}

type itemPayload struct {
	CallID  string      `json:"call_id"`
	Content string      `json:"content"`
	Model   string      `json:"model"`
	Name    string      `json:"name"`
	Role    string      `json:"role"`
	Type    string      `json:"type"`
	Usage   *TokenUsage `json:"usage"`
}

type sessionState struct {
	CWD             string
	SourceSessionID string
	StartedAt       time.Time
	TurnID          string
}

type hookEventSpec struct {
	EventType contracts.EventType
	Payload   map[string]any
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
	specs, err := hookEvents(input, options)
	if err != nil {
		return Collection{}, err
	}
	if len(specs) == 0 {
		return Collection{}, nil
	}
	events := make([]contracts.AgentEvent, 0, len(specs))
	for _, spec := range specs {
		event, err := normalizeEvent(input, spec.EventType, spec.Payload, options)
		if err != nil {
			return Collection{}, err
		}
		events = append(events, event)
	}

	return Collection{Events: events}, nil
}

func ParseSessionJSONL(reader io.Reader, options Options) (Collection, error) {
	var collection Collection
	var state sessionState
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		next, nextState, err := parseSessionLine(scanner.Text(), state, options)
		if err != nil {
			return Collection{}, err
		}
		state = nextState
		collection = mergeCollection(collection, next)
	}
	if err := scanner.Err(); err != nil {
		return Collection{}, err
	}

	return collection, nil
}

func ParseUserInputJSONL(reader io.Reader, options Options) (Collection, error) {
	collection, err := ParseSessionJSONL(reader, options)
	if err != nil {
		return Collection{}, err
	}
	events := make([]contracts.AgentEvent, 0, len(collection.Events))
	for _, event := range collection.Events {
		if event.Type == contracts.EventTypeUserInputRequested {
			events = append(events, event)
		}
	}

	return Collection{Events: events}, nil
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

func parseSessionLine(line string, state sessionState, options Options) (Collection, sessionState, error) {
	if strings.TrimSpace(line) == "" {
		return Collection{}, state, nil
	}
	var row sessionRow
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		return Collection{}, state, err
	}
	nextState := updateState(row, state, options)
	collection, err := collectionFromRow(row, nextState, options)
	if err != nil {
		return Collection{}, state, err
	}

	return collection, nextState, nil
}

func updateState(row sessionRow, state sessionState, options Options) sessionState {
	if row.Type != "session_meta" && row.Type != "turn_context" {
		return state
	}
	next := state
	if row.Payload.SessionID != "" {
		next.SourceSessionID = row.Payload.SessionID
	} else if row.Payload.ID != "" {
		next.SourceSessionID = row.Payload.ID
	}
	if row.Payload.CWD != "" {
		next.CWD = row.Payload.CWD
	}
	if row.Type == "turn_context" && row.Payload.TurnID != "" {
		next.TurnID = row.Payload.TurnID
	}
	if next.StartedAt.IsZero() {
		next.StartedAt = startedAt(options, occurredAt(row.Timestamp, options))
	}

	return next
}

func collectionFromRow(row sessionRow, state sessionState, options Options) (Collection, error) {
	switch row.Type {
	case "session_meta":
		return sessionStartedCollection(row, state, options)
	case "response_item":
		return responseItemCollection(row, state, options)
	case "event_msg":
		return eventMessageCollection(row, state, options)
	default:
		return Collection{}, nil
	}
}

func sessionStartedCollection(row sessionRow, state sessionState, options Options) (Collection, error) {
	input := hookInputFromState(row, state)
	payload, err := sessionStartedPayload(input, options)
	if err != nil {
		return Collection{}, err
	}
	if row.Payload.Model != "" {
		payload["model"] = strings.TrimSpace(row.Payload.Model)
	}
	event, err := normalizeEvent(input, contracts.EventTypeSessionStarted, payload, optionsWithSessionStartedAt(options, state.StartedAt))
	if err != nil {
		return Collection{}, err
	}

	return Collection{Events: []contracts.AgentEvent{event}}, nil
}

func responseItemCollection(row sessionRow, state sessionState, options Options) (Collection, error) {
	input := hookInputFromState(row, state)
	input.ToolName = row.Payload.Item.Name
	input.ToolUseID = row.Payload.Item.CallID
	stateOptions := optionsForState(options, state)
	switch row.Payload.Item.Type {
	case "function_call":
		if isUserInputTool(input.ToolName) {
			event, err := normalizeEvent(
				input,
				contracts.EventTypeUserInputRequested,
				map[string]any{"reason": "elicitation"},
				stateOptions,
			)
			return collectionWithEvent(event, err)
		}
		event, err := normalizeEvent(input, contracts.EventTypeToolStarted, map[string]any{"toolName": toolName(input)}, stateOptions)
		return collectionWithEvent(event, err)
	case "function_call_output":
		payload, err := toolCompletedPayload(input, stateOptions)
		if err != nil {
			return Collection{}, err
		}
		event, err := normalizeEvent(input, contracts.EventTypeToolCompleted, payload, stateOptions)
		return collectionWithEvent(event, err)
	case "message":
		if row.Payload.Item.Role == "user" {
			return promptSubmittedCollection(row, state, stateOptions)
		}
		return usageCollection(row, state, stateOptions)
	default:
		return Collection{}, nil
	}
}

func promptSubmittedCollection(row sessionRow, state sessionState, options Options) (Collection, error) {
	prompt := strings.TrimSpace(row.Payload.Item.Content)
	if prompt == "" {
		return Collection{}, nil
	}
	input := hookInputFromState(row, state)
	summary := normalize.PromptSummary(prompt, options.Redaction)
	payload := map[string]any{"charCount": len([]rune(prompt))}
	if summary != "" {
		payload["promptSummary"] = summary
	}
	event, err := normalizeEvent(input, contracts.EventTypePromptSubmitted, payload, options)

	return collectionWithEvent(event, err)
}

func eventMessageCollection(row sessionRow, state sessionState, options Options) (Collection, error) {
	if !isApprovalEvent(row.Payload.Event, row.Payload.Sandbox) {
		return Collection{}, nil
	}
	input := hookInputFromState(row, state)
	input.ToolName = row.Payload.Tool
	event, err := normalizeEvent(input, contracts.EventTypePermissionRequested, permissionPayload(input), optionsForState(options, state))

	return collectionWithEvent(event, err)
}

func collectionWithEvent(event contracts.AgentEvent, err error) (Collection, error) {
	if err != nil {
		return Collection{}, err
	}

	return Collection{Events: []contracts.AgentEvent{event}}, nil
}

func usageCollection(row sessionRow, state sessionState, options Options) (Collection, error) {
	metric, err := usageMetric(
		state.SourceSessionID,
		state.CWD,
		occurredAt(row.Timestamp, options),
		row.Payload.Item.Model,
		row.Payload.Item.Usage,
		estimatedCost(row.Payload.Item.Usage),
		options,
	)
	if err != nil {
		return Collection{}, err
	}

	return Collection{UsageMetrics: []contracts.UsageMetric{metric}}, nil
}

func hookEvent(input HookInput, options Options) (contracts.EventType, map[string]any, bool, error) {
	switch input.HookEventName {
	case "PermissionRequest":
		return contracts.EventTypePermissionRequested, permissionPayload(input), true, nil
	case "PreToolUse":
		if isUserInputTool(input.ToolName) {
			return contracts.EventTypeUserInputRequested, map[string]any{"reason": "elicitation"}, true, nil
		}
		return contracts.EventTypeToolStarted, map[string]any{"toolName": toolName(input)}, true, nil
	case "PostToolUse":
		if exitCode, failed := exitCodeFromToolResponse(input.ToolResponse); failed {
			return contracts.EventTypeToolFailed, map[string]any{
				"toolName": toolName(input),
				"exitCode": exitCode,
			}, true, nil
		}
		payload, err := toolCompletedPayload(input, options)
		return contracts.EventTypeToolCompleted, payload, true, err
	default:
		return "", nil, false, nil
	}
}

func hookEvents(input HookInput, options Options) ([]hookEventSpec, error) {
	switch input.HookEventName {
	case "UserPromptSubmit":
		if strings.TrimSpace(input.TurnID) == "" {
			return nil, nil
		}
		payload, err := sessionStartedPayload(input, options)
		if err != nil {
			return nil, err
		}
		if model := strings.TrimSpace(input.Model); model != "" {
			payload["model"] = model
		}
		return []hookEventSpec{
			{EventType: contracts.EventTypeSessionStarted, Payload: payload},
			{EventType: contracts.EventTypePromptSubmitted, Payload: promptPayload(input.Prompt, options)},
		}, nil
	case "Stop":
		if strings.TrimSpace(input.TurnID) == "" {
			return nil, nil
		}
		payload, err := sessionStoppedPayload(input, options)
		if err != nil {
			return nil, err
		}
		specs := []hookEventSpec{}
		if model := strings.TrimSpace(input.Model); model != "" {
			specs = append(specs, hookEventSpec{
				EventType: contracts.EventTypeModelResponseCompleted,
				Payload: map[string]any{
					"model": model,
					"cost":  contracts.Cost{Accuracy: contracts.CostAccuracyUnknown},
				},
			})
		}

		return append(specs, hookEventSpec{
			EventType: contracts.EventTypeSessionStopped,
			Payload:   payload,
		}), nil
	default:
		eventType, payload, ok, err := hookEvent(input, options)
		if err != nil || !ok {
			return nil, err
		}

		return []hookEventSpec{{EventType: eventType, Payload: payload}}, nil
	}
}

func normalizeEvent(
	input HookInput,
	eventType contracts.EventType,
	payload map[string]any,
	options Options,
) (contracts.AgentEvent, error) {
	input = input.withCanonicalSessionID()
	occurredAt := occurredAt(input.Timestamp, options)
	sessionID := StableSessionKey(turnScopedSourceSessionID(input), Source, input.CWD, stableStartedAt(options))
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
	sessionID := StableSessionKey(sourceSessionID, Source, cwd, stableStartedAt(options))
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
		IdempotencyKey:      id + ":codex",
	}, nil
}

func hookInputFromState(row sessionRow, state sessionState) HookInput {
	return HookInput{
		CWD:       state.CWD,
		SessionID: state.SourceSessionID,
		Timestamp: row.Timestamp,
		TurnID:    state.TurnID,
	}
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

func occurredAt(timestamp string, options Options) time.Time {
	if timestamp != "" {
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err == nil {
			return parsed.UTC()
		}
	}
	if options.Now != nil {
		return options.Now().UTC()
	}

	return time.Now().UTC()
}

func startedAt(options Options, fallback time.Time) time.Time {
	if !options.SessionStartedAt.IsZero() {
		return options.SessionStartedAt.UTC()
	}

	return fallback.UTC()
}

func stableStartedAt(options Options) time.Time {
	if !options.SessionStartedAt.IsZero() {
		return options.SessionStartedAt.UTC()
	}

	return time.Unix(0, 0).UTC()
}

func optionsWithSessionStartedAt(options Options, startedAt time.Time) Options {
	if !options.SessionStartedAt.IsZero() || startedAt.IsZero() {
		return options
	}
	next := options
	next.SessionStartedAt = startedAt.UTC()

	return next
}

func optionsForState(options Options, state sessionState) Options {
	if strings.TrimSpace(state.TurnID) != "" {
		return options
	}

	return optionsWithSessionStartedAt(options, state.StartedAt)
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

	return map[string]any{"_localSnapshot": snapshot, "repo": repo}, nil
}

func sessionStoppedPayload(input HookInput, options Options) (map[string]any, error) {
	payload := map[string]any{
		"reason":     "normal",
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

func permissionPayload(input HookInput) map[string]any {
	return map[string]any{
		"toolName": toolName(input),
		"action":   "approval_required",
	}
}

func promptPayload(prompt string, options Options) map[string]any {
	prompt = strings.TrimSpace(prompt)
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
		return "Codex"
	}

	return name
}

func isUserInputTool(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	switch normalized {
	case "request_user_input", "ask_user_question", "elicitation":
		return true
	default:
		return strings.HasSuffix(normalized, ".request_user_input")
	}
}

func exitCodeFromToolResponse(response json.RawMessage) (int, bool) {
	if len(response) == 0 {
		return 0, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response, &fields); err != nil {
		return 0, false
	}
	for _, key := range []string{"exit_code", "exitCode"} {
		value, ok := fields[key]
		if !ok {
			continue
		}
		var exitCode int
		if err := json.Unmarshal(value, &exitCode); err == nil {
			return exitCode, exitCode != 0
		}
		var encoded string
		if err := json.Unmarshal(value, &encoded); err != nil {
			continue
		}
		exitCode, err := strconv.Atoi(encoded)
		if err == nil {
			return exitCode, exitCode != 0
		}
	}

	return 0, false
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
	case contracts.EventTypeToolCompleted:
		if payload["filesChanged"] != nil {
			return "L2"
		}
	case contracts.EventTypeSessionStopped:
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

func isApprovalEvent(event string, sandbox string) bool {
	return strings.Contains(event, "approval") || strings.TrimSpace(sandbox) != ""
}

func estimatedCost(usage *TokenUsage) contracts.Cost {
	amountUSD := float64(unpricedEstimatedAmountUSD)
	return contracts.Cost{
		Accuracy:     contracts.CostAccuracyEstimated,
		AmountUSD:    &amountUSD,
		InputTokens:  usage.inputTokens(),
		OutputTokens: usage.outputTokens(),
	}
}

func eventID(sessionID string, input HookInput, eventType contracts.EventType, occurredAt time.Time) string {
	return "evt_" + shortHash(strings.Join([]string{
		sessionID,
		string(eventType),
		eventDiscriminator(input),
		idempotencyTimestamp(input, occurredAt),
	}, "\x00"))
}

func idempotencyKey(sessionID string, input HookInput, eventType contracts.EventType, occurredAt time.Time) string {
	return strings.Join([]string{
		"collector:" + Source,
		sessionID,
		string(eventType),
		eventDiscriminator(input),
		idempotencyTimestamp(input, occurredAt),
	}, ":")
}

func eventDiscriminator(input HookInput) string {
	if strings.TrimSpace(input.ToolUseID) != "" {
		return input.ToolUseID
	}
	if input.HookEventName == "" {
		return ""
	}

	return "hook_" + shortHash(strings.Join([]string{
		input.HookEventName,
		input.ToolName,
		canonicalToolInput(input.ToolInput),
	}, "\x00"))
}

func canonicalToolInput(input json.RawMessage) string {
	if len(input) == 0 {
		return ""
	}
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return string(input)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return string(input)
	}

	return string(encoded)
}

func idempotencyTimestamp(input HookInput, occurredAt time.Time) string {
	if input.HookEventName != "" && input.Timestamp == "" {
		return ""
	}

	return occurredAt.Format(time.RFC3339Nano)
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

func (input HookInput) withCanonicalSessionID() HookInput {
	if input.SessionID != "" || input.SessionIDCamel == "" {
		return input
	}
	input.SessionID = input.SessionIDCamel

	return input
}

func turnScopedSourceSessionID(input HookInput) string {
	if strings.TrimSpace(input.TurnID) == "" {
		return input.SessionID
	}

	return strings.Join([]string{input.SessionID, input.TurnID}, "\x00")
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
	if attributes["event.name"] != "response.completed" {
		return contracts.UsageMetric{}, false, nil
	}
	usage := &TokenUsage{
		InputTokens:  intPointerFromString(attributes["input_tokens"]),
		OutputTokens: intPointerFromString(attributes["output_tokens"]),
	}
	metric, err := usageMetric(
		attributes["session.id"],
		attributes["cwd"],
		otelOccurredAt(record, options),
		attributes["model"],
		usage,
		estimatedCost(usage),
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

	return occurredAt("", options)
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
