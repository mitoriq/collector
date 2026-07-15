package contracts

type EventType string

const (
	EventTypeSessionStarted         EventType = "session.started"
	EventTypePromptSubmitted        EventType = "prompt.submitted"
	EventTypeModelResponseCompleted EventType = "model.response.completed"
	EventTypeToolStarted            EventType = "tool.started"
	EventTypeToolCompleted          EventType = "tool.completed"
	EventTypeToolFailed             EventType = "tool.failed"
	EventTypePermissionRequested    EventType = "permission.requested"
	EventTypeUserInputRequested     EventType = "user_input.requested"
	EventTypeSessionStopped         EventType = "session.stopped"
	EventTypeHeartbeat              EventType = "heartbeat"
)

type AgentEvent struct {
	ID                     string         `json:"id"`
	SchemaVersion          int            `json:"schemaVersion"`
	OrganizationID         string         `json:"organizationId"`
	MachineID              string         `json:"machineId"`
	MachineEnrollmentID    string         `json:"machineEnrollmentId"`
	MemberID               string         `json:"memberId"`
	SessionID              string         `json:"sessionId"`
	ProjectID              *string        `json:"projectId"`
	Source                 string         `json:"source"`
	OccurredAt             string         `json:"occurredAt"`
	IdempotencyKey         string         `json:"idempotencyKey"`
	PrivacyLevel           string         `json:"privacyLevel"`
	Type                   EventType      `json:"type"`
	Payload                map[string]any `json:"payload"`
	LocalDenyPaths         []string       `json:"-"`
	LocalRepoRemoteURLHash string         `json:"-"`
}

type CostAccuracy string

const (
	CostAccuracyActual    CostAccuracy = "actual"
	CostAccuracyEstimated CostAccuracy = "estimated"
	CostAccuracyUnknown   CostAccuracy = "unknown"
)

type Cost struct {
	Accuracy     CostAccuracy `json:"accuracy"`
	AmountUSD    *float64     `json:"amountUsd,omitempty"`
	InputTokens  *int         `json:"inputTokens,omitempty"`
	OutputTokens *int         `json:"outputTokens,omitempty"`
}

type RepoRef struct {
	RemoteURLHash        string  `json:"remoteUrlHash"`
	Branch               string  `json:"branch"`
	WorktreeRelativePath *string `json:"worktreeRelativePath,omitempty"`
}

type RepoAllowlistEntry struct {
	RemoteURLHash string `json:"remoteUrlHash"`
	Alias         string `json:"alias"`
}

type UsageMetric struct {
	ID                  string `json:"id"`
	SchemaVersion       int    `json:"schemaVersion"`
	OrganizationID      string `json:"organizationId"`
	MachineEnrollmentID string `json:"machineEnrollmentId"`
	SessionID           string `json:"sessionId"`
	Source              string `json:"source,omitempty"`
	Model               string `json:"model"`
	OccurredAt          string `json:"occurredAt"`
	InputTokens         *int   `json:"inputTokens,omitempty"`
	OutputTokens        *int   `json:"outputTokens,omitempty"`
	UsageCount          int    `json:"usageCount,omitempty"`
	Cost                Cost   `json:"cost"`
	IdempotencyKey      string `json:"idempotencyKey"`
}

type CollectorBatch struct {
	Events []AgentEvent `json:"events"`
	SentAt string       `json:"sentAt,omitempty"`
}

type CollectorUsageBatch struct {
	Metrics []UsageMetric `json:"metrics"`
	SentAt  string        `json:"sentAt,omitempty"`
}

type CollectorCounts struct {
	Accepted   int `json:"accepted"`
	Duplicated int `json:"duplicated"`
	Rejected   int `json:"rejected"`
}

type HeartbeatRequest struct {
	SchemaVersion       int    `json:"schemaVersion"`
	MachineID           string `json:"machineId"`
	MachineEnrollmentID string `json:"machineEnrollmentId"`
	CollectorVersion    string `json:"collectorVersion"`
	OccurredAt          string `json:"occurredAt"`
}

type HeartbeatResponse struct {
	ServerTime    string               `json:"serverTime"`
	Accepted      bool                 `json:"accepted"`
	RepoAllowlist []RepoAllowlistEntry `json:"repoAllowlist"`
}
