package normalize

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mitoriq/collector/internal/contracts"
)

var (
	absolutePathPattern        = regexp.MustCompile(`(^|[\s"'])(/[^\s"']+)`)
	windowsDrivePathPattern    = regexp.MustCompile(`(^|[\s"'])([A-Za-z]:[\\/][^\s"']+)`)
	windowsUNCPathPattern      = regexp.MustCompile(`(^|[\s"'])(\\\\[^\\/\s"']+[\\/][^\s"']+)`)
	windowsDriveAbsolutePrefix = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	hexTokenPattern            = regexp.MustCompile(`^[a-fA-F0-9]+$`)
	highEntropyTokenPattern    = regexp.MustCompile(`\b[A-Za-z0-9+/=_-]{32,}\b`)
	secretPatterns             = []secretPattern{
		{
			name:        "private-key",
			placeholder: "[REDACTED:private-key]",
			pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		},
		{
			name:        "db_connection",
			placeholder: "[REDACTED:db_connection]",
			pattern:     regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s"'<>]+`),
		},
		{
			name:        "aws_key",
			placeholder: "[REDACTED:aws_key]",
			pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		},
		{
			name:        "gcp_key",
			placeholder: "[REDACTED:gcp_key]",
			pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		},
		{
			name:        "azure_key",
			placeholder: "[REDACTED:azure_key]",
			pattern:     regexp.MustCompile(`(?i)\b(?:DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{20,};EndpointSuffix=[^\s"']+|AccountKey=[A-Za-z0-9+/=]{20,})`),
		},
		{
			name:        "anthropic_key",
			placeholder: "[REDACTED:anthropic_key]${1}",
			pattern:     regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{8,}([^A-Za-z0-9_-]|$)`),
		},
		{
			name:        "openai_key",
			placeholder: "[REDACTED:openai_key]${1}",
			pattern:     regexp.MustCompile(`\bsk-(?:(?:proj|admin)-[A-Za-z0-9_-]{8,}|[A-Za-z0-9]{8,})([^A-Za-z0-9_-]|$)`),
		},
		{
			name:        "slack_token",
			placeholder: "[REDACTED:slack_token]${1}",
			pattern:     regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{8,}([^A-Za-z0-9-]|$)`),
		},
		{
			name:        "stripe_key",
			placeholder: "[REDACTED:stripe_key]",
			pattern:     regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b`),
		},
		{
			name:        "github_token",
			placeholder: "[REDACTED:github_token]",
			pattern:     regexp.MustCompile(`\bgh[opsru]_[A-Za-z0-9_]{20,}\b`),
		},
		{
			name:        "gitlab_token",
			placeholder: "[REDACTED:gitlab_token]",
			pattern:     regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
		},
		{
			name:        "mitoriq_token",
			placeholder: "[REDACTED:mitoriq_token]",
			pattern:     regexp.MustCompile(`\bmtq_[A-Za-z0-9][A-Za-z0-9_-]{8,}\b`),
		},
		{
			name:        "jwt",
			placeholder: "[REDACTED:jwt]",
			pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		},
	}
)

const highEntropyThreshold = 4.25

type secretPattern struct {
	name        string
	pattern     *regexp.Regexp
	placeholder string
}

type RawEvent struct {
	ID             string
	IdempotencyKey string
	LocalDenyPaths []string
	OccurredAt     string
	Payload        map[string]any
	ProjectID      *string
	SessionID      string
	Source         string
	Type           string
}

type NormalizeOptions struct {
	MachineEnrollmentID string
	MachineID           string
	MemberID            string
	OrganizationID      string
	PrivacyLevel        string
	Redaction           RedactionOptions
}

type RedactionOptions struct {
	Environment map[string]string
	Hostname    string
	RepoRoot    string
	Username    string
}

const promptSummaryMaxRunes = 200

func AgentName(value string) string {
	return strings.TrimSpace(value)
}

func NormalizeRawEvent(raw RawEvent, options NormalizeOptions) (contracts.AgentEvent, error) {
	payload, err := RedactPayload(raw.Payload, options.Redaction)
	if err != nil {
		return contracts.AgentEvent{}, err
	}
	source := raw.Source
	if source == "" {
		source = "generic"
	}
	eventType := contracts.EventType(raw.Type)
	privacyLevel := options.PrivacyLevel
	if privacyLevel == "" {
		privacyLevel = defaultPrivacyLevel(eventType)
	}
	idempotencyKey := raw.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = fmt.Sprintf("%s:%s:%s", options.MachineEnrollmentID, source, raw.ID)
	}

	event := contracts.AgentEvent{
		ID:                  raw.ID,
		SchemaVersion:       1,
		OrganizationID:      options.OrganizationID,
		MachineID:           options.MachineID,
		MachineEnrollmentID: options.MachineEnrollmentID,
		MemberID:            options.MemberID,
		SessionID:           raw.SessionID,
		ProjectID:           raw.ProjectID,
		Source:              source,
		OccurredAt:          raw.OccurredAt,
		IdempotencyKey:      idempotencyKey,
		PrivacyLevel:        privacyLevel,
		Type:                eventType,
		Payload:             payload,
		LocalDenyPaths:      append([]string(nil), raw.LocalDenyPaths...),
	}
	if err := validateNormalizedEvent(event); err != nil {
		return contracts.AgentEvent{}, err
	}

	return event, nil
}

func RedactPayload(input map[string]any, options RedactionOptions) (map[string]any, error) {
	normalized, err := normalizeJSONPayload(input)
	if err != nil {
		return nil, err
	}

	return redactMap(normalized, options)
}

func RedactText(value string, options RedactionOptions) string {
	return redactString(value, options)
}

func PromptSummary(value string, options RedactionOptions) string {
	redacted := strings.Join(strings.Fields(RedactText(value, options)), " ")
	runes := []rune(redacted)
	if len(runes) <= promptSummaryMaxRunes {
		return redacted
	}

	return string(runes[:promptSummaryMaxRunes])
}

func redactValue(value any, options RedactionOptions) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed, options)
	case []any:
		next := make([]any, 0, len(typed))
		for _, entry := range typed {
			redacted, err := redactValue(entry, options)
			if err != nil {
				return nil, err
			}
			next = append(next, redacted)
		}
		return next, nil
	case string:
		return redactString(typed, options), nil
	default:
		return value, nil
	}
}

func normalizeJSONPayload(input map[string]any) (map[string]any, error) {
	bytes, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func redactMap(input map[string]any, options RedactionOptions) (map[string]any, error) {
	next := make(map[string]any, len(input))
	for key, entry := range input {
		redacted, err := redactValue(entry, options)
		if err != nil {
			return nil, err
		}
		next[redactString(key, options)] = redacted
	}

	return next, nil
}

func redactString(value string, options RedactionOptions) string {
	redacted := redactPath(value, options.RepoRoot)
	redacted = redactKnownSecrets(redacted)
	redacted = replaceSecret(redacted, options.Hostname, "[redacted:hostname]")
	redacted = replaceSecret(redacted, options.Username, "[redacted:user]")
	for _, envValue := range options.Environment {
		redacted = replaceSecret(redacted, envValue, "[redacted:env]")
	}

	return redacted
}

func redactKnownSecrets(value string) string {
	redacted := value
	for _, entry := range secretPatterns {
		redacted = entry.pattern.ReplaceAllString(redacted, entry.placeholder)
	}

	return highEntropyTokenPattern.ReplaceAllStringFunc(redacted, func(token string) string {
		if shouldRedactHighEntropy(token) {
			return "[REDACTED:high_entropy]"
		}

		return token
	})
}

func shouldRedactHighEntropy(value string) bool {
	return !hexTokenPattern.MatchString(value) && shannonEntropy(value) >= highEntropyThreshold
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, char := range value {
		counts[char]++
	}
	length := float64(len([]rune(value)))
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

func redactPath(value string, repoRoot string) string {
	redacted := value
	if repoRoot == "" {
		if isAbsolutePath(redacted) {
			return "[redacted:absolute-path]"
		}
		return redactEmbeddedAbsolutePaths(redacted, "")
	}

	cleanRoot := cleanComparablePath(repoRoot)
	if isAbsolutePath(redacted) {
		return redactAbsolutePath(redacted, cleanRoot)
	}
	return redactEmbeddedAbsolutePaths(redacted, cleanRoot)
}

func redactAbsolutePath(value string, repoRoot string) string {
	cleanValue := cleanComparablePath(value)
	if relative, ok := relativePathWithin(repoRoot, cleanValue); ok && relative != "." {
		return relative
	}
	if cleanValue == repoRoot {
		return "."
	}

	return "[redacted:absolute-path]"
}

func replaceSecret(value string, secret string, placeholder string) string {
	if len(secret) < 3 {
		return value
	}

	return strings.ReplaceAll(value, secret, placeholder)
}

func redactEmbeddedAbsolutePaths(value string, repoRoot string) string {
	redacted := absolutePathPattern.ReplaceAllStringFunc(value, func(match string) string {
		pathStart := strings.Index(match, "/")
		if pathStart < 0 {
			return match
		}
		prefix := match[:pathStart]
		path := match[pathStart:]
		if repoRoot != "" {
			return prefix + redactAbsolutePath(path, repoRoot)
		}

		return prefix + "[redacted:absolute-path]"
	})

	redacted = windowsDrivePathPattern.ReplaceAllStringFunc(redacted, func(match string) string {
		pathStart := windowsDrivePathStart(match)
		if pathStart < 0 {
			return match
		}
		prefix := match[:pathStart]
		value := match[pathStart:]
		if repoRoot != "" {
			return prefix + redactAbsolutePath(value, repoRoot)
		}

		return prefix + "[redacted:absolute-path]"
	})

	return windowsUNCPathPattern.ReplaceAllStringFunc(redacted, func(match string) string {
		pathStart := strings.Index(match, `\\`)
		if pathStart < 0 {
			return match
		}
		prefix := match[:pathStart]
		value := match[pathStart:]
		if repoRoot != "" {
			return prefix + redactAbsolutePath(value, repoRoot)
		}

		return prefix + "[redacted:absolute-path]"
	})
}

func isAbsolutePath(value string) bool {
	return filepath.IsAbs(value) || windowsDriveAbsolutePrefix.MatchString(value) || strings.HasPrefix(value, `\\`)
}

func cleanComparablePath(value string) string {
	if windowsDriveAbsolutePrefix.MatchString(value) || strings.HasPrefix(value, `\\`) {
		normalized := strings.ReplaceAll(value, "\\", "/")
		cleaned := path.Clean(normalized)
		if windowsDriveAbsolutePrefix.MatchString(value) && len(cleaned) >= 2 {
			return strings.ToLower(cleaned[:2]) + cleaned[2:]
		}

		return strings.ToLower(cleaned)
	}

	return filepath.ToSlash(filepath.Clean(value))
}

func relativePathWithin(root string, value string) (string, bool) {
	if root == "" {
		return "", false
	}
	if strings.EqualFold(value, root) {
		return ".", true
	}
	prefix := strings.TrimRight(root, "/") + "/"
	if !strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
		return "", false
	}

	return value[len(prefix):], true
}

func windowsDrivePathStart(value string) int {
	for index := 0; index+2 < len(value); index++ {
		char := value[index]
		if ((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')) &&
			value[index+1] == ':' &&
			(value[index+2] == '\\' || value[index+2] == '/') {
			return index
		}
	}

	return -1
}

func defaultPrivacyLevel(eventType contracts.EventType) string {
	if eventType == contracts.EventTypeHeartbeat {
		return "L0"
	}

	return "L1"
}

func validateNormalizedEvent(event contracts.AgentEvent) error {
	if event.Payload == nil {
		return fmt.Errorf("payload is required")
	}
	allowedLevels, ok := allowedPrivacyLevels[event.Type]
	if !ok {
		return fmt.Errorf("unknown event type: %s", event.Type)
	}
	if !allowedLevels[event.PrivacyLevel] {
		return fmt.Errorf("privacy level %s is not allowed for %s", event.PrivacyLevel, event.Type)
	}

	return nil
}

var allowedPrivacyLevels = map[contracts.EventType]map[string]bool{
	contracts.EventTypeSessionStarted: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypePromptSubmitted: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeModelResponseCompleted: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeToolStarted: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeToolCompleted: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeToolFailed: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypePermissionRequested: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeUserInputRequested: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeSessionStopped: {
		"L1": true,
		"L2": true,
		"L3": true,
		"L4": true,
	},
	contracts.EventTypeHeartbeat: {
		"L0": true,
	},
}
