package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestHookSettingsJSONUsesExactSupportedEventsAndMatchers(t *testing.T) {
	tests := []struct {
		tool             string
		expectedEvents   []string
		expectedMatchers map[string]string
	}{
		{
			tool: "claude",
			expectedEvents: []string{
				"Elicitation",
				"Notification",
				"PermissionRequest",
				"PostToolUse",
				"PostToolUseFailure",
				"PreToolUse",
				"SessionEnd",
				"SessionStart",
				"UserPromptSubmit",
			},
			expectedMatchers: map[string]string{
				"Elicitation":        "*",
				"Notification":       "*",
				"PermissionRequest":  "*",
				"PostToolUse":        "*",
				"PostToolUseFailure": "*",
				"PreToolUse":         "*",
				"SessionEnd":         "",
				"SessionStart":       "startup|resume|clear|compact",
				"UserPromptSubmit":   "",
			},
		},
		{
			tool:           "codex",
			expectedEvents: []string{"PermissionRequest", "PostToolUse", "PreToolUse", "Stop", "UserPromptSubmit"},
			expectedMatchers: map[string]string{
				"PermissionRequest": "*",
				"PostToolUse":       "*",
				"PreToolUse":        "*",
				"Stop":              "",
				"UserPromptSubmit":  "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.tool, func(t *testing.T) {
			body, err := (installPlan{
				BinaryPath: "/opt/mitoriq/bin/mitoriq-collector",
				Tools:      []string{test.tool},
			}).hookSettingsJSON()
			if err != nil {
				t.Fatal(err)
			}
			var settings nestedHookSettings
			if err := json.Unmarshal(body, &settings); err != nil {
				t.Fatal(err)
			}
			if got := sortedNestedHookNames(settings.Hooks); !reflect.DeepEqual(got, test.expectedEvents) {
				t.Fatalf("events = %#v, want %#v", got, test.expectedEvents)
			}
			for event, groups := range settings.Hooks {
				if len(groups) != 1 || len(groups[0].Hooks) != 1 {
					t.Fatalf("%s groups = %#v", event, groups)
				}
				if groups[0].Matcher != test.expectedMatchers[event] {
					t.Fatalf("%s matcher = %q, want %q", event, groups[0].Matcher, test.expectedMatchers[event])
				}
				if groups[0].Hooks[0].Type != "command" {
					t.Fatalf("%s handler = %#v", event, groups[0].Hooks[0])
				}
			}
		})
	}
}

func TestCursorHookSettingsJSONUsesFlatSchemaAndQuotesBinaryPath(t *testing.T) {
	body, err := (installPlan{
		BinaryPath: "/opt/Mitoriq Collector's/bin/mitoriq-collector",
		Tools:      []string{"cursor"},
	}).hookSettingsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var settings cursorHookSettings
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatal(err)
	}
	expectedEvents := []string{
		"beforeSubmitPrompt",
		"postToolUse",
		"postToolUseFailure",
		"preToolUse",
		"sessionEnd",
		"sessionStart",
	}
	if settings.Version != 1 {
		t.Fatalf("version = %d", settings.Version)
	}
	if got := sortedCursorHookNames(settings.Hooks); !reflect.DeepEqual(got, expectedEvents) {
		t.Fatalf("events = %#v, want %#v", got, expectedEvents)
	}
	expectedCommand := `'/opt/Mitoriq Collector'\''s/bin/mitoriq-collector' cursor-hook --cursor-hooks-beta`
	for event, handlers := range settings.Hooks {
		if len(handlers) != 1 || handlers[0].Command != expectedCommand {
			t.Fatalf("%s handlers = %#v", event, handlers)
		}
		if isCursorToolEvent(event) && handlers[0].Matcher != "*" {
			t.Fatalf("%s matcher = %q", event, handlers[0].Matcher)
		}
		if !isCursorToolEvent(event) && handlers[0].Matcher != "" {
			t.Fatalf("%s matcher = %q", event, handlers[0].Matcher)
		}
	}
}

func TestHookSettingsJSONQuotesShellMetacharactersAndPreservesJSONRoundTrip(t *testing.T) {
	binaryPath := "/opt/Mitoriq \"Collector\";$HOME/$(whoami)/`tick`\\bin/mitoriq-collector"
	body, err := (installPlan{
		BinaryPath: binaryPath,
		Tools:      []string{"claude"},
	}).hookSettingsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var settings nestedHookSettings
	if err := json.Unmarshal(body, &settings); err != nil {
		t.Fatal(err)
	}
	expectedCommand := "'" + binaryPath + "' claude-hook"
	for event, groups := range settings.Hooks {
		if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Command != expectedCommand {
			t.Fatalf("%s groups = %#v", event, groups)
		}
	}
}

func TestHookSettingsJSONRejectsEmptyAndControlCharacterBinaryPaths(t *testing.T) {
	for _, binaryPath := range []string{"", "/opt/mitoriq\ncollector", "/opt/mitoriq\rcollector", "/opt/mitoriq\x00collector"} {
		_, err := (installPlan{
			BinaryPath: binaryPath,
			Tools:      []string{"claude"},
		}).hookSettingsJSON()
		if err == nil {
			t.Fatalf("binary path = %q, expected error", binaryPath)
		}
	}
}

func sortedNestedHookNames(hooks map[string][]nestedHookGroup) []string {
	names := make([]string, 0, len(hooks))
	for name := range hooks {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

func sortedCursorHookNames(hooks map[string][]cursorHookHandler) []string {
	names := make([]string, 0, len(hooks))
	for name := range hooks {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

func isCursorToolEvent(event string) bool {
	switch event {
	case "preToolUse", "postToolUse", "postToolUseFailure":
		return true
	default:
		return false
	}
}
