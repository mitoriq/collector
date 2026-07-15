package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

type nestedHookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

type nestedHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []nestedHookHandler `json:"hooks"`
}

type nestedHookSettings struct {
	Hooks map[string][]nestedHookGroup `json:"hooks"`
}

type cursorHookHandler struct {
	Matcher string `json:"matcher,omitempty"`
	Command string `json:"command"`
}

type cursorHookSettings struct {
	Version int                            `json:"version"`
	Hooks   map[string][]cursorHookHandler `json:"hooks"`
}

type hookEvent struct {
	Name    string
	Matcher string
}

func (plan installPlan) hookSettingsJSON() ([]byte, error) {
	if len(plan.Tools) != 1 || !isSupportedHookTool(plan.Tools[0]) {
		return nil, fmt.Errorf("--print-settings-json requires exactly one supported tool: claude, codex, or cursor")
	}
	tool := plan.Tools[0]
	command, err := hookCommand(plan.BinaryPath, tool)
	if err != nil {
		return nil, err
	}

	switch tool {
	case "claude":
		return json.MarshalIndent(nestedSettings(command, []hookEvent{
			{Name: "SessionStart", Matcher: "startup|resume|clear|compact"},
			{Name: "UserPromptSubmit"},
			{Name: "PreToolUse", Matcher: "*"},
			{Name: "PermissionRequest", Matcher: "*"},
			{Name: "PostToolUse", Matcher: "*"},
			{Name: "PostToolUseFailure", Matcher: "*"},
			{Name: "Notification", Matcher: "*"},
			{Name: "Elicitation", Matcher: "*"},
			{Name: "SessionEnd"},
		}), "", "  ")
	case "codex":
		return json.MarshalIndent(nestedSettings(command, []hookEvent{
			{Name: "UserPromptSubmit"},
			{Name: "PreToolUse", Matcher: "*"},
			{Name: "PermissionRequest", Matcher: "*"},
			{Name: "PostToolUse", Matcher: "*"},
			{Name: "Stop"},
		}), "", "  ")
	case "cursor":
		return json.MarshalIndent(cursorSettings(command, []hookEvent{
			{Name: "sessionStart"},
			{Name: "beforeSubmitPrompt"},
			{Name: "preToolUse", Matcher: "*"},
			{Name: "postToolUse", Matcher: "*"},
			{Name: "postToolUseFailure", Matcher: "*"},
			{Name: "sessionEnd"},
		}), "", "  ")
	}

	return nil, fmt.Errorf("unsupported hook tool: %s", tool)
}

func nestedSettings(command string, events []hookEvent) nestedHookSettings {
	hooks := make(map[string][]nestedHookGroup, len(events))
	for _, event := range events {
		hooks[event.Name] = []nestedHookGroup{{
			Matcher: event.Matcher,
			Hooks: []nestedHookHandler{{
				Type:    "command",
				Command: command,
			}},
		}}
	}

	return nestedHookSettings{Hooks: hooks}
}

func cursorSettings(command string, events []hookEvent) cursorHookSettings {
	hooks := make(map[string][]cursorHookHandler, len(events))
	for _, event := range events {
		hooks[event.Name] = []cursorHookHandler{{
			Matcher: event.Matcher,
			Command: command,
		}}
	}

	return cursorHookSettings{Version: 1, Hooks: hooks}
}

func hookCommand(binaryPath string, tool string) (string, error) {
	if binaryPath == "" || strings.ContainsAny(binaryPath, "\x00\r\n") {
		return "", fmt.Errorf("binary path contains unsupported characters")
	}
	subcommand := tool + "-hook"
	if tool == "cursor" {
		subcommand += " --cursor-hooks-beta"
	}

	return quoteHookArgument(binaryPath) + " " + subcommand, nil
}

func quoteHookArgument(value string) string {
	if strings.IndexFunc(value, func(char rune) bool {
		return !(unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("/._-", char))
	}) == -1 {
		return value
	}

	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func isSupportedHookTool(tool string) bool {
	switch tool {
	case "claude", "codex", "cursor":
		return true
	default:
		return false
	}
}
