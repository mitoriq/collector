package main

import (
	"encoding/xml"
	"path/filepath"
	"strings"
)

type launchdPlistXMLNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr            `xml:",any,attr"`
	Text     string                `xml:",chardata"`
	Children []launchdPlistXMLNode `xml:",any"`
}

func isOwnedLaunchdPlist(body []byte) bool {
	var root launchdPlistXMLNode
	if err := xml.Unmarshal(body, &root); err != nil {
		return false
	}
	if root.XMLName.Local != "plist" || strings.TrimSpace(root.Text) != "" ||
		len(root.Children) != 1 || !hasExactPlistVersion(root.Attrs) {
		return false
	}
	entries, ok := launchdPlistDictionary(root.Children[0])
	if !ok || !hasOwnedLaunchdCore(entries) {
		return false
	}
	if environment, exists := entries["EnvironmentVariables"]; exists {
		return hasExactLaunchdKeys(
			entries,
			"Label",
			"ProgramArguments",
			"EnvironmentVariables",
			"RunAtLoad",
			"KeepAlive",
		) && isCurrentLaunchdOwnershipEnvironment(environment)
	}

	return hasExactLaunchdKeys(
		entries,
		"Label",
		"ProgramArguments",
		"RunAtLoad",
		"KeepAlive",
	)
}

func hasExactPlistVersion(attributes []xml.Attr) bool {
	return len(attributes) == 1 &&
		attributes[0].Name.Local == "version" &&
		attributes[0].Value == "1.0"
}

func launchdPlistDictionary(node launchdPlistXMLNode) (map[string]launchdPlistXMLNode, bool) {
	if node.XMLName.Local != "dict" || len(node.Attrs) != 0 ||
		strings.TrimSpace(node.Text) != "" || len(node.Children)%2 != 0 {
		return nil, false
	}
	entries := make(map[string]launchdPlistXMLNode, len(node.Children)/2)
	for index := 0; index < len(node.Children); index += 2 {
		keyNode := node.Children[index]
		if keyNode.XMLName.Local != "key" || len(keyNode.Attrs) != 0 ||
			len(keyNode.Children) != 0 || strings.TrimSpace(keyNode.Text) == "" {
			return nil, false
		}
		key := keyNode.Text
		if _, exists := entries[key]; exists {
			return nil, false
		}
		entries[key] = node.Children[index+1]
	}

	return entries, true
}

func hasOwnedLaunchdCore(entries map[string]launchdPlistXMLNode) bool {
	label, hasLabel := launchdPlistString(entries["Label"])
	arguments, hasArguments := launchdPlistStringArray(entries["ProgramArguments"])
	if !hasLabel || label != launchdServiceLabel || !hasArguments || len(arguments) != 2 ||
		arguments[1] != "daemon" || !isSafeAbsoluteLaunchdBinary(arguments[0]) {
		return false
	}

	return launchdPlistTrue(entries["RunAtLoad"]) && launchdPlistTrue(entries["KeepAlive"])
}

func isCurrentLaunchdOwnershipEnvironment(node launchdPlistXMLNode) bool {
	environment, ok := launchdPlistDictionary(node)
	if !ok || !hasExactLaunchdKeys(environment, launchdOwnershipMarker) {
		return false
	}
	marker, ok := launchdPlistString(environment[launchdOwnershipMarker])

	return ok && marker == launchdOwnershipValue
}

func hasExactLaunchdKeys(entries map[string]launchdPlistXMLNode, keys ...string) bool {
	if len(entries) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := entries[key]; !exists {
			return false
		}
	}

	return true
}

func launchdPlistString(node launchdPlistXMLNode) (string, bool) {
	if node.XMLName.Local != "string" || len(node.Attrs) != 0 || len(node.Children) != 0 {
		return "", false
	}

	return node.Text, true
}

func launchdPlistStringArray(node launchdPlistXMLNode) ([]string, bool) {
	if node.XMLName.Local != "array" || len(node.Attrs) != 0 || strings.TrimSpace(node.Text) != "" {
		return nil, false
	}
	values := make([]string, 0, len(node.Children))
	for _, child := range node.Children {
		value, ok := launchdPlistString(child)
		if !ok {
			return nil, false
		}
		values = append(values, value)
	}

	return values, true
}

func launchdPlistTrue(node launchdPlistXMLNode) bool {
	return node.XMLName.Local == "true" && len(node.Attrs) == 0 &&
		len(node.Children) == 0 && strings.TrimSpace(node.Text) == ""
}

func isSafeAbsoluteLaunchdBinary(binaryPath string) bool {
	return filepath.IsAbs(binaryPath) && binaryPath != "" &&
		!strings.ContainsAny(binaryPath, "\x00\r\n")
}
