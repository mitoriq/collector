package localconfig

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

type RepoDenyEntry struct {
	Alias         string `json:"alias,omitempty"`
	RemoteURLHash string `json:"remoteUrlHash"`
}

type DenyRules struct {
	PathGlobs   []string        `json:"pathGlobs,omitempty"`
	PathRegexes []string        `json:"pathRegexes,omitempty"`
	Repos       []RepoDenyEntry `json:"repos,omitempty"`
}

type DenyPolicy struct {
	invalidReasons []string
	pathGlobs      []compiledGlob
	pathRegexes    []*regexp.Regexp
	repoHashes     map[string]bool
	rules          DenyRules
}

type compiledGlob struct {
	matchBase bool
	pattern   string
	regex     *regexp.Regexp
}

func CompileDenyPolicy(rules DenyRules) DenyPolicy {
	policy := DenyPolicy{
		repoHashes: map[string]bool{},
		rules: DenyRules{
			PathGlobs:   append([]string(nil), rules.PathGlobs...),
			PathRegexes: append([]string(nil), rules.PathRegexes...),
			Repos:       append([]RepoDenyEntry(nil), rules.Repos...),
		},
	}
	for _, entry := range rules.Repos {
		hash := strings.TrimSpace(entry.RemoteURLHash)
		if hash == "" {
			policy.invalidReasons = append(policy.invalidReasons, "deny.repos contains an empty remoteUrlHash")
			continue
		}
		policy.repoHashes[hash] = true
	}
	for _, pattern := range rules.PathGlobs {
		glob, err := compileGlob(pattern)
		if err != nil {
			policy.invalidReasons = append(policy.invalidReasons, err.Error())
			continue
		}
		policy.pathGlobs = append(policy.pathGlobs, glob)
	}
	for _, pattern := range rules.PathRegexes {
		normalized := strings.TrimSpace(pattern)
		if normalized == "" {
			policy.invalidReasons = append(policy.invalidReasons, "deny.pathRegexes contains an empty pattern")
			continue
		}
		compiled, err := regexp.Compile(normalized)
		if err != nil {
			policy.invalidReasons = append(policy.invalidReasons, fmt.Sprintf("deny.pathRegexes %q is invalid: %v", normalized, err))
			continue
		}
		policy.pathRegexes = append(policy.pathRegexes, compiled)
	}
	sort.Strings(policy.invalidReasons)

	return policy
}

func (policy DenyPolicy) InvalidReasons() []string {
	return append([]string(nil), policy.invalidReasons...)
}

func (policy DenyPolicy) Empty() bool {
	return len(policy.rules.Repos) == 0 && len(policy.rules.PathGlobs) == 0 && len(policy.rules.PathRegexes) == 0
}

func (policy DenyPolicy) DeniesAllL2() bool {
	return len(policy.invalidReasons) > 0
}

func (policy DenyPolicy) DeniesRepo(remoteURLHash string) bool {
	if policy.DeniesAllL2() {
		return true
	}

	return policy.repoHashes[strings.TrimSpace(remoteURLHash)]
}

func (policy DenyPolicy) DeniesAnyPath(paths []string) bool {
	if policy.DeniesAllL2() {
		return true
	}
	for _, candidate := range paths {
		if policy.DeniesPath(candidate) {
			return true
		}
	}

	return false
}

func (policy DenyPolicy) DeniesPath(candidate string) bool {
	if policy.DeniesAllL2() {
		return true
	}
	normalized := normalizePath(candidate)
	if normalized == "" {
		return false
	}
	for _, glob := range policy.pathGlobs {
		if glob.matches(normalized) {
			return true
		}
	}
	for _, regex := range policy.pathRegexes {
		if regex.MatchString(normalized) {
			return true
		}
	}

	return false
}

func compileGlob(pattern string) (compiledGlob, error) {
	normalized := normalizePath(pattern)
	if normalized == "" {
		return compiledGlob{}, fmt.Errorf("deny.pathGlobs contains an empty pattern")
	}
	if _, err := path.Match(normalized, ""); err != nil {
		return compiledGlob{}, fmt.Errorf("deny.pathGlobs %q is invalid: %v", normalized, err)
	}
	expression, err := globExpression(normalized)
	if err != nil {
		return compiledGlob{}, err
	}
	regex, err := regexp.Compile(expression)
	if err != nil {
		return compiledGlob{}, fmt.Errorf("deny.pathGlobs %q is invalid: %v", normalized, err)
	}

	return compiledGlob{
		matchBase: !strings.Contains(normalized, "/"),
		pattern:   normalized,
		regex:     regex,
	}, nil
}

func (glob compiledGlob) matches(candidate string) bool {
	if glob.matchBase {
		for _, segment := range strings.Split(candidate, "/") {
			if glob.regex.MatchString(segment) {
				return true
			}
		}

		return false
	}

	return glob.regex.MatchString(candidate) || glob.regex.MatchString(candidate+"/")
}

func normalizePath(value string) string {
	normalized := path.Clean(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
	if normalized == "." {
		return ""
	}
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")

	return normalized
}

func globExpression(pattern string) (string, error) {
	var builder strings.Builder
	builder.WriteString("^")
	for index := 0; index < len(pattern); index++ {
		character := pattern[index]
		switch character {
		case '*':
			if index+1 < len(pattern) && pattern[index+1] == '*' {
				builder.WriteString(".*")
				index++
			} else {
				builder.WriteString("[^/]*")
			}
		case '?':
			builder.WriteString("[^/]")
		case '[':
			end := strings.IndexByte(pattern[index+1:], ']')
			if end < 0 {
				return "", fmt.Errorf("deny.pathGlobs %q is invalid: missing ]", pattern)
			}
			class := pattern[index+1 : index+1+end]
			expression, err := globCharacterClassExpression(pattern, class)
			if err != nil {
				return "", err
			}
			builder.WriteString(expression)
			index += end + 1
		case '\\':
			if index+1 >= len(pattern) {
				return "", fmt.Errorf("deny.pathGlobs %q is invalid: dangling escape", pattern)
			}
			index++
			builder.WriteString(regexp.QuoteMeta(string(pattern[index])))
		default:
			builder.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	builder.WriteString("$")

	return builder.String(), nil
}

func globCharacterClassExpression(pattern string, class string) (string, error) {
	if class == "" {
		return "", fmt.Errorf("deny.pathGlobs %q is invalid: empty character class", pattern)
	}
	var builder strings.Builder
	builder.WriteString("[")
	for index := 0; index < len(class); index++ {
		character := class[index]
		if character == '\\' {
			if index+1 >= len(class) {
				return "", fmt.Errorf("deny.pathGlobs %q is invalid: dangling character class escape", pattern)
			}
			index++
			builder.WriteString(regexp.QuoteMeta(string(class[index])))
			continue
		}
		switch character {
		case '[', ']':
			builder.WriteString(regexp.QuoteMeta(string(character)))
		default:
			builder.WriteByte(character)
		}
	}
	builder.WriteString("]")

	return builder.String(), nil
}
