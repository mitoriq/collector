package discovery

import (
	"os"
	"runtime"
	"strings"
)

type Candidate struct {
	Tool   string
	Kind   string
	Path   string
	Source string
}

type Options struct {
	Env  map[string]string
	GOOS string
	Home string
}

func RuntimeOptions() Options {
	return Options{
		Env:  runtimeEnv(),
		GOOS: runtime.GOOS,
		Home: homeDir(),
	}
}

func Candidates(options Options) []Candidate {
	goos := options.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	home, homeSource := homePath(options, goos)

	var candidates []Candidate
	if codexHome := strings.TrimSpace(options.Env["CODEX_HOME"]); codexHome != "" {
		candidates = appendCodexCandidates(candidates, codexHome, "CODEX_HOME", goos)
	} else if home != "" {
		candidates = appendCodexCandidates(candidates, join(goos, home, ".codex"), homeSource, goos)
	}
	if goos == "windows" && home != "" {
		if sharedHome := windowsHomeToWSLPath(home); sharedHome != "" {
			candidates = append(candidates, Candidate{
				Tool:   "codex",
				Kind:   "wsl-shared-home",
				Path:   join("linux", sharedHome, ".codex"),
				Source: homeSource,
			})
		}
	}
	if home != "" {
		claudeHome := join(goos, home, ".claude")
		candidates = append(candidates,
			Candidate{Tool: "claude-code", Kind: "home", Path: claudeHome, Source: homeSource},
			Candidate{Tool: "claude-code", Kind: "settings", Path: join(goos, claudeHome, "settings.json"), Source: homeSource},
			Candidate{Tool: "claude-code", Kind: "session-log-dir", Path: join(goos, claudeHome, "projects"), Source: homeSource},
		)
	}

	return dedupe(candidates)
}

func appendCodexCandidates(candidates []Candidate, codexHome string, source string, goos string) []Candidate {
	return append(candidates,
		Candidate{Tool: "codex", Kind: "home", Path: codexHome, Source: source},
		Candidate{Tool: "codex", Kind: "config", Path: join(goos, codexHome, "config.toml"), Source: source},
		Candidate{Tool: "codex", Kind: "session-log-dir", Path: join(goos, codexHome, "sessions"), Source: source},
	)
}

func homePath(options Options, goos string) (string, string) {
	if goos == "windows" {
		if userProfile := strings.TrimSpace(options.Env["USERPROFILE"]); userProfile != "" {
			return userProfile, "USERPROFILE"
		}
		if homeDrive := strings.TrimSpace(options.Env["HOMEDRIVE"]); homeDrive != "" {
			if homePath := strings.TrimSpace(options.Env["HOMEPATH"]); homePath != "" {
				return homeDrive + homePath, "HOMEDRIVE+HOMEPATH"
			}
		}
	}
	if options.Home != "" {
		return options.Home, "home"
	}
	if home := strings.TrimSpace(options.Env["HOME"]); home != "" {
		return home, "HOME"
	}

	return "", ""
}

func windowsHomeToWSLPath(home string) string {
	normalized := strings.ReplaceAll(home, "\\", "/")
	if len(normalized) < 3 || normalized[1] != ':' || normalized[2] != '/' {
		return ""
	}
	drive := strings.ToLower(normalized[:1])
	rest := strings.TrimPrefix(normalized[2:], "/")
	if rest == "" {
		return "/mnt/" + drive
	}

	return "/mnt/" + drive + "/" + rest
}

func join(goos string, base string, parts ...string) string {
	separator := "/"
	if goos == "windows" {
		separator = "\\"
	}
	path := strings.TrimRight(base, `/\`)
	for _, part := range parts {
		cleanPart := strings.Trim(part, `/\`)
		if cleanPart == "" {
			continue
		}
		if path == "" {
			path = cleanPart
			continue
		}
		path += separator + cleanPart
	}

	return path
}

func dedupe(candidates []Candidate) []Candidate {
	seen := make(map[Candidate]bool, len(candidates))
	next := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Path == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true
		next = append(next, candidate)
	}

	return next
}

func runtimeEnv() map[string]string {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			env[key] = value
		}
	}

	return env
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return home
}
