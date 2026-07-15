package discovery

import "testing"

func TestCandidatesIncludesWindowsCodexAndWSLSharedHome(t *testing.T) {
	candidates := Candidates(Options{
		Env: map[string]string{
			"USERPROFILE": "C:\\Users\\dev",
		},
		GOOS: "windows",
		Home: "C:\\Users\\dev",
	})

	assertCandidate(t, candidates, Candidate{
		Tool:   "codex",
		Kind:   "home",
		Path:   "C:\\Users\\dev\\.codex",
		Source: "USERPROFILE",
	})
	assertCandidate(t, candidates, Candidate{
		Tool:   "codex",
		Kind:   "wsl-shared-home",
		Path:   "/mnt/c/Users/dev/.codex",
		Source: "USERPROFILE",
	})
	assertCandidate(t, candidates, Candidate{
		Tool:   "claude-code",
		Kind:   "session-log-dir",
		Path:   "C:\\Users\\dev\\.claude\\projects",
		Source: "USERPROFILE",
	})
}

func TestCandidatesIncludesExplicitCodexHome(t *testing.T) {
	candidates := Candidates(Options{
		Env: map[string]string{
			"CODEX_HOME": "/mnt/c/Users/dev/.codex",
		},
		GOOS: "linux",
		Home: "/home/dev",
	})

	assertCandidate(t, candidates, Candidate{
		Tool:   "codex",
		Kind:   "home",
		Path:   "/mnt/c/Users/dev/.codex",
		Source: "CODEX_HOME",
	})
	assertCandidate(t, candidates, Candidate{
		Tool:   "codex",
		Kind:   "session-log-dir",
		Path:   "/mnt/c/Users/dev/.codex/sessions",
		Source: "CODEX_HOME",
	})
}

func assertCandidate(t *testing.T, candidates []Candidate, expected Candidate) {
	t.Helper()
	for _, candidate := range candidates {
		if candidate == expected {
			return
		}
	}

	t.Fatalf("candidate %#v missing from %#v", expected, candidates)
}
