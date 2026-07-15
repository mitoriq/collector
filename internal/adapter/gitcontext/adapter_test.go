package gitcontext_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mitoriq/collector/internal/adapter/gitcontext"
)

type commandResult struct {
	output string
	err    error
}

type recordingRunner struct {
	calls   [][]string
	results map[string]commandResult
}

func (runner *recordingRunner) Run(_ context.Context, _ string, args []string) (string, error) {
	next := append([]string(nil), args...)
	runner.calls = append(runner.calls, next)
	result := runner.results[strings.Join(args, "\x00")]

	return result.output, result.err
}

func TestResolveCollectsPrivacySafeRepoMetadataAndDiffStat(t *testing.T) {
	remoteURL := "git@github.com:example-org/example-repo.git"
	runner := &recordingRunner{results: map[string]commandResult{
		key("rev-parse", "--show-toplevel"):         {output: "/Users/dev/work/example-repo\n"},
		key("config", "--get", "remote.origin.url"): {output: remoteURL + "\n"},
		key("symbolic-ref", "--short", "HEAD"):      {output: "feat/git-adapter\n"},
		key("rev-parse", "--show-prefix"):           {output: "apps/collector/\n"},
		key("diff", "--numstat", "HEAD", "--"):      {output: "3\t1\tapps/collector/main.go\n-\t-\tassets/logo.png\n"},
	}}

	snapshot, err := gitcontext.NewResolver(runner).Resolve(context.Background(), "/Users/dev/work/example-repo/apps/collector")

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo == nil {
		t.Fatal("repo should be resolved")
	}
	if snapshot.Repo.RemoteURLHash != sha256Hex(remoteURL) {
		t.Fatalf("remote hash = %s", snapshot.Repo.RemoteURLHash)
	}
	if snapshot.Repo.Branch != "feat/git-adapter" {
		t.Fatalf("branch = %q", snapshot.Repo.Branch)
	}
	if snapshot.Repo.WorktreeRelativePath == nil || *snapshot.Repo.WorktreeRelativePath != "apps/collector" {
		t.Fatalf("worktree relative path = %#v", snapshot.Repo.WorktreeRelativePath)
	}
	if snapshot.DiffStat.FilesChanged != 2 || snapshot.DiffStat.AddedLines != 3 || snapshot.DiffStat.DeletedLines != 1 {
		t.Fatalf("diff stat = %#v", snapshot.DiffStat)
	}
	if strings.Join(snapshot.DiffStat.ChangedPaths, ",") != "apps/collector/main.go,assets/logo.png" {
		t.Fatalf("changed paths = %#v", snapshot.DiffStat.ChangedPaths)
	}
	encoded, err := json.Marshal(snapshot.Repo)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), remoteURL) || strings.Contains(string(encoded), "/Users/dev") {
		t.Fatalf("repo ref leaked sensitive values: %s", string(encoded))
	}
	for _, call := range runner.calls {
		if !gitcontext.IsReadOnlyGitArgs(call) {
			t.Fatalf("non read-only git args used: %v", call)
		}
	}
}

func TestResolveReturnsNullRepoOutsideGitWorktree(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		key("rev-parse", "--show-toplevel"): {err: gitcontext.CommandError{ExitCode: 128}},
	}}

	snapshot, err := gitcontext.NewResolver(runner).Resolve(context.Background(), "/tmp/not-a-repo")

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo != nil {
		t.Fatalf("repo = %#v", snapshot.Repo)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %#v", runner.calls)
	}
}

func TestResolveReturnsNullRepoWhenRemoteIsMissing(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		key("rev-parse", "--show-toplevel"):         {output: "/repo\n"},
		key("config", "--get", "remote.origin.url"): {err: gitcontext.CommandError{ExitCode: 1}},
	}}

	snapshot, err := gitcontext.NewResolver(runner).Resolve(context.Background(), "/repo")

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo != nil {
		t.Fatalf("repo = %#v", snapshot.Repo)
	}
}

func TestResolveHandlesDetachedHeadAndDiffFallback(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		key("rev-parse", "--show-toplevel"):         {output: "/repo\n"},
		key("config", "--get", "remote.origin.url"): {output: "https://github.com/example-org/example-repo.git\n"},
		key("symbolic-ref", "--short", "HEAD"):      {err: gitcontext.CommandError{ExitCode: 1}},
		key("rev-parse", "--short", "HEAD"):         {output: "abc1234\n"},
		key("rev-parse", "--show-prefix"):           {output: "\n"},
		key("diff", "--numstat", "HEAD", "--"):      {err: gitcontext.CommandError{ExitCode: 128}},
		key("diff", "--numstat", "--"):              {output: "2\t0\tREADME.md\n"},
	}}

	snapshot, err := gitcontext.NewResolver(runner).Resolve(context.Background(), "/repo")

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo == nil || snapshot.Repo.Branch != "detached:abc1234" {
		t.Fatalf("repo = %#v", snapshot.Repo)
	}
	if snapshot.Repo.WorktreeRelativePath != nil {
		t.Fatalf("worktreeRelativePath = %#v", snapshot.Repo.WorktreeRelativePath)
	}
	if snapshot.DiffStat.FilesChanged != 1 || snapshot.DiffStat.AddedLines != 2 {
		t.Fatalf("diff stat = %#v", snapshot.DiffStat)
	}
	if len(snapshot.DiffStat.ChangedPaths) != 1 || snapshot.DiffStat.ChangedPaths[0] != "README.md" {
		t.Fatalf("changed paths = %#v", snapshot.DiffStat.ChangedPaths)
	}
}

func TestResolveRejectsUnsafeRelativePath(t *testing.T) {
	runner := &recordingRunner{results: map[string]commandResult{
		key("rev-parse", "--show-toplevel"):         {output: "/repo\n"},
		key("config", "--get", "remote.origin.url"): {output: "https://github.com/example-org/example-repo.git\n"},
		key("symbolic-ref", "--short", "HEAD"):      {output: "main\n"},
		key("rev-parse", "--show-prefix"):           {output: "../private\n"},
	}}

	_, err := gitcontext.NewResolver(runner).Resolve(context.Background(), "/repo")

	if err == nil {
		t.Fatal("expected unsafe relative path error")
	}
}

func TestDefaultResolverReadsRealGitRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := filepath.Join(t.TempDir(), "repo")
	runGit(t, "", "init", "-b", "main", repo)
	runGit(t, repo, "remote", "add", "origin", "git@github.com:example-org/example-repo.git")
	readme := filepath.Join(repo, "README.md")
	if err := os.WriteFile(readme, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "README.md")
	runGit(t, repo, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init")
	if err := os.WriteFile(readme, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(repo, "apps", "collector")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}

	snapshot, err := gitcontext.DefaultResolver().Resolve(context.Background(), cwd)

	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Repo == nil || snapshot.Repo.Branch != "main" {
		t.Fatalf("repo = %#v", snapshot.Repo)
	}
	if snapshot.Repo.WorktreeRelativePath == nil || *snapshot.Repo.WorktreeRelativePath != "apps/collector" {
		t.Fatalf("worktreeRelativePath = %#v", snapshot.Repo.WorktreeRelativePath)
	}
	if snapshot.DiffStat.FilesChanged != 1 || snapshot.DiffStat.AddedLines != 1 {
		t.Fatalf("diff stat = %#v", snapshot.DiffStat)
	}
	if len(snapshot.DiffStat.ChangedPaths) != 1 || snapshot.DiffStat.ChangedPaths[0] != "README.md" {
		t.Fatalf("changed paths = %#v", snapshot.DiffStat.ChangedPaths)
	}
}

func TestIsReadOnlyGitArgsRejectsWriteCommands(t *testing.T) {
	for _, args := range [][]string{
		{"status"},
		{"add", "."},
		{"config", "--global", "--add", "safe.directory", "*"},
		nil,
	} {
		if gitcontext.IsReadOnlyGitArgs(args) {
			t.Fatalf("args should not be read-only: %v", args)
		}
	}
}

func TestCommandErrorFormatsExitCodeAndStderr(t *testing.T) {
	withStderr := gitcontext.CommandError{ExitCode: 128, Stderr: "fatal: not a git repository\n"}
	withoutStderr := gitcontext.CommandError{ExitCode: 1}

	if !strings.Contains(withStderr.Error(), "fatal: not a git repository") {
		t.Fatalf("error = %q", withStderr.Error())
	}
	if !strings.Contains(withoutStderr.Error(), "exit code 1") {
		t.Fatalf("error = %q", withoutStderr.Error())
	}
}

func key(args ...string) string {
	return strings.Join(args, "\x00")
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:])
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	if dir != "" {
		command.Dir = dir
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
}
