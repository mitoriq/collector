package gitcontext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mitoriq/collector/internal/contracts"
)

type CommandRunner interface {
	Run(ctx context.Context, cwd string, args []string) (string, error)
}

type ExecRunner struct {
	GitPath string
}

type CommandError struct {
	ExitCode int
	Stderr   string
}

type DiffStat struct {
	AddedLines   int
	ChangedPaths []string
	DeletedLines int
	FilesChanged int
}

type Snapshot struct {
	DiffStat DiffStat
	Repo     *contracts.RepoRef
}

type Resolver struct {
	runner CommandRunner
}

func NewResolver(runner CommandRunner) Resolver {
	return Resolver{runner: runner}
}

func DefaultResolver() Resolver {
	return NewResolver(ExecRunner{GitPath: "git"})
}

func (runner ExecRunner) Run(ctx context.Context, cwd string, args []string) (string, error) {
	gitPath := runner.GitPath
	if strings.TrimSpace(gitPath) == "" {
		gitPath = "git"
	}
	cmdArgs := append([]string{"-C", cwd}, args...)
	command := exec.CommandContext(ctx, gitPath, cmdArgs...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", CommandError{ExitCode: exitErr.ExitCode(), Stderr: stderr.String()}
		}

		return "", err
	}

	return string(output), nil
}

func (err CommandError) Error() string {
	if strings.TrimSpace(err.Stderr) == "" {
		return fmt.Sprintf("git command failed with exit code %d", err.ExitCode)
	}

	return fmt.Sprintf("git command failed with exit code %d: %s", err.ExitCode, strings.TrimSpace(err.Stderr))
}

func (resolver Resolver) Resolve(ctx context.Context, cwd string) (Snapshot, error) {
	normalizedCWD := strings.TrimSpace(cwd)
	if normalizedCWD == "" {
		return Snapshot{}, nil
	}
	root, ok, err := resolver.requiredOutput(ctx, normalizedCWD, []string{"rev-parse", "--show-toplevel"})
	if err != nil || !ok {
		return Snapshot{}, err
	}
	remoteURL, ok, err := resolver.optionalOutput(ctx, normalizedCWD, []string{"config", "--get", "remote.origin.url"})
	if err != nil || !ok || strings.TrimSpace(remoteURL) == "" {
		return Snapshot{}, err
	}
	branch, err := resolver.branch(ctx, normalizedCWD)
	if err != nil {
		return Snapshot{}, err
	}
	relativePath, err := resolver.relativePath(ctx, normalizedCWD)
	if err != nil {
		return Snapshot{}, err
	}
	diffStat, err := resolver.diffStat(ctx, normalizedCWD)
	if err != nil {
		return Snapshot{}, err
	}
	repo := contracts.RepoRef{
		RemoteURLHash:        hashRemoteURL(remoteURL),
		Branch:               branch,
		WorktreeRelativePath: relativePath,
	}
	if strings.TrimSpace(root) == "" {
		return Snapshot{}, nil
	}

	return Snapshot{DiffStat: diffStat, Repo: &repo}, nil
}

func IsReadOnlyGitArgs(args []string) bool {
	allowed := [][]string{
		{"rev-parse", "--show-toplevel"},
		{"rev-parse", "--show-prefix"},
		{"rev-parse", "--short", "HEAD"},
		{"config", "--get", "remote.origin.url"},
		{"symbolic-ref", "--short", "HEAD"},
		{"diff", "--numstat", "HEAD", "--"},
		{"diff", "--numstat", "--"},
	}
	for _, candidate := range allowed {
		if stringSlicesEqual(args, candidate) {
			return true
		}
	}

	return false
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index, value := range left {
		if value != right[index] {
			return false
		}
	}

	return true
}

func (resolver Resolver) requiredOutput(ctx context.Context, cwd string, args []string) (string, bool, error) {
	output, err := resolver.runner.Run(ctx, cwd, args)
	if err != nil {
		if isGitExitError(err) {
			return "", false, nil
		}

		return "", false, err
	}

	return strings.TrimSpace(output), true, nil
}

func (resolver Resolver) optionalOutput(ctx context.Context, cwd string, args []string) (string, bool, error) {
	output, err := resolver.runner.Run(ctx, cwd, args)
	if err != nil {
		if isGitExitError(err) {
			return "", false, nil
		}

		return "", false, err
	}

	return strings.TrimSpace(output), true, nil
}

func (resolver Resolver) branch(ctx context.Context, cwd string) (string, error) {
	branch, ok, err := resolver.optionalOutput(ctx, cwd, []string{"symbolic-ref", "--short", "HEAD"})
	if err != nil {
		return "", err
	}
	if ok && strings.TrimSpace(branch) != "" {
		return strings.TrimSpace(branch), nil
	}
	commit, ok, err := resolver.optionalOutput(ctx, cwd, []string{"rev-parse", "--short", "HEAD"})
	if err != nil {
		return "", err
	}
	if ok && strings.TrimSpace(commit) != "" {
		return "detached:" + strings.TrimSpace(commit), nil
	}

	return "unknown", nil
}

func (resolver Resolver) relativePath(ctx context.Context, cwd string) (*string, error) {
	prefix, ok, err := resolver.optionalOutput(ctx, cwd, []string{"rev-parse", "--show-prefix"})
	if err != nil || !ok {
		return nil, err
	}
	relativePath := strings.Trim(strings.TrimSpace(prefix), "/")
	if relativePath == "" {
		return nil, nil
	}
	if !isSafeRelativePath(relativePath) {
		return nil, fmt.Errorf("unsafe repo-relative path")
	}

	return &relativePath, nil
}

func (resolver Resolver) diffStat(ctx context.Context, cwd string) (DiffStat, error) {
	output, ok, err := resolver.optionalOutput(ctx, cwd, []string{"diff", "--numstat", "HEAD", "--"})
	if err != nil {
		return DiffStat{}, err
	}
	if !ok {
		output, ok, err = resolver.optionalOutput(ctx, cwd, []string{"diff", "--numstat", "--"})
		if err != nil || !ok {
			return DiffStat{}, err
		}
	}

	return parseDiffStat(output), nil
}

func parseDiffStat(output string) DiffStat {
	var stat DiffStat
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		stat.FilesChanged++
		stat.AddedLines += parseNumStatCount(parts[0])
		stat.DeletedLines += parseNumStatCount(parts[1])
		if isSafeRelativePath(parts[2]) {
			stat.ChangedPaths = append(stat.ChangedPaths, strings.TrimSpace(parts[2]))
		}
	}

	return stat
}

func parseNumStatCount(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 0 {
		return 0
	}

	return parsed
}

func hashRemoteURL(remoteURL string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(remoteURL)))

	return hex.EncodeToString(sum[:])
}

func isGitExitError(err error) bool {
	var commandErr CommandError

	return errors.As(err, &commandErr)
}

func isSafeRelativePath(value string) bool {
	if strings.HasPrefix(value, "/") || strings.Contains(value, "://") {
		return false
	}
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return false
		}
	}
	if len(value) >= 2 && value[1] == ':' {
		return false
	}

	return true
}
