package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	launchdServiceLabel = "com.mitoriq.collector"
	systemdServiceName  = "mitoriq-collector.service"
)

type commandRunner interface {
	Run(name string, args ...string) error
}

type execCommandRunner struct{}

func (execCommandRunner) Run(name string, args ...string) error {
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", name, err)
	}

	return fmt.Errorf("%s: %w: %s", name, err, message)
}

type launchdAtomicFileOps struct {
	createTemp func(dir string, pattern string) (*os.File, error)
	remove     func(name string) error
	rename     func(oldPath string, newPath string) error
	write      func(file *os.File, body []byte) error
}

func defaultLaunchdAtomicFileOps() launchdAtomicFileOps {
	return launchdAtomicFileOps{
		createTemp: os.CreateTemp,
		remove:     os.Remove,
		rename:     os.Rename,
		write: func(file *os.File, body []byte) error {
			written, err := file.Write(body)
			if err != nil {
				return err
			}
			if written != len(body) {
				return io.ErrShortWrite
			}

			return nil
		},
	}
}

func runInstall(args []string, stdout io.Writer, stderr io.Writer) error {
	return runInstallForOS(args, stdout, stderr, runtime.GOOS, execCommandRunner{}, "")
}

func runInstallForOS(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	goos string,
	runner commandRunner,
	userIdentity string,
) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	binaryPath := flags.String("binary", "", "mitoriq-collector binary path")
	dryRun := flags.Bool("dry-run", false, "print planned files without writing")
	printSettingsJSON := flags.Bool("print-settings-json", false, "print a complete hook settings JSON block without installing")
	tools := flags.String("tools", "", "comma-separated tools: claude,codex,cursor")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*tools) == "" {
		return fmt.Errorf("--tools is required")
	}
	resolvedBinary := *binaryPath
	if resolvedBinary == "" {
		current, err := os.Executable()
		if err != nil {
			return err
		}
		resolvedBinary = current
	}
	plan := installPlan{
		BinaryPath:  resolvedBinary,
		LaunchdPath: defaultLaunchdPath(),
		Tools:       parseTools(*tools),
	}
	if *printSettingsJSON {
		if goos != "darwin" && goos != "linux" {
			return fmt.Errorf("unsupported operating system for install: %s", goos)
		}
		settings, err := plan.hookSettingsJSON()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(settings))

		return err
	}

	switch goos {
	case "darwin":
		if !*dryRun && strings.TrimSpace(userIdentity) == "" {
			currentUser, err := user.Current()
			if err != nil {
				return fmt.Errorf("resolve current user for launchd: %w", err)
			}
			userIdentity = currentUser.Uid
		}
		return installLaunchd(plan, *dryRun, stdout, runner, userIdentity)
	case "linux":
		if !*dryRun && strings.TrimSpace(userIdentity) == "" {
			currentUser, err := user.Current()
			if err != nil {
				return fmt.Errorf("resolve current user for systemd linger: %w", err)
			}
			userIdentity = currentUser.Username
		}
		return installSystemdUser(plan, *dryRun, stdout, runner, userIdentity)
	default:
		return fmt.Errorf("unsupported operating system for install: %s", goos)
	}
}

func installLaunchd(
	plan installPlan,
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	if !dryRun {
		if err := activateLaunchdService(plan, runner, userID); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(stdout, "collector_install_status=%s launchd_plist=%s\n", installStatus(dryRun), plan.LaunchdPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, plan.launchdPlist()); err != nil {
		return err
	}

	return writeHookSnippets(stdout, plan)
}

func activateLaunchdService(plan installPlan, runner commandRunner, userID string) error {
	domain, err := launchdUserDomain(userID)
	if err != nil {
		return err
	}
	serviceTarget := domain + "/" + launchdServiceLabel
	isLoaded, err := launchdServiceLoaded(runner, serviceTarget)
	if err != nil {
		return err
	}
	previousPlist, readErr := os.ReadFile(plan.LaunchdPath)
	hadPreviousPlist := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read existing launchd plist: %w", readErr)
	}
	if isLoaded && !hadPreviousPlist {
		return fmt.Errorf("loaded launchd service is missing its owned plist: %s", plan.LaunchdPath)
	}
	if err := writeLaunchdPlist(plan.LaunchdPath, plan.launchdPlist()); err != nil {
		return err
	}
	if isLoaded {
		if err := runner.Run("launchctl", "bootout", serviceTarget); err != nil {
			restoreErr := restoreLaunchdPlist(plan.LaunchdPath, previousPlist, hadPreviousPlist)
			return errors.Join(fmt.Errorf("boot out existing launchd service: %w", err), restoreErr)
		}
	}
	if err := runner.Run("launchctl", "bootstrap", domain, plan.LaunchdPath); err != nil {
		restoreErr := restoreLaunchdPlist(plan.LaunchdPath, previousPlist, hadPreviousPlist)
		var restartErr error
		if isLoaded && restoreErr == nil {
			if err := runner.Run("launchctl", "bootstrap", domain, plan.LaunchdPath); err != nil {
				restartErr = fmt.Errorf("restart previous launchd service after rollback: %w", err)
			}
		}
		return errors.Join(fmt.Errorf("bootstrap launchd service: %w", err), restoreErr, restartErr)
	}

	return nil
}

func launchdUserDomain(userID string) (string, error) {
	uid, err := strconv.Atoi(strings.TrimSpace(userID))
	if err != nil || uid < 0 {
		return "", fmt.Errorf("current user ID is required to activate launchd service")
	}

	return fmt.Sprintf("gui/%d", uid), nil
}

func launchdServiceLoaded(runner commandRunner, serviceTarget string) (bool, error) {
	err := runner.Run("launchctl", "print", serviceTarget)
	if err == nil {
		return true, nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "could not find service") {
		return false, nil
	}

	return false, fmt.Errorf("inspect launchd service: %w", err)
}

func restoreLaunchdPlist(path string, previous []byte, existed bool) error {
	if existed {
		if err := writeLaunchdPlistBytesWithOps(
			path,
			previous,
			defaultLaunchdAtomicFileOps(),
		); err != nil {
			return fmt.Errorf("restore previous launchd plist: %w", err)
		}

		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove failed launchd plist: %w", err)
	}

	return nil
}

func writeLaunchdPlistWithOps(
	filePath string,
	body string,
	ops launchdAtomicFileOps,
) error {
	return writeLaunchdPlistBytesWithOps(filePath, []byte(body+"\n"), ops)
}

func writeLaunchdPlistBytesWithOps(
	filePath string,
	body []byte,
	ops launchdAtomicFileOps,
) error {
	directory := filepath.Dir(filePath)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temp, err := ops.createTemp(directory, "."+filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	shouldRemoveTemp := true
	defer func() {
		_ = temp.Close()
		if shouldRemoveTemp {
			_ = ops.remove(tempPath)
		}
	}()

	if err := ops.write(temp, body); err != nil {
		return err
	}
	if err := temp.Chmod(0o644); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := ops.rename(tempPath, filePath); err != nil {
		return err
	}
	shouldRemoveTemp = false
	syncLaunchdDirectory(directory)

	return nil
}

func syncLaunchdDirectory(directory string) {
	handle, err := os.Open(directory)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

func installSystemdUser(
	plan installPlan,
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	username string,
) error {
	unitPath := defaultSystemdUserPath()
	unit, err := plan.systemdUserUnit()
	if err != nil {
		return err
	}
	if !dryRun {
		if strings.TrimSpace(username) == "" {
			return fmt.Errorf("current username is required to enable systemd linger")
		}
		if err := writeServiceFile(unitPath, unit); err != nil {
			return fmt.Errorf("write systemd user unit: %w", err)
		}
		if err := runner.Run("systemctl", "--user", "daemon-reload"); err != nil {
			_ = os.Remove(unitPath)
			return fmt.Errorf("reload systemd user manager: %w", err)
		}
		if err := runner.Run("loginctl", "enable-linger", username); err != nil {
			rollbackErr := rollbackSystemdInstall(unitPath, runner, false)
			return errors.Join(fmt.Errorf("enable systemd linger: %w", err), rollbackErr)
		}
		if err := runner.Run("systemctl", "--user", "enable", "--now", systemdServiceName); err != nil {
			rollbackErr := rollbackSystemdInstall(unitPath, runner, true)
			return errors.Join(fmt.Errorf("enable systemd user service: %w", err), rollbackErr)
		}
	}
	if _, err := fmt.Fprintf(stdout, "collector_install_status=%s systemd_unit=%s\n", installStatus(dryRun), unitPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, unit); err != nil {
		return err
	}

	return writeHookSnippets(stdout, plan)
}

func rollbackSystemdInstall(unitPath string, runner commandRunner, disable bool) error {
	var rollbackErrors []error
	if disable {
		if err := runner.Run("systemctl", "--user", "disable", "--now", systemdServiceName); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("disable partially enabled systemd user service: %w", err))
		}
	}
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("remove systemd user unit: %w", err))
	}
	if err := runner.Run("systemctl", "--user", "daemon-reload"); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("reload systemd user manager after rollback: %w", err))
	}

	return errors.Join(rollbackErrors...)
}

func runUninstall(args []string, stdout io.Writer, stderr io.Writer) error {
	return runUninstallForOS(args, stdout, stderr, runtime.GOOS, execCommandRunner{}, "")
}

func runUninstallForOS(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	goos string,
	runner commandRunner,
	userIdentity string,
) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "print planned removals without writing")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	switch goos {
	case "darwin":
		if !*dryRun && strings.TrimSpace(userIdentity) == "" {
			currentUser, err := user.Current()
			if err != nil {
				return fmt.Errorf("resolve current user for launchd: %w", err)
			}
			userIdentity = currentUser.Uid
		}
		return uninstallLaunchd(*dryRun, stdout, runner, userIdentity)
	case "linux":
		return uninstallSystemdUser(*dryRun, stdout, runner)
	default:
		return fmt.Errorf("unsupported operating system for uninstall: %s", goos)
	}
}

func uninstallLaunchd(
	dryRun bool,
	stdout io.Writer,
	runner commandRunner,
	userID string,
) error {
	launchdPath := defaultLaunchdPath()
	if !dryRun {
		domain, err := launchdUserDomain(userID)
		if err != nil {
			return err
		}
		serviceTarget := domain + "/" + launchdServiceLabel
		isLoaded, err := launchdServiceLoaded(runner, serviceTarget)
		if err != nil {
			return err
		}
		if isLoaded {
			if err := runner.Run("launchctl", "bootout", serviceTarget); err != nil {
				return fmt.Errorf("boot out launchd service: %w", err)
			}
		}
		if err := os.Remove(launchdPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove launchd plist: %w", err)
		}
	}
	_, err := fmt.Fprintf(stdout, "collector_uninstall_status=%s launchd_plist=%s\n", installStatus(dryRun), launchdPath)

	return err
}

func uninstallSystemdUser(dryRun bool, stdout io.Writer, runner commandRunner) error {
	unitPath := defaultSystemdUserPath()
	if !dryRun {
		if err := runner.Run("systemctl", "--user", "disable", "--now", systemdServiceName); err != nil {
			return fmt.Errorf("disable systemd user service: %w", err)
		}
		if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove systemd user unit: %w", err)
		}
		if err := runner.Run("systemctl", "--user", "daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd user manager: %w", err)
		}
	}
	_, err := fmt.Fprintf(stdout, "collector_uninstall_status=%s systemd_unit=%s\n", installStatus(dryRun), unitPath)

	return err
}

func writeHookSnippets(stdout io.Writer, plan installPlan) error {
	for _, snippet := range plan.hookSnippets() {
		if _, err := fmt.Fprintln(stdout, snippet); err != nil {
			return err
		}
	}

	return nil
}

func (plan installPlan) systemdUserUnit() (string, error) {
	quotedBinary, err := quoteSystemdArgument(plan.BinaryPath)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`[Unit]
Description=Mitoriq Collector
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=%s daemon
Restart=always
RestartSec=5s

[Install]
WantedBy=default.target`, quotedBinary), nil
}

func quoteSystemdArgument(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("binary path contains unsupported characters")
	}
	if !path.IsAbs(value) {
		return "", fmt.Errorf("Linux service binary path must be absolute")
	}
	escaped := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`$`, `$$`,
		`%`, `%%`,
	).Replace(value)

	return `"` + escaped + `"`, nil
}

func defaultSystemdUserPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err == nil {
			home = userHome
		}
	}
	if home == "" {
		home = "."
	}

	return filepath.Join(home, ".config", "systemd", "user", systemdServiceName)
}

func writeServiceFile(path string, body string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(body+"\n"), 0o644)
}
