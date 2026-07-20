package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/mitoriq/collector/internal/deviceauth"
	"github.com/mitoriq/collector/internal/enroll"
	"github.com/mitoriq/collector/internal/filelock"
	"github.com/mitoriq/collector/internal/localconfig"
	"github.com/mitoriq/collector/internal/version"
)

const (
	setupJournalName = "device-authorization-journal.json"
	setupLockName    = "device-authorization.lock"
	setupWebPath     = "/now#collector-setup"
)

type setupCommandHelper interface {
	URL() string
	Done() <-chan error
	Update(deviceauth.HelperView) error
}

type setupCommandDependencies struct {
	GOOS        string
	Grace       time.Duration
	HTTPClient  deviceauth.HTTPClient
	HomeDir     func() (string, error)
	OpenBrowser func(context.Context, string, string) error
	Origins     func() (version.ServiceOrigins, error)
	RunSetup    func(context.Context, deviceauth.Setup) error
	Sleep       func(context.Context, time.Duration) error
	StartHelper func(context.Context, deviceauth.HelperView, deviceauth.RetryFunc) (setupCommandHelper, error)
}

func runSetup(args []string, stdout, stderr io.Writer) error {
	return runSetupCommand(args, stdout, stderr, defaultSetupCommandDependencies())
}

func defaultSetupCommandDependencies() setupCommandDependencies {
	return setupCommandDependencies{
		GOOS: runtime.GOOS, Grace: 1500 * time.Millisecond, HTTPClient: &http.Client{Timeout: 30 * time.Second}, HomeDir: os.UserHomeDir,
		OpenBrowser: openSetupPages, Origins: func() (version.ServiceOrigins, error) {
			return resolveSetupOrigins(version.Current().Version == "dev", os.Getenv, version.CurrentServiceOrigins)
		},
		RunSetup: func(ctx context.Context, setup deviceauth.Setup) error { return setup.Run(ctx) },
		StartHelper: func(ctx context.Context, view deviceauth.HelperView, retry deviceauth.RetryFunc) (setupCommandHelper, error) {
			return deviceauth.StartHelper(ctx, view, retry)
		},
	}
}

func runSetupCommand(args []string, stdout, stderr io.Writer, dependencies setupCommandDependencies) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup does not accept arguments")
	}
	platform := dependencies.GOOS
	if platform == "" {
		platform = runtime.GOOS
	}
	if platform == "windows" {
		return deviceauth.ErrUnsupportedPlatform
	}
	if dependencies.Origins == nil || dependencies.HomeDir == nil {
		return setupRecoveryError()
	}
	origins, err := dependencies.Origins()
	if err != nil {
		return setupRecoveryError()
	}
	home, err := dependencies.HomeDir()
	if err != nil || home == "" {
		return setupRecoveryError()
	}
	dependencies = fillSetupDependencies(dependencies, platform)
	runner := newSetupCommandRunner(dependencies, origins, platform, home, stdout, stderr)
	return withSetupLock(home, runner.run)
}

func withSetupLock(home string, run func() error) error {
	baseDirectory := filepath.Join(home, ".config", "mitoriq")
	if os.MkdirAll(baseDirectory, 0o700) != nil {
		return setupRecoveryError()
	}
	ran := false
	err := filelock.With(filepath.Join(baseDirectory, setupLockName), func() error {
		ran = true
		return run()
	})
	if !ran {
		return setupRecoveryError()
	}
	return err
}

type setupCommandRunner struct {
	dependencies  setupCommandDependencies
	origins       version.ServiceOrigins
	stdout        io.Writer
	stderr        io.Writer
	protocol      *setupHelperProtocol
	helper        setupCommandHelper
	helperContext context.Context
	cancelHelper  context.CancelFunc
	completed     chan struct{}
	config        localconfig.Store
	saga          deviceauth.Setup
}

func newSetupCommandRunner(dependencies setupCommandDependencies, origins version.ServiceOrigins, platform, home string, stdout, stderr io.Writer) *setupCommandRunner {
	baseDirectory := filepath.Join(home, ".config", "mitoriq")
	configPath := filepath.Join(baseDirectory, "collector.json")
	config := localconfig.Store{Path: configPath}
	journal := deviceauth.JournalStore{Path: filepath.Join(baseDirectory, setupJournalName)}
	protocol := &setupHelperProtocol{delegate: deviceauth.Client{BaseURL: origins.APIURL, HTTPClient: dependencies.HTTPClient}}
	helperContext, cancelHelper := context.WithCancel(context.Background())
	runner := &setupCommandRunner{
		dependencies: dependencies, origins: origins, stdout: stdout, stderr: stderr, protocol: protocol, config: config,
		helperContext: helperContext, cancelHelper: cancelHelper, completed: make(chan struct{}, 1),
	}
	runner.saga = deviceauth.Setup{
		GOOS: platform, APIURL: origins.APIURL, DisplayName: defaultDisplayName(), CollectorVersion: version.Current().Version,
		Protocol: protocol, Tokens: setupTokenStoreWithoutKeychainCLIArgv(home, platform), Config: config, Journal: journal,
		Preflight: func(context.Context, string) error {
			return preflightSetupDirectories([]string{baseDirectory, filepath.Join(baseDirectory, "enrollment-tokens")})
		},
		Challenge: runner.challenge, Sleep: dependencies.Sleep,
	}
	return runner
}

func (runner *setupCommandRunner) run() error {
	defer runner.cancelHelper()
	localUUID, err := runner.stableLocalUUID()
	if err != nil {
		return setupRecoveryError()
	}
	runner.saga.LocalUUID = localUUID
	if runner.dependencies.RunSetup(context.Background(), runner.saga) != nil {
		if err := runner.awaitRetry(); err != nil {
			return err
		}
	}
	return runner.finish()
}

func (runner *setupCommandRunner) stableLocalUUID() (string, error) {
	config, err := runner.config.Load()
	if err == nil && config.MachineLocalUUID != "" {
		return config.MachineLocalUUID, nil
	}
	if err != nil && !localconfig.IsNotFound(err) {
		return "", err
	}
	return enroll.NewLocalUUID()
}

func (runner *setupCommandRunner) retry(ctx context.Context) (deviceauth.HelperView, error) {
	if runner.dependencies.RunSetup(ctx, runner.saga) != nil {
		return runner.protocol.failureView(), errors.New("setup retry failed")
	}
	select {
	case runner.completed <- struct{}{}:
	default:
	}
	return deviceauth.HelperView{State: deviceauth.Enrolled, UserCode: runner.protocol.userCode}, nil
}

func (runner *setupCommandRunner) challenge(userCode string, _ time.Time) error {
	runner.protocol.userCode = userCode
	if runner.helper != nil {
		return runner.helper.Update(deviceauth.HelperView{State: deviceauth.HelperReady, UserCode: userCode})
	}
	helper, err := runner.dependencies.StartHelper(runner.helperContext, deviceauth.HelperView{State: deviceauth.HelperReady, UserCode: userCode}, runner.retry)
	if err != nil {
		return errors.New("start local setup helper failed")
	}
	runner.helper, runner.protocol.helper = helper, helper
	webURL := runner.origins.WebURL + setupWebPath
	if _, err := fmt.Fprintf(runner.stdout, "setup_helper_url=%s\nsetup_web_url=%s\n", helper.URL(), webURL); err != nil {
		return errors.New("write setup guidance failed")
	}
	if runner.dependencies.OpenBrowser(runner.helperContext, helper.URL(), webURL) != nil {
		_, _ = fmt.Fprintln(runner.stderr, "ブラウザを自動で開けませんでした。表示されたURLを手動で開いてください。")
	}
	return nil
}

func (runner *setupCommandRunner) awaitRetry() error {
	if runner.helper == nil {
		return setupRecoveryError()
	}
	_ = runner.helper.Update(runner.protocol.failureView())
	select {
	case <-runner.completed:
		return nil
	case <-runner.helper.Done():
		return errors.New("ローカルHelperが終了しました。setupを再実行してください")
	}
}

func (runner *setupCommandRunner) finish() error {
	if runner.helper == nil {
		return setupRecoveryError()
	}
	_ = runner.helper.Update(deviceauth.HelperView{State: deviceauth.Enrolled, UserCode: runner.protocol.userCode})
	if waitSetupGrace(runner.dependencies.Grace) != nil {
		return errors.New("setup完了待機が中断されました")
	}
	runner.cancelHelper()
	select {
	case <-runner.helper.Done():
	case <-time.After(2 * time.Second):
		return errors.New("ローカルHelperを終了できませんでした")
	}
	_, err := fmt.Fprintln(runner.stdout, "setup_status=enrolled next=mitoriq-collector install")
	return err
}

func setupTokenStoreWithoutKeychainCLIArgv(home, platform string) enroll.TokenStore {
	if platform == "darwin" {
		platform = "linux"
	}
	return enroll.TokenStore{GOOS: platform, Home: home}
}

type setupHelperProtocol struct {
	delegate deviceauth.Protocol
	helper   setupCommandHelper
	userCode string
	state    deviceauth.HelperState
}

func (protocol *setupHelperProtocol) Start(ctx context.Context, request deviceauth.StartRequest) (deviceauth.StartResponse, error) {
	response, err := protocol.delegate.Start(ctx, request)
	if err == nil {
		protocol.userCode, protocol.state = response.UserCode, deviceauth.HelperReady
	}
	return response, err
}
func (protocol *setupHelperProtocol) Poll(ctx context.Context, request deviceauth.PollRequest) (deviceauth.PollResponse, error) {
	response, err := protocol.delegate.Poll(ctx, request)
	if err != nil {
		protocol.update(deviceauth.HelperError)
		return response, err
	}
	states := map[deviceauth.Status]deviceauth.HelperState{
		deviceauth.StatusAuthorizationPending: deviceauth.HelperReady, deviceauth.StatusSlowDown: deviceauth.HelperReady,
		deviceauth.StatusAuthorized: deviceauth.Authorized, deviceauth.StatusEnrolled: deviceauth.Enrolled,
		deviceauth.StatusExpiredToken: deviceauth.Expired, deviceauth.StatusAccessDenied: deviceauth.HelperError,
	}
	protocol.update(states[response.Status])
	return response, nil
}
func (protocol *setupHelperProtocol) Complete(ctx context.Context, request deviceauth.CompleteRequest) (deviceauth.CompleteResponse, error) {
	response, err := protocol.delegate.Complete(ctx, request)
	if err != nil {
		protocol.update(deviceauth.HelperError)
	} else {
		protocol.update(deviceauth.Enrolled)
	}
	return response, err
}
func (protocol *setupHelperProtocol) update(state deviceauth.HelperState) {
	protocol.state = state
	if protocol.helper != nil {
		_ = protocol.helper.Update(deviceauth.HelperView{State: state, UserCode: protocol.userCode})
	}
}
func (protocol *setupHelperProtocol) failureView() deviceauth.HelperView {
	state := deviceauth.HelperError
	if protocol.state == deviceauth.Expired {
		state = deviceauth.Expired
	}
	return deviceauth.HelperView{State: state, UserCode: protocol.userCode}
}

func fillSetupDependencies(dependencies setupCommandDependencies, platform string) setupCommandDependencies {
	if dependencies.RunSetup == nil {
		dependencies.RunSetup = func(ctx context.Context, setup deviceauth.Setup) error { return setup.Run(ctx) }
	}
	if dependencies.StartHelper == nil {
		dependencies.StartHelper = func(ctx context.Context, view deviceauth.HelperView, retry deviceauth.RetryFunc) (setupCommandHelper, error) {
			return deviceauth.StartHelper(ctx, view, retry)
		}
	}
	if dependencies.OpenBrowser == nil {
		dependencies.OpenBrowser = func(ctx context.Context, localURL, webURL string) error {
			return openSetupPagesForPlatform(ctx, platform, localURL, webURL)
		}
	}
	return dependencies
}

func resolveSetupOrigins(isDevelopment bool, getenv func(string) string, embedded func() (version.ServiceOrigins, error)) (version.ServiceOrigins, error) {
	if !isDevelopment {
		return embedded()
	}
	apiURL, webURL := getenv("MITORIQ_API_ORIGIN"), getenv("MITORIQ_WEB_ORIGIN")
	if apiURL == "" && webURL == "" {
		return embedded()
	}
	if !validSetupOrigin(apiURL) || !validSetupOrigin(webURL) {
		return version.ServiceOrigins{}, errors.New("development service origins must be absolute HTTPS origins")
	}
	return version.ServiceOrigins{APIURL: apiURL, WebURL: webURL}, nil
}

func validSetupOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && !parsed.ForceQuery
}

func preflightSetupDirectories(directories []string) error {
	for _, directory := range directories {
		if os.MkdirAll(directory, 0o700) != nil {
			return errors.New("setup preflight failed")
		}
		file, err := os.CreateTemp(directory, ".setup-preflight-*")
		if err != nil {
			return errors.New("setup preflight failed")
		}
		temporaryPath, renamedPath := file.Name(), file.Name()+".ready"
		if file.Chmod(0o600) != nil || writeSetupProbe(file) != nil || os.Rename(temporaryPath, renamedPath) != nil {
			file.Close()
			os.Remove(temporaryPath)
			os.Remove(renamedPath)
			return errors.New("setup preflight failed")
		}
		info, statErr := os.Stat(renamedPath)
		removeErr := os.Remove(renamedPath)
		if statErr != nil || info.Mode().Perm() != 0o600 || removeErr != nil {
			return errors.New("setup preflight failed")
		}
	}
	return nil
}

func writeSetupProbe(file *os.File) error {
	if _, err := file.Write([]byte("setup-preflight\n")); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func openSetupPages(ctx context.Context, localURL, webURL string) error {
	return openSetupPagesForPlatform(ctx, runtime.GOOS, localURL, webURL)
}
func openSetupPagesForPlatform(ctx context.Context, platform, localURL, webURL string) error {
	command := "xdg-open"
	if platform == "darwin" {
		command = "open"
	}
	for _, target := range []string{localURL, webURL} {
		if err := exec.CommandContext(ctx, command, target).Run(); err != nil {
			return errors.New("open setup page failed")
		}
	}
	return nil
}

func waitSetupGrace(duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	<-timer.C
	return nil
}

func setupRecoveryError() error {
	return errors.New("セットアップを開始できません。書き込み権限とネットワーク接続を確認してsetupを再実行してください")
}
