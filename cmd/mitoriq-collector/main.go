package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mitoriq/collector/internal/adapter/claudecode"
	"github.com/mitoriq/collector/internal/adapter/codexcli"
	"github.com/mitoriq/collector/internal/adapter/cursor"
	"github.com/mitoriq/collector/internal/adapter/gitcontext"
	"github.com/mitoriq/collector/internal/contracts"
	"github.com/mitoriq/collector/internal/discovery"
	"github.com/mitoriq/collector/internal/enroll"
	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/localconfig"
	"github.com/mitoriq/collector/internal/otlpserver"
	"github.com/mitoriq/collector/internal/queue"
	"github.com/mitoriq/collector/internal/uplink"
	"github.com/mitoriq/collector/internal/version"
)

const topLevelHelp = `Collect privacy-preserving AI development telemetry.

Usage: mitoriq-collector <command> [options]

Commands:
  audit-log       Print recent local audit metadata
  claude-hook     Process a Claude Code hook event
  codex-hook      Process a Codex CLI hook event
  cursor-collect  Collect Cursor usage metrics
  cursor-hook     Process a Cursor hook event
  daemon          Run the OTLP collector daemon
  doctor          Check collector configuration and discovery
  enroll          Enroll this machine with Mitoriq
  install         Install the collector service and hooks
  uninstall       Uninstall the collector service and hooks
  update          Update the collector
  version         Print collector version information

Use "mitoriq-collector <command> -h" for command-specific options.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	var err error
	if len(args) == 0 {
		_, err = io.WriteString(stdout, topLevelHelp)
	} else {
		switch args[0] {
		case "-h", "--help", "help":
			_, err = io.WriteString(stdout, topLevelHelp)
		case "audit-log":
			err = runAuditLog(args[1:], stdout, stderr)
		case "claude-hook":
			err = runClaudeHook(args[1:], os.Stdin, stdout, stderr)
		case "codex-hook":
			err = runCodexHook(args[1:], os.Stdin, stdout, stderr)
		case "cursor-collect":
			err = runCursorCollect(args[1:], stdout, stderr)
		case "cursor-hook":
			err = runCursorHook(args[1:], os.Stdin, stdout, stderr)
		case "daemon":
			err = runDaemon(args[1:], stdout, stderr)
		case "doctor":
			err = runDoctor(args[1:], stdout, stderr)
		case "enroll":
			err = runEnroll(args[1:], stdout, stderr)
		case "install":
			err = runInstall(args[1:], stdout, stderr)
		case "uninstall":
			err = runUninstall(args[1:], stdout, stderr)
		case "update":
			err = runUpdate(args[1:], stdout, stderr)
		case "version":
			err = runVersion(args[1:], stdout, stderr)
		default:
			err = fmt.Errorf("unknown subcommand: %s", args[0])
		}
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "エラー: %v\n", err)
		return 1
	}

	return 0
}

type adapterIdentity = claudecode.Identity

type daemonAdapterConfig struct {
	APIURL            string
	AllowInsecureHTTP bool
	AuditLogPath      string
	ConfigPath        string
	CursorHooksBeta   bool
	Identity          adapterIdentity
	Deny              localconfig.DenyRules
	MaxPrivacyLevel   string
	RepoAllowlist     []localconfig.RepoAllowlistEntry
	Token             string
	UnmappedRepoMode  string
	UpdateChannel     string
}

type daemonAdapterState struct {
	config            daemonAdapterConfig
	eventQueue        *queue.Store
	mu                sync.RWMutex
	sessionLocalDeny  map[string]bool
	sessionRepoHashes map[string]string
}

type adapterFlags struct {
	apiURL              *string
	allowInsecureHTTP   *bool
	auditLogPath        *string
	configPath          *string
	machineEnrollmentID *string
	machineID           *string
	maxPrivacyLevel     *string
	memberID            *string
	organizationID      *string
	token               *string
}

func addAdapterFlags(flags *flag.FlagSet) adapterFlags {
	return adapterFlags{
		apiURL:              flags.String("api-url", "", "Mitoriq API origin"),
		allowInsecureHTTP:   flags.Bool("allow-insecure-http", false, "allow loopback HTTP API URL"),
		auditLogPath:        flags.String("audit-log", "", "local metadata-only audit log path"),
		configPath:          flags.String("config", "", "collector config path"),
		machineEnrollmentID: flags.String("machine-enrollment-id", "", "Machine enrollment ID"),
		machineID:           flags.String("machine-id", "", "Machine ID"),
		maxPrivacyLevel:     flags.String("max-privacy-level", "", "maximum collector privacy level: L0, L1, L2, L3, or L4"),
		memberID:            flags.String("member-id", "", "Member ID"),
		organizationID:      flags.String("organization-id", "", "Organization ID"),
		token:               flags.String("token", "", "Enrollment token"),
	}
}

func newDaemonAdapterState(config daemonAdapterConfig) *daemonAdapterState {
	return &daemonAdapterState{
		config:            config,
		sessionLocalDeny:  map[string]bool{},
		sessionRepoHashes: map[string]string{},
	}
}

func (state *daemonAdapterState) snapshot() daemonAdapterConfig {
	state.mu.RLock()
	defer state.mu.RUnlock()

	return state.config
}

func (state *daemonAdapterState) updateRepoAllowlist(entries []contracts.RepoAllowlistEntry) daemonAdapterConfig {
	nextAllowlist := make([]localconfig.RepoAllowlistEntry, 0, len(entries))
	for _, entry := range entries {
		nextAllowlist = append(nextAllowlist, localconfig.RepoAllowlistEntry{
			Alias:         entry.Alias,
			RemoteURLHash: entry.RemoteURLHash,
		})
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.config.RepoAllowlist = nextAllowlist
	return state.config
}

func (state *daemonAdapterState) gateRepoAllowlist(events []contracts.AgentEvent) []contracts.AgentEvent {
	state.mu.Lock()
	defer state.mu.Unlock()

	return gateRepoAllowlistWithSessionState(events, state.config, state.sessionRepoHashes, state.sessionLocalDeny)
}

func (values adapterFlags) config(ctx context.Context) (daemonAdapterConfig, error) {
	config := daemonAdapterConfig{
		APIURL:            *values.apiURL,
		AllowInsecureHTTP: *values.allowInsecureHTTP,
		AuditLogPath:      *values.auditLogPath,
		ConfigPath:        *values.configPath,
		Identity: adapterIdentity{
			MachineEnrollmentID: *values.machineEnrollmentID,
			MachineID:           *values.machineID,
			MemberID:            *values.memberID,
			OrganizationID:      *values.organizationID,
		},
		MaxPrivacyLevel: *values.maxPrivacyLevel,
		Token:           *values.token,
	}
	saved, err := localconfig.Store{Path: *values.configPath}.Load()
	if err != nil && !localconfig.IsNotFound(err) {
		return daemonAdapterConfig{}, err
	}
	if err == nil {
		config = mergeSavedConfig(config, saved)
	}
	if config.Token == "" {
		token, err := loadEnrollmentToken(ctx, config.Identity.OrganizationID)
		if err != nil && !enroll.IsTokenNotFound(err) {
			return daemonAdapterConfig{}, err
		}
		config.Token = token
	}

	return config, nil
}

func loadEnrollmentToken(ctx context.Context, organizationID string) (string, error) {
	store := enroll.TokenStore{}
	if organizationID != "" {
		token, err := store.LoadForOrganization(ctx, organizationID)
		if err == nil || !enroll.IsTokenNotFound(err) {
			return token, err
		}
	}

	return store.Load(ctx)
}

func mergeSavedConfig(config daemonAdapterConfig, saved localconfig.Config) daemonAdapterConfig {
	if config.APIURL == "" {
		config.APIURL = saved.APIURL
	}
	if !config.AllowInsecureHTTP {
		config.AllowInsecureHTTP = saved.AllowInsecureHTTP
	}
	if config.AuditLogPath == "" {
		config.AuditLogPath = saved.AuditLogPath
	}
	if config.Identity.MachineEnrollmentID == "" {
		config.Identity.MachineEnrollmentID = saved.MachineEnrollmentID
	}
	if config.Identity.MachineID == "" {
		config.Identity.MachineID = saved.MachineID
	}
	if config.Identity.MemberID == "" {
		config.Identity.MemberID = saved.MemberID
	}
	if config.Identity.OrganizationID == "" {
		config.Identity.OrganizationID = saved.OrganizationID
	}
	if isEmptyDeny(config.Deny) {
		config.Deny = saved.Deny
	}
	if config.MaxPrivacyLevel == "" {
		config.MaxPrivacyLevel = saved.MaxPrivacyLevel
	}
	if !config.CursorHooksBeta {
		config.CursorHooksBeta = saved.CursorHooksBeta
	}
	if len(config.RepoAllowlist) == 0 {
		config.RepoAllowlist = saved.RepoAllowlist
	}
	if config.UnmappedRepoMode == "" {
		config.UnmappedRepoMode = saved.UnmappedRepoMode
	}
	if config.UpdateChannel == "" {
		config.UpdateChannel = saved.UpdateChannel
	}

	return config
}

func (config daemonAdapterConfig) savedConfig() localconfig.Config {
	return localconfig.Config{
		APIURL:              config.APIURL,
		AllowInsecureHTTP:   config.AllowInsecureHTTP,
		AuditLogPath:        config.AuditLogPath,
		CursorHooksBeta:     config.CursorHooksBeta,
		Deny:                config.Deny,
		MaxPrivacyLevel:     config.MaxPrivacyLevel,
		MachineEnrollmentID: config.Identity.MachineEnrollmentID,
		MachineID:           config.Identity.MachineID,
		MemberID:            config.Identity.MemberID,
		OrganizationID:      config.Identity.OrganizationID,
		RepoAllowlist:       config.RepoAllowlist,
		UnmappedRepoMode:    config.UnmappedRepoMode,
		UpdateChannel:       config.UpdateChannel,
	}
}

func runEnroll(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	apiURL := flags.String("api-url", "http://localhost:8787", "Mitoriq API origin")
	allowInsecureHTTP := flags.Bool("allow-insecure-http", false, "persist loopback HTTP API URL allowance")
	bootstrapCode := flags.String("bootstrap-code", "", "Mitoriq bootstrap code")
	configPath := flags.String("config", "", "collector config path")
	displayName := flags.String("display-name", defaultDisplayName(), "Machine display name")
	localUUID := flags.String("local-uuid", "", "Installer generated local UUID")
	machineOS := flags.String("os", defaultOS(), "Machine OS")

	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bootstrapCode == "" {
		return fmt.Errorf("--bootstrap-code is required")
	}
	if *localUUID == "" {
		generated, err := enroll.NewLocalUUID()
		if err != nil {
			return err
		}
		*localUUID = generated
	}

	response, err := enroll.Enroll(context.Background(), http.DefaultClient, enroll.TokenStore{}, enroll.EnrollOptions{
		APIURL:           *apiURL,
		BootstrapCode:    *bootstrapCode,
		CollectorVersion: version.Current().Version,
		DisplayName:      *displayName,
		LocalUUID:        *localUUID,
		OS:               *machineOS,
		Stderr:           stderr,
		Stdout:           stdout,
	})
	if err != nil {
		return err
	}

	store := localconfig.Store{Path: *configPath}
	return store.Update(func(nextConfig localconfig.Config) (localconfig.Config, error) {
		nextConfig.APIURL = *apiURL
		nextConfig.AllowInsecureHTTP = allowInsecureForSavedConfig(*apiURL, *allowInsecureHTTP)
		nextConfig.MachineEnrollmentID = response.MachineEnrollmentID
		nextConfig.MachineID = response.MachineID
		nextConfig.MemberID = response.MemberID
		nextConfig.OrganizationID = response.OrganizationID

		return nextConfig, nil
	})
}

func runClaudeHook(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("claude-hook", flag.ContinueOnError)
	adapterValues := addAdapterFlags(flags)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := adapterValues.config(context.Background())
	if err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	collection, err := claudecode.NormalizeHookJSON(body, config.claudeOptions())
	if err != nil {
		return err
	}
	deliveryTimeout := min(eventDeliveryTimeout, hookDeliveryTimeout)
	if err := deliverHookCollection(
		config,
		deliveryTimeout,
		gateRepoAllowlist(collection.Events, config),
		collection.UsageMetrics,
	); err != nil {
		return err
	}
	return nil
}

func runCodexHook(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("codex-hook", flag.ContinueOnError)
	adapterValues := addAdapterFlags(flags)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := adapterValues.config(context.Background())
	if err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}
	var input codexcli.HookInput
	if err := json.Unmarshal(body, &input); err != nil {
		return err
	}
	collection, err := codexcli.NormalizeHook(input, config.codexOptions())
	if err != nil {
		return err
	}
	transcriptCollection, transcriptErr := codexUserInputCollection(input, config.codexOptions())
	if transcriptErr != nil {
		_, _ = fmt.Fprintln(stderr, "codex_transcript_warning=unavailable")
	} else {
		collection.Events = append(transcriptCollection.Events, collection.Events...)
		collection.UsageMetrics = append(transcriptCollection.UsageMetrics, collection.UsageMetrics...)
		collection.Events = omitTerminalEventsForWaitingUser(collection.Events, transcriptCollection.Events)
	}
	deliveryTimeout := min(eventDeliveryTimeout, hookDeliveryTimeout)
	if err := deliverHookCollection(
		config,
		deliveryTimeout,
		gateRepoAllowlist(collection.Events, config),
		collection.UsageMetrics,
	); err != nil {
		return err
	}
	if input.HookEventName == "Stop" {
		_, err = io.WriteString(stdout, "{\"continue\":true}\n")
	}

	return err
}

func codexUserInputCollection(input codexcli.HookInput, options codexcli.Options) (codexcli.Collection, error) {
	if input.TranscriptPath == nil || strings.TrimSpace(*input.TranscriptPath) == "" {
		return codexcli.Collection{}, nil
	}
	file, err := os.Open(*input.TranscriptPath)
	if err != nil {
		return codexcli.Collection{}, err
	}
	defer file.Close()

	return codexcli.ParseUserInputJSONL(file, options)
}

func omitTerminalEventsForWaitingUser(
	events []contracts.AgentEvent,
	userInputEvents []contracts.AgentEvent,
) []contracts.AgentEvent {
	waitingSessionIDs := make(map[string]struct{}, len(userInputEvents))
	for _, event := range userInputEvents {
		waitingSessionIDs[event.SessionID] = struct{}{}
	}
	filtered := make([]contracts.AgentEvent, 0, len(events))
	for _, event := range events {
		_, isWaitingForUser := waitingSessionIDs[event.SessionID]
		if event.Type == contracts.EventTypeSessionStopped && isWaitingForUser {
			continue
		}
		filtered = append(filtered, event)
	}

	return filtered
}

func runCursorHook(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	return runCursorHookWithTimeout(args, stdin, stdout, stderr, 2*time.Second)
}

func runCursorHookWithTimeout(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	timeout time.Duration,
) error {
	telemetryErr := collectAndDeliverCursorHook(args, stdin, stderr, timeout)
	if errors.Is(telemetryErr, flag.ErrHelp) {
		return telemetryErr
	}
	if telemetryErr != nil {
		_, _ = fmt.Fprintf(stderr, "cursor_hook_warning=%q\n", telemetryErr.Error())
	}
	_, responseErr := io.WriteString(stdout, "{\"continue\":true}\n")

	return responseErr
}

func collectAndDeliverCursorHook(
	args []string,
	stdin io.Reader,
	stderr io.Writer,
	timeout time.Duration,
) error {
	flags := flag.NewFlagSet("cursor-hook", flag.ContinueOnError)
	adapterValues := addAdapterFlags(flags)
	cursorHooksBeta := flags.Bool("cursor-hooks-beta", false, "enable Cursor Hooks beta adapter")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := adapterValues.config(context.Background())
	if err != nil {
		return err
	}
	config.CursorHooksBeta = config.CursorHooksBeta || *cursorHooksBeta
	if err := config.validate(); err != nil {
		return err
	}
	body, err := readCursorHookBody(stdin)
	if err != nil {
		return err
	}
	collection, err := cursor.NormalizeHookJSON(body, config.cursorOptions())
	if err != nil {
		return err
	}
	deliveryTimeout := min(timeout, hookDeliveryTimeout)
	if err := deliverHookCollection(
		config,
		deliveryTimeout,
		gateRepoAllowlist(collection.Events, config),
		collection.UsageMetrics,
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "cursor_hook_events=%d usage_metrics=%d\n", len(collection.Events), len(collection.UsageMetrics))

	return err
}

func readCursorHookBody(reader io.Reader) ([]byte, error) {
	const maxPayloadBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(reader, maxPayloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPayloadBytes {
		return nil, fmt.Errorf("Cursor hook の payload が 1 MiB を超えています")
	}

	return body, nil
}

func runCursorCollect(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("cursor-collect", flag.ContinueOnError)
	adapterValues := addAdapterFlags(flags)
	cursorAPIBaseURL := flags.String("cursor-api-base-url", "", "Cursor Analytics API origin")
	cursorAPIKey := flags.String("cursor-api-key", "", "Cursor Analytics API key")
	cursorEndDate := flags.String("cursor-end-date", "", "Cursor Analytics endDate")
	cursorStartDate := flags.String("cursor-start-date", "", "Cursor Analytics startDate")
	cursorStateDB := flags.String("cursor-state-db", "", "Cursor state.vscdb path")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := adapterValues.config(context.Background())
	if err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	options := config.cursorOptions()
	options.APIBaseURL = *cursorAPIBaseURL
	options.APIKey = firstNonEmpty(*cursorAPIKey, os.Getenv("CURSOR_API_KEY"))
	options.AnalyticsEndDate = *cursorEndDate
	options.AnalyticsStartDate = *cursorStartDate
	options.LocalStateDBPath = firstNonEmpty(*cursorStateDB, defaultCursorStateDBPath())

	localCollection, err := cursor.CollectLocalState(context.Background(), options)
	if err != nil {
		return err
	}
	apiCollection, err := cursor.FetchAnalytics(context.Background(), options)
	if err != nil {
		return err
	}
	collection := mergeCursorCollections(localCollection, apiCollection)
	client := uplink.NewClient(config.uplinkConfig(http.DefaultClient))
	if err := deliverCollection(
		context.Background(),
		client,
		nil,
		nil,
		collection.UsageMetrics,
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "cursor_usage_metrics=%d local_metrics=%d analytics_metrics=%d\n", len(collection.UsageMetrics), len(localCollection.UsageMetrics), len(apiCollection.UsageMetrics))

	return err
}

func runDoctor(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := flags.String("config", "", "collector config path")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}

	info := version.Current()
	if _, err := fmt.Fprintf(
		stdout,
		"collector_status=ok %s os=%s arch=%s\n",
		info.Line(),
		runtime.GOOS,
		runtime.GOARCH,
	); err != nil {
		return err
	}
	for _, candidate := range discovery.Candidates(discovery.RuntimeOptions()) {
		if _, err := fmt.Fprintf(
			stdout,
			"collector_discovery tool=%s kind=%s source=%s path=%q\n",
			candidate.Tool,
			candidate.Kind,
			candidate.Source,
			candidate.Path,
		); err != nil {
			return err
		}
	}

	if err := writeDoctorDenyStatus(*configPath, stdout); err != nil {
		return err
	}

	return writeDoctorLocalStatus(*configPath, stdout)
}

func runVersion(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}

	_, err := fmt.Fprintln(stdout, version.Current().Line())

	return err
}

func runDaemon(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	otlpHTTPAddr := flags.String("otlp-http-addr", "127.0.0.1:4318", "OTLP HTTP listen address")
	once := flags.Bool("once", false, "Validate daemon configuration and exit")
	adapterValues := addAdapterFlags(flags)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	adapterConfig, err := adapterValues.config(context.Background())
	if err != nil {
		return err
	}
	if *once {
		_, err := fmt.Fprintf(stdout, "collector_status=daemon_ready otlp_http_addr=%s\n", *otlpHTTPAddr)
		return err
	}
	updated, updateErr := runStableAutoUpdate(adapterConfig.ConfigPath, adapterConfig.AuditLogPath, stdout)
	if updateErr != nil {
		fmt.Fprintf(stderr, "自動更新をスキップしました: %v\n", updateErr)
	}
	if updated {
		return nil
	}

	state := newDaemonAdapterState(adapterConfig)
	if adapterConfig.configured() {
		eventQueue, err := openEventQueue(adapterConfig)
		if err != nil {
			return err
		}
		state.eventQueue = eventQueue
		defer eventQueue.Close()
	}
	heartbeatContext, stopHeartbeat := context.WithCancel(context.Background())
	defer stopHeartbeat()
	if adapterConfig.configured() {
		go runRepoAllowlistHeartbeatLoop(heartbeatContext, state, http.DefaultClient)
	}
	if state.eventQueue != nil {
		queueContext, stopQueueLoop := context.WithCancel(context.Background())
		queueDone := make(chan struct{})
		go func() {
			defer close(queueDone)
			runQueueDrainLoop(queueContext, state.eventQueue, uplink.NewClient(adapterConfig.uplinkConfig(&http.Client{Timeout: eventDeliveryTimeout})), stderr)
		}()
		defer func() {
			stopQueueLoop()
			<-queueDone
		}()
	}

	server := &http.Server{
		Addr:    *otlpHTTPAddr,
		Handler: newDaemonHandlerWithState(state),
	}
	updateContext, stopUpdateLoop := context.WithCancel(context.Background())
	defer stopUpdateLoop()
	go runStableAutoUpdateLoop(
		updateContext,
		adapterConfig.ConfigPath,
		adapterConfig.AuditLogPath,
		stdout,
		stderr,
		func() error {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(shutdownContext)
		},
	)
	fmt.Fprintf(stdout, "collector_status=daemon_listening otlp_http_addr=%s\n", *otlpHTTPAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func newDaemonHandler(config daemonAdapterConfig) http.Handler {
	return newDaemonHandlerWithState(newDaemonAdapterState(config))
}

func newDaemonHandlerWithState(state *daemonAdapterState) http.Handler {
	config := state.snapshot()
	if !config.configured() {
		return otlpserver.NewHTTPHandler(otlpserver.Options{})
	}
	client := uplink.NewClient(config.uplinkConfig(&http.Client{Timeout: eventDeliveryTimeout}))

	return otlpserver.NewHTTPHandler(otlpserver.Options{
		OnReceive: func(_ string, body []byte) error {
			ctx, cancel := context.WithTimeout(context.Background(), eventDeliveryTimeout)
			defer cancel()
			config := state.snapshot()
			claudeCollection, err := claudecode.ParseOTelJSON(body, config.claudeOptions())
			if err != nil {
				return err
			}
			if err := deliverCollection(
				ctx,
				client,
				state.eventQueue,
				state.gateRepoAllowlist(claudeCollection.Events),
				claudeCollection.UsageMetrics,
			); err != nil {
				return err
			}
			codexCollection, err := codexcli.ParseOTelJSON(body, config.codexOptions())
			if err != nil {
				return err
			}

			return deliverCollection(
				ctx,
				client,
				state.eventQueue,
				state.gateRepoAllowlist(codexCollection.Events),
				codexCollection.UsageMetrics,
			)
		},
	})
}

func runRepoAllowlistHeartbeatLoop(
	ctx context.Context,
	state *daemonAdapterState,
	httpClient *http.Client,
) {
	ticker := time.NewTicker(uplink.HeartbeatInterval)
	defer ticker.Stop()

	for {
		syncRepoAllowlist(ctx, state, httpClient)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func syncRepoAllowlist(
	ctx context.Context,
	state *daemonAdapterState,
	httpClient *http.Client,
) {
	config := state.snapshot()
	if !config.configured() {
		return
	}

	client := uplink.NewClient(config.uplinkConfig(httpClient))
	response, err := client.SendHeartbeat(ctx, contracts.HeartbeatRequest{
		SchemaVersion:       1,
		MachineID:           config.Identity.MachineID,
		MachineEnrollmentID: config.Identity.MachineEnrollmentID,
		CollectorVersion:    version.Current().Version,
		OccurredAt:          time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil || !response.Accepted {
		return
	}

	nextConfig := state.updateRepoAllowlist(response.RepoAllowlist)
	_ = persistRepoAllowlist(nextConfig)
}

func persistRepoAllowlist(config daemonAdapterConfig) error {
	store := localconfig.Store{Path: config.ConfigPath}
	return store.Update(func(current localconfig.Config) (localconfig.Config, error) {
		if current.APIURL == "" && current.OrganizationID == "" {
			current = config.savedConfig()
		}
		current.RepoAllowlist = append([]localconfig.RepoAllowlistEntry(nil), config.RepoAllowlist...)

		return current, nil
	})
}

func gateRepoAllowlist(
	events []contracts.AgentEvent,
	config daemonAdapterConfig,
) []contracts.AgentEvent {
	return gateRepoAllowlistWithSessionHashes(events, config, map[string]string{})
}

func gateRepoAllowlistWithSessionHashes(
	events []contracts.AgentEvent,
	config daemonAdapterConfig,
	sessionRepoHashes map[string]string,
) []contracts.AgentEvent {
	return gateRepoAllowlistWithSessionState(events, config, sessionRepoHashes, map[string]bool{})
}

func gateRepoAllowlistWithSessionState(
	events []contracts.AgentEvent,
	config daemonAdapterConfig,
	sessionRepoHashes map[string]string,
	sessionLocalDeny map[string]bool,
) []contracts.AgentEvent {
	if len(events) == 0 {
		return events
	}
	approvedHashes := make(map[string]bool, len(config.RepoAllowlist))
	for _, entry := range config.RepoAllowlist {
		approvedHashes[entry.RemoteURLHash] = true
	}
	denyPolicy := localconfig.CompileDenyPolicy(config.Deny)

	next := make([]contracts.AgentEvent, 0, len(events))
	for _, event := range events {
		gated, keep := gateRepoBoundEvent(event, approvedHashes, sessionRepoHashes, sessionLocalDeny, config, denyPolicy)
		if keep {
			gated.LocalDenyPaths = nil
			next = append(next, gated)
		}
	}

	return next
}

func gateRepoBoundEvent(
	event contracts.AgentEvent,
	approvedHashes map[string]bool,
	sessionRepoHashes map[string]string,
	sessionLocalDeny map[string]bool,
	config daemonAdapterConfig,
	denyPolicy localconfig.DenyPolicy,
) (contracts.AgentEvent, bool) {
	if maxPrivacyBelowL3(config.MaxPrivacyLevel) {
		event = capEventToL2(event)
	}

	if denyPolicy.DeniesAllL2() && privacyAtLeastL2(event.PrivacyLevel) {
		return locallyDeniedEvent(event)
	}

	if maxPrivacyBelowL2(config.MaxPrivacyLevel) {
		return downgradeRepoBoundEvent(event), true
	}

	if event.Type == contracts.EventTypeSessionStarted {
		hash, hasRepoHash := repoRemoteURLHash(event.Payload["repo"])
		if !hasRepoHash {
			if denyPolicy.DeniesAnyPath(event.LocalDenyPaths) {
				sessionLocalDeny[event.SessionID] = true
				return locallyDeniedEvent(event)
			}

			return event, true
		}
		sessionRepoHashes[event.SessionID] = hash
		if denyPolicy.DeniesRepo(hash) || denyPolicy.DeniesAnyPath(event.LocalDenyPaths) {
			sessionLocalDeny[event.SessionID] = true
			return locallyDeniedEvent(event)
		}
		if approvedHashes[hash] {
			return event, true
		}

		return downgradeSessionStartedForRepoDiscovery(event, hash), true
	}

	if event.Payload["filesChanged"] == nil {
		return event, true
	}
	if sessionLocalDeny[event.SessionID] {
		return locallyDeniedEvent(event)
	}
	if denyPolicy.DeniesAnyPath(event.LocalDenyPaths) {
		return locallyDeniedEvent(event)
	}
	if hash := strings.TrimSpace(event.LocalRepoRemoteURLHash); hash != "" {
		if denyPolicy.DeniesRepo(hash) {
			return locallyDeniedEvent(event)
		}
		if approvedHashes[hash] {
			return event, true
		}

		return unmappedRepoEvent(event, config.UnmappedRepoMode)
	}
	if hash, ok := sessionRepoHashes[event.SessionID]; ok && denyPolicy.DeniesRepo(hash) {
		return locallyDeniedEvent(event)
	}
	if hash, ok := sessionRepoHashes[event.SessionID]; ok && approvedHashes[hash] {
		return event, true
	}

	return unmappedRepoEvent(event, config.UnmappedRepoMode)
}

func capEventToL2(event contracts.AgentEvent) contracts.AgentEvent {
	if !privacyAtLeastL3(event.PrivacyLevel) {
		return event
	}

	next := event
	next.Payload = make(map[string]any, len(event.Payload))
	for key, value := range event.Payload {
		if isL3PayloadField(event.Type, key) {
			continue
		}
		next.Payload[key] = value
	}
	next.PrivacyLevel = "L2"

	return next
}

func isL3PayloadField(eventType contracts.EventType, key string) bool {
	switch eventType {
	case contracts.EventTypePromptSubmitted:
		return key == "promptSummary"
	case contracts.EventTypeToolStarted:
		return key == "command"
	case contracts.EventTypeToolFailed:
		return key == "errorSummary"
	case contracts.EventTypeUserInputRequested:
		return key == "promptSummary"
	default:
		return false
	}
}

func unmappedRepoEvent(event contracts.AgentEvent, mode string) (contracts.AgentEvent, bool) {
	if mode == "drop" && privacyAtLeastL2(event.PrivacyLevel) {
		return event, false
	}

	return downgradeRepoBoundEvent(event), true
}

func locallyDeniedEvent(event contracts.AgentEvent) (contracts.AgentEvent, bool) {
	if !privacyAtLeastL2(event.PrivacyLevel) {
		return event, true
	}
	if event.Type == contracts.EventTypeSessionStarted ||
		event.Type == contracts.EventTypeSessionStopped ||
		event.Type == contracts.EventTypeToolCompleted {
		return downgradeRepoBoundEvent(event), true
	}

	return event, false
}

func downgradeSessionStartedForRepoDiscovery(
	event contracts.AgentEvent,
	remoteURLHash string,
) contracts.AgentEvent {
	next := downgradeRepoBoundEvent(event)
	next.Payload["repoDiscovery"] = map[string]any{"remoteUrlHash": remoteURLHash}

	return next
}

func downgradeRepoBoundEvent(event contracts.AgentEvent) contracts.AgentEvent {
	if !privacyAtLeastL2(event.PrivacyLevel) {
		return event
	}

	next := event
	next.PrivacyLevel = "L1"
	next.LocalDenyPaths = nil
	next.Payload = make(map[string]any, len(event.Payload))
	for key, value := range event.Payload {
		if key == "repo" || key == "filesChanged" {
			continue
		}
		next.Payload[key] = value
	}
	if event.Type == contracts.EventTypeSessionStarted {
		next.Payload["repo"] = nil
	}

	return next
}

func repoRemoteURLHash(value any) (string, bool) {
	repo, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	hash, ok := repo["remoteUrlHash"].(string)

	return hash, ok && hash != ""
}

func maxPrivacyBelowL2(value string) bool {
	return value == "L0" || value == "L1"
}

func maxPrivacyBelowL3(value string) bool {
	return value != "L3" && value != "L4"
}

func privacyAtLeastL2(value string) bool {
	return value == "L2" || value == "L3" || value == "L4"
}

func privacyAtLeastL3(value string) bool {
	return value == "L3" || value == "L4"
}

func isEmptyDeny(deny localconfig.DenyRules) bool {
	return len(deny.Repos) == 0 && len(deny.PathGlobs) == 0 && len(deny.PathRegexes) == 0
}

func writeDoctorDenyStatus(configPath string, stdout io.Writer) error {
	config, err := localconfig.Store{Path: configPath}.Load()
	if err != nil {
		if localconfig.IsNotFound(err) {
			_, err = fmt.Fprintln(stdout, "deny_status=not_configured fail_closed=false")
			return err
		}
		_, writeErr := fmt.Fprintf(stdout, "deny_status=invalid fail_closed=true reason=%q\n", err.Error())
		if writeErr != nil {
			return writeErr
		}

		return nil
	}
	policy := localconfig.CompileDenyPolicy(config.Deny)
	failClosed := policy.DeniesAllL2()
	if policy.Empty() {
		_, err = fmt.Fprintln(stdout, "deny_status=not_configured fail_closed=false")
		return err
	}
	_, err = fmt.Fprintf(
		stdout,
		"deny_status=configured fail_closed=%t repos=%d path_globs=%d path_regexes=%d applies_to=L2+\n",
		failClosed,
		len(config.Deny.Repos),
		len(config.Deny.PathGlobs),
		len(config.Deny.PathRegexes),
	)
	if err != nil {
		return err
	}
	for _, reason := range policy.InvalidReasons() {
		if _, err := fmt.Fprintf(stdout, "deny_invalid_reason=%q\n", reason); err != nil {
			return err
		}
	}
	for _, entry := range config.Deny.Repos {
		if _, err := fmt.Fprintf(stdout, "deny_repo alias=%q remote_url_hash=%q\n", entry.Alias, entry.RemoteURLHash); err != nil {
			return err
		}
	}
	for _, pattern := range config.Deny.PathGlobs {
		if _, err := fmt.Fprintf(stdout, "deny_path_glob pattern=%q\n", pattern); err != nil {
			return err
		}
	}
	for _, pattern := range config.Deny.PathRegexes {
		if _, err := fmt.Fprintf(stdout, "deny_path_regex pattern=%q\n", pattern); err != nil {
			return err
		}
	}

	return nil
}

const (
	hookCollectionTimeout = 350 * time.Millisecond
	hookDeliveryTimeout   = 200 * time.Millisecond
	queueDrainInterval    = time.Minute
	queueWriteTimeout     = 250 * time.Millisecond
)

var eventDeliveryTimeout = 2 * time.Second

func deliverHookCollection(
	config daemonAdapterConfig,
	deliveryTimeout time.Duration,
	events []contracts.AgentEvent,
	metrics []contracts.UsageMetric,
) error {
	hookCtx, stopHook := context.WithTimeout(context.Background(), hookCollectionTimeout)
	defer stopHook()
	client := uplink.NewClient(config.uplinkConfig(&http.Client{Timeout: deliveryTimeout}))
	versionedEvents := withCollectorVersion(events, version.Current().Version)
	if err := sendHookEventsOrQueue(hookCtx, config, deliveryTimeout, client, versionedEvents); err != nil {
		return err
	}
	if len(metrics) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(hookCtx, deliveryTimeout)
	defer cancel()
	counts, err := client.SendUsage(ctx, metrics)
	if err != nil {
		return err
	}
	if counts.Accepted+counts.Duplicated != len(metrics) || counts.Rejected > 0 {
		return fmt.Errorf("collector usage metrics not fully accepted")
	}

	return nil
}

func sendHookEventsOrQueue(
	hookCtx context.Context,
	config daemonAdapterConfig,
	deliveryTimeout time.Duration,
	client uplink.Client,
	events []contracts.AgentEvent,
) error {
	return sendHookEventsOrQueueWithOpener(
		hookCtx,
		config,
		deliveryTimeout,
		client,
		events,
		openHookEventQueueContext,
	)
}

type hookQueueOpener func(
	context.Context,
	daemonAdapterConfig,
) (*queue.Store, error)

type hookQueueOpenResult struct {
	store *queue.Store
	err   error
}

func sendHookEventsOrQueueWithOpener(
	hookCtx context.Context,
	config daemonAdapterConfig,
	deliveryTimeout time.Duration,
	client uplink.Client,
	events []contracts.AgentEvent,
	openQueue hookQueueOpener,
) error {
	if len(events) == 0 {
		return nil
	}
	queueCtx, stopQueue := context.WithCancel(context.WithoutCancel(hookCtx))
	defer stopQueue()
	queueResult := make(chan hookQueueOpenResult, 1)
	go func() {
		eventQueue, err := openQueue(queueCtx, config)
		queueResult <- hookQueueOpenResult{store: eventQueue, err: err}
	}()

	ctx, cancel := context.WithTimeout(hookCtx, deliveryTimeout)
	counts, sendErr := client.SendEvents(ctx, events)
	cancel()
	if sendErr == nil && counts.Accepted+counts.Duplicated == len(events) && counts.Rejected == 0 {
		stopQueue()
		result := <-queueResult
		closeHookQueue(result.store)
		return nil
	}
	if sendErr == nil {
		sendErr = fmt.Errorf("collector events not fully accepted")
	}

	fallbackCtx, stopFallback := context.WithTimeout(
		context.WithoutCancel(hookCtx),
		queueWriteTimeout,
	)
	defer stopFallback()
	result, waitErr := waitForHookQueueOpen(fallbackCtx, stopQueue, queueResult)
	if waitErr != nil {
		closeHookQueue(result.store)
		return errors.Join(sendErr, fmt.Errorf("open collector event queue: %w", waitErr))
	}
	if result.err != nil {
		closeHookQueue(result.store)
		return errors.Join(sendErr, fmt.Errorf("open collector event queue: %w", result.err))
	}
	if result.store == nil {
		return errors.Join(sendErr, fmt.Errorf("open collector event queue: returned nil store"))
	}
	if queueErr := enqueueEvents(fallbackCtx, result.store, events); queueErr != nil {
		closeHookQueue(result.store)
		return errors.Join(sendErr, queueErr)
	}
	closeHookQueue(result.store)

	return nil
}

func waitForHookQueueOpen(
	ctx context.Context,
	stopQueue context.CancelFunc,
	queueResult <-chan hookQueueOpenResult,
) (hookQueueOpenResult, error) {
	select {
	case result := <-queueResult:
		return result, nil
	case <-ctx.Done():
		select {
		case result := <-queueResult:
			return result, nil
		default:
		}
		stopQueue()
		result := <-queueResult
		return result, ctx.Err()
	}
}

func closeHookQueue(eventQueue *queue.Store) {
	if eventQueue != nil {
		_ = eventQueue.Close()
	}
}

func deliverCollection(
	ctx context.Context,
	client uplink.Client,
	eventQueue *queue.Store,
	events []contracts.AgentEvent,
	metrics []contracts.UsageMetric,
) error {
	versionedEvents := withCollectorVersion(events, version.Current().Version)
	if err := sendEventsOrQueue(ctx, client, eventQueue, versionedEvents); err != nil {
		return err
	}
	if len(metrics) > 0 {
		counts, err := client.SendUsage(ctx, metrics)
		if err != nil {
			return err
		}
		if counts.Accepted+counts.Duplicated != len(metrics) || counts.Rejected > 0 {
			return fmt.Errorf("collector usage metrics not fully accepted")
		}
	}

	return nil
}

func withCollectorVersion(events []contracts.AgentEvent, collectorVersion string) []contracts.AgentEvent {
	versionedEvents := make([]contracts.AgentEvent, len(events))
	for index, event := range events {
		if event.CollectorVersion == "" {
			event.CollectorVersion = collectorVersion
		}
		versionedEvents[index] = event
	}

	return versionedEvents
}

func sendEventsOrQueue(
	ctx context.Context,
	client uplink.Client,
	eventQueue *queue.Store,
	events []contracts.AgentEvent,
) error {
	queueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), queueWriteTimeout)
	defer cancel()

	return sendEventsOrQueueContext(ctx, queueCtx, client, eventQueue, events)
}

func sendEventsOrQueueContext(
	ctx context.Context,
	queueCtx context.Context,
	client uplink.Client,
	eventQueue *queue.Store,
	events []contracts.AgentEvent,
) error {
	if len(events) == 0 {
		return nil
	}
	counts, err := client.SendEvents(ctx, events)
	if err == nil && counts.Accepted+counts.Duplicated == len(events) && counts.Rejected == 0 {
		return nil
	}
	if err == nil {
		err = fmt.Errorf("collector events not fully accepted")
	}
	if eventQueue == nil {
		return err
	}
	if queueErr := enqueueEvents(queueCtx, eventQueue, events); queueErr != nil {
		return errors.Join(err, queueErr)
	}

	return nil
}

func openEventQueue(config daemonAdapterConfig) (*queue.Store, error) {
	return openEventQueueContext(context.Background(), config)
}

func openEventQueueContext(
	ctx context.Context,
	config daemonAdapterConfig,
) (*queue.Store, error) {
	return openEventQueueContextWithOptions(ctx, config, queue.Options{})
}

func openHookEventQueueContext(
	ctx context.Context,
	config daemonAdapterConfig,
) (*queue.Store, error) {
	return openEventQueueContextWithOptions(ctx, config, queue.Options{
		SkipJournalModeConfiguration: true,
	})
}

func openEventQueueContextWithOptions(
	ctx context.Context,
	config daemonAdapterConfig,
	options queue.Options,
) (*queue.Store, error) {
	auditPath := (localaudit.Store{Path: config.AuditLogPath}).ResolvedPath()
	return queue.OpenContext(
		ctx,
		filepath.Join(filepath.Dir(auditPath), "collector-queue.db"),
		options,
	)
}

func enqueueEvents(
	ctx context.Context,
	eventQueue *queue.Store,
	events []contracts.AgentEvent,
) error {
	for _, event := range events {
		if _, err := eventQueue.Enqueue(ctx, event); err != nil {
			return fmt.Errorf("enqueue collector event: %w", err)
		}
	}

	return nil
}

func runQueueDrainLoop(
	ctx context.Context,
	eventQueue *queue.Store,
	client uplink.Client,
	stderr io.Writer,
) {
	ticker := time.NewTicker(queueDrainInterval)
	defer ticker.Stop()

	for {
		drainContext, cancel := context.WithTimeout(ctx, eventDeliveryTimeout)
		err := uplink.DrainQueue(drainContext, eventQueue, client, uplink.DrainOptions{})
		cancel()
		if err != nil && ctx.Err() == nil {
			_, _ = fmt.Fprintln(stderr, "queue_drain_status=retry_pending")
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (config daemonAdapterConfig) configured() bool {
	return config.APIURL != "" && config.Token != "" && config.Identity.OrganizationID != "" &&
		config.Identity.MachineID != "" && config.Identity.MachineEnrollmentID != "" &&
		config.Identity.MemberID != ""
}

func (config daemonAdapterConfig) validate() error {
	if config.MaxPrivacyLevel != "" && !validPrivacyLevel(config.MaxPrivacyLevel) {
		return fmt.Errorf("--max-privacy-level must be one of L0, L1, L2, L3, or L4")
	}
	if config.configured() {
		return nil
	}

	return fmt.Errorf("--api-url, --token, --organization-id, --machine-id, --machine-enrollment-id, and --member-id are required")
}

func validPrivacyLevel(value string) bool {
	return value == "L0" || value == "L1" || value == "L2" || value == "L3" || value == "L4"
}

func (config daemonAdapterConfig) claudeOptions() claudecode.Options {
	return claudecode.Options{
		Identity:     config.Identity,
		RepoResolver: resolveGitContext,
	}
}

func (config daemonAdapterConfig) codexOptions() codexcli.Options {
	return codexcli.Options{
		Identity: codexcli.Identity{
			MachineEnrollmentID: config.Identity.MachineEnrollmentID,
			MachineID:           config.Identity.MachineID,
			MemberID:            config.Identity.MemberID,
			OrganizationID:      config.Identity.OrganizationID,
			ProjectID:           config.Identity.ProjectID,
		},
		RepoResolver: resolveGitContext,
	}
}

func (config daemonAdapterConfig) cursorOptions() cursor.Options {
	return cursor.Options{
		EnableHooksBeta: config.CursorHooksBeta,
		Identity: cursor.Identity{
			MachineEnrollmentID: config.Identity.MachineEnrollmentID,
			MachineID:           config.Identity.MachineID,
			MemberID:            config.Identity.MemberID,
			OrganizationID:      config.Identity.OrganizationID,
			ProjectID:           config.Identity.ProjectID,
		},
	}
}

func resolveGitContext(cwd string) (gitcontext.Snapshot, error) {
	return gitcontext.DefaultResolver().Resolve(context.Background(), cwd)
}

func (config daemonAdapterConfig) uplinkConfig(client *http.Client) uplink.Config {
	auditLog := localaudit.Store{Path: config.AuditLogPath}
	return uplink.Config{
		APIURL:            config.APIURL,
		AllowInsecureHTTP: config.AllowInsecureHTTP,
		AuditLog:          &auditLog,
		HTTPClient:        client,
		Token:             config.Token,
	}
}

func defaultDisplayName() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "Mitoriq Machine"
	}

	return hostname
}

func defaultOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return "unknown"
	}
}

type installPlan struct {
	BinaryPath  string
	LaunchdPath string
	Tools       []string
}

func parseTools(value string) []string {
	parts := strings.Split(value, ",")
	tools := make([]string, 0, len(parts))
	for _, part := range parts {
		tool := strings.TrimSpace(part)
		if tool != "" {
			tools = append(tools, tool)
		}
	}

	return tools
}

func mergeCursorCollections(collections ...cursor.Collection) cursor.Collection {
	var merged cursor.Collection
	for _, collection := range collections {
		merged.Events = append(merged.Events, collection.Events...)
		merged.UsageMetrics = append(merged.UsageMetrics, collection.UsageMetrics...)
	}

	return merged
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}

func defaultCursorStateDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}

	return filepath.Join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "state.vscdb")
}

func (plan installPlan) hookSnippets() []string {
	snippets := make([]string, 0, len(plan.Tools))
	for _, tool := range plan.Tools {
		switch tool {
		case "claude":
			snippets = append(snippets, fmt.Sprintf("claude_hook_command=%s claude-hook", plan.BinaryPath))
		case "codex":
			snippets = append(snippets, fmt.Sprintf("codex_hook_command=%s codex-hook", plan.BinaryPath))
		case "cursor":
			snippets = append(snippets, fmt.Sprintf("cursor_hook_command=%s cursor-hook --cursor-hooks-beta", plan.BinaryPath))
		}
	}

	return snippets
}

func (plan installPlan) launchdPlist() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.mitoriq.collector</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>`, plan.BinaryPath)
}

func defaultLaunchdPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}

	return filepath.Join(home, "Library", "LaunchAgents", launchdServiceLabel+".plist")
}

func defaultLaunchdLifecycleLockPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}

	return filepath.Join(
		home,
		"Library",
		"Application Support",
		launchdLifecycleLockDirectory,
		launchdLifecycleLockFileName,
	)
}

func installStatus(dryRun bool) string {
	if dryRun {
		return "planned"
	}

	return "written"
}

func writeLaunchdPlist(path string, body string) error {
	return writeLaunchdPlistWithOps(path, body, defaultLaunchdAtomicFileOps())
}

func allowInsecureForSavedConfig(apiURL string, explicit bool) bool {
	if explicit {
		return true
	}
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
