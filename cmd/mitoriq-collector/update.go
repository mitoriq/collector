package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitoriq/collector/internal/autoupdate"
	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/localconfig"
	"github.com/mitoriq/collector/internal/version"
)

const stableUpdateInterval = 24 * time.Hour

var collectorReleaseHTTPSHosts = []string{
	"api.github.com",
	"github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
}

func runUpdate(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	configPath := flags.String("config", "", "collector config path")
	setChannel := flags.String("set-channel", "", "persist update channel: manual or stable")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	store := localconfig.Store{Path: *configPath}
	if *setChannel != "" {
		if err := saveUpdateChannel(store, *setChannel); err != nil {
			return err
		}
		_, err := fmt.Fprintf(stdout, "update_channel=%s\n", *setChannel)
		return err
	}

	config, err := loadOptionalCollectorConfig(store)
	if err != nil {
		return err
	}
	result, err := applySignedUpdate(context.Background(), config.AuditLogPath)
	if err != nil {
		return err
	}
	if !result.Updated {
		_, err = fmt.Fprintf(stdout, "collector_update_status=not_needed reason=%s\n", result.NoUpdateReason)
		return err
	}
	_, err = fmt.Fprintf(stdout, "collector_update_status=updated tag=%s\n", result.TagName)

	return err
}

func runStableAutoUpdate(configPath string, auditLogPath string, stdout io.Writer) (bool, error) {
	store := localconfig.Store{Path: configPath}
	config, err := loadOptionalCollectorConfig(store)
	if err != nil {
		return false, err
	}
	if localconfig.EffectiveUpdateChannel(config.UpdateChannel) != localconfig.UpdateChannelStable {
		return false, nil
	}
	result, err := applySignedUpdate(context.Background(), auditLogPath)
	if err != nil {
		shouldDisable := result.RolledBack || errors.Is(err, autoupdate.ErrRollbackFailed)
		return result.Updated, disableStableAfterRollback(store, shouldDisable, err)
	}

	return reportStableUpdateResult(result, stdout)
}

func reportStableUpdateResult(result autoupdate.Result, stdout io.Writer) (bool, error) {
	if !result.Updated {
		return false, nil
	}
	_, err := fmt.Fprintf(stdout, "collector_update_status=updated tag=%s restart_required=true\n", result.TagName)

	return true, err
}

func disableStableAfterRollback(store localconfig.Store, rolledBack bool, updateErr error) error {
	if !rolledBack {
		return updateErr
	}
	if err := saveUpdateChannel(store, localconfig.UpdateChannelManual); err != nil {
		return errors.Join(updateErr, fmt.Errorf("disable stable channel after rollback: %w", err))
	}

	return updateErr
}

func runStableAutoUpdateLoop(
	ctx context.Context,
	configPath string,
	auditLogPath string,
	stdout io.Writer,
	stderr io.Writer,
	onUpdated func() error,
) {
	ticker := time.NewTicker(stableUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updated, err := runStableAutoUpdate(configPath, auditLogPath, stdout)
			if err != nil {
				fmt.Fprintf(stderr, "自動更新をスキップしました: %v\n", err)
			}
			if !updated {
				continue
			}
			if err := onUpdated(); err != nil {
				fmt.Fprintf(stderr, "更新後の再起動準備に失敗しました: %v\n", err)
			}
			return
		}
	}
}

func applySignedUpdate(ctx context.Context, auditLogPath string) (autoupdate.Result, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return autoupdate.Result{}, fmt.Errorf("resolve collector executable: %w", err)
	}
	if resolvedPath, resolveErr := filepath.EvalSymlinks(executablePath); resolveErr == nil {
		executablePath = resolvedPath
	}
	if isPackageManagerManaged(executablePath) {
		return autoupdate.Result{}, fmt.Errorf("package-manager installation must be updated with brew upgrade --cask mitoriq-collector")
	}
	trust, err := version.CurrentReleaseTrust()
	if err != nil {
		return autoupdate.Result{}, err
	}
	manager, err := autoupdate.New(autoupdate.Config{
		ReleaseURL:              trust.APIURL,
		PublicKeyPEM:            trust.PublicKeyPEM,
		AdditionalPublicKeysPEM: trust.AdditionalPublicKeysPEM,
		CurrentVersion:          version.Current().Version,
		ExecutablePath:          executablePath,
		MacOSTeamID:             trust.MacOSTeamID,
		AllowedHTTPSHosts:       collectorReleaseHTTPSHosts,
	})
	if err != nil {
		return autoupdate.Result{}, err
	}

	auditLog := localaudit.Store{Path: auditLogPath}
	attempt := localaudit.Entry{
		Category:         "update",
		Phase:            "attempted",
		Count:            1,
		ReleaseKeySHA256: trust.PublicKeySHA256,
		Version:          version.Current().Version,
	}
	if err := auditLog.Append(attempt); err != nil {
		return autoupdate.Result{}, fmt.Errorf("write update audit log before update: %w", err)
	}
	result, updateErr := manager.Update(ctx)
	if updateErr != nil {
		auditErr := auditLog.Append(localaudit.Entry{
			Category:    "update",
			Phase:       "failed",
			Count:       1,
			FailureCode: updateFailureCode(updateErr),
		})
		if auditErr != nil {
			return result, errors.Join(updateErr, auditErr)
		}

		return result, updateErr
	}
	if err := auditLog.Append(localaudit.Entry{
		Category:         "update",
		Phase:            "accepted",
		Count:            1,
		ReleaseKeySHA256: trust.PublicKeySHA256,
		Version:          result.TagName,
	}); err != nil {
		return result, err
	}

	return result, nil
}

func saveUpdateChannel(store localconfig.Store, channel string) error {
	if !localconfig.ValidUpdateChannel(channel) || channel == "" {
		return fmt.Errorf("update channel must be manual or stable")
	}
	return store.Update(func(config localconfig.Config) (localconfig.Config, error) {
		config.UpdateChannel = channel

		return config, nil
	})
}

func loadOptionalCollectorConfig(store localconfig.Store) (localconfig.Config, error) {
	config, err := store.Load()
	if err == nil {
		return config, nil
	}
	if localconfig.IsNotFound(err) {
		return localconfig.Config{}, nil
	}

	return localconfig.Config{}, err
}

func isPackageManagerManaged(path string) bool {
	for _, part := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if part == "Cellar" || part == "Caskroom" {
			return true
		}
	}

	return false
}

func updateFailureCode(err error) string {
	switch {
	case errors.Is(err, autoupdate.ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, autoupdate.ErrChecksumMismatch):
		return "checksum_mismatch"
	case errors.Is(err, autoupdate.ErrRollbackFailed):
		return "rollback_failed"
	default:
		return "update_failed"
	}
}
