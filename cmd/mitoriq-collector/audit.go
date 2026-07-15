package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/mitoriq/collector/internal/localaudit"
	"github.com/mitoriq/collector/internal/localconfig"
)

func runAuditLog(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("audit-log", flag.ContinueOnError)
	limit := flags.Int("limit", 100, "maximum number of recent audit entries")
	path := flags.String("path", "", "local audit log path")
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}

	store := localaudit.Store{Path: *path}
	entries, err := store.Tail(*limit)
	if err != nil {
		if localaudit.IsNotFound(err) {
			_, writeErr := fmt.Fprintf(stdout, "audit_log_status=empty path=%q\n", store.ResolvedPath())
			return writeErr
		}

		return err
	}
	encoder := json.NewEncoder(stdout)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return err
		}
	}

	return nil
}

func writeDoctorLocalStatus(configPath string, stdout io.Writer) error {
	config := localconfig.Config{}
	loaded, err := (localconfig.Store{Path: configPath}).Load()
	if err == nil {
		config = loaded
	} else if !localconfig.IsNotFound(err) {
		return err
	}
	auditPath := (localaudit.Store{Path: config.AuditLogPath}).ResolvedPath()
	_, err = fmt.Fprintf(
		stdout,
		"update_channel=%s audit_log_path=%q\n",
		localconfig.EffectiveUpdateChannel(config.UpdateChannel),
		auditPath,
	)

	return err
}
