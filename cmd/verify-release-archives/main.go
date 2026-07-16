package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitoriq/collector/internal/releasearchive"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "verify release archives: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: verify-release-archives [dist-directory]")
	}
	repoRoot, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	distDir := filepath.Join(repoRoot, "dist")
	if len(args) == 1 {
		distDir = args[0]
	}
	thirdPartyEntries, err := releasearchive.CollectThirdPartyEntries(repoRoot)
	if err != nil {
		return err
	}
	return releasearchive.VerifyDirectory(distDir, thirdPartyEntries)
}
