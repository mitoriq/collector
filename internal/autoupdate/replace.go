package autoupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type replaceResult struct {
	updated    bool
	rolledBack bool
	backupPath string
}

func (manager *Manager) replace(
	ctx context.Context,
	release extractedRelease,
	validator Validator,
) (replaceResult, error) {
	executablePath := manager.config.ExecutablePath
	currentInfo, err := os.Lstat(executablePath)
	if err != nil {
		return replaceResult{}, fmt.Errorf("stat current executable: %w", err)
	}
	if !currentInfo.Mode().IsRegular() {
		return replaceResult{}, fmt.Errorf("current executable is not a regular file: %s", executablePath)
	}
	directory := filepath.Dir(executablePath)
	stagedPath, err := writeStagedBinary(directory, filepath.Base(executablePath), release.binary, currentInfo.Mode().Perm())
	if err != nil {
		return replaceResult{}, err
	}
	defer os.Remove(stagedPath)
	backupPath, err := reserveBackupPath(directory, filepath.Base(executablePath))
	if err != nil {
		return replaceResult{}, err
	}
	result := replaceResult{backupPath: backupPath}
	if err := os.Link(executablePath, backupPath); err != nil {
		return result, fmt.Errorf("create executable backup: %w", err)
	}
	currentAfterLink, currentErr := os.Lstat(executablePath)
	backupInfo, backupErr := os.Lstat(backupPath)
	if currentErr != nil || backupErr != nil || !os.SameFile(currentInfo, currentAfterLink) || !os.SameFile(currentInfo, backupInfo) {
		_ = os.Remove(backupPath)
		return result, fmt.Errorf("current executable changed during update")
	}
	if err := os.Rename(stagedPath, executablePath); err != nil {
		if cleanupErr := os.Remove(backupPath); cleanupErr != nil {
			return result, errors.Join(fmt.Errorf("install updated executable: %w", err), fmt.Errorf("remove unused backup: %w", cleanupErr))
		}
		return result, fmt.Errorf("install updated executable: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		rollbackErr := rollbackExecutable(executablePath, backupPath)
		if rollbackErr != nil {
			return result, errors.Join(err, fmt.Errorf("%w: %v", ErrRollbackFailed, rollbackErr))
		}
		result.rolledBack = true
		return result, fmt.Errorf("sync updated executable: %w", err)
	}

	validationCtx, cancel := context.WithTimeout(ctx, manager.config.ValidationTimeout)
	validationErr := validator.Validate(validationCtx, executablePath)
	cancel()
	if validationErr != nil {
		rollbackErr := rollbackExecutable(executablePath, backupPath)
		if rollbackErr != nil {
			return result, errors.Join(validationErr, fmt.Errorf("%w: %v", ErrRollbackFailed, rollbackErr))
		}
		result.rolledBack = true
		return result, fmt.Errorf("validate updated executable: %w", validationErr)
	}
	result.updated = true
	if err := os.Remove(backupPath); err != nil {
		return result, fmt.Errorf("remove executable backup: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return result, fmt.Errorf("sync executable directory: %w", err)
	}
	return result, nil
}

func writeStagedBinary(directory string, baseName string, content []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(directory, "."+baseName+".update-*")
	if err != nil {
		return "", fmt.Errorf("create staged executable: %w", err)
	}
	path := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(mode); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("set staged executable permissions: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write staged executable: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("sync staged executable: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close staged executable: %w", err)
	}
	closed = true
	return path, nil
}

func reserveBackupPath(directory string, baseName string) (string, error) {
	file, err := os.CreateTemp(directory, "."+baseName+".backup-*")
	if err != nil {
		return "", fmt.Errorf("reserve executable backup path: %w", err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close executable backup reservation: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("clear executable backup reservation: %w", err)
	}
	return path, nil
}

func rollbackExecutable(executablePath string, backupPath string) error {
	if err := os.Rename(backupPath, executablePath); err != nil {
		return fmt.Errorf("restore executable backup: %w", err)
	}

	return syncDirectory(filepath.Dir(executablePath))
}
