package deviceauth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const journalLocalUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

func TestJournalIsAtomic0600AndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	store := JournalStore{Path: path}
	state := JournalState{Version: journalVersion, DeviceCode: "secret", UserCode: "ABCD", PrivateKeyPEM: "private", LocalUUID: journalLocalUUID, Progress: ProgressStarted, Interval: 5, ExpiresAt: 10}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v, want 0600", info.Mode().Perm())
	}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil {
			t.Fatal("insecure journal was accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || errors.Is(err, ErrJournalNotFound) {
		t.Fatal("invalid journal was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1}{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("trailing journal data was accepted")
	}
}

func TestJournalSaveSyncsParentDirectoryAndSurfacesFailure(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "journal.json")
	state := JournalState{Version: journalVersion, DeviceCode: "secret", UserCode: "ABCD", PrivateKeyPEM: "private", LocalUUID: journalLocalUUID, Progress: ProgressStarted, Interval: 5, ExpiresAt: 10}
	var syncedDirectory string
	store := JournalStore{
		Path: path,
		syncParent: func(path string) error {
			syncedDirectory = path
			return errors.New("sync failed")
		},
	}

	if err := store.Save(state); err == nil {
		t.Fatal("parent directory sync failure was ignored")
	}
	if syncedDirectory != directory {
		t.Fatalf("synced directory = %q", syncedDirectory)
	}
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		t.Fatalf("renamed journal missing: size=%d err=%v", len(content), err)
	}
}

func TestJournalRequiresAndPersistsLocalUUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	state := JournalState{Version: journalVersion, DeviceCode: "secret", UserCode: "ABCD", PrivateKeyPEM: "private", Progress: ProgressStarted, Interval: 5, ExpiresAt: 10}
	if err := (JournalStore{Path: path}).Save(state); err == nil {
		t.Fatal("journal without local UUID was accepted")
	}
	state.LocalUUID = "local-uuid"
	if err := (JournalStore{Path: path}).Save(state); err == nil {
		t.Fatal("journal with non-canonical local UUID was accepted")
	}
	state.LocalUUID = journalLocalUUID
	if err := (JournalStore{Path: path}).Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := (JournalStore{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LocalUUID != state.LocalUUID {
		t.Fatalf("LocalUUID = %q", loaded.LocalUUID)
	}
}

func TestJournalRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires platform-specific privileges on Windows")
	}
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "target.json")
	linkPath := filepath.Join(directory, "journal.json")
	state := JournalState{Version: journalVersion, DeviceCode: "secret", UserCode: "ABCD", PrivateKeyPEM: "private", LocalUUID: journalLocalUUID, Progress: ProgressStarted, Interval: 5, ExpiresAt: 10}
	if err := (JournalStore{Path: targetPath}).Save(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatal(err)
	}

	if _, err := (JournalStore{Path: linkPath}).Load(); err == nil {
		t.Fatal("symlinked journal was accepted")
	}
}

func TestJournalRejectsFileSwappedBetweenInspectionAndOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "journal.json")
	replacementPath := filepath.Join(directory, "replacement.json")
	state := JournalState{Version: journalVersion, DeviceCode: "secret", UserCode: "ABCD", PrivateKeyPEM: "private", LocalUUID: journalLocalUUID, Progress: ProgressStarted, Interval: 5, ExpiresAt: 10}
	if err := (JournalStore{Path: path}).Save(state); err != nil {
		t.Fatal(err)
	}
	if err := (JournalStore{Path: replacementPath}).Save(state); err != nil {
		t.Fatal(err)
	}
	store := JournalStore{
		Path: path,
		openFile: func(openPath string) (*os.File, error) {
			if err := os.Rename(replacementPath, path); err != nil {
				return nil, err
			}
			return os.Open(openPath)
		},
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("journal swapped before open was accepted")
	}
}
