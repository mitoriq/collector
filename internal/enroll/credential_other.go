//go:build !windows

package enroll

func newWindowsCredentialStore() CredentialStore {
	return nil
}
