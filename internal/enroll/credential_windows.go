//go:build windows

package enroll

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredFree   = advapi32.NewProc("CredFree")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredWriteW = advapi32.NewProc("CredWriteW")
)

type windowsCredential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type windowsCredentialStore struct{}

func newWindowsCredentialStore() CredentialStore {
	return windowsCredentialStore{}
}

func (store windowsCredentialStore) Save(ctx context.Context, service string, token string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	target, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString("mitoriq-collector")
	if err != nil {
		return err
	}
	blob := []byte(token)
	if len(blob) == 0 {
		return fmt.Errorf("credential token is required")
	}
	credential := windowsCredential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(blob)),
		CredentialBlob:     &blob[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}

	result, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&credential)), 0)
	runtime.KeepAlive(blob)
	if result == 0 {
		return callErr
	}

	return nil
}

func (store windowsCredentialStore) Load(ctx context.Context, service string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	target, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return "", err
	}
	var credentialPtr uintptr
	result, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credentialPtr)),
	)
	if result == 0 {
		if callErr == windows.ERROR_NOT_FOUND {
			return "", fmt.Errorf("%w: %s", ErrTokenNotFound, service)
		}

		return "", callErr
	}
	defer procCredFree.Call(credentialPtr)

	credential := (*windowsCredential)(unsafe.Pointer(credentialPtr))
	if credential.CredentialBlobSize == 0 || credential.CredentialBlob == nil {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, service)
	}
	token := strings.TrimSpace(string(unsafe.Slice(
		credential.CredentialBlob,
		int(credential.CredentialBlobSize),
	)))
	if token == "" {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, service)
	}

	return token, nil
}
