package version

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	releaseAPIURL              = ""
	releaseMacOSTeamID         = ""
	releaseNextPublicKeyBase64 = ""
	releasePublicKeyBase64     = ""
)

type Info struct {
	Version string
	Commit  string
	Date    string
}

func Current() Info {
	return Info{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
}

func (info Info) Line() string {
	line := fmt.Sprintf("version=%s commit=%s date=%s", info.Version, info.Commit, info.Date)
	trust, err := CurrentReleaseTrust()
	if err != nil {
		return line + " release_trust=unconfigured"
	}

	return fmt.Sprintf(
		"%s release_key_sha256=%s release_next_key_sha256=%s release_team_id=%s",
		line,
		trust.PublicKeySHA256,
		strings.Join(trust.AdditionalPublicKeySHA256, ","),
		trust.MacOSTeamID,
	)
}

type ReleaseTrust struct {
	APIURL                    string
	AdditionalPublicKeysPEM   [][]byte
	AdditionalPublicKeySHA256 []string
	MacOSTeamID               string
	PublicKeyPEM              []byte
	PublicKeySHA256           string
}

func CurrentReleaseTrust() (ReleaseTrust, error) {
	if releaseAPIURL == "" || releaseMacOSTeamID == "" || releasePublicKeyBase64 == "" {
		return ReleaseTrust{}, fmt.Errorf("release trust metadata is not configured in this build")
	}
	publicKey, fingerprint, err := decodeReleasePublicKey(releasePublicKeyBase64)
	if err != nil {
		return ReleaseTrust{}, err
	}
	additionalKeys := make([][]byte, 0, 1)
	additionalFingerprints := make([]string, 0, 1)
	if releaseNextPublicKeyBase64 != "" {
		nextKey, nextFingerprint, err := decodeReleasePublicKey(releaseNextPublicKeyBase64)
		if err != nil {
			return ReleaseTrust{}, fmt.Errorf("decode next release public key: %w", err)
		}
		if nextFingerprint == fingerprint {
			return ReleaseTrust{}, fmt.Errorf("next release public key duplicates current key")
		}
		additionalKeys = append(additionalKeys, nextKey)
		additionalFingerprints = append(additionalFingerprints, nextFingerprint)
	}

	return ReleaseTrust{
		APIURL:                    releaseAPIURL,
		AdditionalPublicKeysPEM:   additionalKeys,
		AdditionalPublicKeySHA256: additionalFingerprints,
		MacOSTeamID:               releaseMacOSTeamID,
		PublicKeyPEM:              publicKey,
		PublicKeySHA256:           fingerprint,
	}, nil
}

func decodeReleasePublicKey(encoded string) ([]byte, string, error) {
	publicKey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("decode release public key: %w", err)
	}
	if len(publicKey) == 0 {
		return nil, "", fmt.Errorf("release public key is empty")
	}
	block, remainder := pem.Decode(publicKey)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 {
		return nil, "", fmt.Errorf("release public key is not valid PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse release public key: %w", err)
	}
	ecdsaKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok || ecdsaKey.Curve == nil || ecdsaKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, "", fmt.Errorf("release public key must be ECDSA P-256")
	}
	digest := sha256.Sum256(block.Bytes)

	return publicKey, hex.EncodeToString(digest[:]), nil
}
