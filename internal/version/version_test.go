package version

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestCurrentReleaseTrustDecodesBuildMetadata(t *testing.T) {
	previousURL := releaseAPIURL
	previousTeamID := releaseMacOSTeamID
	previousNextKey := releaseNextPublicKeyBase64
	previousKey := releasePublicKeyBase64
	t.Cleanup(func() {
		releaseAPIURL = previousURL
		releaseMacOSTeamID = previousTeamID
		releaseNextPublicKeyBase64 = previousNextKey
		releasePublicKeyBase64 = previousKey
	})
	releaseAPIURL = "https://api.example.test/releases/latest"
	releaseMacOSTeamID = "TEAMID1234"
	releasePublicKeyBase64 = base64.StdEncoding.EncodeToString(testPublicKeyPEM(t))

	trust, err := CurrentReleaseTrust()
	if err != nil {
		t.Fatal(err)
	}
	if trust.APIURL != releaseAPIURL || trust.MacOSTeamID != releaseMacOSTeamID || len(trust.PublicKeySHA256) != 64 {
		t.Fatalf("trust = %#v", trust)
	}
}

func TestCurrentReleaseTrustRejectsUnconfiguredDevelopmentBuild(t *testing.T) {
	previousURL := releaseAPIURL
	previousTeamID := releaseMacOSTeamID
	previousNextKey := releaseNextPublicKeyBase64
	previousKey := releasePublicKeyBase64
	t.Cleanup(func() {
		releaseAPIURL = previousURL
		releaseMacOSTeamID = previousTeamID
		releaseNextPublicKeyBase64 = previousNextKey
		releasePublicKeyBase64 = previousKey
	})
	releaseAPIURL = ""
	releaseMacOSTeamID = ""
	releaseNextPublicKeyBase64 = ""
	releasePublicKeyBase64 = ""

	if _, err := CurrentReleaseTrust(); err == nil {
		t.Fatal("expected missing release trust error")
	}
}

func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
