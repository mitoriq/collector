package version

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestCurrentServiceOriginsAcceptsEmbeddedHTTPSOrigins(t *testing.T) {
	setServiceOrigins(t, "https://api.mitoriq.example", "https://mitoriq.example")
	origins, err := CurrentServiceOrigins()
	if err != nil {
		t.Fatal(err)
	}
	if origins.APIURL != "https://api.mitoriq.example" || origins.WebURL != "https://mitoriq.example" {
		t.Fatalf("origins = %#v", origins)
	}
}

func TestCurrentServiceOriginsRejectsNonOrigins(t *testing.T) {
	tests := []struct{ apiURL, webURL string }{
		{"", "https://web.example"}, {"https://api.example", ""},
		{"http://api.example", "https://web.example"}, {"https://user@api.example", "https://web.example"},
		{"https://api.example/path", "https://web.example"}, {"https://api.example?query=1", "https://web.example"},
		{"https://api.example#fragment", "https://web.example"}, {"https://api.example", "https://web.example/"},
	}
	for _, test := range tests {
		setServiceOrigins(t, test.apiURL, test.webURL)
		if _, err := CurrentServiceOrigins(); err == nil {
			t.Fatalf("accepted api=%q web=%q", test.apiURL, test.webURL)
		}
	}
}

func TestReleaseConfigurationEmbedsAndValidatesServiceOrigins(t *testing.T) {
	goreleaser, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"MITORIQ_API_ORIGIN", "MITORIQ_WEB_ORIGIN", "internal/version.serviceAPIURL", "internal/version.serviceWebURL"} {
		if strings.Count(string(goreleaser), required) < 2 {
			t.Fatalf("GoReleaser missing %s for both builds", required)
		}
	}
	for _, required := range []string{"MITORIQ_API_ORIGIN: https://mitoriq-production.up.railway.app", "MITORIQ_WEB_ORIGIN: https://mitoriq.vercel.app", "Validate embedded service origins", "expected_origins", "parsed.scheme != \"https\""} {
		if !strings.Contains(string(workflow), required) {
			t.Fatalf("release workflow missing %s", required)
		}
	}
}

func setServiceOrigins(t *testing.T, apiURL, webURL string) {
	t.Helper()
	previousAPIURL, previousWebURL := serviceAPIURL, serviceWebURL
	t.Cleanup(func() { serviceAPIURL, serviceWebURL = previousAPIURL, previousWebURL })
	serviceAPIURL, serviceWebURL = apiURL, webURL
}

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
