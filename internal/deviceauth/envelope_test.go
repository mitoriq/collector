package deviceauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mitoriq/collector/internal/enroll"
)

func TestDecryptEnrollmentEnvelope(t *testing.T) {
	privateKey, _ := generateKey(t)
	want := enroll.EnrollResponse{
		EnrollmentToken: "mtq_e_token_secret", MachineEnrollmentID: "enrollment-1", MachineID: "machine-1",
		MemberID: "member-1", OrganizationID: "org-1", TokenPrefix: "mtq_e_token",
	}
	envelope := sealEnvelope(t, &privateKey.PublicKey, want)
	actual, err := DecryptEnrollmentEnvelope(privateKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if actual != want {
		t.Fatalf("response = %#v", actual)
	}
}
func TestDecryptEnrollmentEnvelopeFailsClosedOnTamper(t *testing.T) {
	privateKey, _ := generateKey(t)
	secret := "mtq_e_token_secret"
	envelope := sealEnvelope(t, &privateKey.PublicKey, enroll.EnrollResponse{
		EnrollmentToken: secret, MachineEnrollmentID: "enrollment-1", MachineID: "machine-1",
		MemberID: "member-1", OrganizationID: "org-1", TokenPrefix: "mtq_e_token",
	})
	ciphertext := must(base64.StdEncoding.DecodeString(envelope.Ciphertext))
	ciphertext[0] ^= 0xff
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	_, err := DecryptEnrollmentEnvelope(privateKey, envelope)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error = %v", err)
	}
}
func generateKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, publicKey, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(publicKey))
	if privateKey.N.BitLen() != 2048 || block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("invalid generated key")
	}
	return privateKey, publicKey
}
func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func sealEnvelope(t *testing.T, publicKey *rsa.PublicKey, value enroll.EnrollResponse) Envelope {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block := must(aes.NewCipher(key))
	gcm := must(cipher.NewGCM(block))
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	plaintext := must(json.Marshal(value))
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tagStart := len(sealed) - gcm.Overhead()
	encryptedKey := must(rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, key, nil))
	encode := base64.StdEncoding.EncodeToString
	return Envelope{
		Algorithm: "RSA-OAEP-256+A256GCM", EncryptedKey: encode(encryptedKey), IV: encode(iv),
		Ciphertext: encode(sealed[:tagStart]), Tag: encode(sealed[tagStart:]),
	}
}
