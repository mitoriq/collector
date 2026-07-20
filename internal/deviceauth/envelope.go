package deviceauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/mitoriq/collector/internal/enroll"
)

const envelopeAlgorithm = "RSA-OAEP-256+A256GCM"

type Envelope struct {
	Algorithm    string `json:"algorithm"`
	EncryptedKey string `json:"encryptedKey"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}

func GenerateEphemeralKey() (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", errors.New("generate device authorization key")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, "", errors.New("encode device authorization key")
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privateKey, string(publicPEM), nil
}
func DecryptEnrollmentEnvelope(privateKey *rsa.PrivateKey, envelope Envelope) (enroll.EnrollResponse, error) {
	if privateKey == nil || envelope.Algorithm != envelopeAlgorithm {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment envelope")
	}
	encryptedKey, err := decodeEnvelopeField(envelope.EncryptedKey)
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	iv, err := decodeEnvelopeField(envelope.IV)
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	ciphertext, err := decodeEnvelopeField(envelope.Ciphertext)
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	tag, err := decodeEnvelopeField(envelope.Tag)
	if err != nil {
		return enroll.EnrollResponse{}, err
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil || len(key) != 32 {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment envelope")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment envelope")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment envelope")
	}
	plaintext, err := gcm.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), nil)
	if err != nil {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment envelope")
	}
	var response enroll.EnrollResponse
	if json.Unmarshal(plaintext, &response) != nil || !validEnrollment(response) {
		return enroll.EnrollResponse{}, errors.New("invalid enrollment payload")
	}
	return response, nil
}
func decodeEnvelopeField(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("invalid enrollment envelope")
	}
	return decoded, nil
}
func validEnrollment(response enroll.EnrollResponse) bool {
	return response.EnrollmentToken != "" && response.MachineEnrollmentID != "" && response.MachineID != "" && response.MemberID != "" && response.OrganizationID != "" && response.TokenPrefix != ""
}
