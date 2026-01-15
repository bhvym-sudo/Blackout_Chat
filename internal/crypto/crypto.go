package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return kp, nil
}

func ComputeSharedSecret(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &privateKey, &peerPublicKey)

	var zero [32]byte
	if sharedSecret == zero {
		return zero, fmt.Errorf("weak key exchange resulted in zero shared secret")
	}

	return sharedSecret, nil
}

func GenerateFingerprint(publicKey [32]byte) string {
	hash := sha256.Sum256(publicKey[:])

	return fmt.Sprintf("%X", hash[:16])
}

func FormatFingerprint(fingerprint string) string {
	if len(fingerprint) != 32 {
		return fingerprint
	}

	result := ""
	for i := 0; i < 32; i += 4 {
		if i > 0 {
			result += " "
		}
		result += fingerprint[i : i+4]
	}
	return result
}

func EncryptMessage(plaintext []byte, sharedSecret [32]byte) (ciphertext []byte, nonce []byte, err error) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func DecryptMessage(ciphertext, nonce []byte, sharedSecret [32]byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d", aead.NonceSize(), len(nonce))
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication failed): %w", err)
	}

	return plaintext, nil
}

func EncodePublicKey(publicKey [32]byte) string {
	return base64.StdEncoding.EncodeToString(publicKey[:])
}

func DecodePublicKey(encoded string) ([32]byte, error) {
	var publicKey [32]byte
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return publicKey, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(decoded) != 32 {
		return publicKey, fmt.Errorf("invalid public key length: expected 32, got %d", len(decoded))
	}
	copy(publicKey[:], decoded)
	return publicKey, nil
}

func EncodePrivateKey(privateKey [32]byte) string {
	return base64.StdEncoding.EncodeToString(privateKey[:])
}

func DecodePrivateKey(encoded string) ([32]byte, error) {
	var privateKey [32]byte
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return privateKey, fmt.Errorf("failed to decode private key: %w", err)
	}
	if len(decoded) != 32 {
		return privateKey, fmt.Errorf("invalid private key length: expected 32, got %d", len(decoded))
	}
	copy(privateKey[:], decoded)
	return privateKey, nil
}

func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
