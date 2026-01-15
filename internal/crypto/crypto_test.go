package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	var zero [32]byte
	if kp.PrivateKey == zero {
		t.Error("Private key is all zeros")
	}
	if kp.PublicKey == zero {
		t.Error("Public key is all zeros")
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Second GenerateKeyPair failed: %v", err)
	}

	if kp.PrivateKey == kp2.PrivateKey {
		t.Error("Generated same private key twice")
	}
	if kp.PublicKey == kp2.PublicKey {
		t.Error("Generated same public key twice")
	}
}

func TestComputeSharedSecret(t *testing.T) {

	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's key pair: %v", err)
	}

	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	aliceShared, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("Alice's shared secret computation failed: %v", err)
	}

	bobShared, err := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("Bob's shared secret computation failed: %v", err)
	}

	if aliceShared != bobShared {
		t.Error("Shared secrets don't match")
	}

	var zero [32]byte
	if aliceShared == zero {
		t.Error("Shared secret is all zeros")
	}
}

func TestGenerateFingerprint(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	fingerprint := GenerateFingerprint(kp.PublicKey)

	if len(fingerprint) != 32 {
		t.Errorf("Fingerprint length is %d, expected 32", len(fingerprint))
	}

	fingerprint2 := GenerateFingerprint(kp.PublicKey)
	if fingerprint != fingerprint2 {
		t.Error("Fingerprint generation is not deterministic")
	}
}

func TestFormatFingerprint(t *testing.T) {
	fingerprint := "0123456789ABCDEF0123456789ABCDEF"
	formatted := FormatFingerprint(fingerprint)
	expected := "0123 4567 89AB CDEF 0123 4567 89AB CDEF"

	if formatted != expected {
		t.Errorf("Formatted fingerprint is %q, expected %q", formatted, expected)
	}
}

func TestEncryptDecryptMessage(t *testing.T) {

	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute shared secret: %v", err)
	}

	message := []byte("Hello, this is a secret message!")

	ciphertext, nonce, err := EncryptMessage(message, sharedSecret)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if bytes.Equal(ciphertext, message) {
		t.Error("Ciphertext is same as plaintext")
	}

	decrypted, err := DecryptMessage(ciphertext, nonce, sharedSecret)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Errorf("Decrypted message doesn't match original")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()

	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	wrongSecret, _ := ComputeSharedSecret(eve.PrivateKey, bob.PublicKey)

	message := []byte("Secret message")
	ciphertext, nonce, _ := EncryptMessage(message, sharedSecret)

	_, err := DecryptMessage(ciphertext, nonce, wrongSecret)
	if err == nil {
		t.Error("Decryption with wrong key should fail")
	}
}

func TestDecryptWithModifiedCiphertext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)

	message := []byte("Secret message")
	ciphertext, nonce, _ := EncryptMessage(message, sharedSecret)

	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	_, err := DecryptMessage(ciphertext, nonce, sharedSecret)
	if err == nil {
		t.Error("Decryption with modified ciphertext should fail")
	}
}

func TestEncodeDecodePublicKey(t *testing.T) {
	kp, _ := GenerateKeyPair()

	encoded := EncodePublicKey(kp.PublicKey)
	decoded, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	if decoded != kp.PublicKey {
		t.Error("Decoded public key doesn't match original")
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	kp, _ := GenerateKeyPair()

	encoded := EncodePrivateKey(kp.PrivateKey)
	decoded, err := DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	if decoded != kp.PrivateKey {
		t.Error("Decoded private key doesn't match original")
	}
}

func TestSecureCompare(t *testing.T) {
	a := []byte("test")
	b := []byte("test")
	c := []byte("different")

	if !SecureCompare(a, b) {
		t.Error("SecureCompare should return true for identical slices")
	}

	if SecureCompare(a, c) {
		t.Error("SecureCompare should return false for different slices")
	}

	if SecureCompare(a, []byte("tes")) {
		t.Error("SecureCompare should return false for different lengths")
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair()
	}
}

func BenchmarkEncryptMessage(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	message := []byte("Hello, this is a benchmark message!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptMessage(message, sharedSecret)
	}
}

func BenchmarkDecryptMessage(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedSecret, _ := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	message := []byte("Hello, this is a benchmark message!")
	ciphertext, nonce, _ := EncryptMessage(message, sharedSecret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptMessage(ciphertext, nonce, sharedSecret)
	}
}
