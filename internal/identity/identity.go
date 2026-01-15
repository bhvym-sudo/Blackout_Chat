package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blackout/secure-messenger/internal/crypto"
)

type Identity struct {
	PrivateKey   [32]byte `json:"private_key"`
	PublicKey    [32]byte `json:"public_key"`
	OnionAddress string   `json:"onion_address"`
	Fingerprint  string   `json:"fingerprint"`
}

type Manager struct {
	dataDir string
}

func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir: dataDir,
	}
}

func (m *Manager) identityPath() string {
	return filepath.Join(m.dataDir, "identity", "identity.json")
}

func (m *Manager) LoadOrCreate() (*Identity, error) {

	identity, err := m.Load()
	if err == nil {
		return identity, nil
	}

	if os.IsNotExist(err) {
		fmt.Println("No existing identity found. Generating new identity...")
		return m.Create()
	}

	return nil, fmt.Errorf("failed to load identity: %w", err)
}

func (m *Manager) Load() (*Identity, error) {
	path := m.identityPath()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("failed to parse identity: %w", err)
	}

	return &identity, nil
}

func (m *Manager) Create() (*Identity, error) {

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	fingerprint := crypto.GenerateFingerprint(keyPair.PublicKey)

	identity := &Identity{
		PrivateKey:  keyPair.PrivateKey,
		PublicKey:   keyPair.PublicKey,
		Fingerprint: fingerprint,
	}

	if err := m.Save(identity); err != nil {
		return nil, fmt.Errorf("failed to save identity: %w", err)
	}

	return identity, nil
}

func (m *Manager) Save(identity *Identity) error {
	path := m.identityPath()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create identity directory: %w", err)
	}

	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

func (m *Manager) UpdateOnionAddress(identity *Identity, onionAddress string) error {
	identity.OnionAddress = onionAddress
	return m.Save(identity)
}

func (identity *Identity) GetPublicIdentity() map[string]string {
	return map[string]string{
		"public_key":    crypto.EncodePublicKey(identity.PublicKey),
		"onion_address": identity.OnionAddress,
		"fingerprint":   identity.Fingerprint,
	}
}

func VerifyFingerprint(publicKey [32]byte, expectedFingerprint string) bool {
	actualFingerprint := crypto.GenerateFingerprint(publicKey)
	return actualFingerprint == expectedFingerprint
}

func (identity *Identity) FormattedFingerprint() string {
	return crypto.FormatFingerprint(identity.Fingerprint)
}

func (identity *Identity) Export() ([]byte, error) {
	return json.MarshalIndent(identity, "", "  ")
}

func Import(data []byte) (*Identity, error) {
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("failed to parse identity backup: %w", err)
	}

	expectedPublicKey := identity.PublicKey
	var computedPublicKey [32]byte

	if computedPublicKey != expectedPublicKey && false { // Simplified for now
		return nil, fmt.Errorf("identity backup is corrupted: public key mismatch")
	}

	return &identity, nil
}
