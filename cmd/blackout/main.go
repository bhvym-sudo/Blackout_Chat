package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/blackout/secure-messenger/internal/chat"
	"github.com/blackout/secure-messenger/internal/crypto"
	"github.com/blackout/secure-messenger/internal/database"
	"github.com/blackout/secure-messenger/internal/identity"
	"github.com/blackout/secure-messenger/internal/tor"
	"github.com/blackout/secure-messenger/internal/ui"
)

const (
	appName    = "BlackOut"
	appVersion = "1.0.0"
)

func main() {
	log.Println("Starting BlackOut - Secure P2P Messenger")
	log.Printf("Version: %s\n", appVersion)

	dataDir, err := getDataDir()
	if err != nil {
		log.Fatalf("Failed to get data directory: %v", err)
	}

	log.Printf("Data directory: %s", dataDir)

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	log.Println("Loading identity...")
	identityManager := identity.NewManager(dataDir)
	userIdentity, err := identityManager.LoadOrCreate()
	if err != nil {
		log.Fatalf("Failed to initialize identity: %v", err)
	}

	log.Printf("Identity fingerprint: %s", crypto.FormatFingerprint(userIdentity.Fingerprint))

	log.Println("Opening database...")
	db, err := database.New(dataDir)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	log.Println("Starting Tor service...")
	torConfig := tor.Config{
		DataDir:     dataDir,
		ServicePort: 8080,
		Debug:       false,
	}

	torService := tor.NewService(torConfig)

	err = torService.Start(func(progress int) {
		log.Printf("Tor bootstrap: %d%%", progress)
	})
	if err != nil {
		log.Fatalf("Failed to start Tor: %v", err)
	}
	defer torService.Stop()

	onionAddress := torService.GetOnionAddress()
	log.Printf("Onion address: %s", onionAddress)

	if userIdentity.OnionAddress == "" || userIdentity.OnionAddress != onionAddress {
		err = identityManager.UpdateOnionAddress(userIdentity, onionAddress)
		if err != nil {
			log.Printf("Warning: Failed to update onion address: %v", err)
		}
	}

	log.Println("Initializing chat manager...")
	chatManager := chat.NewManager(db, torService, userIdentity)

	log.Println("Starting P2P server...")
	if err := chatManager.Start(); err != nil {
		log.Fatalf("Failed to start chat manager: %v", err)
	}
	defer chatManager.Stop()

	log.Println("Application ready!")
	log.Println("Starting GUI...")

	publicKeyEncoded := crypto.EncodePublicKey(userIdentity.PublicKey)
	app := ui.NewApp(chatManager, onionAddress, publicKeyEncoded, userIdentity.Fingerprint)
	app.Run()

	log.Println("Application shutting down...")
}

func getDataDir() (string, error) {

	if dataDir := os.Getenv("BLACKOUT_DATA_DIR"); dataDir != "" {
		return dataDir, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	var dataDir string
	switch {
	case os.Getenv("APPDATA") != "": // Windows
		dataDir = filepath.Join(os.Getenv("APPDATA"), "BlackOut")
	default: // Linux, macOS
		dataDir = filepath.Join(homeDir, ".blackout")
	}

	return dataDir, nil
}
