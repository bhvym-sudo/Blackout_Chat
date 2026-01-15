package tor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cretz/bine/tor"
)

type Service struct {
	tor          *tor.Tor
	onion        *tor.OnionService
	ctx          context.Context
	cancel       context.CancelFunc
	dataDir      string
	servicePort  int
	onionAddress string
	dialer       *tor.Dialer
}

type Config struct {
	DataDir     string
	ServicePort int
	Debug       bool
}

func NewService(config Config) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		ctx:         ctx,
		cancel:      cancel,
		dataDir:     config.DataDir,
		servicePort: config.ServicePort,
	}
}

func (s *Service) Start(progressCallback func(int)) error {
	torDir := filepath.Join(s.dataDir, "tor")
	if err := os.MkdirAll(torDir, 0700); err != nil {
		return fmt.Errorf("failed to create tor directory: %w", err)
	}

	log.Println("Starting Tor...")

	torExePath := ""

	localTor := filepath.Join("tor", "tor", "tor.exe")
	if _, err := os.Stat(localTor); err == nil {
		torExePath, _ = filepath.Abs(localTor)
		log.Printf("Using local Tor executable: %s", torExePath)
	} else {

		localTor = filepath.Join("tor", "tor.exe")
		if _, err := os.Stat(localTor); err == nil {
			torExePath, _ = filepath.Abs(localTor)
			log.Printf("Using local Tor executable: %s", torExePath)
		}
	}

	startConf := &tor.StartConf{
		DataDir:         torDir,
		NoAutoSocksPort: false,
		TempDataDirBase: torDir,
	}

	if torExePath != "" {
		startConf.ExePath = torExePath
	}

	t, err := tor.Start(s.ctx, startConf)
	if err != nil {
		return fmt.Errorf("failed to start tor: %w\n\nTor executable not found. Please:\n1. Download Tor Browser from https://www.torproject.org/download/\n2. Copy tor.exe to tor/ directory, OR\n3. Install Tor and add to PATH", err)
	}
	s.tor = t

	log.Println("Tor started. Waiting for bootstrap...")

	if err := s.waitForBootstrap(progressCallback); err != nil {
		s.Stop()
		return fmt.Errorf("tor bootstrap failed: %w", err)
	}

	log.Println("Tor bootstrapped successfully")

	dialer, err := t.Dialer(s.ctx, nil)
	if err != nil {
		s.Stop()
		return fmt.Errorf("failed to create tor dialer: %w", err)
	}
	s.dialer = dialer

	onionDir := filepath.Join(torDir, "hidden_service")
	if err := os.MkdirAll(onionDir, 0700); err != nil {
		s.Stop()
		return fmt.Errorf("failed to create hidden service directory: %w", err)
	}

	log.Println("Creating hidden service...")

	onion, err := t.Listen(s.ctx, &tor.ListenConf{
		RemotePorts: []int{80},
		LocalPort:   s.servicePort,
		Version3:    true,
	})
	if err != nil {
		s.Stop()
		return fmt.Errorf("failed to create onion service: %w", err)
	}
	s.onion = onion
	s.onionAddress = onion.ID + ".onion"

	log.Printf("Onion service created: %s", s.onionAddress)

	return nil
}

func (s *Service) waitForBootstrap(progressCallback func(int)) error {

	timeout := time.After(120 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	lastProgress := 0
	for {
		select {
		case <-timeout:
			return fmt.Errorf("bootstrap timeout after 120 seconds")
		case <-ticker.C:

			if s.tor != nil {

				testDialer, err := s.tor.Dialer(s.ctx, nil)
				if err == nil && testDialer != nil {
					if progressCallback != nil {
						progressCallback(100)
					}
					return nil
				}
			}

			if lastProgress < 90 {
				lastProgress += 10
				if progressCallback != nil {
					progressCallback(lastProgress)
				}
			}
		}
	}
}

func (s *Service) Stop() error {
	log.Println("Stopping Tor service...")

	if s.onion != nil {
		s.onion.Close()
	}

	if s.tor != nil {
		s.tor.Close()
	}

	s.cancel()

	log.Println("Tor service stopped")
	return nil
}

func (s *Service) GetOnionAddress() string {
	return s.onionAddress
}

func (s *Service) Listen() net.Listener {
	return s.onion
}

func (s *Service) Dial(address string) (net.Conn, error) {
	if s.dialer == nil {
		return nil, fmt.Errorf("tor dialer not initialized")
	}

	log.Printf("Dialing %s through Tor...", address)

	conn, err := s.dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial through tor: %w", err)
	}

	log.Printf("Successfully connected to %s", address)
	return conn, nil
}

func (s *Service) IsReady() bool {
	return s.tor != nil && s.onion != nil && s.dialer != nil
}

func (s *Service) GetDialer() *tor.Dialer {
	return s.dialer
}
