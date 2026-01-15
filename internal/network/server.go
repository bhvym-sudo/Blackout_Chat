package network

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/blackout/secure-messenger/internal/crypto"
	"github.com/blackout/secure-messenger/internal/identity"
	"github.com/blackout/secure-messenger/internal/tor"
)

type MessageHandler interface {
	OnChatMessage(from string, message *ChatMessage) error
	OnPeerConnected(onionAddr string) error
	OnPeerDisconnected(onionAddr string) error
}

type Server struct {
	torService  *tor.Service
	identity    *identity.Identity
	peerManager *PeerManager
	handler     MessageHandler
	listener    net.Listener
	running     bool
	mu          sync.Mutex
	wg          sync.WaitGroup
}

func NewServer(torService *tor.Service, identity *identity.Identity, handler MessageHandler) *Server {
	return &Server{
		torService: torService,
		identity:   identity,
		handler:    handler,
		peerManager: NewPeerManager(
			identity.OnionAddress,
			identity.PrivateKey,
		),
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.mu.Unlock()

	s.listener = s.torService.Listen()
	if s.listener == nil {
		return fmt.Errorf("tor listener not available")
	}

	log.Println("P2P server started, accepting connections...")

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	log.Println("Stopping P2P server...")

	if s.listener != nil {
		s.listener.Close()
	}

	s.peerManager.Close()

	s.wg.Wait()

	log.Println("P2P server stopped")
	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		log.Println("Incoming connection accepted")

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	peer, err := s.performHandshake(conn, false)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}

	log.Printf("Handshake completed with %s", peer.OnionAddress)

	if s.handler != nil {
		if err := s.handler.OnPeerConnected(peer.OnionAddress); err != nil {
			log.Printf("OnPeerConnected error: %v", err)
		}
	}

	s.handlePeerMessages(peer)

	s.peerManager.RemovePeer(peer.OnionAddress)

	if s.handler != nil {
		s.handler.OnPeerDisconnected(peer.OnionAddress)
	}
}

func (s *Server) ConnectToPeer(onionAddr string, publicKey [32]byte) error {
	log.Printf("Connecting to peer: %s", onionAddr)

	conn, err := s.torService.Dial(onionAddr + ":80")
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	peer, err := s.performHandshake(conn, true)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	if peer.PublicKey != publicKey {
		conn.Close()
		s.peerManager.RemovePeer(peer.OnionAddress)
		return fmt.Errorf("public key mismatch - possible MITM attack")
	}

	log.Printf("Successfully connected to %s", onionAddr)

	if s.handler != nil {
		if err := s.handler.OnPeerConnected(peer.OnionAddress); err != nil {
			log.Printf("OnPeerConnected error: %v", err)
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer conn.Close()

		s.handlePeerMessages(peer)

		s.peerManager.RemovePeer(peer.OnionAddress)
		if s.handler != nil {
			s.handler.OnPeerDisconnected(peer.OnionAddress)
		}
	}()

	return nil
}

func (s *Server) performHandshake(conn net.Conn, isInitiator bool) (*Peer, error) {
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if isInitiator {

		handshake := &ProtocolMessage{
			Type:      MessageTypeHandshake,
			From:      s.identity.OnionAddress,
			PublicKey: crypto.EncodePublicKey(s.identity.PublicKey),
			Timestamp: time.Now().Unix(),
		}

		data, _ := json.Marshal(handshake)
		writer.Write(append(data, '\n'))
		writer.Flush()

		respData, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read handshake ack: %w", err)
		}

		var ack ProtocolMessage
		if err := json.Unmarshal(respData, &ack); err != nil {
			return nil, fmt.Errorf("failed to parse handshake ack: %w", err)
		}

		if ack.Type != MessageTypeHandshakeAck {
			return nil, fmt.Errorf("unexpected message type: %s", ack.Type)
		}

		peerPublicKey, err := crypto.DecodePublicKey(ack.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode peer public key: %w", err)
		}

		peer, err := s.peerManager.AddPeer(ack.From, conn, peerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to add peer: %w", err)
		}

		return peer, nil

	} else {

		data, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read handshake: %w", err)
		}

		var handshake ProtocolMessage
		if err := json.Unmarshal(data, &handshake); err != nil {
			return nil, fmt.Errorf("failed to parse handshake: %w", err)
		}

		if handshake.Type != MessageTypeHandshake {
			return nil, fmt.Errorf("unexpected message type: %s", handshake.Type)
		}

		peerPublicKey, err := crypto.DecodePublicKey(handshake.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode peer public key: %w", err)
		}

		ack := &ProtocolMessage{
			Type:      MessageTypeHandshakeAck,
			From:      s.identity.OnionAddress,
			PublicKey: crypto.EncodePublicKey(s.identity.PublicKey),
			Timestamp: time.Now().Unix(),
		}

		ackData, _ := json.Marshal(ack)
		writer.Write(append(ackData, '\n'))
		writer.Flush()

		peer, err := s.peerManager.AddPeer(handshake.From, conn, peerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to add peer: %w", err)
		}

		return peer, nil
	}
}

func (s *Server) handlePeerMessages(peer *Peer) {
	for s.running {
		msg, err := peer.ReceiveMessage()
		if err != nil {
			log.Printf("Error receiving message from %s: %v", peer.OnionAddress, err)
			break
		}

		if err := s.handleMessage(peer, msg); err != nil {
			log.Printf("Error handling message: %v", err)
		}
	}
}

func (s *Server) handleMessage(peer *Peer, msg *ProtocolMessage) error {
	switch msg.Type {
	case MessageTypeChat:
		chatMsg, err := peer.DecryptChatMessage(msg)
		if err != nil {
			return fmt.Errorf("failed to decrypt chat message: %w", err)
		}

		ack := &ProtocolMessage{
			Type:      MessageTypeDeliveryAck,
			MessageID: msg.MessageID,
			Timestamp: time.Now().Unix(),
		}
		peer.SendMessage(ack)

		if s.handler != nil {
			return s.handler.OnChatMessage(peer.OnionAddress, chatMsg)
		}

	case MessageTypeDeliveryAck:
		log.Printf("Message %s delivered", msg.MessageID)

	case MessageTypePing:

		pong := &ProtocolMessage{
			Type:      MessageTypePong,
			Timestamp: time.Now().Unix(),
		}
		return peer.SendMessage(pong)

	case MessageTypePong:

		log.Printf("Pong received from %s", peer.OnionAddress)

	case MessageTypeTyping:

		log.Printf("Peer %s is typing...", peer.OnionAddress)
	}

	return nil
}

func (s *Server) SendChatMessage(onionAddr, content, messageID string) error {
	peer, ok := s.peerManager.GetPeer(onionAddr)
	if !ok {
		return fmt.Errorf("peer not connected: %s", onionAddr)
	}

	protocolMsg, err := peer.EncryptChatMessage(content, messageID)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	protocolMsg.From = s.identity.OnionAddress
	protocolMsg.To = onionAddr

	return peer.SendMessage(protocolMsg)
}

func (s *Server) IsPeerConnected(onionAddr string) bool {
	_, ok := s.peerManager.GetPeer(onionAddr)
	return ok
}

func (s *Server) GetConnectedPeers() []string {
	peers := s.peerManager.GetAllPeers()
	addresses := make([]string, len(peers))
	for i, peer := range peers {
		addresses[i] = peer.OnionAddress
	}
	return addresses
}
