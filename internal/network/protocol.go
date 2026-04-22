package network

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/blackout/secure-messenger/internal/crypto"
)

type MessageType string

const (
	MessageTypeHandshake    MessageType = "handshake"
	MessageTypeHandshakeAck MessageType = "handshake_ack"
	MessageTypeChat         MessageType = "chat"
	MessageTypeDeliveryAck  MessageType = "delivery_ack"
	MessageTypeTyping       MessageType = "typing"
	MessageTypePing         MessageType = "ping"
	MessageTypePong         MessageType = "pong"
)

type ProtocolMessage struct {
	Type             MessageType `json:"type"`
	From             string      `json:"from"`
	To               string      `json:"to"`
	Timestamp        int64       `json:"timestamp"`
	PublicKey        string      `json:"public_key,omitempty"`
	EncryptedPayload string      `json:"encrypted_payload,omitempty"`
	Nonce            string      `json:"nonce,omitempty"`
	MessageID        string      `json:"message_id,omitempty"`
}

type ChatMessage struct {
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	MessageID string `json:"message_id"`
}

type Peer struct {
	Conn         net.Conn
	OnionAddress string
	PublicKey    [32]byte
	SharedSecret [32]byte
	LastSeen     time.Time
	Writer       *bufio.Writer
	mu           sync.Mutex
}

type PeerManager struct {
	peers     map[string]*Peer
	mu        sync.RWMutex
	localAddr string
	localKey  [32]byte
}

func NewPeerManager(localAddr string, localPrivateKey [32]byte) *PeerManager {
	return &PeerManager{
		peers:     make(map[string]*Peer),
		localAddr: localAddr,
		localKey:  localPrivateKey,
	}
}

func (pm *PeerManager) AddPeer(onionAddr string, conn net.Conn, publicKey [32]byte) (*Peer, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if existing, ok := pm.peers[onionAddr]; ok {
		existing.Conn.Close()
	}

	sharedSecret, err := crypto.ComputeSharedSecret(pm.localKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	peer := &Peer{
		Conn:         conn,
		OnionAddress: onionAddr,
		PublicKey:    publicKey,
		SharedSecret: sharedSecret,
		LastSeen:     time.Now(),
		Writer:       bufio.NewWriter(conn),
	}

	pm.peers[onionAddr] = peer
	log.Printf("Added peer: %s", onionAddr)

	return peer, nil
}

func (pm *PeerManager) GetPeer(onionAddr string) (*Peer, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	peer, ok := pm.peers[onionAddr]
	return peer, ok
}

func (pm *PeerManager) RemovePeer(onionAddr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if peer, ok := pm.peers[onionAddr]; ok {
		peer.Conn.Close()
		delete(pm.peers, onionAddr)
		log.Printf("Removed peer: %s", onionAddr)
	}
}

func (pm *PeerManager) GetAllPeers() []*Peer {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	peers := make([]*Peer, 0, len(pm.peers))
	for _, peer := range pm.peers {
		peers = append(peers, peer)
	}
	return peers
}

func (pm *PeerManager) Close() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, peer := range pm.peers {
		peer.Conn.Close()
	}
	pm.peers = make(map[string]*Peer)
}

func (p *Peer) SendMessage(msg *ProtocolMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	_, err = p.Writer.Write(append(data, '\n'))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := p.Writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush message: %w", err)
	}

	p.LastSeen = time.Now()
	return nil
}

func (p *Peer) ReceiveMessage() (*ProtocolMessage, error) {
	reader := bufio.NewReader(p.Conn)

	p.Conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

	data, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	var msg ProtocolMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	p.LastSeen = time.Now()
	return &msg, nil
}

func (p *Peer) EncryptChatMessage(content, messageID string) (*ProtocolMessage, error) {
	chatMsg := ChatMessage{
		Content:   content,
		Timestamp: time.Now().Unix(),
		MessageID: messageID,
	}

	plaintext, err := json.Marshal(chatMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chat message: %w", err)
	}

	ciphertext, nonce, err := crypto.EncryptMessage(plaintext, p.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	return &ProtocolMessage{
		Type:             MessageTypeChat,
		Timestamp:        time.Now().Unix(),
		EncryptedPayload: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		MessageID:        messageID,
	}, nil
}

func (p *Peer) DecryptChatMessage(msg *ProtocolMessage) (*ChatMessage, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(msg.EncryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted payload: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(msg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	plaintext, err := crypto.DecryptMessage(ciphertext, nonce, p.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	var chatMsg ChatMessage
	if err := json.Unmarshal(plaintext, &chatMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chat message: %w", err)
	}

	return &chatMsg, nil
}

func (p *Peer) IsAlive() bool {

	ping := &ProtocolMessage{
		Type:      MessageTypePing,
		Timestamp: time.Now().Unix(),
	}

	if err := p.SendMessage(ping); err != nil {
		return false
	}

	p.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer p.Conn.SetReadDeadline(time.Time{})

	msg, err := p.ReceiveMessage()
	if err != nil {
		return false
	}

	return msg.Type == MessageTypePong
}
