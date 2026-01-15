package chat

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/blackout/secure-messenger/internal/crypto"
	"github.com/blackout/secure-messenger/internal/database"
	"github.com/blackout/secure-messenger/internal/identity"
	"github.com/blackout/secure-messenger/internal/network"
	"github.com/blackout/secure-messenger/internal/tor"
)

type Manager struct {
	db         *database.DB
	torService *tor.Service
	identity   *identity.Identity
	server     *network.Server
	listeners  []EventListener
	mu         sync.RWMutex
}

type EventListener interface {
	OnMessageReceived(contactID int64, message *database.Message)
	OnMessageSent(contactID int64, message *database.Message)
	OnContactOnline(contactID int64)
	OnContactOffline(contactID int64)
	OnError(err error)
}

func NewManager(db *database.DB, torService *tor.Service, identity *identity.Identity) *Manager {
	manager := &Manager{
		db:         db,
		torService: torService,
		identity:   identity,
		listeners:  make([]EventListener, 0),
	}

	manager.server = network.NewServer(torService, identity, manager)

	return manager
}

func (m *Manager) Start() error {
	return m.server.Start()
}

func (m *Manager) Stop() error {
	return m.server.Stop()
}

func (m *Manager) AddListener(listener EventListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

func (m *Manager) notifyMessageReceived(contactID int64, message *database.Message) {
	m.mu.RLock()
	listeners := m.listeners
	m.mu.RUnlock()

	for _, listener := range listeners {
		go listener.OnMessageReceived(contactID, message)
	}
}

func (m *Manager) notifyMessageSent(contactID int64, message *database.Message) {
	m.mu.RLock()
	listeners := m.listeners
	m.mu.RUnlock()

	for _, listener := range listeners {
		go listener.OnMessageSent(contactID, message)
	}
}

func (m *Manager) notifyContactOnline(contactID int64) {
	m.mu.RLock()
	listeners := m.listeners
	m.mu.RUnlock()

	for _, listener := range listeners {
		go listener.OnContactOnline(contactID)
	}
}

func (m *Manager) notifyContactOffline(contactID int64) {
	m.mu.RLock()
	listeners := m.listeners
	m.mu.RUnlock()

	for _, listener := range listeners {
		go listener.OnContactOffline(contactID)
	}
}

func (m *Manager) notifyError(err error) {
	m.mu.RLock()
	listeners := m.listeners
	m.mu.RUnlock()

	for _, listener := range listeners {
		go listener.OnError(err)
	}
}

func (m *Manager) AddContact(name, onionAddress, publicKeyStr string) error {

	publicKey, err := crypto.DecodePublicKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	fingerprint := crypto.GenerateFingerprint(publicKey)

	contact := &database.Contact{
		Name:         name,
		OnionAddress: onionAddress,
		PublicKey:    publicKeyStr,
		Fingerprint:  fingerprint,
		AddedAt:      time.Now(),
		Verified:     false,
	}

	if err := m.db.AddContact(contact); err != nil {
		return fmt.Errorf("failed to add contact: %w", err)
	}

	log.Printf("Added contact: %s (%s)", name, onionAddress)
	return nil
}

func (m *Manager) GetContact(id int64) (*database.Contact, error) {
	return m.db.GetContact(id)
}

func (m *Manager) GetAllContacts() ([]*database.Contact, error) {
	return m.db.GetAllContacts()
}

func (m *Manager) UpdateContact(contact *database.Contact) error {
	return m.db.UpdateContact(contact)
}

func (m *Manager) DeleteContact(id int64) error {

	contact, err := m.db.GetContact(id)
	if err == nil && m.server.IsPeerConnected(contact.OnionAddress) {

		m.server.ConnectToPeer(contact.OnionAddress, [32]byte{}) // This will fail and disconnect
	}

	return m.db.DeleteContact(id)
}

func (m *Manager) ConnectToContact(contactID int64) error {
	contact, err := m.db.GetContact(contactID)
	if err != nil {
		return fmt.Errorf("contact not found: %w", err)
	}

	publicKey, err := crypto.DecodePublicKey(contact.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid contact public key: %w", err)
	}

	return m.server.ConnectToPeer(contact.OnionAddress, publicKey)
}

func (m *Manager) SendMessage(contactID int64, content string) error {
	contact, err := m.db.GetContact(contactID)
	if err != nil {
		return fmt.Errorf("contact not found: %w", err)
	}

	if !m.server.IsPeerConnected(contact.OnionAddress) {

		if err := m.ConnectToContact(contactID); err != nil {
			return fmt.Errorf("peer not connected and connection failed: %w", err)
		}

		time.Sleep(2 * time.Second)

		if !m.server.IsPeerConnected(contact.OnionAddress) {
			return fmt.Errorf("peer not connected")
		}
	}

	messageID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), contactID)

	if err := m.server.SendChatMessage(contact.OnionAddress, content, messageID); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	message := &database.Message{
		ContactID:   contactID,
		Content:     content,
		Timestamp:   time.Now(),
		IsOutgoing:  true,
		IsDelivered: false,
		IsRead:      true, // Our own messages are always "read"
	}

	if err := m.db.AddMessage(message); err != nil {
		log.Printf("Failed to store sent message: %v", err)
	}

	m.notifyMessageSent(contactID, message)

	return nil
}

func (m *Manager) GetMessages(contactID int64, limit, offset int) ([]*database.Message, error) {
	return m.db.GetMessages(contactID, limit, offset)
}

func (m *Manager) MarkMessagesRead(contactID int64) error {
	return m.db.MarkAllMessagesRead(contactID)
}

func (m *Manager) GetUnreadCount(contactID int64) (int, error) {
	return m.db.GetUnreadMessageCount(contactID)
}

func (m *Manager) IsContactOnline(contactID int64) bool {
	contact, err := m.db.GetContact(contactID)
	if err != nil {
		return false
	}
	return m.server.IsPeerConnected(contact.OnionAddress)
}

func (m *Manager) OnChatMessage(from string, netMsg *network.ChatMessage) error {
	log.Printf("Received message from %s: %s", from, netMsg.Content)

	contact, err := m.db.GetContactByOnionAddress(from)
	if err != nil {
		log.Printf("Received message from unknown contact: %s", from)
		return fmt.Errorf("unknown contact: %s", from)
	}

	m.db.UpdateContactLastSeen(contact.ID, time.Now())

	message := &database.Message{
		ContactID:   contact.ID,
		Content:     netMsg.Content,
		Timestamp:   time.Unix(netMsg.Timestamp, 0),
		IsOutgoing:  false,
		IsDelivered: true,
		IsRead:      false,
	}

	if err := m.db.AddMessage(message); err != nil {
		return fmt.Errorf("failed to store message: %w", err)
	}

	m.notifyMessageReceived(contact.ID, message)

	return nil
}

func (m *Manager) OnPeerConnected(onionAddr string) error {
	log.Printf("Peer connected: %s", onionAddr)

	contact, err := m.db.GetContactByOnionAddress(onionAddr)
	if err != nil {
		log.Printf("Connected peer is not in contacts: %s", onionAddr)
		return nil
	}

	m.db.UpdateContactLastSeen(contact.ID, time.Now())

	m.notifyContactOnline(contact.ID)

	return nil
}

func (m *Manager) OnPeerDisconnected(onionAddr string) error {
	log.Printf("Peer disconnected: %s", onionAddr)

	contact, err := m.db.GetContactByOnionAddress(onionAddr)
	if err != nil {
		return nil
	}

	m.db.UpdateContactLastSeen(contact.ID, time.Now())

	m.notifyContactOffline(contact.ID)

	return nil
}

func (m *Manager) VerifyContactFingerprint(contactID int64, expectedFingerprint string) (bool, error) {
	contact, err := m.db.GetContact(contactID)
	if err != nil {
		return false, err
	}

	publicKey, err := crypto.DecodePublicKey(contact.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	matches := identity.VerifyFingerprint(publicKey, expectedFingerprint)

	if matches {

		contact.Verified = true
		m.db.UpdateContact(contact)
	}

	return matches, nil
}
