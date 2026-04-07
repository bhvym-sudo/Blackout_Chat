package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	conn *sql.DB
}

type Contact struct {
	ID           int64
	Name         string
	OnionAddress string
	PublicKey    string
	Fingerprint  string
	AddedAt      time.Time
	LastSeen     *time.Time
	Verified     bool
}

type Message struct {
	ID           int64
	ContactID    int64
	Content      string
	Timestamp    time.Time
	IsOutgoing   bool
	IsDelivered  bool
	IsRead       bool
	EncryptedKey string // For future re-keying
}

func New(dataDir string) (*DB, error) {
	dbPath := filepath.Join(dataDir, "chat.db")

	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{conn: conn}

	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

func (db *DB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS contacts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		onion_address TEXT UNIQUE NOT NULL,
		public_key TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		added_at DATETIME NOT NULL,
		last_seen DATETIME,
		verified BOOLEAN DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		contact_id INTEGER NOT NULL,
		content TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		is_outgoing BOOLEAN NOT NULL,
		is_delivered BOOLEAN DEFAULT 0,
		is_read BOOLEAN DEFAULT 0,
		encrypted_key TEXT,
		FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_messages_contact_id ON messages(contact_id);
	CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
	CREATE INDEX IF NOT EXISTS idx_contacts_onion_address ON contacts(onion_address);
	`

	_, err := db.conn.Exec(schema)
	if err != nil {
		return err
	}

	// Seed sample data if database is empty
	if err := db.seedSampleData(); err != nil {
		return err
	}

	return nil
}

func (db *DB) Close() error {
	if db.conn != nil {
		return db.conn.Close()
	}
	return nil
}

func (db *DB) AddContact(contact *Contact) error {
	result, err := db.conn.Exec(`
		INSERT INTO contacts (name, onion_address, public_key, fingerprint, added_at, verified)
		VALUES (?, ?, ?, ?, ?, ?)
	`, contact.Name, contact.OnionAddress, contact.PublicKey, contact.Fingerprint, contact.AddedAt, contact.Verified)

	if err != nil {
		return fmt.Errorf("failed to add contact: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get contact ID: %w", err)
	}

	contact.ID = id
	return nil
}

func (db *DB) GetContact(id int64) (*Contact, error) {
	contact := &Contact{}
	var lastSeen sql.NullTime

	err := db.conn.QueryRow(`
		SELECT id, name, onion_address, public_key, fingerprint, added_at, last_seen, verified
		FROM contacts WHERE id = ?
	`, id).Scan(&contact.ID, &contact.Name, &contact.OnionAddress, &contact.PublicKey,
		&contact.Fingerprint, &contact.AddedAt, &lastSeen, &contact.Verified)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("contact not found")
		}
		return nil, err
	}

	if lastSeen.Valid {
		contact.LastSeen = &lastSeen.Time
	}

	return contact, nil
}

func (db *DB) GetContactByOnionAddress(address string) (*Contact, error) {
	contact := &Contact{}
	var lastSeen sql.NullTime

	err := db.conn.QueryRow(`
		SELECT id, name, onion_address, public_key, fingerprint, added_at, last_seen, verified
		FROM contacts WHERE onion_address = ?
	`, address).Scan(&contact.ID, &contact.Name, &contact.OnionAddress, &contact.PublicKey,
		&contact.Fingerprint, &contact.AddedAt, &lastSeen, &contact.Verified)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("contact not found")
		}
		return nil, err
	}

	if lastSeen.Valid {
		contact.LastSeen = &lastSeen.Time
	}

	return contact, nil
}

func (db *DB) GetAllContacts() ([]*Contact, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, onion_address, public_key, fingerprint, added_at, last_seen, verified
		FROM contacts ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		contact := &Contact{}
		var lastSeen sql.NullTime

		err := rows.Scan(&contact.ID, &contact.Name, &contact.OnionAddress, &contact.PublicKey,
			&contact.Fingerprint, &contact.AddedAt, &lastSeen, &contact.Verified)
		if err != nil {
			return nil, err
		}

		if lastSeen.Valid {
			contact.LastSeen = &lastSeen.Time
		}

		contacts = append(contacts, contact)
	}

	return contacts, rows.Err()
}

func (db *DB) UpdateContact(contact *Contact) error {
	_, err := db.conn.Exec(`
		UPDATE contacts
		SET name = ?, onion_address = ?, public_key = ?, fingerprint = ?, verified = ?
		WHERE id = ?
	`, contact.Name, contact.OnionAddress, contact.PublicKey, contact.Fingerprint, contact.Verified, contact.ID)

	return err
}

func (db *DB) UpdateContactLastSeen(contactID int64, lastSeen time.Time) error {
	_, err := db.conn.Exec(`
		UPDATE contacts SET last_seen = ? WHERE id = ?
	`, lastSeen, contactID)
	return err
}

func (db *DB) DeleteContact(id int64) error {
	_, err := db.conn.Exec("DELETE FROM contacts WHERE id = ?", id)
	return err
}

func (db *DB) AddMessage(message *Message) error {
	result, err := db.conn.Exec(`
		INSERT INTO messages (contact_id, content, timestamp, is_outgoing, is_delivered, is_read)
		VALUES (?, ?, ?, ?, ?, ?)
	`, message.ContactID, message.Content, message.Timestamp, message.IsOutgoing, message.IsDelivered, message.IsRead)

	if err != nil {
		return fmt.Errorf("failed to add message: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get message ID: %w", err)
	}

	message.ID = id
	return nil
}

func (db *DB) GetMessages(contactID int64, limit, offset int) ([]*Message, error) {
	rows, err := db.conn.Query(`
		SELECT id, contact_id, content, timestamp, is_outgoing, is_delivered, is_read, encrypted_key
		FROM messages
		WHERE contact_id = ?
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?
	`, contactID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		message := &Message{}
		var encryptedKey sql.NullString

		err := rows.Scan(&message.ID, &message.ContactID, &message.Content, &message.Timestamp,
			&message.IsOutgoing, &message.IsDelivered, &message.IsRead, &encryptedKey)
		if err != nil {
			return nil, err
		}

		if encryptedKey.Valid {
			message.EncryptedKey = encryptedKey.String
		}

		messages = append(messages, message)
	}

	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, rows.Err()
}

func (db *DB) GetRecentMessages(limit int) ([]*Message, error) {
	rows, err := db.conn.Query(`
		SELECT id, contact_id, content, timestamp, is_outgoing, is_delivered, is_read, encrypted_key
		FROM messages
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		message := &Message{}
		var encryptedKey sql.NullString

		err := rows.Scan(&message.ID, &message.ContactID, &message.Content, &message.Timestamp,
			&message.IsOutgoing, &message.IsDelivered, &message.IsRead, &encryptedKey)
		if err != nil {
			return nil, err
		}

		if encryptedKey.Valid {
			message.EncryptedKey = encryptedKey.String
		}

		messages = append(messages, message)
	}

	return messages, rows.Err()
}

func (db *DB) MarkMessageDelivered(id int64) error {
	_, err := db.conn.Exec("UPDATE messages SET is_delivered = 1 WHERE id = ?", id)
	return err
}

func (db *DB) MarkMessageRead(id int64) error {
	_, err := db.conn.Exec("UPDATE messages SET is_read = 1 WHERE id = ?", id)
	return err
}

func (db *DB) MarkAllMessagesRead(contactID int64) error {
	_, err := db.conn.Exec(`
		UPDATE messages SET is_read = 1 
		WHERE contact_id = ? AND is_outgoing = 0 AND is_read = 0
	`, contactID)
	return err
}

func (db *DB) GetUnreadMessageCount(contactID int64) (int, error) {
	var count int
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM messages 
		WHERE contact_id = ? AND is_outgoing = 0 AND is_read = 0
	`, contactID).Scan(&count)
	return count, err
}

func (db *DB) DeleteMessage(id int64) error {
	_, err := db.conn.Exec("DELETE FROM messages WHERE id = ?", id)
	return err
}

func (db *DB) DeleteAllMessages(contactID int64) error {
	_, err := db.conn.Exec("DELETE FROM messages WHERE contact_id = ?", contactID)
	return err
}

func (db *DB) seedSampleData() error {
	// Check if contacts already exist to avoid duplicating data
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM contacts").Scan(&count)
	if err != nil {
		return err
	}

	// If contacts already exist, don't seed
	if count > 0 {
		return nil
	}

	// Sample contacts with predefined data
	sampleContacts := []struct {
		name         string
		onionAddress string
		publicKey    string
		fingerprint  string
	}{
		{
			name:         "Alex Security",
			onionAddress: "a1b2c3d4e5f6g7h8.onion",
			publicKey:    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkWqfVxQnq4Hy8N9z3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3CM=",
			fingerprint:  "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ",
		},
		{
			name:         "Jordan Privacy",
			onionAddress: "i9j8k7l6m5n4o3p2.onion",
			publicKey:    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALk234GkWqfVxQnq4Hy8N9z3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3YCN=",
			fingerprint:  "KKKK LLLL MMMM NNNN OOOO PPPP QQQQ RRRR SSSS TTTT",
		},
		{
			name:         "Casey Encrypted",
			onionAddress: "q1r2s3t4u5v6w7x8.onion",
			publicKey:    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMl934GkWqfVxQnq4Hy8N9z3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3Y3YCO=",
			fingerprint:  "UUUU VVVV WWWW XXXX YYYY ZZZZ AAAA BBBB CCCC DDDD",
		},
	}

	// Insert sample contacts and their messages
	now := time.Now()
	for _, contact := range sampleContacts {
		c := &Contact{
			Name:         contact.name,
			OnionAddress: contact.onionAddress,
			PublicKey:    contact.publicKey,
			Fingerprint:  contact.fingerprint,
			AddedAt:      now.AddDate(0, -1, 0), // 1 month ago
			Verified:     true,
		}

		if err := db.AddContact(c); err != nil {
			continue // Skip if contact already exists
		}

		// Add sample messages
		messages := db.getSampleMessages(c.ID, contact.name, now)
		for _, msg := range messages {
			if err := db.AddMessage(&msg); err != nil {
				continue
			}
		}
	}

	return nil
}

func (db *DB) getSampleMessages(contactID int64, contactName string, now time.Time) []Message {
	messages := []Message{}

	// Create sample conversation messages
	sampleConversations := map[string][]struct {
		content    string
		isOutgoing bool
		minutesAgo int
	}{
		"Alex Security": {
			{content: "Hey, how's the security setup going?", isOutgoing: false, minutesAgo: 120},
			{content: "Going great! Just finished the initial configuration.", isOutgoing: true, minutesAgo: 115},
			{content: "Cool! Don't forget to verify the fingerprints", isOutgoing: false, minutesAgo: 110},
			{content: "Already done. Everything looks good.", isOutgoing: true, minutesAgo: 105},
			{content: "Perfect! Let me know if you need anything", isOutgoing: false, minutesAgo: 100},
		},
		"Jordan Privacy": {
			{content: "Hi! Testing the connection here", isOutgoing: false, minutesAgo: 240},
			{content: "Connection works perfectly!", isOutgoing: true, minutesAgo: 235},
			{content: "Awesome! Encryption is end-to-end right?", isOutgoing: false, minutesAgo: 230},
			{content: "Yes, all messages are encrypted with your public key", isOutgoing: true, minutesAgo: 225},
			{content: "That's exactly what I needed. Thanks!", isOutgoing: false, minutesAgo: 220},
			{content: "Anytime! Stay safe out there", isOutgoing: true, minutesAgo: 215},
		},
		"Casey Encrypted": {
			{content: "Are you online?", isOutgoing: false, minutesAgo: 60},
			{content: "Yes, just came online", isOutgoing: true, minutesAgo: 55},
			{content: "Great! I wanted to discuss the new protocol update", isOutgoing: false, minutesAgo: 50},
			{content: "Sure, what's the update about?", isOutgoing: true, minutesAgo: 45},
			{content: "It includes better key rotation and improved message authentication", isOutgoing: false, minutesAgo: 40},
			{content: "Sounds good. When can I install it?", isOutgoing: true, minutesAgo: 35},
			{content: "It'll be available next week. I'll send you the details", isOutgoing: false, minutesAgo: 30},
		},
	}

	if convo, exists := sampleConversations[contactName]; exists {
		for _, msg := range convo {
			messages = append(messages, Message{
				ContactID:   contactID,
				Content:     msg.content,
				Timestamp:   now.Add(time.Duration(-msg.minutesAgo) * time.Minute),
				IsOutgoing:  msg.isOutgoing,
				IsDelivered: true,
				IsRead:      true,
			})
		}
	}

	return messages
}
