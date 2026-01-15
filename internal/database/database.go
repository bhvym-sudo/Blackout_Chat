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
	return err
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
