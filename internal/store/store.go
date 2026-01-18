package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type Attachment struct {
	ID         string            `json:"id"`
	Target     string            `json:"target"`
	Type       string            `json:"type"`
	Mode       string            `json:"mode"`
	DnsMode    string            `json:"dns_mode"`
	DnsAddress string            `json:"dns_address"`
	Metadata   map[string]string `json:"metadata"`
	AttachedAt time.Time         `json:"attached_at"`
}

func New(dbPath string) (*Store, error) {
	dsn := dbPath
	if dbPath != ":memory:" {
		dsn = dbPath + "?_journal_mode=WAL&_busy_timeout=5000"
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if dbPath != ":memory:" {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting WAL mode: %w", err)
		}
		if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting busy timeout: %w", err)
		}
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS attachments (
			id TEXT PRIMARY KEY,
			target TEXT NOT NULL,
			type TEXT NOT NULL,
			mode TEXT NOT NULL,
			dns_mode TEXT NOT NULL,
			dns_address TEXT NOT NULL,
			metadata TEXT NOT NULL,
			attached_at TEXT NOT NULL
		) STRICT, WITHOUT ROWID
	`)
	return err
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveAttachment(a *Attachment) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ID, a.Target, a.Type, a.Mode, a.DnsMode, a.DnsAddress, string(metadata), a.AttachedAt.Format(time.RFC3339Nano))
	return err
}

func (s *Store) DeleteAttachment(id string) error {
	_, err := s.db.Exec("DELETE FROM attachments WHERE id = ?", id)
	return err
}

func (s *Store) GetAttachment(id string) (*Attachment, error) {
	row := s.db.QueryRow(`
		SELECT id, target, type, mode, dns_mode, dns_address, metadata, attached_at
		FROM attachments WHERE id = ?
	`, id)

	return scanAttachment(row)
}

func (s *Store) ListAttachments(pageSize int, pageToken string) ([]Attachment, string, int, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	var totalCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM attachments").Scan(&totalCount); err != nil {
		return nil, "", 0, fmt.Errorf("counting attachments: %w", err)
	}

	query := `
		SELECT id, target, type, mode, dns_mode, dns_address, metadata, attached_at
		FROM attachments
		WHERE (attached_at, id) > (?, ?)
		ORDER BY attached_at, id
		LIMIT ?
	`

	var afterTime, afterID string
	if pageToken != "" {
		parts := strings.SplitN(pageToken, "|", 2)
		if len(parts) == 2 {
			afterTime = parts[0]
			afterID = parts[1]
		}
	}
	if afterTime == "" {
		afterTime = "0001-01-01T00:00:00Z"
	}

	rows, err := s.db.Query(query, afterTime, afterID, pageSize+1)
	if err != nil {
		return nil, "", 0, fmt.Errorf("querying attachments: %w", err)
	}
	defer rows.Close()

	var attachments []Attachment
	for rows.Next() {
		a, err := scanAttachmentRows(rows)
		if err != nil {
			return nil, "", 0, err
		}
		attachments = append(attachments, *a)
	}

	var nextPageToken string
	if len(attachments) > pageSize {
		last := attachments[pageSize-1]
		nextPageToken = last.AttachedAt.Format(time.RFC3339Nano) + "|" + last.ID
		attachments = attachments[:pageSize]
	}

	return attachments, nextPageToken, totalCount, nil
}

func (s *Store) GetAllAttachments() ([]Attachment, error) {
	rows, err := s.db.Query(`
		SELECT id, target, type, mode, dns_mode, dns_address, metadata, attached_at
		FROM attachments ORDER BY attached_at, id
	`)
	if err != nil {
		return nil, fmt.Errorf("querying attachments: %w", err)
	}
	defer rows.Close()

	var attachments []Attachment
	for rows.Next() {
		a, err := scanAttachmentRows(rows)
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, *a)
	}
	return attachments, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAttachment(row *sql.Row) (*Attachment, error) {
	var a Attachment
	var metadata, attachedAt string
	err := row.Scan(&a.ID, &a.Target, &a.Type, &a.Mode, &a.DnsMode, &a.DnsAddress, &metadata, &attachedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scanning attachment: %w", err)
	}

	if err := json.Unmarshal([]byte(metadata), &a.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	if a.AttachedAt, err = time.Parse(time.RFC3339Nano, attachedAt); err != nil {
		return nil, fmt.Errorf("parsing attached_at: %w", err)
	}
	return &a, nil
}

func scanAttachmentRows(rows *sql.Rows) (*Attachment, error) {
	var a Attachment
	var metadata, attachedAt string
	err := rows.Scan(&a.ID, &a.Target, &a.Type, &a.Mode, &a.DnsMode, &a.DnsAddress, &metadata, &attachedAt)
	if err != nil {
		return nil, fmt.Errorf("scanning attachment: %w", err)
	}

	if err := json.Unmarshal([]byte(metadata), &a.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	if a.AttachedAt, err = time.Parse(time.RFC3339Nano, attachedAt); err != nil {
		return nil, fmt.Errorf("parsing attached_at: %w", err)
	}
	return &a, nil
}
