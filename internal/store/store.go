package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// attachedAtLayout is the canonical stored form of attached_at: UTC with
// fixed-width zero-padded nanoseconds. Unlike time.RFC3339Nano (which trims
// trailing zeros, so "…:00Z" sorts lexically AFTER "…:00.5Z"), every value
// formatted with this layout is exactly 30 bytes and lexical order equals
// temporal order — which the keyset pagination in ListAttachments depends on.
// Values are stored at nanosecond precision in UTC; reads return UTC times.
const attachedAtLayout = "2006-01-02T15:04:05.000000000Z"

// attachedAtGlob matches canonical attachedAtLayout-shaped values. Used by the
// migration as a cheap prefilter for rows that still need rewriting; the
// authoritative check is the Go-side parse.
const attachedAtGlob = "????-??-??T??:??:??.?????????Z"

type Store struct {
	db *sql.DB
}

type Attachment struct {
	ID         string `json:"id"`
	Target     string `json:"target"`
	Type       string `json:"type"`
	Mode       string `json:"mode"`
	DnsMode    string `json:"dns_mode"`
	DnsAddress string `json:"dns_address"`
	// Direction is the TC attach direction (a TcDirection enum name) for TC
	// attachments. Empty for cgroup attachments and for rows written before
	// the column existed; readers treat empty as EGRESS.
	Direction string `json:"direction"`
	// CleanupNeeded is an internal durable tombstone. It marks an attachment
	// whose enforcing resources are being destroyed but whose pin removal or
	// row deletion has not yet been proven complete. The daemon must never
	// restore or subscribe such a row as a live policy attachment.
	CleanupNeeded bool `json:"cleanup_needed"`
	// PolicyDegradedReason is a daemon-defined protected-policy safety code.
	// The in-progress code is a transient crash journal cleared by its successful
	// operation; startup converts a surviving journal to interrupted after proving
	// BLOCK_ALL. Interrupted and stable failure codes require complete
	// authoritative recovery before packet policy can reactivate.
	PolicyDegradedReason string `json:"policy_degraded_reason"`
	// PinDir is the exact bpffs directory used by this attachment. Empty with
	// PinPathKnown=true explicitly means pinning was disabled; false denotes a
	// legacy row whose pin identity must be established before cleanup.
	PinDir       string            `json:"pin_dir"`
	PinPathKnown bool              `json:"pin_path_known"`
	Metadata     map[string]string `json:"metadata"`
	AttachedAt   time.Time         `json:"attached_at"`
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

	if dbPath == ":memory:" {
		// mattn/go-sqlite3 gives every pooled database/sql connection its OWN
		// independent in-memory database, so with the default unbounded pool a
		// concurrent query can land on a fresh connection whose database never
		// saw the migration ("no such table: attachments"). Capping the pool at
		// one connection means there is exactly one in-memory database, shared
		// by construction; it also serializes access, eliminating SQLITE_BUSY.
		// database/sql keeps the idle connection open indefinitely (no
		// ConnMaxLifetime/IdleTime is set), so the database survives idle
		// periods. The file-backed path below keeps the default pool.
		db.SetMaxOpenConns(1)
	} else {
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
	if _, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS attachments (
				id TEXT PRIMARY KEY,
				target TEXT NOT NULL,
			type TEXT NOT NULL,
			mode TEXT NOT NULL,
			dns_mode TEXT NOT NULL,
			dns_address TEXT NOT NULL,
			metadata TEXT NOT NULL,
				attached_at TEXT NOT NULL,
				direction TEXT NOT NULL DEFAULT '',
				cleanup_needed INTEGER NOT NULL DEFAULT 0,
				pin_dir TEXT NOT NULL DEFAULT '',
				pin_path_known INTEGER NOT NULL DEFAULT 0,
				policy_degraded_reason TEXT NOT NULL DEFAULT ''
			) STRICT, WITHOUT ROWID
		`); err != nil {
		return err
	}
	// Databases created before the direction column existed need it added.
	// SQLite has no ADD COLUMN IF NOT EXISTS, so tolerate the duplicate-column
	// error to keep the migration idempotent.
	if _, err := db.Exec(`
		ALTER TABLE attachments ADD COLUMN direction TEXT NOT NULL DEFAULT ''
	`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	// Cleanup tombstones were added after direction. Existing rows are live
	// attachments and therefore migrate to the safe false default.
	if _, err := db.Exec(`
		ALTER TABLE attachments ADD COLUMN cleanup_needed INTEGER NOT NULL DEFAULT 0
	`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	if _, err := db.Exec(`
		ALTER TABLE attachments ADD COLUMN pin_dir TEXT NOT NULL DEFAULT ''
	`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	if _, err := db.Exec(`
		ALTER TABLE attachments ADD COLUMN pin_path_known INTEGER NOT NULL DEFAULT 0
	`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	if _, err := db.Exec(`
		ALTER TABLE attachments ADD COLUMN policy_degraded_reason TEXT NOT NULL DEFAULT ''
	`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return err
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_attachments_attached_at_id
		ON attachments(attached_at, id)
	`); err != nil {
		return err
	}
	// Small key/value table for daemon-level state (e.g. the persisted daemon
	// id). Additive: databases created before this table existed gain it here.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		) STRICT, WITHOUT ROWID
	`); err != nil {
		return err
	}
	return migrateAttachedAtFormat(db)
}

// migrateAttachedAtFormat rewrites attached_at values written before the
// canonical fixed-width layout existed (they were RFC3339Nano, whose trimmed
// trailing zeros break lexical ordering). Idempotent: canonical rows are
// excluded by the GLOB prefilter, and rewriting is a pure re-format, so a
// migrated database and a fresh one converge on identical stored text.
// Unparseable values are left untouched — they were already read errors
// before this migration, and reads still surface them per row.
func migrateAttachedAtFormat(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning attached_at migration: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query(
		`SELECT id, attached_at FROM attachments WHERE attached_at NOT GLOB ?`,
		attachedAtGlob,
	)
	if err != nil {
		return fmt.Errorf("selecting rows for attached_at migration: %w", err)
	}
	type rewrite struct{ id, attachedAt string }
	var rewrites []rewrite
	for rows.Next() {
		var id, attachedAt string
		if err := rows.Scan(&id, &attachedAt); err != nil {
			rows.Close()
			return fmt.Errorf("scanning row for attached_at migration: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, attachedAt)
		if err != nil {
			continue // pre-existing bad value; leave as-is
		}
		rewrites = append(rewrites, rewrite{id, t.UTC().Format(attachedAtLayout)})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterating rows for attached_at migration: %w", err)
	}
	rows.Close()

	for _, r := range rewrites {
		if _, err := tx.Exec(
			`UPDATE attachments SET attached_at = ? WHERE id = ?`,
			r.attachedAt, r.id,
		); err != nil {
			return fmt.Errorf("rewriting attached_at for %q: %w", r.id, err)
		}
	}
	return tx.Commit()
}

func (s *Store) Close() error {
	return s.db.Close()
}

// GetOrCreateDaemonID returns the persisted daemon identifier, generating and
// persisting a fresh UUID on first call. The INSERT OR IGNORE + SELECT pair
// makes it race-safe and idempotent: a pre-existing id always wins and is
// never overwritten, so the id is stable for the lifetime of the database
// (across restarts for file-backed stores; per-instance for :memory:).
func (s *Store) GetOrCreateDaemonID() (string, error) {
	fresh, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generating daemon id: %w", err)
	}
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO metadata (key, value) VALUES ('daemon_id', ?)`,
		fresh.String(),
	); err != nil {
		return "", fmt.Errorf("persisting daemon id: %w", err)
	}
	var id string
	if err := s.db.QueryRow(
		`SELECT value FROM metadata WHERE key = 'daemon_id'`,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("reading daemon id: %w", err)
	}
	return id, nil
}

func (s *Store) SaveAttachment(a *Attachment) error {
	metadata, err := json.Marshal(a.Metadata)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO attachments (id, target, type, mode, dns_mode, dns_address, direction, cleanup_needed, pin_dir, pin_path_known, policy_degraded_reason, metadata, attached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ID, a.Target, a.Type, a.Mode, a.DnsMode, a.DnsAddress, a.Direction, a.CleanupNeeded, a.PinDir, a.PinPathKnown, a.PolicyDegradedReason, string(metadata), a.AttachedAt.UTC().Format(attachedAtLayout))
	return err
}

func (s *Store) DeleteAttachment(id string) error {
	_, err := s.db.Exec("DELETE FROM attachments WHERE id = ?", id)
	return err
}

func (s *Store) GetAttachment(id string) (*Attachment, error) {
	row := s.db.QueryRow(`
		SELECT id, target, type, mode, dns_mode, dns_address, direction, cleanup_needed, pin_dir, pin_path_known, policy_degraded_reason, metadata, attached_at
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
		SELECT id, target, type, mode, dns_mode, dns_address, direction, cleanup_needed, pin_dir, pin_path_known, policy_degraded_reason, metadata, attached_at
		FROM attachments
		WHERE (attached_at, id) > (?, ?)
		ORDER BY attached_at, id
		LIMIT ?
	`

	afterTime, afterID, err := parsePageToken(pageToken)
	if err != nil {
		return nil, "", 0, err
	}

	rows, err := s.db.Query(query, afterTime, afterID, pageSize+1)
	if err != nil {
		return nil, "", 0, fmt.Errorf("querying attachments: %w", err)
	}
	defer rows.Close()

	var attachments []Attachment
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, "", 0, err
		}
		attachments = append(attachments, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, fmt.Errorf("iterating attachments: %w", err)
	}

	var nextPageToken string
	if len(attachments) > pageSize {
		last := attachments[pageSize-1]
		nextPageToken = last.AttachedAt.UTC().Format(attachedAtLayout) + "|" + last.ID
		attachments = attachments[:pageSize]
	}

	return attachments, nextPageToken, totalCount, nil
}

func (s *Store) GetAllAttachments() ([]Attachment, error) {
	rows, err := s.db.Query(`
		SELECT id, target, type, mode, dns_mode, dns_address, direction, cleanup_needed, pin_dir, pin_path_known, policy_degraded_reason, metadata, attached_at
		FROM attachments ORDER BY attached_at, id
	`)
	if err != nil {
		return nil, fmt.Errorf("querying attachments: %w", err)
	}
	defer rows.Close()

	var attachments []Attachment
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		attachments = append(attachments, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating attachments: %w", err)
	}
	return attachments, nil
}

func parsePageToken(pageToken string) (string, string, error) {
	if pageToken == "" {
		return time.Time{}.Format(attachedAtLayout), "", nil
	}
	parts := strings.SplitN(pageToken, "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", fmt.Errorf("invalid page token")
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return "", "", fmt.Errorf("invalid page token timestamp: %w", err)
	}
	// Canonicalize so tokens minted before the fixed-width layout (or by an
	// older daemon) still compare correctly against stored values — the text
	// comparison in ListAttachments requires the canonical representation.
	return ts.UTC().Format(attachedAtLayout), parts[1], nil
}

// scanner is the subset of *sql.Row / *sql.Rows that scanAttachment needs.
type scanner interface {
	Scan(dest ...any) error
}

func scanAttachment(s scanner) (*Attachment, error) {
	var a Attachment
	var cleanupNeeded, pinPathKnown int
	var metadata, attachedAt string
	err := s.Scan(&a.ID, &a.Target, &a.Type, &a.Mode, &a.DnsMode, &a.DnsAddress, &a.Direction, &cleanupNeeded, &a.PinDir, &pinPathKnown, &a.PolicyDegradedReason, &metadata, &attachedAt)
	if err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("scanning attachment: %w", err)
	}

	if err := json.Unmarshal([]byte(metadata), &a.Metadata); err != nil {
		return nil, fmt.Errorf("unmarshaling metadata: %w", err)
	}
	a.CleanupNeeded = cleanupNeeded != 0
	a.PinPathKnown = pinPathKnown != 0
	// Parse with RFC3339Nano: it accepts the canonical fixed-width layout as
	// well as any pre-migration value, keeping reads tolerant of old rows.
	if a.AttachedAt, err = time.Parse(time.RFC3339Nano, attachedAt); err != nil {
		return nil, fmt.Errorf("parsing attached_at: %w", err)
	}
	return &a, nil
}
