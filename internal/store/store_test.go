package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})
	return st
}

func testAttachment(id string, attachedAt time.Time) *Attachment {
	return &Attachment{
		ID:         id,
		Target:     "target-" + id,
		Type:       "ATTACHMENT_TYPE_TC",
		Mode:       "POLICY_MODE_DISABLED",
		DnsMode:    "DNS_MODE_DISABLED",
		DnsAddress: "127.0.0.1:12000",
		Metadata:   map[string]string{"id": id},
		AttachedAt: attachedAt,
	}
}

func TestListAttachmentsPaginatesDuplicateTimestamps(t *testing.T) {
	st := newTestStore(t)
	ts := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	for _, id := range []string{"a", "b", "c"} {
		require.NoError(t, st.SaveAttachment(testAttachment(id, ts)))
	}

	page, next, total, err := st.ListAttachments(2, "")
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Len(t, page, 2)
	assert.Equal(t, []string{"a", "b"}, []string{page[0].ID, page[1].ID})
	require.NotEmpty(t, next)

	page, next, total, err = st.ListAttachments(2, next)
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Len(t, page, 1)
	assert.Equal(t, "c", page[0].ID)
	assert.Empty(t, next)
}

func TestListAttachmentsRejectsInvalidPageTokens(t *testing.T) {
	st := newTestStore(t)

	_, _, _, err := st.ListAttachments(100, "not-a-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid page token")

	_, _, _, err = st.ListAttachments(100, "not-a-time|id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid page token timestamp")
}

func TestListAttachmentsPageSizeDefaultAndClamp(t *testing.T) {
	st := newTestStore(t)
	ts := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 1005; i++ {
		require.NoError(t, st.SaveAttachment(testAttachment(fmt.Sprintf("%04d", i), ts.Add(time.Duration(i)*time.Nanosecond))))
	}

	page, _, total, err := st.ListAttachments(0, "")
	require.NoError(t, err)
	assert.Equal(t, 1005, total)
	assert.Len(t, page, 100)

	page, _, _, err = st.ListAttachments(5000, "")
	require.NoError(t, err)
	assert.Len(t, page, 1000)
}

func TestGetAttachmentMissingMalformedMetadataAndMalformedTime(t *testing.T) {
	st := newTestStore(t)

	_, err := st.GetAttachment("missing")
	require.ErrorIs(t, err, sql.ErrNoRows)

	_, err = st.db.Exec(`
		INSERT INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "bad-json", "target", "ATTACHMENT_TYPE_TC", "POLICY_MODE_DISABLED", "DNS_MODE_DISABLED", "127.0.0.1:12000", "{", time.Now().UTC().Format(time.RFC3339Nano))
	require.NoError(t, err)
	_, err = st.GetAttachment("bad-json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshaling metadata")

	_, err = st.db.Exec(`
		INSERT INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "bad-time", "target", "ATTACHMENT_TYPE_TC", "POLICY_MODE_DISABLED", "DNS_MODE_DISABLED", "127.0.0.1:12000", "{}", "not-a-time")
	require.NoError(t, err)
	_, err = st.GetAttachment("bad-time")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing attached_at")
}

func TestListAttachmentsUsesAttachedAtIDIndex(t *testing.T) {
	st := newTestStore(t)

	rows, err := st.db.Query(`
		EXPLAIN QUERY PLAN
		SELECT id, target, type, mode, dns_mode, dns_address, metadata, attached_at
		FROM attachments
		WHERE (attached_at, id) > (?, ?)
		ORDER BY attached_at, id
		LIMIT ?
	`, "0001-01-01T00:00:00Z", "", 101)
	require.NoError(t, err)
	defer rows.Close()

	var plans []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notUsed, &detail))
		plans = append(plans, detail)
	}
	require.NoError(t, rows.Err())
	assert.Contains(t, strings.Join(plans, "\n"), "idx_attachments_attached_at_id")
}

func TestDirectionPersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netfence.db")
	st, err := New(dbPath)
	require.NoError(t, err)

	a := testAttachment("tc-ingress", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	a.Direction = "TC_DIRECTION_INGRESS"
	require.NoError(t, st.SaveAttachment(a))

	got, err := st.GetAttachment("tc-ingress")
	require.NoError(t, err)
	assert.Equal(t, "TC_DIRECTION_INGRESS", got.Direction)
	require.NoError(t, st.Close())

	// Reopen: migrate() runs again on an existing DB, so the ALTER TABLE hits
	// the duplicate-column path and must be tolerated.
	st, err = New(dbPath)
	require.NoError(t, err)
	defer st.Close()

	got, err = st.GetAttachment("tc-ingress")
	require.NoError(t, err)
	assert.Equal(t, "TC_DIRECTION_INGRESS", got.Direction)

	all, err := st.GetAllAttachments()
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "TC_DIRECTION_INGRESS", all[0].Direction)
}

// TestMemoryStoreConcurrentOps reproduces the :memory: connection-pool bug:
// mattn/go-sqlite3 gives each pooled connection its own in-memory database, so
// without SetMaxOpenConns(1) concurrent calls land on fresh connections whose
// databases never saw the migration ("no such table: attachments"). The
// default DBPath() is :memory:, and the daemon serves Save/Get/List/Delete
// from concurrent gRPC handlers, so this must be race- and error-free.
func TestMemoryStoreConcurrentOps(t *testing.T) {
	st, err := New(":memory:")
	require.NoError(t, err)
	defer st.Close()

	const workers = 8
	const iters = 50

	errCh := make(chan error, workers*iters*5)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
			for i := 0; i < iters; i++ {
				id := fmt.Sprintf("w%d-i%d", w, i)
				a := testAttachment(id, base.Add(time.Duration(w*iters+i)*time.Millisecond))
				if err := st.SaveAttachment(a); err != nil {
					errCh <- fmt.Errorf("save %s: %w", id, err)
					continue
				}
				if _, err := st.GetAttachment(id); err != nil {
					errCh <- fmt.Errorf("get %s: %w", id, err)
				}
				if _, _, _, err := st.ListAttachments(10, ""); err != nil {
					errCh <- fmt.Errorf("list: %w", err)
				}
				if _, err := st.GetAllAttachments(); err != nil {
					errCh <- fmt.Errorf("get all: %w", err)
				}
				if i%2 == 0 {
					if err := st.DeleteAttachment(id); err != nil {
						errCh <- fmt.Errorf("delete %s: %w", id, err)
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent store op failed: %v", err)
	}
}

// TestListAttachmentsOrdersMixedPrecisionTimestamps catches the RFC3339Nano
// trailing-zero-trimming bug: a whole-second value ("…:00Z") sorted lexically
// AFTER a fractional one ("…:00.5Z"), so the TEXT keyset pagination returned
// rows out of temporal order and could skip/duplicate across pages.
func TestListAttachmentsOrdersMixedPrecisionTimestamps(t *testing.T) {
	st := newTestStore(t)

	tWhole := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	tNano := tWhole.Add(time.Nanosecond)
	tHalf := tWhole.Add(500 * time.Millisecond)
	tNext := tWhole.Add(time.Second)

	// w1/w2 share a whole-second timestamp (id is the tiebreaker).
	inserts := []struct {
		id string
		ts time.Time
	}{
		{"h", tHalf}, {"w2", tWhole}, {"s", tNext}, {"n", tNano}, {"w1", tWhole},
	}
	for _, in := range inserts {
		require.NoError(t, st.SaveAttachment(testAttachment(in.id, in.ts)))
	}
	wantOrder := []string{"w1", "w2", "n", "h", "s"}

	// Page through with a small page size; every row must appear exactly once,
	// in (attached_at, id) temporal order.
	var got []string
	var prev time.Time
	var prevID string
	token := ""
	for pages := 0; ; pages++ {
		require.Less(t, pages, len(inserts)+1, "pagination did not terminate")
		page, next, total, err := st.ListAttachments(2, token)
		require.NoError(t, err)
		require.Equal(t, len(inserts), total)
		for _, a := range page {
			if len(got) > 0 {
				require.True(t,
					prev.Before(a.AttachedAt) || (prev.Equal(a.AttachedAt) && prevID < a.ID),
					"rows out of (attached_at, id) order: (%s, %s) then (%s, %s)",
					prev, prevID, a.AttachedAt, a.ID)
			}
			got = append(got, a.ID)
			prev, prevID = a.AttachedAt, a.ID
		}
		if next == "" {
			break
		}
		token = next
	}
	assert.Equal(t, wantOrder, got, "every row exactly once, in temporal order")
}

func TestAttachedAtRoundTrip(t *testing.T) {
	st := newTestStore(t)

	// Nanosecond precision and non-UTC zones must round-trip: values are
	// stored in UTC at nanosecond precision, and read back in UTC.
	zone := time.FixedZone("UTC+2", 2*60*60)
	cases := []struct {
		id string
		ts time.Time
	}{
		{"whole-second", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)},
		{"nanos", time.Date(2026, 5, 27, 12, 0, 0, 123456789, time.UTC)},
		{"trailing-zero-nanos", time.Date(2026, 5, 27, 12, 0, 0, 500000000, time.UTC)},
		{"offset-zone", time.Date(2026, 5, 27, 14, 30, 0, 42, zone)},
	}
	for _, c := range cases {
		require.NoError(t, st.SaveAttachment(testAttachment(c.id, c.ts)))
		got, err := st.GetAttachment(c.id)
		require.NoError(t, err)
		assert.True(t, got.AttachedAt.Equal(c.ts), "%s: got %s want %s", c.id, got.AttachedAt, c.ts)
		assert.Equal(t, time.UTC, got.AttachedAt.Location(), "%s: reads return UTC", c.id)
	}
}

// TestAttachedAtMigrationRewritesLegacyRows verifies that rows written in the
// old RFC3339Nano format are rewritten to the canonical fixed-width layout on
// open, that the migration is idempotent, and that a migrated database and a
// fresh one converge on identical stored text.
func TestAttachedAtMigrationRewritesLegacyRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netfence.db")

	// Create the schema, then insert rows in the legacy trimmed format the
	// pre-3C store wrote (including a whole-second value and a non-UTC offset).
	st, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, st.Close())

	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	for _, row := range []struct{ id, attachedAt string }{
		{"legacy-whole", "2026-05-27T12:00:00Z"},
		{"legacy-offset", "2026-05-27T14:00:00.25+02:00"}, // = 12:00:00.25Z
		{"legacy-frac", "2026-05-27T12:00:00.5Z"},
	} {
		_, err = db.Exec(`
			INSERT INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
			VALUES (?, ?, 'ATTACHMENT_TYPE_TC', 'POLICY_MODE_DISABLED', 'DNS_MODE_DISABLED', '127.0.0.1:12000', '{}', ?)
		`, row.id, "target-"+row.id, row.attachedAt)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	readRaw := func(t *testing.T, st *Store) map[string]string {
		t.Helper()
		raw := map[string]string{}
		rows, err := st.db.Query(`SELECT id, attached_at FROM attachments`)
		require.NoError(t, err)
		defer rows.Close()
		for rows.Next() {
			var id, attachedAt string
			require.NoError(t, rows.Scan(&id, &attachedAt))
			raw[id] = attachedAt
		}
		require.NoError(t, rows.Err())
		return raw
	}

	// Opening the store migrates the legacy rows to the canonical layout.
	st, err = New(dbPath)
	require.NoError(t, err)
	wantRaw := map[string]string{
		"legacy-whole":  "2026-05-27T12:00:00.000000000Z",
		"legacy-offset": "2026-05-27T12:00:00.250000000Z",
		"legacy-frac":   "2026-05-27T12:00:00.500000000Z",
	}
	assert.Equal(t, wantRaw, readRaw(t, st))

	// Migrated rows read back at the correct instants, in temporal order
	// (pre-migration, legacy-whole sorted last instead of first).
	all, err := st.GetAllAttachments()
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, "legacy-whole", all[0].ID)
	assert.Equal(t, "legacy-offset", all[1].ID)
	assert.Equal(t, "legacy-frac", all[2].ID)
	assert.True(t, all[0].AttachedAt.Equal(time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)))
	assert.True(t, all[1].AttachedAt.Equal(time.Date(2026, 5, 27, 12, 0, 0, 250000000, time.UTC)))
	assert.True(t, all[2].AttachedAt.Equal(time.Date(2026, 5, 27, 12, 0, 0, 500000000, time.UTC)))

	// A freshly saved row at the same instant converges on the same stored
	// text as the migrated row's format.
	require.NoError(t, st.SaveAttachment(testAttachment("fresh", time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))))
	raw := readRaw(t, st)
	assert.Equal(t, raw["legacy-whole"], raw["fresh"])
	require.NoError(t, st.Close())

	// Re-opening runs the migration again: idempotent, values unchanged.
	st, err = New(dbPath)
	require.NoError(t, err)
	defer st.Close()
	raw2 := readRaw(t, st)
	assert.Equal(t, raw, raw2)
}

// TestAttachedAtMigrationLeavesUnparseableRows guards the migration's
// documented "unparseable values are left untouched" behavior: a garbage
// value and a GLOB-shaped-but-unparseable value must survive migration
// byte-identical without erroring, while a parseable legacy row beside them is
// still rewritten. These rows were already read errors before the migration
// existed; the migration must not drop or corrupt them.
func TestAttachedAtMigrationLeavesUnparseableRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netfence.db")

	st, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, st.Close())

	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	for _, row := range []struct{ id, attachedAt string }{
		{"garbage", "not-a-time"},
		{"glob-shaped-garbage", "abcd-ef-ghTij:kl:mn.opqrstuvwZ"}, // 30 chars, matches glob, unparseable
		{"legacy-frac", "2026-05-27T12:00:00.5Z"},                 // parseable: must be rewritten
	} {
		_, err = db.Exec(`
			INSERT INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
			VALUES (?, ?, 'ATTACHMENT_TYPE_TC', 'POLICY_MODE_DISABLED', 'DNS_MODE_DISABLED', '127.0.0.1:12000', '{}', ?)
		`, row.id, "target-"+row.id, row.attachedAt)
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	// Opening the store runs the migration; it must not error on the bad rows.
	st, err = New(dbPath)
	require.NoError(t, err)
	defer st.Close()

	raw := map[string]string{}
	rows, err := st.db.Query(`SELECT id, attached_at FROM attachments`)
	require.NoError(t, err)
	for rows.Next() {
		var id, attachedAt string
		require.NoError(t, rows.Scan(&id, &attachedAt))
		raw[id] = attachedAt
	}
	require.NoError(t, rows.Err())
	rows.Close()

	assert.Equal(t, "not-a-time", raw["garbage"], "unparseable value left untouched")
	assert.Equal(t, "abcd-ef-ghTij:kl:mn.opqrstuvwZ", raw["glob-shaped-garbage"], "glob-shaped-but-unparseable value left untouched")
	assert.Equal(t, "2026-05-27T12:00:00.500000000Z", raw["legacy-frac"], "parseable legacy value still rewritten")
}

// TestListAttachmentsAcceptsLegacyPageToken feeds trimmed RFC3339Nano page
// tokens (as an older daemon mid-pagination would have minted) through
// ListAttachments and confirms they resume at exactly the right row against
// canonical fixed-width storage — the cross-version scenario parsePageToken's
// canonicalization exists for.
func TestListAttachmentsAcceptsLegacyPageToken(t *testing.T) {
	st := newTestStore(t)

	tWhole := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	tHalf := tWhole.Add(500 * time.Millisecond)
	tNext := tWhole.Add(time.Second)
	for _, in := range []struct {
		id string
		ts time.Time
	}{{"a", tWhole}, {"c", tHalf}, {"e", tNext}} {
		require.NoError(t, st.SaveAttachment(testAttachment(in.id, in.ts)))
	}

	// A whole-second legacy token ("…:00Z", trimmed) must resume after row "a".
	page, _, _, err := st.ListAttachments(10, tWhole.Format(time.RFC3339Nano)+"|a")
	require.NoError(t, err)
	got := make([]string, len(page))
	for i, a := range page {
		got[i] = a.ID
	}
	assert.Equal(t, []string{"c", "e"}, got, "whole-second legacy token resumes correctly")

	// A fractional legacy token ("…:00.5Z") must resume after row "c".
	page, _, _, err = st.ListAttachments(10, tHalf.Format(time.RFC3339Nano)+"|c")
	require.NoError(t, err)
	got = got[:0]
	for _, a := range page {
		got = append(got, a.ID)
	}
	assert.Equal(t, []string{"e"}, got, "fractional legacy token resumes correctly")
}

func TestDirectionMigrationAddsColumnToOldSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "netfence.db")

	// Create a database with the pre-direction schema and a row in it.
	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE attachments (
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
	require.NoError(t, err)
	_, err = db.Exec(`
		INSERT INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
		VALUES ('old-row', 'nf-old', 'ATTACHMENT_TYPE_TC', 'POLICY_MODE_DISABLED', 'DNS_MODE_DISABLED', '127.0.0.1:12000', '{}', '2026-05-27T12:00:00Z')
	`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// Opening the store migrates the old schema in place.
	st, err := New(dbPath)
	require.NoError(t, err)
	defer st.Close()

	got, err := st.GetAttachment("old-row")
	require.NoError(t, err)
	assert.Empty(t, got.Direction, "pre-migration rows read back with empty direction")

	// And the migrated table accepts direction on save.
	a := testAttachment("new-row", time.Date(2026, 5, 27, 13, 0, 0, 0, time.UTC))
	a.Direction = "TC_DIRECTION_INGRESS"
	require.NoError(t, st.SaveAttachment(a))
	got, err = st.GetAttachment("new-row")
	require.NoError(t, err)
	assert.Equal(t, "TC_DIRECTION_INGRESS", got.Direction)
}
