package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
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
