package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkStoreListAttachmentsFirstPage(b *testing.B) {
	st := newBenchmarkStore(b, 10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := st.ListAttachments(100, ""); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStoreListAttachmentsDeepPage(b *testing.B) {
	st := newBenchmarkStore(b, 10000)
	token := time.Date(2026, 5, 27, 12, 0, 0, 5000, time.UTC).Format(time.RFC3339Nano) + "|005000"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, err := st.ListAttachments(100, token); err != nil {
			b.Fatal(err)
		}
	}
}

func newBenchmarkStore(b *testing.B, rows int) *Store {
	b.Helper()
	st, err := New(filepath.Join(b.TempDir(), "netfence.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = st.Close()
	})

	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	tx, err := st.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO attachments (id, target, type, mode, dns_mode, dns_address, metadata, attached_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		b.Fatal(err)
	}
	defer stmt.Close()

	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("%06d", i)
		if _, err := stmt.Exec(
			id,
			"target-"+id,
			"ATTACHMENT_TYPE_TC",
			"POLICY_MODE_DISABLED",
			"DNS_MODE_DISABLED",
			"127.0.0.1:12000",
			"{}",
			base.Add(time.Duration(i)*time.Nanosecond).Format(time.RFC3339Nano),
		); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	return st
}
