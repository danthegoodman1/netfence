package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// restoreEnv drives Server.Start's restore path with a persisted attachment
// row, a plain-tempdir pin root (the ensurePinRoot/loadPinnedFilter seams
// stand in for bpffs), and full visibility into which construction path ran.
type restoreEnv struct {
	server  *Server
	st      *store.Store
	id      string
	pinRoot string

	mu              sync.Mutex
	adopted         *fakeFilter // returned by the loadPinnedFilter seam
	loadPinnedCalls int
	newFilterCalls  int
	created         []*fakeFilter
}

func newRestoreEnv(t *testing.T, port int, storeMode apiv1.PolicyMode) *restoreEnv {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	pinRoot := t.TempDir()
	id := "att-restore-1"
	// The target must be a REAL interface ("lo"): on linux the production
	// TargetWatcher runs during these tests, and a watched-but-nonexistent
	// interface would be reconciled away (handleTargetRemoved -> Detach),
	// poisoning the teardown-path assertions.
	require.NoError(t, st.SaveAttachment(&store.Attachment{
		ID:         id,
		Target:     "lo",
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
		Mode:       storeMode.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		AttachedAt: time.Now().UTC(),
	}))

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    port,
			PortMax:    port,
			Upstream:   "127.0.0.1:1",
		},
		Filter: config.FilterConfig{BPFPinDir: pinRoot},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "test")
	require.NoError(t, err)
	server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) { return 1, nil })

	env := &restoreEnv{server: server, st: st, id: id, pinRoot: pinRoot}

	// Seams: plain temp dirs stand in for bpffs, the fake target always
	// exists, and both construction paths are observable.
	server.ensurePinRoot = func(string) error { return nil }
	server.targetExists = func(apiv1.AttachmentType, string) bool { return true }
	server.loadPinnedFilter = func(pinDir, target string, attachType apiv1.AttachmentType, direction apiv1.TcDirection) (filter.Filter, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.loadPinnedCalls++
		return env.adopted, nil
	}
	server.newFilter = func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		env.newFilterCalls++
		ff := &fakeFilter{mode: apiModeToFilterMode(mode)}
		env.created = append(env.created, ff)
		return ff, nil
	}

	return env
}

// mkPinDir simulates a pinned prior life for the attachment.
func (e *restoreEnv) mkPinDir(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Join(e.pinRoot, e.id), 0o700))
}

func (e *restoreEnv) counts() (loadPinned, newFilter int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.loadPinnedCalls, e.newFilterCalls
}

// TestRestoreReadoptsPinsAndReconcileRemovesStale is the restore-reseed
// contract test: an attachment re-adopted from pins with rules {A,B} must
// survive a later control-plane BulkUpdate that declares {A,C} — B (removed
// while the daemon was down, from the CP's perspective) is deleted from the
// kernel map, C is added, and A is NEVER removed at any point (the complete
// mutation log proves there was no transient window for the survivor).
func TestRestoreReadoptsPinsAndReconcileRemovesStale(t *testing.T) {
	env := newRestoreEnv(t, 12300, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)

	cidrA := mustCIDR(t, "198.51.100.1/32")
	cidrB := mustCIDR(t, "203.0.113.5/32")
	cidrC := mustCIDR(t, "192.0.2.7/32")

	// The pinned maps come back holding {A, B} in allowlist mode.
	env.adopted = &fakeFilter{
		mode:    filter.ModeAllowlist,
		allowed: []string{cidrA.String(), cidrB.String()},
	}
	env.mkPinDir(t)

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	loadPinned, newFilter := env.counts()
	assert.Equal(t, 1, loadPinned, "restore must re-adopt from pins")
	assert.Zero(t, newFilter, "restore must NOT recreate a filter when pins are adoptable")

	// The registry was reseeded from the adopted maps: both rules tracked.
	env.server.mu.RLock()
	state := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	require.NotNil(t, state)
	assert.Same(t, filter.Filter(env.adopted), state.filter)
	assert.Equal(t, 2, state.ttls.len(), "adopted rules must be seeded into the TTL registry")

	// Control-plane resync (BulkUpdate) now declares {A, C}.
	require.NoError(t, env.server.ReconcileCIDRs(env.id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		[]parsedCIDR{{cidr: cidrA}, {cidr: cidrC}}, nil))

	mode, allowed, _, _ := env.adopted.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.ElementsMatch(t, []string{cidrA.String(), cidrC.String()}, allowed,
		"B must be removed, C added, A kept")

	// The complete mutation log proves the survivor was never touched: no
	// remove of A ever happened, so there was no window in which A's traffic
	// could have been blocked.
	events := env.adopted.eventLog()
	assert.NotContains(t, events, "remove-allow "+cidrA.String(), "survivor A must never be removed")
	assert.Contains(t, events, "remove-allow "+cidrB.String(), "stale B must be removed")
	assert.Contains(t, events, "allow "+cidrC.String(), "new C must be added")
}

// TestRestoreStoreModeLagsPinnedMode: the pinned policy_mode map is what is
// actually enforcing, so when the store row lags it (crash between the map
// write and the store save), restore trusts the kernel and fixes the row.
func TestRestoreStoreModeLagsPinnedMode(t *testing.T) {
	env := newRestoreEnv(t, 12301, apiv1.PolicyMode_POLICY_MODE_DISABLED)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	env.mkPinDir(t)

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	row, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), row.Mode,
		"store row must be corrected to the live (pinned) mode")
}

// TestRestoreFallsBackWithoutPins: no pin dir (detach_on_stop prior run or
// pre-pinning data) means the old recreate-empty path runs.
func TestRestoreFallsBackWithoutPins(t *testing.T) {
	env := newRestoreEnv(t, 12302, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	loadPinned, newFilter := env.counts()
	assert.Zero(t, loadPinned, "no pins to adopt")
	assert.Equal(t, 1, newFilter, "must fall back to recreating the filter")
}

// TestRestoreDiscardsPinsWhenTargetGone: pins whose target vanished while
// the daemon was down are defunct; restore must discard them and clean up
// the attachment rather than adopt a zombie.
func TestRestoreDiscardsPinsWhenTargetGone(t *testing.T) {
	env := newRestoreEnv(t, 12303, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	env.mkPinDir(t)
	env.server.targetExists = func(apiv1.AttachmentType, string) bool { return false }
	env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
		return nil, os.ErrNotExist // recreate against the gone target fails
	}

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	loadPinned, _ := env.counts()
	assert.Zero(t, loadPinned, "defunct pins must not be adopted")
	assert.NoDirExists(t, filepath.Join(env.pinRoot, env.id), "defunct pin dir must be removed")

	env.server.mu.RLock()
	_, present := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	assert.False(t, present, "attachment for a gone target must be cleaned up")

	rows, err := env.st.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows, "store row for a gone target must be deleted")
}

// TestRestoreRemovesOrphanPinDirs: a pin dir with no store row (crash
// between pinning and the store save) is unowned state and must be removed.
func TestRestoreRemovesOrphanPinDirs(t *testing.T) {
	env := newRestoreEnv(t, 12304, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	env.mkPinDir(t)

	orphan := filepath.Join(env.pinRoot, "0198ffff-dead-beef-0000-000000000000")
	require.NoError(t, os.MkdirAll(orphan, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(orphan, "allowed_ipv4"), []byte{}, 0o600))

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)

	assert.NoDirExists(t, orphan, "orphaned pin dir must be removed")
	assert.DirExists(t, filepath.Join(env.pinRoot, env.id), "live attachment's pin dir must be kept")
}

// TestStopTeardownRespectsDetachOnStop: default keep-enforcing Stop must
// Close (pins survive); detach_on_stop must Detach (pins destroyed).
func TestStopTeardownRespectsDetachOnStop(t *testing.T) {
	t.Run("default_keep_enforcing", func(t *testing.T) {
		env := newRestoreEnv(t, 12305, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
		env.mkPinDir(t)
		require.NoError(t, env.server.Start())

		env.server.Stop()
		assert.Equal(t, 1, env.adopted.closeCallCount(), "stop must close the filter")
		assert.Zero(t, env.adopted.detachCallCount(), "default stop must NOT detach (pins keep enforcing)")
	})

	t.Run("detach_on_stop", func(t *testing.T) {
		env := newRestoreEnv(t, 12306, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
		env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
		env.mkPinDir(t)
		env.server.detachOnStop = true
		require.NoError(t, env.server.Start())

		env.server.Stop()
		assert.Equal(t, 1, env.adopted.detachCallCount(), "detach_on_stop must detach the filter")
	})
}
