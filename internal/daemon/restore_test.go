package daemon

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
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
	port    int
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

	env := &restoreEnv{server: server, st: st, id: id, port: port, pinRoot: server.pinRoot}

	// Seams: plain temp dirs stand in for bpffs, the fake target always
	// exists, and both construction paths are observable.
	server.ensurePinRoot = func(string) error { return nil }
	server.validatePinRoot = func(string) error { return nil }
	server.inspectPinSchema = func(string) (filter.PinnedSchemaState, error) { return filter.PinnedSchemaCurrent, nil }
	server.targetPresence = func(apiv1.AttachmentType, string) (bool, error) { return true, nil }
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

func TestRestoreCommitFailureRollsBackEarlierAdoptedBootstrapFailClosed(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	pinRoot := t.TempDir()
	firstID, secondID := "a-first", "b-second"
	firstPort, secondPort := 12328, 12329
	for _, row := range []*store.Attachment{
		{ID: firstID, Target: "first-if", Type: apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(), Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), DnsMode: apiv1.DnsMode_DNS_MODE_DISABLED.String(), DnsAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(firstPort)), AttachedAt: time.Now().UTC()},
		{ID: secondID, Target: "second-if", Type: apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(), Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), DnsMode: apiv1.DnsMode_DNS_MODE_DISABLED.String(), DnsAddress: net.JoinHostPort("127.0.0.1", strconv.Itoa(secondPort)), AttachedAt: time.Now().UTC()},
	} {
		require.NoError(t, st.SaveAttachment(row))
		require.NoError(t, os.MkdirAll(filepath.Join(pinRoot, row.ID), 0o755))
	}

	cfg := &config.Config{
		DNS:    config.DNSConfig{ListenAddr: "127.0.0.1", PortMin: firstPort, PortMax: secondPort, Upstream: "127.0.0.1:1"},
		Filter: config.FilterConfig{BPFPinDir: pinRoot},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "test")
	require.NoError(t, err)
	server.ensurePinRoot = func(string) error { return nil }
	server.validatePinRoot = func(string) error { return nil }
	server.targetPresence = func(apiv1.AttachmentType, string) (bool, error) { return true, nil }
	server.setTargetIdentityResolver(func(_ apiv1.AttachmentType, target string) (uint64, error) {
		if target == "first-if" {
			return 1, nil
		}
		return 2, nil
	})
	server.startWatcher = func() error { return nil }
	server.stopWatcher = func() {}
	first := &fakeFilter{mode: filter.ModeAllowlist}
	first.setRemoveAllowedErr(syscall.EIO)
	second := &fakeFilter{mode: filter.ModeAllowlist}
	second.setAllowErr(syscall.ENOSPC)
	server.loadPinnedFilter = func(pinDir, _ string, _ apiv1.AttachmentType, _ apiv1.TcDirection) (filter.Filter, error) {
		switch filepath.Base(pinDir) {
		case firstID:
			return first, nil
		case secondID:
			return second, nil
		default:
			return nil, errors.New("unexpected pin directory")
		}
	}

	err = server.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "installing protected DNS bootstrap route for attachment "+secondID)
	assert.Contains(t, err.Error(), "restoring bootstrap for "+firstID)
	assert.Zero(t, first.detachCallCount())
	assert.Zero(t, second.detachCallCount())
	assert.Equal(t, 1, first.closeCallCount())
	assert.Equal(t, 1, second.closeCallCount())
	firstMode, _, _, _ := first.snapshot()
	assert.Equal(t, filter.ModeBlockAll, firstMode)
	assert.DirExists(t, filepath.Join(pinRoot, firstID))
	assert.DirExists(t, filepath.Join(pinRoot, secondID))
	assertDNSPortFree(t, firstPort)
	assertDNSPortFree(t, secondPort)

	storedFirst, getErr := st.GetAttachment(firstID)
	require.NoError(t, getErr)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), storedFirst.Mode)
	storedSecond, getErr := st.GetAttachment(secondID)
	require.NoError(t, getErr)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), storedSecond.Mode)
	server.mu.RLock()
	for _, id := range []string{firstID, secondID} {
		state := server.attachments[id]
		require.NotNil(t, state)
		assert.Nil(t, state.filter)
		assert.Nil(t, state.dns)
		assert.False(t, state.needsResync)
		assert.False(t, state.watch.valid())
	}
	server.mu.RUnlock()
}

func TestRestoreHostnameResolvesExactlyOnceForBindAdvertisePersistAndBootstrap(t *testing.T) {
	env := newRestoreEnv(t, 12330, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	hostnameAddress := net.JoinHostPort("resolver.internal", strconv.Itoa(env.port))
	env.server.mu.Lock()
	env.server.attachments[env.id].info.DnsAddress = hostnameAddress
	row := cloneAttachment(env.server.attachments[env.id].info)
	env.server.mu.Unlock()
	require.NoError(t, env.st.SaveAttachment(row))

	resolveCalls := 0
	env.server.resolveDNSListenIP = func(host string) (string, error) {
		resolveCalls++
		if resolveCalls > 1 {
			return "", errors.New("listener hostname resolved more than once")
		}
		if host != "resolver.internal" {
			return "", fmt.Errorf("unexpected listener hostname %q", host)
		}
		return "127.0.0.1", nil
	}

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	assert.Equal(t, 1, resolveCalls)
	canonical := net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port))
	env.server.mu.RLock()
	state := env.server.attachments[env.id]
	require.NotNil(t, state)
	assert.Equal(t, canonical, state.info.DnsAddress, "advertised endpoint must use the one resolved IP")
	require.NotNil(t, state.dns)
	assert.Equal(t, canonical, state.dns.listenAddr, "listener bind must use the one resolved IP")
	env.server.mu.RUnlock()
	persisted, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	assert.Equal(t, canonical, persisted.DnsAddress)
	require.Len(t, env.created, 1)
	_, allowed, _, _ := env.created[0].snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, allowed, "bootstrap must derive from the same resolved IP")
}

func TestRestoreFilteringDNSModesStayRefusedUntilAuthoritativeAck(t *testing.T) {
	tests := []struct {
		name      string
		port      int
		adopted   bool
		delayedCP bool
	}{
		{name: "adopted_delayed_control_plane", port: 12334, adopted: true, delayedCP: true},
		{name: "recreated_without_control_plane", port: 12335},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			env.server.mu.Lock()
			env.server.attachments[env.id].info.DnsMode = apiv1.DnsMode_DNS_MODE_DENYLIST.String()
			row := cloneAttachment(env.server.attachments[env.id].info)
			env.server.mu.Unlock()
			require.NoError(t, env.st.SaveAttachment(row))
			if tt.adopted {
				env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
				env.mkPinDir(t)
			}
			if tt.delayedCP {
				env.server.SetControlPlaneClient(NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil))
			}

			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)
			env.server.mu.RLock()
			dnsServer := env.server.attachments[env.id].dns
			addr := env.server.attachments[env.id].info.DnsAddress
			env.server.mu.RUnlock()
			dnsServer.mu.RLock()
			assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
			assert.Empty(t, dnsServer.allowedDomains)
			dnsServer.mu.RUnlock()

			req := new(dns.Msg)
			req.SetQuestion("blocked-until-resync.example.", dns.TypeA)
			resp, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(req, addr)
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, dns.RcodeRefused, resp.Rcode)
			assert.True(t, attachmentNeedsResync(t, env.server, env.id))
		})
	}
}

func TestRestoreDNSSetupFailureAbortsAndRetainsDurableRow(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		adopted bool
		serve   bool
	}{
		{name: "adopted_bind", port: 12344, adopted: true},
		{name: "adopted_serve", port: 12345, adopted: true, serve: true},
		{name: "recreated_bind", port: 12346},
		{name: "recreated_serve", port: 12347, serve: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			stubRestoreWatcher(env.server)
			before, err := env.st.GetAttachment(env.id)
			require.NoError(t, err)
			if tt.adopted {
				env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
				env.mkPinDir(t)
			}
			if tt.serve {
				env.server.serveDNSServer = func(*DNSServer) error { return syscall.EIO }
			} else {
				env.server.bindDNSServer = func(*DNSServer) error { return syscall.EIO }
			}

			err = env.server.Start()
			require.Error(t, err)
			if tt.adopted {
				assert.Contains(t, err.Error(), "starting DNS server for re-adopted attachment")
				assert.Equal(t, 1, env.adopted.closeCallCount())
				assert.Zero(t, env.adopted.detachCallCount())
				assert.DirExists(t, filepath.Join(env.pinRoot, env.id))
			} else {
				assert.Contains(t, err.Error(), "starting DNS server for recreated attachment")
				require.Len(t, env.created, 1)
				assert.Equal(t, 1, env.created[0].detachCallCount())
			}
			assertRestoreDurableOwnershipRetained(t, env, before)
			assertDNSPortFree(t, env.port)
		})
	}
}

func TestRestoreAmbiguousNewFilterFailureAbortsAndRetainsDurableRow(t *testing.T) {
	env := newRestoreEnv(t, 12348, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	stubRestoreWatcher(env.server)
	before, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	removeCalls, deleteCalls := 0, 0
	env.server.newFilter = func(string, string, apiv1.AttachmentType, apiv1.PolicyMode, apiv1.TcDirection, uint32) (filter.Filter, error) {
		return nil, syscall.EACCES
	}
	env.server.removePinDir = func(string) error {
		removeCalls++
		return nil
	}
	env.server.deleteAttachment = func(string) error {
		deleteCalls++
		return nil
	}

	err = env.server.Start()
	require.ErrorContains(t, err, "while target remains present")
	assert.ErrorIs(t, err, syscall.EACCES)
	assert.Zero(t, removeCalls, "ambiguous construction failure must not remove enforcement state")
	assert.Zero(t, deleteCalls, "ambiguous construction failure must not delete ownership")
	assertRestoreDurableOwnershipRetained(t, env, before)
	assertDNSPortFree(t, env.port)
}

func TestRestoreConstructorErrorCleansReturnedPartialOwnership(t *testing.T) {
	for i, detachErr := range []error{nil, syscall.EIO} {
		name := "detach_succeeds"
		if detachErr != nil {
			name = "detach_ambiguous"
		}
		t.Run(name, func(t *testing.T) {
			env := newRestoreEnv(t, 12361+i, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			stubRestoreWatcher(env.server)
			before, err := env.st.GetAttachment(env.id)
			require.NoError(t, err)
			partial := &fakeFilter{mode: filter.ModeBlockAll}
			partial.setDetachErr(detachErr)
			env.server.newFilter = func(string, string, apiv1.AttachmentType, apiv1.PolicyMode, apiv1.TcDirection, uint32) (filter.Filter, error) {
				return partial, syscall.EACCES
			}

			err = env.server.Start()
			require.Error(t, err)
			assert.ErrorIs(t, err, syscall.EACCES)
			if detachErr != nil {
				assert.ErrorIs(t, err, detachErr)
				assert.ErrorContains(t, err, "cleaning partially constructed replacement filter")
			}
			assert.Equal(t, 1, partial.detachCallCount(), "restore must clean constructor-returned partial ownership")
			assertRestoreDurableOwnershipRetained(t, env, before)
			assertDNSPortFree(t, env.port)
		})
	}
}

func TestRestoreAmbiguousTargetWatchFailureAbortsAndRetainsDurableRow(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		adopted bool
	}{
		{name: "adopted", port: 12349, adopted: true},
		{name: "recreated", port: 12350},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			stubRestoreWatcher(env.server)
			before, err := env.st.GetAttachment(env.id)
			require.NoError(t, err)
			if tt.adopted {
				env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
				env.mkPinDir(t)
			}
			identityCalls := 0
			env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) {
				identityCalls++
				return 1, nil
			})
			env.server.watchTarget = func(_ apiv1.AttachmentType, target string, identity uint64) (watchToken, error) {
				return watchToken{generation: 1, target: target, kind: watchKindInterface, identity: identity}, syscall.EIO
			}

			err = env.server.Start()
			require.Error(t, err)
			assert.Equal(t, 2, identityCalls, "target must remain stable through the pre-registration identity check")
			assert.ErrorIs(t, err, syscall.EIO)
			if tt.adopted {
				assert.Contains(t, err.Error(), "watching re-adopted attachment")
				assert.Equal(t, 1, env.adopted.closeCallCount())
				assert.Zero(t, env.adopted.detachCallCount())
				assert.DirExists(t, filepath.Join(env.pinRoot, env.id))
			} else {
				assert.Contains(t, err.Error(), "watching recreated attachment")
				require.Len(t, env.created, 1)
				assert.Equal(t, 1, env.created[0].detachCallCount())
			}
			assertRestoreDurableOwnershipRetained(t, env, before)
			assertDNSPortFree(t, env.port)
		})
	}
}

func TestRestoreExplicitTargetIdentityChangeCleansStaleAttachment(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		adopted bool
	}{
		{name: "adopted", port: 12351, adopted: true},
		{name: "recreated", port: 12352},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			stubRestoreWatcher(env.server)
			if tt.adopted {
				env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
				env.mkPinDir(t)
			}
			identityCalls := 0
			env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) {
				identityCalls++
				return 1, nil
			})
			env.server.watchTarget = func(_ apiv1.AttachmentType, target string, identity uint64) (watchToken, error) {
				return watchToken{generation: 1, target: target, kind: watchKindInterface, identity: identity},
					fmt.Errorf("interface identity changed during watch registration: was %d, now %d: %w", identity, identity+1, errTargetIdentityChanged)
			}

			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)
			assert.Equal(t, 2, identityCalls, "target must remain stable until the watcher's exact registration check")
			if tt.adopted {
				assert.Equal(t, 1, env.adopted.closeCallCount())
				assert.Zero(t, env.adopted.detachCallCount())
				assert.NoDirExists(t, filepath.Join(env.pinRoot, env.id))
			} else {
				require.Len(t, env.created, 1)
				assert.Equal(t, 1, env.created[0].detachCallCount())
			}
			_, getErr := env.st.GetAttachment(env.id)
			assert.ErrorIs(t, getErr, sql.ErrNoRows)
			env.server.mu.RLock()
			_, live := env.server.attachments[env.id]
			_, targeted := env.server.targetIndex["lo"]
			portClaimed := env.server.portPool[env.port]
			env.server.mu.RUnlock()
			assert.False(t, live)
			assert.False(t, targeted)
			assert.False(t, portClaimed)
			assertDNSPortFree(t, env.port)
		})
	}
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

func (e *restoreEnv) persistPinIdentity(t *testing.T, pinDir string, cleanupNeeded bool) {
	t.Helper()
	e.server.mu.Lock()
	state := e.server.attachments[e.id]
	require.NotNil(t, state)
	state.info.PinDir = pinDir
	state.info.PinPathKnown = true
	state.info.CleanupNeeded = cleanupNeeded
	state.cleanupNeeded = cleanupNeeded
	row := cloneAttachment(state.info)
	e.server.mu.Unlock()
	require.NoError(t, e.st.SaveAttachment(row))
}

func assertRestoreDurableOwnershipRetained(t *testing.T, env *restoreEnv, before *store.Attachment) {
	t.Helper()
	after, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	assert.Equal(t, before, after, "startup rollback must retain the exact durable attachment row")
	env.server.mu.RLock()
	state, live := env.server.attachments[env.id]
	indexedID, targeted := env.server.targetIndex[before.Target]
	portClaimed := env.server.portPool[env.port]
	if live {
		assert.Nil(t, state.filter)
		assert.Nil(t, state.dns)
		assert.False(t, state.watch.valid())
	}
	env.server.mu.RUnlock()
	require.True(t, live, "ambiguous startup failure must retain attachment ownership")
	assert.True(t, targeted)
	assert.Equal(t, env.id, indexedID)
	assert.True(t, portClaimed, "ambiguous startup failure must retain DNS port ownership")
}

func stubRestoreWatcher(server *Server) {
	server.startWatcher = func() error { return nil }
	server.stopWatcher = func() {}
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	root, err := canonicalizeConfiguredPath(t.TempDir())
	require.NoError(t, err)
	return root
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

	// The registry was reseeded from the adopted maps and gained the protected
	// DNS-listener bootstrap route.
	env.server.mu.RLock()
	state := env.server.attachments[env.id]
	env.server.mu.RUnlock()
	require.NotNil(t, state)
	assert.Same(t, filter.Filter(env.adopted), state.filter)
	assert.Equal(t, 3, state.ttls.len(), "adopted rules and DNS bootstrap must be tracked")

	// Control-plane resync (BulkUpdate) now declares {A, C}.
	require.NoError(t, env.server.ReconcileCIDRs(env.id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		[]parsedCIDR{{cidr: cidrA}, {cidr: cidrC}}, nil))

	mode, allowed, _, _ := env.adopted.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)
	assert.ElementsMatch(t, []string{cidrA.String(), cidrC.String(), testDNSBootstrapCIDR}, allowed,
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
	env.server.targetPresence = func(apiv1.AttachmentType, string) (bool, error) { return false, nil }

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

func TestRestoreDurableCleanupUsesPersistedPinPathAcrossConfigChanges(t *testing.T) {
	tests := []struct {
		name           string
		disablePinning bool
	}{
		{name: "pin_root_changed"},
		{name: "pinning_disabled", disablePinning: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12336, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL)
			oldRoot := canonicalTempDir(t)
			oldPinDir := filepath.Join(oldRoot, env.id)
			require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
			env.persistPinIdentity(t, oldPinDir, true)
			if tt.disablePinning {
				env.server.pinRoot = ""
			}
			stubRestoreWatcher(env.server)

			var removed []string
			env.server.removePinDir = func(path string) error {
				removed = append(removed, path)
				return os.RemoveAll(path)
			}

			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)
			assert.Equal(t, []string{oldPinDir}, removed)
			assert.NoDirExists(t, oldPinDir)
			rows, err := env.st.GetAllAttachments()
			require.NoError(t, err)
			assert.Empty(t, rows)
			env.server.mu.RLock()
			_, attached := env.server.attachments[env.id]
			_, targeted := env.server.targetIndex["lo"]
			env.server.mu.RUnlock()
			assert.False(t, attached)
			assert.False(t, targeted)
			assert.False(t, env.server.portPool[env.port], "cleanup must release the reserved DNS port")
		})
	}
}

func TestRestoreDurableCleanupFailureRemainsRetryable(t *testing.T) {
	tests := []struct {
		name       string
		failRemove bool
		failDelete bool
	}{
		{name: "pin_removal_failure", failRemove: true},
		{name: "row_deletion_failure", failDelete: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12337, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL)
			oldRoot := canonicalTempDir(t)
			oldPinDir := filepath.Join(oldRoot, env.id)
			require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
			env.persistPinIdentity(t, oldPinDir, true)
			stubRestoreWatcher(env.server)

			removeCalls := 0
			env.server.removePinDir = func(path string) error {
				removeCalls++
				require.Equal(t, oldPinDir, path)
				if tt.failRemove && removeCalls == 1 {
					return syscall.EIO
				}
				return os.RemoveAll(path)
			}
			deleteCalls := 0
			env.server.deleteAttachment = func(id string) error {
				deleteCalls++
				require.Equal(t, env.id, id)
				if tt.failDelete && deleteCalls == 1 {
					return syscall.EIO
				}
				return env.st.DeleteAttachment(id)
			}

			err := env.server.Start()
			require.Error(t, err)
			row, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
			assert.True(t, row.CleanupNeeded)
			assert.Equal(t, oldPinDir, row.PinDir)
			env.server.mu.RLock()
			state := env.server.attachments[env.id]
			assert.Same(t, state, env.server.attachments[env.server.targetIndex["lo"]])
			env.server.mu.RUnlock()
			assert.True(t, env.server.portPool[env.port], "failed cleanup must retain the reserved DNS port")

			stubRestoreWatcher(env.server) // abortStart resets watcher seams
			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)
			_, getErr = env.st.GetAttachment(env.id)
			assert.ErrorIs(t, getErr, sql.ErrNoRows)
			assert.NoDirExists(t, oldPinDir)
			assert.False(t, env.server.portPool[env.port])
			if tt.failRemove {
				assert.Equal(t, 2, removeCalls)
				assert.Equal(t, 1, deleteCalls)
			} else {
				assert.Equal(t, 2, removeCalls, "retry must tolerate the already-removed exact path")
				assert.Equal(t, 2, deleteCalls)
			}
		})
	}
}

func TestRestoreRejectsUnsafePersistedCleanupPinPathsWithoutMutation(t *testing.T) {
	tests := []struct {
		name string
		path func(*testing.T, *restoreEnv) string
	}{
		{name: "filesystem_root", path: func(_ *testing.T, _ *restoreEnv) string { return "/" }},
		{name: "unsafe_root_parent", path: func(_ *testing.T, env *restoreEnv) string { return filepath.Join(string(filepath.Separator), env.id) }},
		{name: "traversal", path: func(t *testing.T, env *restoreEnv) string { return t.TempDir() + "/child/../" + env.id }},
		{name: "wrong_attachment_leaf", path: func(t *testing.T, _ *restoreEnv) string { return filepath.Join(t.TempDir(), "some-other-attachment") }},
		{name: "relative", path: func(_ *testing.T, env *restoreEnv) string { return filepath.Join("pins", env.id) }},
		{name: "symlink_parent", path: func(t *testing.T, env *restoreEnv) string {
			realRoot := t.TempDir()
			link := filepath.Join(t.TempDir(), "linked-root")
			require.NoError(t, os.Symlink(realRoot, link))
			return filepath.Join(link, env.id)
		}},
		{name: "symlink_leaf", path: func(t *testing.T, env *restoreEnv) string {
			root := t.TempDir()
			require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(root, env.id)))
			return filepath.Join(root, env.id)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12338, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL)
			env.persistPinIdentity(t, tt.path(t, env), true)
			removeCalls, deleteCalls := 0, 0
			env.server.removePinDir = func(string) error {
				removeCalls++
				return nil
			}
			env.server.deleteAttachment = func(string) error {
				deleteCalls++
				return nil
			}

			err := env.server.Start()
			require.Error(t, err)
			assert.Zero(t, removeCalls, "invalid persisted identity must never reach recursive removal")
			assert.Zero(t, deleteCalls, "invalid persisted identity must retain its ownership row")
			row, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
			assert.True(t, row.CleanupNeeded)
		})
	}
}

func TestRestoreTargetGoneUsesOldPersistedPinRootAndAbortsOnRemovalFailure(t *testing.T) {
	tests := []struct {
		name         string
		removeErr    error
		wantStartErr bool
	}{
		{name: "cleanup_succeeds"},
		{name: "cleanup_fails", removeErr: syscall.EIO, wantStartErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12339, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			oldRoot := canonicalTempDir(t)
			oldPinDir := filepath.Join(oldRoot, env.id)
			require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
			env.persistPinIdentity(t, oldPinDir, false)
			env.server.targetPresence = func(apiv1.AttachmentType, string) (bool, error) { return false, nil }
			stubRestoreWatcher(env.server)
			newFilterCalls := 0
			env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
				newFilterCalls++
				return nil, os.ErrNotExist
			}
			var removed []string
			env.server.removePinDir = func(path string) error {
				removed = append(removed, path)
				if tt.removeErr != nil {
					return tt.removeErr
				}
				return os.RemoveAll(path)
			}

			err := env.server.Start()
			if tt.wantStartErr {
				require.Error(t, err)
				assert.Zero(t, newFilterCalls, "ambiguous pin cleanup must prevent replacement attachment")
				require.Len(t, removed, 1)
				assert.Equal(t, oldPinDir, removed[0])
				_, getErr := env.st.GetAttachment(env.id)
				require.NoError(t, getErr)
				assert.DirExists(t, oldPinDir)
				return
			}

			require.NoError(t, err)
			t.Cleanup(env.server.Stop)
			assert.Zero(t, newFilterCalls, "proven target absence must authorize cleanup without probing a replacement filter")
			assert.Equal(t, []string{oldPinDir}, removed,
				"gone-target cleanup removes the proven current pin path once")
			_, getErr := env.st.GetAttachment(env.id)
			assert.ErrorIs(t, getErr, sql.ErrNoRows)
		})
	}
}

func TestRestoreMissingTargetPreservesUncommittedAndFuturePins(t *testing.T) {
	tests := []struct {
		name      string
		inspect   func(string) (filter.PinnedSchemaState, error)
		wantCause error
	}{
		{
			name: "uncommitted",
			inspect: func(string) (filter.PinnedSchemaState, error) {
				return filter.PinnedSchemaUncommitted, nil
			},
		},
		{
			name: "future",
			inspect: func(string) (filter.PinnedSchemaState, error) {
				return filter.PinnedSchemaUncommitted, fmt.Errorf("%w: future marker", filter.ErrPinnedSchemaIncompatible)
			},
			wantCause: filter.ErrPinnedSchemaIncompatible,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12370+i, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			stubRestoreWatcher(env.server)
			env.mkPinDir(t)
			pinDir := filepath.Join(env.pinRoot, env.id)
			before, err := env.st.GetAttachment(env.id)
			require.NoError(t, err)
			env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) {
				return 0, os.ErrNotExist
			})
			env.server.inspectPinSchema = tt.inspect
			removeCalls, deleteCalls, newFilterCalls := 0, 0, 0
			env.server.removePinDir = func(string) error { removeCalls++; return nil }
			env.server.deleteAttachment = func(string) error { deleteCalls++; return nil }
			env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
				newFilterCalls++
				return &fakeFilter{}, nil
			}

			err = env.server.Start()
			require.ErrorContains(t, err, "preserving pinned state for missing attachment target")
			if tt.wantCause != nil {
				assert.ErrorIs(t, err, tt.wantCause)
			}
			assert.Zero(t, removeCalls)
			assert.Zero(t, deleteCalls)
			assert.Zero(t, newFilterCalls)
			assertRestoreDurableOwnershipRetained(t, env, before)
			assert.DirExists(t, pinDir)
		})
	}
}

func TestRestoreAmbiguousPinnedAdoptionFailureAbortsWithoutRemovingPins(t *testing.T) {
	tests := []struct {
		name             string
		port             int
		loadErr          error
		returnPartial    bool
		partialCloseErr  error
		wantCause        error
		wantCloseFailure bool
	}{
		{name: "io", port: 12340, loadErr: syscall.EIO, returnPartial: true, wantCause: syscall.EIO},
		{name: "permission", port: 12353, loadErr: syscall.EACCES, wantCause: syscall.EACCES},
		{name: "cgroup_wrong_kind_link_metadata", port: 12359, loadErr: fmt.Errorf("%w: pinned link has no cgroup metadata", filter.ErrPinnedSchemaIncompatible), wantCause: filter.ErrPinnedSchemaIncompatible},
		{name: "tcx_wrong_kind_link_metadata", port: 12360, loadErr: fmt.Errorf("%w: pinned link has no TCX metadata", filter.ErrPinnedSchemaIncompatible), wantCause: filter.ErrPinnedSchemaIncompatible},
		{
			name:             "discardable_primary_with_returned_partial_close_failure",
			port:             12357,
			loadErr:          fmt.Errorf("%w: required map missing", filter.ErrPinnedStateInvalid),
			returnPartial:    true,
			partialCloseErr:  syscall.EIO,
			wantCause:        syscall.EIO,
			wantCloseFailure: true,
		},
		{
			name: "discardable_primary_with_loader_propagated_close_failure",
			port: 12358,
			loadErr: errors.Join(
				fmt.Errorf("%w: required map missing", filter.ErrPinnedStateInvalid),
				fmt.Errorf("%w: %w", filter.ErrPinnedStateCloseFailed, syscall.EIO),
			),
			wantCause:        filter.ErrPinnedStateCloseFailed,
			wantCloseFailure: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			oldRoot := canonicalTempDir(t)
			oldPinDir := filepath.Join(oldRoot, env.id)
			require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
			env.persistPinIdentity(t, oldPinDir, false)
			before, err := env.st.GetAttachment(env.id)
			require.NoError(t, err)
			stubRestoreWatcher(env.server)
			var partial *fakeFilter
			if tt.returnPartial {
				partial = &fakeFilter{mode: filter.ModeAllowlist}
				partial.setCloseErr(tt.partialCloseErr)
			}
			env.server.loadPinnedFilter = func(string, string, apiv1.AttachmentType, apiv1.TcDirection) (filter.Filter, error) {
				if partial == nil {
					return nil, tt.loadErr
				}
				return partial, tt.loadErr
			}
			removeCalls, newFilterCalls := 0, 0
			env.server.removePinDir = func(string) error { removeCalls++; return nil }
			env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
				newFilterCalls++
				return &fakeFilter{}, nil
			}

			err = env.server.Start()
			require.ErrorContains(t, err, "re-adopting pinned BPF state")
			assert.ErrorIs(t, err, tt.wantCause)
			if tt.wantCloseFailure {
				assert.ErrorIs(t, err, syscall.EIO)
				assert.ErrorIs(t, err, filter.ErrPinnedStateInvalid)
			}
			assert.Zero(t, removeCalls, "ambiguous adoption failure must preserve potentially live pins")
			assert.Zero(t, newFilterCalls, "ambiguous adoption failure must not attach a replacement")
			if partial != nil {
				assert.Equal(t, 1, partial.closeCallCount(), "partial adoption handles must close without unpinning")
				assert.Zero(t, partial.detachCallCount())
			}
			assertRestoreDurableOwnershipRetained(t, env, before)
			assert.DirExists(t, oldPinDir)
			assertDNSPortFree(t, env.port)
		})
	}
}

func TestRestoreExplicitInvalidPinsAbortIfExactRemovalFails(t *testing.T) {
	env := newRestoreEnv(t, 12354, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	oldRoot := canonicalTempDir(t)
	oldPinDir := filepath.Join(oldRoot, env.id)
	require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
	env.persistPinIdentity(t, oldPinDir, false)
	before, err := env.st.GetAttachment(env.id)
	require.NoError(t, err)
	stubRestoreWatcher(env.server)
	env.server.loadPinnedFilter = func(string, string, apiv1.AttachmentType, apiv1.TcDirection) (filter.Filter, error) {
		return nil, fmt.Errorf("%w: required policy map is missing", filter.ErrPinnedStateInvalid)
	}
	removeCalls, newFilterCalls := 0, 0
	env.server.removePinDir = func(path string) error {
		removeCalls++
		require.Equal(t, oldPinDir, path)
		return syscall.EIO
	}
	env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
		newFilterCalls++
		return &fakeFilter{}, nil
	}

	err = env.server.Start()
	require.ErrorContains(t, err, "removing unusable pin dir")
	assert.Equal(t, 1, removeCalls)
	assert.Zero(t, newFilterCalls)
	assertRestoreDurableOwnershipRetained(t, env, before)
	assert.DirExists(t, oldPinDir)
}

func TestRestoreExplicitInvalidOrMismatchedPinsDiscardAndRecreate(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		loadErr error
	}{
		{
			name:    "structurally_incomplete",
			port:    12355,
			loadErr: fmt.Errorf("%w: required link is missing: %w", filter.ErrPinnedStateInvalid, os.ErrNotExist),
		},
		{
			name:    "target_reincarnated",
			port:    12356,
			loadErr: fmt.Errorf("%w: old ifindex no longer names target", filter.ErrPinnedTargetMismatch),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, tt.port, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			oldPinDir := filepath.Join(env.pinRoot, env.id)
			require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
			env.persistPinIdentity(t, oldPinDir, false)
			stubRestoreWatcher(env.server)
			env.server.loadPinnedFilter = func(string, string, apiv1.AttachmentType, apiv1.TcDirection) (filter.Filter, error) {
				return nil, tt.loadErr
			}
			var removed []string
			env.server.removePinDir = func(path string) error {
				removed = append(removed, path)
				return os.RemoveAll(path)
			}

			require.NoError(t, env.server.Start())
			t.Cleanup(env.server.Stop)
			assert.Equal(t, []string{oldPinDir}, removed)
			assert.NoDirExists(t, oldPinDir)
			loadPinnedCalls, newFilterCalls := env.counts()
			assert.Zero(t, loadPinnedCalls, "overridden loader owns its own call accounting")
			assert.Equal(t, 1, newFilterCalls)
			require.Len(t, env.created, 1)
			env.server.mu.RLock()
			state := env.server.attachments[env.id]
			env.server.mu.RUnlock()
			require.NotNil(t, state)
			assert.Same(t, filter.Filter(env.created[0]), state.filter)
			_, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
		})
	}
}

func TestRestoreAmbiguousTargetStateNeverCleansOrRecreates(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*restoreEnv)
	}{
		{name: "identity_lookup", configure: func(env *restoreEnv) {
			env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) { return 0, syscall.EIO })
		}},
		{name: "presence_lookup", configure: func(env *restoreEnv) {
			env.server.targetPresence = func(apiv1.AttachmentType, string) (bool, error) { return false, syscall.EIO }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12341, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			pinDir := filepath.Join(env.pinRoot, env.id)
			require.NoError(t, os.MkdirAll(pinDir, 0o700))
			env.persistPinIdentity(t, pinDir, false)
			stubRestoreWatcher(env.server)
			tt.configure(env)
			removeCalls, deleteCalls, newFilterCalls := 0, 0, 0
			env.server.removePinDir = func(string) error { removeCalls++; return nil }
			env.server.deleteAttachment = func(string) error { deleteCalls++; return nil }
			env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
				newFilterCalls++
				return &fakeFilter{}, nil
			}

			err := env.server.Start()
			require.Error(t, err)
			assert.Zero(t, removeCalls)
			assert.Zero(t, deleteCalls)
			assert.Zero(t, newFilterCalls)
			_, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
			assert.DirExists(t, pinDir)
		})
	}
}

func TestRestoreOrphanScanFailuresAbortStartup(t *testing.T) {
	tests := []struct {
		name       string
		failRead   bool
		failRemove bool
	}{
		{name: "read_failure", failRead: true},
		{name: "remove_failure", failRemove: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newRestoreEnv(t, 12342, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
			env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
			env.mkPinDir(t)
			env.persistPinIdentity(t, filepath.Join(env.pinRoot, env.id), false)
			orphan := filepath.Join(env.pinRoot, "orphan")
			require.NoError(t, os.MkdirAll(orphan, 0o700))
			if tt.failRead {
				env.server.readPinRoot = func(string) ([]os.DirEntry, error) { return nil, syscall.EIO }
			}
			if tt.failRemove {
				env.server.removePinDir = func(path string) error {
					if path == orphan {
						return syscall.EIO
					}
					return os.RemoveAll(path)
				}
			}

			err := env.server.Start()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "orphan")
			assert.DirExists(t, filepath.Join(env.pinRoot, env.id))
			assert.DirExists(t, orphan)
			_, getErr := env.st.GetAttachment(env.id)
			require.NoError(t, getErr)
			assert.Equal(t, 1, env.adopted.closeCallCount(), "aborted startup must close, not detach, adopted handles")
			assert.Zero(t, env.adopted.detachCallCount())
		})
	}
}

func TestRestorePreservesUncommittedCrashPartialOrphan(t *testing.T) {
	env := newRestoreEnv(t, 12352, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	env.mkPinDir(t)
	env.persistPinIdentity(t, filepath.Join(env.pinRoot, env.id), false)
	orphan := filepath.Join(env.pinRoot, "crash-partial")
	require.NoError(t, os.MkdirAll(orphan, 0o700))
	env.server.inspectPinSchema = func(path string) (filter.PinnedSchemaState, error) {
		if path == orphan {
			return filter.PinnedSchemaUncommitted, nil
		}
		return filter.PinnedSchemaCurrent, nil
	}
	removeCalls := 0
	env.server.removePinDir = func(path string) error {
		if path == orphan {
			removeCalls++
		}
		return os.RemoveAll(path)
	}

	err := env.server.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uncommitted schema marker")
	assert.Zero(t, removeCalls, "possible live partial enforcement must never be unpinned")
	assert.DirExists(t, orphan)
	assert.Equal(t, 1, env.adopted.closeCallCount(), "startup abort closes adopted handles but retains pins")
}

func TestRestoreSameIDCurrentRootDirectoryIsOrphanWhenLiveRowOwnsOldRoot(t *testing.T) {
	env := newRestoreEnv(t, 12343, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST)
	oldRoot := canonicalTempDir(t)
	oldPinDir := filepath.Join(oldRoot, env.id)
	currentSameIDDir := filepath.Join(env.pinRoot, env.id)
	require.NoError(t, os.MkdirAll(oldPinDir, 0o700))
	require.NoError(t, os.MkdirAll(currentSameIDDir, 0o700))
	env.persistPinIdentity(t, oldPinDir, false)
	env.adopted = &fakeFilter{mode: filter.ModeAllowlist}
	var removed []string
	env.server.removePinDir = func(path string) error {
		removed = append(removed, path)
		return os.RemoveAll(path)
	}

	require.NoError(t, env.server.Start())
	t.Cleanup(env.server.Stop)
	assert.Equal(t, []string{currentSameIDDir}, removed)
	assert.DirExists(t, oldPinDir)
	assert.NoDirExists(t, currentSameIDDir)
	loadPinned, newFilter := env.counts()
	assert.Equal(t, 1, loadPinned)
	assert.Zero(t, newFilter)
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
