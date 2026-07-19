package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func TestDetachTombstoneRetriesClosedFilterCleanupExactlyOnce(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	ff.setDetachErrors(errors.New("injected unpin failure"), nil)

	_, err := server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.Error(t, err)
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.True(t, row.CleanupNeeded)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
	server.mu.RLock()
	state := server.attachments[id]
	require.NotNil(t, state)
	assert.True(t, state.cleanupNeeded)
	assert.True(t, state.mutationsClosed)
	assert.Equal(t, id, server.targetIndex[state.info.Target])
	server.mu.RUnlock()
	assert.Empty(t, server.GetSyncAttachments())
	assert.Empty(t, server.GetAttachmentStats())
	before := ff.eventLog()
	require.Error(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
	assert.Equal(t, before, ff.eventLog())

	_, err = server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, 2, ff.detachCallCount())
	assert.Equal(t, 1, ff.closeCallCount(), "retry does not close already-closed handles")
	rows, err := st.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows)
	server.mu.RLock()
	assert.Empty(t, server.attachments)
	assert.Empty(t, server.targetIndex)
	server.mu.RUnlock()
}

func TestDetachDeleteFailureRetainsTombstoneUntilRetry(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	deleteCalls := 0
	server.deleteAttachment = func(id string) error {
		deleteCalls++
		if deleteCalls == 1 {
			return errors.New("injected delete failure")
		}
		return st.DeleteAttachment(id)
	}

	_, err := server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.Error(t, err)
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.True(t, row.CleanupNeeded)
	server.mu.RLock()
	state := server.attachments[id]
	require.NotNil(t, state)
	assert.Nil(t, state.filter, "proven filter removal is remembered across row-delete retry")
	server.mu.RUnlock()
	assert.Equal(t, 1, ff.detachCallCount())

	_, err = server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, 1, ff.detachCallCount(), "row-delete retry does not touch closed filter")
	assert.Equal(t, 2, deleteCalls)
}

func TestTargetRemovalRetainsCleanupOwnershipUntilLocalRetry(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	ff.setDetachErrors(errors.New("injected target-removal unpin failure"), nil)
	server.mu.Lock()
	state := server.attachments[id]
	token := watchToken{generation: 1, target: state.info.Target, kind: watchKindInterface, identity: 1}
	state.watch = token
	server.mu.Unlock()

	server.handleTargetRemoved(token)
	server.mu.RLock()
	assert.Same(t, state, server.attachments[id])
	assert.True(t, state.cleanupNeeded)
	assert.Equal(t, id, server.targetIndex[state.info.Target])
	assert.False(t, state.watch.valid())
	server.mu.RUnlock()
	_, err := server.Attach(context.Background(), &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: state.info.Target},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target already attached")

	_, err = server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.NoError(t, err)
	assert.Equal(t, 2, ff.detachCallCount())
}

func TestCleanupClosesAndDrainsMutationAdmissionBeforeBlockAll(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	expiring, err := filter.ParseCIDR("192.0.2.44/32")
	require.NoError(t, err)
	require.NoError(t, server.AllowCIDR(id, expiring, time.Millisecond))
	ff.setDetachErr(errors.New("retain cleanup for inspection"))

	enteredSave := make(chan struct{})
	releaseSave := make(chan struct{})
	originalSave := server.saveAttachment
	var once sync.Once
	server.saveAttachment = func(row *store.Attachment) error {
		if row.CleanupNeeded {
			once.Do(func() { close(enteredSave) })
			<-releaseSave
		}
		return originalSave(row)
	}
	detachDone := make(chan error, 1)
	go func() {
		_, err := server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
		detachDone <- err
	}()
	select {
	case <-enteredSave:
	case <-time.After(time.Second):
		t.Fatal("Detach did not reach tombstone save")
	}
	eventsAtBlockAll := ff.eventLog()
	require.Error(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
	require.Error(t, server.AllowCIDR(id, expiring, 0))
	server.sweepExpiredTTLs(time.Now().Add(time.Hour))
	assert.Empty(t, server.GetAttachmentStats())
	assert.Equal(t, eventsAtBlockAll, ff.eventLog(), "no mutation reaches filter after cleanup BLOCK_ALL")

	close(releaseSave)
	require.Error(t, <-detachDone)
	assert.Zero(t, ff.mutationAfterCloseCount())
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.True(t, row.CleanupNeeded)
}

func TestExtractPortHandlesJoinHostPortAddresses(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want int
	}{
		{name: "ipv4", addr: "127.0.0.1:12000", want: 12000},
		{name: "hostname", addr: "localhost:12001", want: 12001},
		{name: "ipv6", addr: "[::1]:12002", want: 12002},
		{name: "invalid missing brackets", addr: "::1:12002", want: 0},
		{name: "invalid port", addr: "127.0.0.1:not-a-port", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractPort(tt.addr))
		})
	}
}

func TestParseTcDirectionDefaultsToEgress(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want apiv1.TcDirection
	}{
		{name: "empty (pre-migration row or cgroup)", in: "", want: apiv1.TcDirection_TC_DIRECTION_EGRESS},
		{name: "unspecified", in: "TC_DIRECTION_UNSPECIFIED", want: apiv1.TcDirection_TC_DIRECTION_EGRESS},
		{name: "egress", in: "TC_DIRECTION_EGRESS", want: apiv1.TcDirection_TC_DIRECTION_EGRESS},
		{name: "ingress", in: "TC_DIRECTION_INGRESS", want: apiv1.TcDirection_TC_DIRECTION_INGRESS},
		{name: "garbage", in: "sideways", want: apiv1.TcDirection_TC_DIRECTION_EGRESS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseTcDirection(tt.in))
		})
	}
}

func TestServerModeChangesPersistToStoreAndSyncViews(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)

	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST))
	require.NoError(t, server.SetDnsMode(id, apiv1.DnsMode_DNS_MODE_DENYLIST))

	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeAllowlist, mode)

	stored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST.String(), stored.Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST.String(), stored.DnsMode)

	list, err := server.List(context.Background(), &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Attachments, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, list.Attachments[0].Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, list.Attachments[0].DnsMode)

	syncAttachments := server.GetSyncAttachments()
	require.Len(t, syncAttachments, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_ALLOWLIST, syncAttachments[0].Mode)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_DENYLIST, syncAttachments[0].DnsMode)
}

func TestListSkipsProtectedOccupancyWhileHeartbeatStatsRefreshesIt(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	ff.mu.Lock()
	ff.stats = filter.Stats{Allowed: 17, Blocked: 9}
	ff.mu.Unlock()

	listed, err := server.List(context.Background(), &apiv1.ListRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Attachments, 1)
	assert.Equal(t, id, listed.Attachments[0].Id)
	assert.Equal(t, uint64(17), listed.Attachments[0].PacketsAllowed)
	assert.Equal(t, uint64(9), listed.Attachments[0].PacketsBlocked)
	assert.Zero(t, ff.protectedOccupancyCallCount(),
		"List does not expose protected telemetry and must not walk four LPM maps")

	heartbeatStats := server.GetAttachmentStats()
	require.Len(t, heartbeatStats, 1)
	assert.Equal(t, id, heartbeatStats[0].Id)
	assert.Equal(t, 1, ff.protectedOccupancyCallCount(),
		"GetAttachmentStats is the fixed-cadence heartbeat refresh path")

	_, err = server.List(context.Background(), &apiv1.ListRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, ff.protectedOccupancyCallCount(),
		"repeated caller-driven List requests must not refresh protected occupancy")
}

func TestNewServerRestoresIPv6DNSPortReservation(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})

	require.NoError(t, st.SaveAttachment(&store.Attachment{
		ID:         "restored",
		Target:     "target",
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
		Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: net.JoinHostPort("::1", "12005"),
		Metadata:   map[string]string{},
		AttachedAt: time.Now().UTC(),
	}))

	server, err := NewServer(&config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "::1",
			PortMin:    12005,
			PortMax:    12005,
			Upstream:   "127.0.0.1:1",
		},
	}, st, zerolog.Nop(), "test")
	require.NoError(t, err)

	server.mu.RLock()
	defer server.mu.RUnlock()
	assert.True(t, server.portPool[12005])
}

// TestDaemonIDStableAcrossRestartAndUniquePerDataDir verifies the identity
// contract from control.proto ("stable across restarts"): a daemon built on a
// file-backed store reports the same UUID after a simulated restart, and two
// daemons with different data dirs never share an id (the old
// netfenced-<hostname> scheme collided for co-hosted daemons).
func TestDaemonIDStableAcrossRestartAndUniquePerDataDir(t *testing.T) {
	newServerAt := func(dataDir string) (*Server, *store.Store) {
		cfg := &config.Config{
			DataDir: dataDir,
			DNS: config.DNSConfig{
				ListenAddr: "127.0.0.1",
				PortMin:    12000,
				PortMax:    12010,
				Upstream:   "127.0.0.1:1",
			},
		}
		st, err := store.New(cfg.DBPath())
		require.NoError(t, err)
		server, err := NewServer(cfg, st, zerolog.Nop(), "test")
		require.NoError(t, err)
		return server, st
	}

	dirA := t.TempDir()
	serverA, stA := newServerAt(dirA)
	idA := serverA.DaemonID()
	_, err := uuid.Parse(idA)
	assert.NoError(t, err, "daemon id must be a valid UUID, got %q", idA)
	assert.NotContains(t, idA, "netfenced-", "daemon id must not be hostname-coupled")
	require.NoError(t, stA.Close())

	// Simulated restart: a fresh Server over the same data dir.
	restartedA, stA2 := newServerAt(dirA)
	defer stA2.Close()
	assert.Equal(t, idA, restartedA.DaemonID(), "daemon id must be stable across restarts")

	// A daemon with a different data dir must get a different id.
	serverB, stB := newServerAt(t.TempDir())
	defer stB.Close()
	assert.NotEqual(t, idA, serverB.DaemonID(), "daemons with different data dirs must not share an id")
}

func TestServerReplaceDNSRulesPersists(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	dnsServer.addIPToFilter("example.com", netIP(t, "203.0.113.20"), 32, 60)

	// DNS-populated IPs live only in the exact tier, never the authoritative
	// LPM map.
	_, allowed, _, _ := ff.snapshot()
	require.Empty(t, allowed)
	dnsAllowed, _ := ff.dnsSnapshot()
	require.Equal(t, []string{"203.0.113.20"}, dnsAllowed)

	require.NoError(t, server.ReplaceDNSRules(
		id,
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "allowed.test", IncludeSubdomains: true}},
		[]*apiv1.DomainEntry{{Domain: "denied.test"}},
	))
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed, "replacing away the owner promptly de-allows its exact key")

	stored, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST.String(), stored.DnsMode)

	dnsServer.mu.RLock()
	defer dnsServer.mu.RUnlock()
	assert.Equal(t, map[string]bool{"allowed.test": true}, dnsServer.allowedDomains)
	assert.Equal(t, map[string]bool{"denied.test": false}, dnsServer.deniedDomains)
}

func TestStopOwnsTerminalTeardownExactlyOnce(t *testing.T) {
	tests := []struct {
		name       string
		startOther func(*Server, string, *attachmentState) <-chan error
	}{
		{
			name: "concurrent_detach",
			startOther: func(server *Server, id string, _ *attachmentState) <-chan error {
				done := make(chan error, 1)
				go func() {
					_, err := server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
					done <- err
				}()
				return done
			},
		},
		{
			name: "concurrent_target_removal",
			startOther: func(server *Server, _ string, state *attachmentState) <-chan error {
				done := make(chan error, 1)
				go func() {
					server.handleTargetRemoved(state.watch)
					done <- nil
				}()
				return done
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _, id, ff, _ := newTestServerWithAttachment(t)
			server.mu.Lock()
			state := server.attachments[id]
			state.watch = watchToken{generation: 1, target: state.info.Target, kind: watchKindInterface, identity: 1}
			server.mu.Unlock()

			// Gate both terminal contenders on the exact state. Once Stop has
			// published stopping, Detach/removal must decline ownership and Stop
			// must close the state exactly once.
			state.reconcileMu.Lock()
			otherDone := tt.startOther(server, id, state)
			stopDone := make(chan struct{})
			go func() {
				defer close(stopDone)
				server.Stop()
			}()
			require.Eventually(t, func() bool {
				server.mu.RLock()
				defer server.mu.RUnlock()
				return server.stopping
			}, time.Second, time.Millisecond)
			state.reconcileMu.Unlock()

			select {
			case err := <-otherDone:
				if tt.name == "concurrent_detach" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "daemon is stopping")
				}
			case <-time.After(time.Second):
				t.Fatal("concurrent terminal path did not return")
			}
			select {
			case <-stopDone:
			case <-time.After(time.Second):
				t.Fatal("Stop did not finish")
			}
			assert.Equal(t, 1, ff.closeCallCount())
			assert.Zero(t, ff.detachCallCount())
			assert.Zero(t, ff.mutationAfterCloseCount())
		})
	}
}

func netIP(t *testing.T, value string) net.IP {
	t.Helper()
	ip := net.ParseIP(value)
	require.NotNil(t, ip)
	return ip
}

func TestAllocatePortSkipsExternallyOccupiedTCPAndUDP(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var occupiedPort int
			var closeOccupied func() error
			if network == "tcp" {
				occupied, err := net.Listen(network, "127.0.0.1:0")
				require.NoError(t, err)
				occupiedPort = occupied.Addr().(*net.TCPAddr).Port
				closeOccupied = occupied.Close
			} else {
				occupied, err := net.ListenPacket(network, "127.0.0.1:0")
				require.NoError(t, err)
				occupiedPort = occupied.LocalAddr().(*net.UDPAddr).Port
				closeOccupied = occupied.Close
			}
			defer closeOccupied()

			var freePort int
			for freePort == 0 {
				freeTCP, listenErr := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, listenErr)
				candidate := freeTCP.Addr().(*net.TCPAddr).Port
				freeUDP, packetErr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(candidate)))
				if packetErr == nil && candidate != occupiedPort {
					freePort = candidate
					require.NoError(t, freeUDP.Close())
				} else if freeUDP != nil {
					require.NoError(t, freeUDP.Close())
				}
				require.NoError(t, freeTCP.Close())
			}

			server := &Server{
				cfg:         &config.Config{DNS: config.DNSConfig{PortMin: occupiedPort, PortMax: freePort}},
				dnsListenIP: "127.0.0.1",
				portPool:    map[int]bool{occupiedPort: false, freePort: false},
			}
			got, err := server.allocatePort()
			require.NoError(t, err)
			assert.Equal(t, freePort, got)
			assert.False(t, server.portPool[occupiedPort])
			assert.True(t, server.portPool[freePort])
		})
	}
}
