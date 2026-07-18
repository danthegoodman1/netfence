package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
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

// attachTestEnv builds a Server backed by a real on-disk store and a
// fake-filter constructor (via the Server.newFilter test seam), with a
// single-port DNS pool so port-pool hygiene is directly observable.
type attachTestEnv struct {
	server *Server
	st     *store.Store
	dbPath string
	port   int

	mu        sync.Mutex
	filters   []*fakeFilter
	filterErr error
}

func newAttachTestEnv(t *testing.T, port int) *attachTestEnv {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "netfence.db")
	st, err := store.New(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    port,
			PortMax:    port,
			Upstream:   "127.0.0.1:1",
		},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "test")
	require.NoError(t, err)
	server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) { return 1, nil })

	env := &attachTestEnv{server: server, st: st, dbPath: dbPath, port: port}
	server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		if env.filterErr != nil {
			return nil, env.filterErr
		}
		ff := &fakeFilter{}
		env.filters = append(env.filters, ff)
		return ff, nil
	}

	// Stop any live DNS servers so later tests can reuse ports.
	t.Cleanup(func() {
		server.mu.Lock()
		states := make([]*attachmentState, 0, len(server.attachments))
		for _, state := range server.attachments {
			states = append(states, state)
		}
		server.mu.Unlock()
		for _, state := range states {
			if state.dns != nil {
				_ = state.dns.Stop()
			}
		}
	})

	return env
}

func (e *attachTestEnv) createdFilters() []*fakeFilter {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]*fakeFilter(nil), e.filters...)
}

func (e *attachTestEnv) setFilterErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.filterErr = err
}

func (e *attachTestEnv) portInUse() bool {
	e.server.mu.RLock()
	defer e.server.mu.RUnlock()
	return e.server.portPool[e.port]
}

func (e *attachTestEnv) attachmentCounts() (attachments, targets int) {
	e.server.mu.RLock()
	defer e.server.mu.RUnlock()
	return len(e.server.attachments), len(e.server.targetIndex)
}

// assertNoResidue asserts the zero-leak invariant after a failed Attach: the
// port is back in the free pool, there is no store row, and no
// attachments/targetIndex entry survives.
func (e *attachTestEnv) assertNoResidue(t *testing.T) {
	t.Helper()
	attachments, targets := e.attachmentCounts()
	assert.Zero(t, attachments, "attachments map must be empty")
	assert.Zero(t, targets, "targetIndex must be empty")
	assert.False(t, e.portInUse(), "DNS port must be released back to the pool")

	rows, err := e.st.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows, "store must have no attachment rows")
}

func attachInterfaceReq(name string) *apiv1.AttachRequest {
	return &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_InterfaceName{InterfaceName: name},
	}
}

// assertUDPPortFree asserts nothing (i.e. no leaked DNS server) is bound to
// the port.
func assertUDPPortFree(t *testing.T, port int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err, "expected DNS port to be unbound after rollback")
	require.NoError(t, conn.Close())
}

// TestAttachDetachRaceDuringSubscribeAck is the core race regression: an
// Attach blocked in SubscribeAndWait loses its attachment to a concurrent
// Detach. Attach must then return an ERROR (returning success would hand the
// caller an attachment that nothing is enforcing) and must not tear anything
// down a second time — the Detach already owned the full teardown.
func TestAttachDetachRaceDuringSubscribeAck(t *testing.T) {
	env := newAttachTestEnv(t, 12100)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 30*time.Second, nil)
	env.server.SetControlPlaneClient(cp)

	type attachResult struct {
		resp *apiv1.AttachResponse
		err  error
	}
	resCh := make(chan attachResult, 1)
	go func() {
		resp, err := env.server.Attach(context.Background(), attachInterfaceReq("race-if0"))
		resCh <- attachResult{resp: resp, err: err}
	}()

	// Wait for Attach to reach SubscribeAndWait: the pending-ack registration
	// happens before it blocks, and its key is the attachment ID.
	var id string
	var ackCh chan SubscribedAckResult
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID, ch := range cp.pendingAcks {
			id, ackCh = pendingID, ch
			return true
		}
		return false
	}, 10*time.Second, time.Millisecond, "Attach never reached SubscribeAndWait")

	// Concurrent Detach completes fully while Attach waits for the ack.
	_, err := env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: id})
	require.NoError(t, err)

	filters := env.createdFilters()
	require.Len(t, filters, 1)
	require.Equal(t, 1, filters[0].closeCallCount(), "Detach owns exactly one filter close")
	require.False(t, env.portInUse(), "Detach must free the DNS port")

	// Simulate the freed port being claimed immediately by a newcomer. The
	// in-flight Attach must NOT release it again on its way out (a double
	// release would hand one port to two attachments).
	env.server.mu.Lock()
	env.server.portPool[env.port] = true
	env.server.mu.Unlock()

	// Release the ack: the control plane says "subscribed", but the
	// attachment is gone.
	ackCh <- SubscribedAckResult{Ack: &apiv1.SubscribedAck{}}

	var res attachResult
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Attach did not return")
	}

	require.Error(t, res.err, "Attach must fail when its attachment was detached during the ack wait")
	assert.Nil(t, res.resp)
	assert.Contains(t, res.err.Error(), "detached during setup")

	// Exactly-once teardown: no double close, no double port release, no
	// resurrected bookkeeping, no store row.
	assert.Equal(t, 1, filters[0].closeCallCount(), "Attach must not close the filter the Detach already closed")
	attachments, targets := env.attachmentCounts()
	assert.Zero(t, attachments)
	assert.Zero(t, targets)
	env.server.mu.RLock()
	stillClaimed := env.server.portPool[env.port]
	env.server.mu.RUnlock()
	assert.True(t, stillClaimed, "Attach must not release a port it no longer owns")

	rows, err := env.st.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestAttachHappyPathNoControlPlane pins the seam-preserving happy path: no
// CP configured, Attach commits and everything exists exactly once.
func TestAttachHappyPathNoControlPlane(t *testing.T) {
	env := newAttachTestEnv(t, 12110)

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("ok-if0"))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Id)
	assert.Equal(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port)), resp.DnsAddress)

	attachments, targets := env.attachmentCounts()
	assert.Equal(t, 1, attachments)
	assert.Equal(t, 1, targets)
	assert.True(t, env.portInUse())

	row, err := env.st.GetAttachment(resp.Id)
	require.NoError(t, err)
	assert.Equal(t, "ok-if0", row.Target)

	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Zero(t, filters[0].closeCallCount())

	// Detach releases everything exactly once.
	_, err = env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: resp.Id})
	require.NoError(t, err)
	assert.Equal(t, 1, filters[0].closeCallCount())
	env.assertNoResidue(t)
}

// TestAttachRejectsInterfaceIdentityChangeBeforeWatchRegistration proves the
// filter and watcher cannot silently bind different same-name interfaces. The
// fake filter attaches while the name denotes identity 401, then simulates a
// delete+recreate before WatchInterface; Attach must roll the filter back and
// publish no attachment or watch for identity 402.
func TestAttachRejectsInterfaceIdentityChangeBeforeWatchRegistration(t *testing.T) {
	env := newAttachTestEnv(t, 12111)
	var identity atomic.Uint64
	identity.Store(401)
	env.server.setTargetIdentityResolver(func(apiv1.AttachmentType, string) (uint64, error) {
		return identity.Load(), nil
	})

	newFilter := env.server.newFilter
	env.server.newFilter = func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
		f, err := newFilter(pinDir, target, attachType, mode, direction, maxRuleEntries)
		identity.Store(402) // same name now denotes a different interface
		return f, err
	}

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("identity-race-if0"))
	require.Error(t, err)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "target identity changed")
	env.assertNoResidue(t)

	filters := env.createdFilters()
	require.Len(t, filters, 1)
	require.Equal(t, 1, filters[0].detachCallCount(), "filter attached to the old identity must be rolled back")
}

// TestAttachHappyPathWithControlPlaneAck pins the success path through the
// commit check: an acked subscribe still returns success.
func TestAttachHappyPathWithControlPlaneAck(t *testing.T) {
	env := newAttachTestEnv(t, 12120)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 30*time.Second, nil)
	env.server.SetControlPlaneClient(cp)

	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
			cp.pendingAcksMu.Lock()
			for id, ch := range cp.pendingAcks {
				delete(cp.pendingAcks, id)
				ch <- SubscribedAckResult{Ack: &apiv1.SubscribedAck{}}
			}
			cp.pendingAcksMu.Unlock()
		}
	}()

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("acked-if0"))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Id)

	attachments, _ := env.attachmentCounts()
	assert.Equal(t, 1, attachments)
	assert.True(t, env.portInUse())
}

func TestAttachRollbackOnPortExhaustion(t *testing.T) {
	env := newAttachTestEnv(t, 12130)

	// First attach consumes the single pool port.
	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("full-if0"))
	require.NoError(t, err)

	// Second attach must fail at allocation and leave zero residue of its own.
	_, err = env.server.Attach(context.Background(), attachInterfaceReq("full-if1"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no available DNS ports")

	require.Len(t, env.createdFilters(), 1, "failed attach must not create a filter")
	attachments, targets := env.attachmentCounts()
	assert.Equal(t, 1, attachments, "only the first attachment survives")
	assert.Equal(t, 1, targets)
	assert.True(t, env.portInUse(), "first attachment keeps its port")

	rows, err := env.st.GetAllAttachments()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, resp.Id, rows[0].ID)
}

func TestAttachRollbackOnFilterCreateError(t *testing.T) {
	env := newAttachTestEnv(t, 12140)
	env.setFilterErr(errors.New("injected filter failure"))

	_, err := env.server.Attach(context.Background(), attachInterfaceReq("filtfail-if0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating eBPF filter")

	env.assertNoResidue(t)
	assert.Empty(t, env.createdFilters())
	assertUDPPortFree(t, env.port)
}

func TestAttachRollbackOnDNSStartError(t *testing.T) {
	env := newAttachTestEnv(t, 12150)

	// Occupy the only pool port so the DNS server cannot bind.
	blocker, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port)))
	require.NoError(t, err)
	defer blocker.Close()

	_, err = env.server.Attach(context.Background(), attachInterfaceReq("dnsfail-if0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "starting DNS server")

	env.assertNoResidue(t)
	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Equal(t, 1, filters[0].closeCallCount(), "staged filter must be closed exactly once")
}

func TestAttachRollbackOnStoreSaveError(t *testing.T) {
	env := newAttachTestEnv(t, 12160)

	// Closing the store makes SaveAttachment fail deterministically while
	// filter creation and the DNS bind still succeed — exercising the
	// unwind of both staged resources.
	require.NoError(t, env.st.Close())

	_, err := env.server.Attach(context.Background(), attachInterfaceReq("savefail-if0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "saving attachment")

	attachments, targets := env.attachmentCounts()
	assert.Zero(t, attachments)
	assert.Zero(t, targets)
	assert.False(t, env.portInUse())

	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Equal(t, 1, filters[0].closeCallCount(), "staged filter must be closed exactly once")
	assertUDPPortFree(t, env.port)

	// The row never landed: verify against a fresh store handle.
	reopened, err := store.New(env.dbPath)
	require.NoError(t, err)
	defer reopened.Close()
	rows, err := reopened.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows)
}

// TestAttachRollbackOnSubscribeFailure verifies the full unwind when the
// control-plane subscribe times out: everything staged (including the
// registered attachment) is torn down, and the CP is told via an
// ERROR-reason Unsubscribed.
func TestAttachRollbackOnSubscribeFailure(t *testing.T) {
	env := newAttachTestEnv(t, 12170)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 50*time.Millisecond, nil)
	env.server.SetControlPlaneClient(cp)

	_, err := env.server.Attach(context.Background(), attachInterfaceReq("subfail-if0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control plane subscription failed")

	env.assertNoResidue(t)
	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Equal(t, 1, filters[0].closeCallCount())
	assertUDPPortFree(t, env.port)

	// Outbound queue: Subscribed first, then the ERROR Unsubscribed.
	var events []*apiv1.DaemonEvent
drain:
	for {
		select {
		case out := <-cp.sendCh:
			events = append(events, out.event)
		default:
			break drain
		}
	}
	require.Len(t, events, 2)
	require.NotNil(t, events[0].GetSubscribed())
	unsub := events[1].GetUnsubscribed()
	require.NotNil(t, unsub)
	assert.Equal(t, apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR, unsub.Reason)
}
