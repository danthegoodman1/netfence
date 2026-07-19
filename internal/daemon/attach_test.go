package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
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
	server.newFilter = func(_, _ string, _ apiv1.AttachmentType, mode apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
		env.mu.Lock()
		defer env.mu.Unlock()
		if env.filterErr != nil {
			return nil, env.filterErr
		}
		ff := &fakeFilter{mode: apiModeToFilterMode(mode)}
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

func dispatchAttachAck(t *testing.T, client *ControlPlaneClient, id string, epoch uint64, ack *apiv1.SubscribedAck) {
	t.Helper()
	require.NotZero(t, epoch)
	pending := pendingSubscriptionFor(t, client, id)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case outbound := <-client.sendCh:
			if outbound.pending != pending {
				continue
			}
			require.Same(t, pending.sub, outbound.event.GetSubscribed())
		case <-deadline.C:
			t.Fatal("attach Subscribed was not queued")
		}
		break
	}
	require.True(t, client.beginPendingSend(pending, epoch))
	client.handleCommandForEpoch(&apiv1.ControlCommand{
		Id:      id,
		Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: ack},
	}, epoch)
}

// assertDNSPortFree verifies rollback did not leak either half of the
// dual-protocol DNS endpoint.
func assertDNSPortFree(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	udp, err := net.ListenPacket("udp", addr)
	require.NoError(t, err, "expected DNS port to be unbound after rollback")
	tcp, err := net.Listen("tcp", addr)
	require.NoError(t, err, "expected TCP DNS port to be unbound after rollback")
	require.NoError(t, tcp.Close())
	require.NoError(t, udp.Close())
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
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID := range cp.pendingAcks {
			id = pendingID
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

	var res attachResult
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Attach did not return")
	}

	require.Error(t, res.err, "Attach must fail when its attachment was detached during the ack wait")
	assert.Nil(t, res.resp)
	assert.Contains(t, res.err.Error(), "attachment detached")

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
	_, allowed, _, _ := filters[0].snapshot()
	assert.Equal(t, []string{testDNSBootstrapCIDR}, allowed, "assigned resolver must be reachable without a control-plane DNS-IP rule")

	// Detach releases everything exactly once.
	_, err = env.server.Detach(context.Background(), &apiv1.DetachRequest{Id: resp.Id})
	require.NoError(t, err)
	assert.Equal(t, 1, filters[0].closeCallCount())
	env.assertNoResidue(t)
}

func TestAttachBootstrapInsertionFailureRollsBackEverything(t *testing.T) {
	env := newAttachTestEnv(t, 12112)
	newFilter := env.server.newFilter
	env.server.newFilter = func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
		f, err := newFilter(pinDir, target, attachType, mode, direction, maxRuleEntries)
		if err == nil {
			f.(*fakeFilter).setAllowErr(syscall.ENOSPC)
		}
		return f, err
	}

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("bootstrap-fail-if0"))
	require.ErrorContains(t, err, "protected DNS bootstrap route")
	assert.Nil(t, resp)
	env.assertNoResidue(t)
	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Equal(t, 1, filters[0].detachCallCount())
	assertDNSPortFree(t, env.port)
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

	type attachResult struct {
		resp *apiv1.AttachResponse
		err  error
	}
	done := make(chan attachResult, 1)
	go func() {
		resp, err := env.server.Attach(context.Background(), attachInterfaceReq("acked-if0"))
		done <- attachResult{resp: resp, err: err}
	}()

	var id string
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID := range cp.pendingAcks {
			id = pendingID
			return true
		}
		return false
	}, time.Second, time.Millisecond)
	dispatchAttachAck(t, cp, id, 1, &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED})

	result := <-done
	require.NoError(t, result.err)
	require.NotNil(t, result.resp)
	require.Equal(t, id, result.resp.Id)

	attachments, _ := env.attachmentCounts()
	assert.Equal(t, 1, attachments)
	assert.True(t, env.portInUse())
	env.server.mu.RLock()
	state := env.server.attachments[id]
	needsResync := state != nil && state.needsResync
	env.server.mu.RUnlock()
	require.NotNil(t, state)
	assert.False(t, needsResync, "a newly attached/acked state is not a restored state")
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
	assertDNSPortFree(t, env.port)
}

func TestAttachRollbackOnDNSStartError(t *testing.T) {
	env := newAttachTestEnv(t, 12150)

	// Occupy the only pool port so the DNS server cannot bind.
	blocker, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(env.port)))
	require.NoError(t, err)
	defer blocker.Close()

	_, err = env.server.Attach(context.Background(), attachInterfaceReq("dnsfail-if0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding DNS server")

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
	assertDNSPortFree(t, env.port)

	// The row never landed: verify against a fresh store handle.
	reopened, err := store.New(env.dbPath)
	require.NoError(t, err)
	defer reopened.Close()
	rows, err := reopened.GetAllAttachments()
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestAttachPreRegistrationDetachFailureRetainsOwnedBlockAllState(t *testing.T) {
	env := newAttachTestEnv(t, 12161)
	newFilter := env.server.newFilter
	env.server.newFilter = func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
		f, err := newFilter(pinDir, target, attachType, mode, direction, maxRuleEntries)
		if err == nil {
			f.(*fakeFilter).setDetachErr(syscall.EIO)
		}
		return f, err
	}
	var saveCalls int
	env.server.saveAttachment = func(a *store.Attachment) error {
		saveCalls++
		if saveCalls == 1 {
			return errors.New("injected primary store save failure")
		}
		return env.st.SaveAttachment(a)
	}

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("degraded-pre-if0"))
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "saving attachment")
	assert.Contains(t, err.Error(), "detaching eBPF filter during attach rollback")
	require.Equal(t, 2, saveCalls, "rollback must persist the explicit degraded owner")
	require.Len(t, env.createdFilters(), 1)
	ff := env.createdFilters()[0]
	events := ff.eventLog()
	assert.Less(t,
		indexOfEvent(t, events, "set-mode "+filter.ModeBlockAll.String()),
		indexOfEvent(t, events, "detach"))

	rows, getErr := env.st.GetAllAttachments()
	require.NoError(t, getErr)
	require.Len(t, rows, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), rows[0].Mode)
	env.server.mu.RLock()
	state := env.server.attachments[rows[0].ID]
	require.NotNil(t, state)
	assert.Same(t, ff, state.filter)
	assert.Equal(t, rows[0].ID, env.server.targetIndex["degraded-pre-if0"])
	env.server.mu.RUnlock()
	assert.True(t, env.portInUse(), "ambiguous cleanup keeps port ownership")
	assertDNSPortFree(t, env.port)
}

func TestAttachPostRegistrationDetachFailureRetainsOwnedBlockAllState(t *testing.T) {
	env := newAttachTestEnv(t, 12162)
	newFilter := env.server.newFilter
	env.server.newFilter = func(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
		f, err := newFilter(pinDir, target, attachType, mode, direction, maxRuleEntries)
		if err == nil {
			f.(*fakeFilter).setDetachErr(syscall.EIO)
		}
		return f, err
	}
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 20*time.Millisecond, nil)
	env.server.SetControlPlaneClient(cp)

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("degraded-post-if0"))
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "control plane subscription failed")
	assert.Contains(t, err.Error(), "detaching eBPF filter during attach rollback")
	require.Len(t, env.createdFilters(), 1)
	ff := env.createdFilters()[0]
	events := ff.eventLog()
	assert.Less(t,
		indexOfEvent(t, events, "set-mode "+filter.ModeBlockAll.String()),
		indexOfEvent(t, events, "detach"))

	rows, getErr := env.st.GetAllAttachments()
	require.NoError(t, getErr)
	require.Len(t, rows, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), rows[0].Mode)
	env.server.mu.RLock()
	state := env.server.attachments[rows[0].ID]
	require.NotNil(t, state)
	assert.Same(t, ff, state.filter)
	assert.False(t, state.watch.valid(), "cleanup state owns the target without an active removal watch")
	assert.Equal(t, rows[0].ID, env.server.targetIndex["degraded-post-if0"])
	env.server.mu.RUnlock()
	assert.True(t, env.portInUse())
	assertDNSPortFree(t, env.port)
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
	assertDNSPortFree(t, env.port)

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

func TestAttachRollbackOnSubscribedAckApplyFailure(t *testing.T) {
	env := newAttachTestEnv(t, 12171)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	env.server.SetControlPlaneClient(cp)

	result := make(chan error, 1)
	go func() {
		_, err := env.server.Attach(context.Background(), attachInterfaceReq("badack-if0"))
		result <- err
	}()

	var id string
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID := range cp.pendingAcks {
			id = pendingID
			return true
		}
		return false
	}, time.Second, time.Millisecond)

	// Invalid full desired state fails before mutation, and the actual apply
	// error must reach SubscribeAndWait so Attach owns its ordinary rollback.
	dispatchAttachAck(t, cp, id, 1, &apiv1.SubscribedAck{
		Mode:       apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: "not-a-cidr"}},
	})

	select {
	case err := <-result:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing allow CIDR")
	case <-time.After(5 * time.Second):
		t.Fatal("Attach did not receive the SubscribedAck apply error")
	}

	env.assertNoResidue(t)
	filters := env.createdFilters()
	require.Len(t, filters, 1)
	assert.Equal(t, 1, filters[0].detachCallCount())
}

func TestZeroTimeoutInvalidSubscribedAckQuarantinesCommittedAttachment(t *testing.T) {
	env := newAttachTestEnv(t, 12174)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 0, nil)
	env.server.SetControlPlaneClient(cp)

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("zero-invalid-if0"))
	require.NoError(t, err)
	dispatchAttachAck(t, cp, resp.Id, 1, &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_UNSPECIFIED,
	})

	rows, err := env.st.GetAllAttachments()
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), rows[0].Mode)
	env.server.mu.RLock()
	state := env.server.attachments[resp.Id]
	require.NotNil(t, state)
	assert.True(t, state.mutationsClosed)
	env.server.mu.RUnlock()
	ff := env.createdFilters()[0]
	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	before := ff.eventLog()
	require.Error(t, env.server.SetFilterMode(resp.Id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
	assert.Equal(t, before, ff.eventLog(), "quarantined attachment rejects later policy mutation")
	assertQueuedErrorUnsubscribed(t, cp, resp.Id)
}

func TestZeroTimeoutSubscribedAckApplyFailureQuarantinesPartialDenylist(t *testing.T) {
	env := newAttachTestEnv(t, 12175)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 0, nil)
	env.server.SetControlPlaneClient(cp)

	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("zero-apply-if0"))
	require.NoError(t, err)
	ff := env.createdFilters()[0]
	ff.setDenyErr(errors.New("injected deny-map admission failure"))
	dispatchAttachAck(t, cp, resp.Id, 1, &apiv1.SubscribedAck{
		Mode:      apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "203.0.113.0/24"}},
	})

	mode, _, denied, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode, "partial DENYLIST apply is forced back to fail-closed")
	assert.Empty(t, denied)
	events := ff.eventLog()
	assert.Less(t,
		indexOfEvent(t, events, "set-mode "+filter.ModeDenylist.String()),
		indexOfEvent(t, events, "set-mode "+filter.ModeBlockAll.String()))
	row, err := env.st.GetAttachment(resp.Id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
	assertQueuedErrorUnsubscribed(t, cp, resp.Id)
}

func TestCommittedAttachmentDNSListenerDeathQuarantinesBlockAll(t *testing.T) {
	env := newAttachTestEnv(t, 12176)
	resp, err := env.server.Attach(context.Background(), attachInterfaceReq("dns-fatal-if0"))
	require.NoError(t, err)

	env.server.mu.RLock()
	state := env.server.attachments[resp.Id]
	require.NotNil(t, state)
	dnsServer := state.dns
	env.server.mu.RUnlock()
	dnsServer.serverMu.Lock()
	udpConn := dnsServer.udpConn
	dnsServer.serverMu.Unlock()
	require.NotNil(t, udpConn)
	require.NoError(t, udpConn.Close())

	require.Eventually(t, func() bool {
		env.server.mu.RLock()
		defer env.server.mu.RUnlock()
		return state.mutationsClosed
	}, time.Second, time.Millisecond)
	row, err := env.st.GetAttachment(resp.Id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
	mode, _, _, _ := env.createdFilters()[0].snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	require.Error(t, env.server.SetFilterMode(resp.Id, apiv1.PolicyMode_POLICY_MODE_DISABLED))
}

func assertQueuedErrorUnsubscribed(t *testing.T, cp *ControlPlaneClient, id string) {
	t.Helper()
	for {
		select {
		case outbound := <-cp.sendCh:
			unsub := outbound.event.GetUnsubscribed()
			if unsub == nil {
				continue
			}
			assert.Equal(t, id, unsub.Id)
			assert.Equal(t, apiv1.UnsubscribeReason_UNSUBSCRIBE_REASON_ERROR, unsub.Reason)
			return
		case <-time.After(time.Second):
			t.Fatal("error Unsubscribed was not queued")
		}
	}
}

func TestAttachOwnsClaimedAckApplyBeforeCommit(t *testing.T) {
	env := newAttachTestEnv(t, 12172)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, 75*time.Millisecond, nil)
	env.server.SetControlPlaneClient(cp)

	attachDone := make(chan error, 1)
	go func() {
		_, err := env.server.Attach(context.Background(), attachInterfaceReq("timeout-claimed-ack-if0"))
		attachDone <- err
	}()

	var id string
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID := range cp.pendingAcks {
			id = pendingID
			return true
		}
		return false
	}, time.Second, time.Millisecond)
	filters := env.createdFilters()
	require.Len(t, filters, 1)
	ff := filters[0]
	entered := make(chan struct{})
	release := make(chan struct{})
	ff.blockSetMode(entered, release)
	pending := pendingSubscriptionFor(t, cp, id)
	require.True(t, cp.beginPendingSend(pending, 1))

	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		cp.handleCommandForEpoch(&apiv1.ControlCommand{
			Id: id,
			Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
				Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			}},
		}, 1)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ack did not reach gated apply")
	}

	// The recv path only validates/delivers an attach-purpose ack. Attach owns
	// the gated policy mutation and has committed teardown ownership before it
	// begins, so no rollback can close underneath the apply.
	select {
	case err := <-attachDone:
		t.Fatalf("Attach rollback interleaved with claimed ack: %v", err)
	case <-time.After(125 * time.Millisecond):
	}
	close(release)
	select {
	case <-ackDone:
	case <-time.After(time.Second):
		t.Fatal("ack did not finish after gate release")
	}
	select {
	case err := <-attachDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Attach did not finish after its ack apply was released")
	}

	attachments, targets := env.attachmentCounts()
	assert.Equal(t, 1, attachments)
	assert.Equal(t, 1, targets)
	assert.Zero(t, ff.detachCallCount())
	assert.Zero(t, ff.mutationAfterCloseCount())
}

func TestBoundedSubscribedAckBlocksFollowingStreamCommandUntilAttachApply(t *testing.T) {
	env := newAttachTestEnv(t, 12177)
	cp := NewControlPlaneClient("", env.server, zerolog.Nop(), nil, time.Second, nil)
	env.server.SetControlPlaneClient(cp)
	attachDone := make(chan error, 1)
	go func() {
		_, err := env.server.Attach(context.Background(), attachInterfaceReq("ordered-ack-if0"))
		attachDone <- err
	}()

	var id string
	require.Eventually(t, func() bool {
		cp.pendingAcksMu.Lock()
		defer cp.pendingAcksMu.Unlock()
		for pendingID := range cp.pendingAcks {
			id = pendingID
			return true
		}
		return false
	}, time.Second, time.Millisecond)
	ff := env.createdFilters()[0]
	entered, release := make(chan struct{}), make(chan struct{})
	ff.blockSetMode(entered, release)
	pending := pendingSubscriptionFor(t, cp, id)
	require.True(t, cp.beginPendingSend(pending, 1))

	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		cp.handleCommandForEpoch(&apiv1.ControlCommand{
			Id: id,
			Command: &apiv1.ControlCommand_SubscribedAck{SubscribedAck: &apiv1.SubscribedAck{
				Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
			}},
		}, 1)
		cp.handleCommandForEpoch(&apiv1.ControlCommand{
			Id: id, CommandId: "after-ack",
			Command: &apiv1.ControlCommand_SetMode{SetMode: &apiv1.SetMode{
				Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
			}},
		}, 1)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Attach-owned ack did not reach gated apply")
	}
	select {
	case <-streamDone:
		t.Fatal("following stream command ran before Attach completed ack apply")
	case <-time.After(50 * time.Millisecond):
	}
	assert.NotContains(t, ff.eventLog(), "set-mode "+filter.ModeDenylist.String())

	close(release)
	require.NoError(t, <-attachDone)
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("stream did not resume after Attach completed ack apply")
	}
	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeDenylist, mode)
	row, err := env.st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_DENYLIST.String(), row.Mode)
}

// Stop first publishes terminal admission state, then waits for every Attach
// that passed the admission gate. An Attach blocked in filter construction
// must therefore roll back before Stop snapshots terminal ownership; it can
// never register a new attachment behind that snapshot.
func TestStopWaitsForInFlightAttachRollbackBeforeSnapshot(t *testing.T) {
	env := newAttachTestEnv(t, 12173)
	entered := make(chan struct{})
	release := make(chan struct{})
	ff := &fakeFilter{}
	var once sync.Once
	env.server.newFilter = func(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
		once.Do(func() { close(entered) })
		<-release
		env.mu.Lock()
		env.filters = append(env.filters, ff)
		env.mu.Unlock()
		return ff, nil
	}

	attachDone := make(chan error, 1)
	go func() {
		_, err := env.server.Attach(context.Background(), attachInterfaceReq("stop-race-if0"))
		attachDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Attach did not reach blocked filter construction")
	}

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		env.server.Stop()
	}()
	require.Eventually(t, func() bool {
		env.server.mu.RLock()
		defer env.server.mu.RUnlock()
		return env.server.stopping
	}, time.Second, time.Millisecond)
	select {
	case <-stopDone:
		t.Fatal("Stop returned before the admitted Attach rolled back")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-attachDone:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "daemon is stopping")
	case <-time.After(time.Second):
		t.Fatal("Attach did not roll back after filter construction resumed")
	}
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after the in-flight Attach rolled back")
	}

	env.assertNoResidue(t)
	assert.Equal(t, 1, ff.detachCallCount())
	assert.Equal(t, 1, ff.closeCallCount())
	assert.Zero(t, ff.mutationAfterCloseCount())
	assertDNSPortFree(t, env.port)
}
