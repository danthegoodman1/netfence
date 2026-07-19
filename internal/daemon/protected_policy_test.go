package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func waitProtectedJournalCheckpoint(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for protected-policy journal checkpoint %s", name)
	}
}

type protectedRegistryEntrySnapshot struct {
	systemLive bool
	cpLive     bool
	cpDeadline time.Time
	inFilter   bool
}

func snapshotProtectedRegistry(reg *ttlRegistry) map[ttlKey]protectedRegistryEntrySnapshot {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	out := make(map[ttlKey]protectedRegistryEntrySnapshot, len(reg.entries))
	for key, entry := range reg.entries {
		out[key] = protectedRegistryEntrySnapshot{
			systemLive: entry.systemLive,
			cpLive:     entry.cpLive,
			cpDeadline: entry.cpDeadline,
			inFilter:   entry.inFilter,
		}
	}
	return out
}

// A healthy intentional BLOCK_ALL is otherwise indistinguishable at restart
// from BLOCK_ALL staged by an interrupted safety-sensitive mutation. Exercise
// the exact durable ordering for every such incremental class: the marker is
// persisted before the target syscall, remains durable after that syscall and
// before its clear, and disappears only after the whole operation succeeds.
func TestIntentionalBlockAllSafetyMutationsAreCrashJournaled(t *testing.T) {
	for _, mutation := range []string{"deny_add", "allow_remove", "clear", "mode_change", "ttl_allow_expiry"} {
		t.Run(mutation, func(t *testing.T) {
			server, st, id, ff, _ := newTestServerWithAttachment(t)
			clock := newFakeClock()
			server.now = clock.Now
			cidr := mustCIDR(t, "198.51.100.0/24")

			switch mutation {
			case "allow_remove", "clear":
				require.NoError(t, server.AllowCIDR(id, cidr, 0))
			case "ttl_allow_expiry":
				require.NoError(t, server.AllowCIDR(id, cidr, time.Second))
				clock.Advance(time.Second)
			}
			if mutation == "clear" {
				require.NoError(t, server.DenyCIDR(id, mustCIDR(t, "203.0.113.0/24"), 0))
			}
			require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))

			journalPersisted := make(chan struct{})
			releaseBeforeMutation := make(chan struct{})
			clearEntered := make(chan struct{})
			releaseClear := make(chan struct{})
			var releaseBeforeOnce, releaseClearOnce sync.Once
			defer releaseBeforeOnce.Do(func() { close(releaseBeforeMutation) })
			defer releaseClearOnce.Do(func() { close(releaseClear) })
			var sawJournal, sawClear atomic.Bool
			originalSave := server.saveAttachment
			server.saveAttachment = func(row *store.Attachment) error {
				if row.PolicyDegradedReason == policyMutationInProgress && sawJournal.CompareAndSwap(false, true) {
					if err := originalSave(row); err != nil {
						return err
					}
					close(journalPersisted)
					<-releaseBeforeMutation
					return nil
				}
				if row.PolicyDegradedReason == "" && sawJournal.Load() && sawClear.CompareAndSwap(false, true) {
					close(clearEntered)
					<-releaseClear
				}
				return originalSave(row)
			}

			done := make(chan error, 1)
			go func() {
				switch mutation {
				case "deny_add":
					done <- server.DenyCIDR(id, cidr, 0)
				case "allow_remove":
					done <- server.RemoveAllowedCIDR(id, cidr)
				case "clear":
					done <- server.ClearRules(id)
				case "mode_change":
					done <- server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED)
				case "ttl_allow_expiry":
					server.sweepExpiredTTLs(clock.Now())
					done <- nil
				}
			}()

			waitProtectedJournalCheckpoint(t, journalPersisted, "after durable marker, before target mutation")
			row, err := st.GetAttachment(id)
			require.NoError(t, err)
			assert.Equal(t, policyMutationInProgress, row.PolicyDegradedReason)
			mode, allowed, denied, _ := ff.snapshot()
			switch mutation {
			case "deny_add":
				assert.Empty(t, denied)
			case "allow_remove", "clear", "ttl_allow_expiry":
				assert.Contains(t, allowed, cidr.String())
			case "mode_change":
				assert.Equal(t, filter.ModeBlockAll, mode)
			}

			releaseBeforeOnce.Do(func() { close(releaseBeforeMutation) })
			waitProtectedJournalCheckpoint(t, clearEntered, "after target mutation, before durable clear")
			row, err = st.GetAttachment(id)
			require.NoError(t, err)
			assert.Equal(t, policyMutationInProgress, row.PolicyDegradedReason,
				"effective mutation must not erase restart intent before the clear commits")
			mode, allowed, denied, _ = ff.snapshot()
			switch mutation {
			case "deny_add":
				assert.Contains(t, denied, cidr.String())
			case "allow_remove", "ttl_allow_expiry":
				assert.NotContains(t, allowed, cidr.String())
			case "clear":
				assert.Empty(t, allowed)
				assert.Empty(t, denied)
			case "mode_change":
				assert.Equal(t, filter.ModeDisabled, mode)
			}

			releaseClearOnce.Do(func() { close(releaseClear) })
			require.NoError(t, <-done)
			row, err = st.GetAttachment(id)
			require.NoError(t, err)
			assert.Empty(t, row.PolicyDegradedReason)
			stats := server.GetAttachmentStats()
			require.Len(t, stats, 1)
			assert.False(t, stats[0].PolicyDegraded,
				"healthy intentional BLOCK_ALL outside a journal must not report degraded")
		})
	}
}

func TestProtectedMutationJournalClearFailureBecomesStableDegradation(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	cidr := mustCIDR(t, "203.0.113.0/24")

	originalSave := server.saveAttachment
	var journaled, failedClear atomic.Bool
	server.saveAttachment = func(row *store.Attachment) error {
		if row.PolicyDegradedReason == policyMutationInProgress {
			journaled.Store(true)
		}
		if journaled.Load() && row.PolicyDegradedReason == "" && failedClear.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return originalSave(row)
	}

	err := server.DenyCIDR(id, cidr, 0)
	require.ErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	mode, _, denied, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	assert.Contains(t, denied, cidr.String(), "the effective deny is retained while policy remains fail-closed")
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Equal(t, policyDegradedDenyAdd, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
}

func TestProtectedMutationJournalMarkerSaveFailurePreventsTargetSyscall(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	beforeEvents := ff.eventLog()
	originalSave := server.saveAttachment
	var failed atomic.Bool
	server.saveAttachment = func(row *store.Attachment) error {
		if row.PolicyDegradedReason == policyMutationInProgress && failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return originalSave(row)
	}

	err := server.DenyCIDR(id, mustCIDR(t, "198.51.100.0/24"), 0)
	require.ErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	for _, event := range ff.eventLog()[len(beforeEvents):] {
		assert.NotContains(t, event, "deny ", "target map syscall must wait for the durable marker")
	}
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Equal(t, policyDegradedDenyAdd, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
}

func TestModeChangeIntermediateSaveFailureReturnsToDurableBlockAll(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	originalSave := server.saveAttachment
	var failed atomic.Bool
	server.saveAttachment = func(row *store.Attachment) error {
		if row.PolicyDegradedReason == policyMutationInProgress &&
			row.Mode == apiv1.PolicyMode_POLICY_MODE_DISABLED.String() &&
			failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return originalSave(row)
	}

	err := server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_DISABLED)
	require.ErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	events := ff.eventLog()
	disabledAt, blockAllAfter := -1, -1
	for i, event := range events {
		if event == "set-mode "+filter.ModeDisabled.String() {
			disabledAt = i
		}
		if disabledAt >= 0 && i > disabledAt && event == "set-mode "+filter.ModeBlockAll.String() {
			blockAllAfter = i
		}
	}
	assert.NotEqual(t, -1, disabledAt, "target mode became effective before its intermediate save failed")
	assert.Greater(t, blockAllAfter, disabledAt, "failure must force the effective posture back to BLOCK_ALL")
	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Equal(t, policyDegradedMode, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
}

func TestAppliedJournalClearSaveErrorStillBecomesStableDegradation(t *testing.T) {
	server, st, id, _, _ := newTestServerWithAttachment(t)
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	originalSave := server.saveAttachment
	var journaled, failed atomic.Bool
	server.saveAttachment = func(row *store.Attachment) error {
		if row.PolicyDegradedReason == policyMutationInProgress {
			journaled.Store(true)
		}
		if journaled.Load() && row.PolicyDegradedReason == "" && failed.CompareAndSwap(false, true) {
			if err := originalSave(row); err != nil {
				return err
			}
			return syscall.EIO // ambiguous: the clear reached durable storage.
		}
		return originalSave(row)
	}

	err := server.DenyCIDR(id, mustCIDR(t, "203.0.113.0/24"), 0)
	require.ErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Equal(t, policyDegradedDenyAdd, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
}

func TestDenyOnlyClearFailureClearsJournalWithoutDegradation(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	allow := mustCIDR(t, "198.51.100.0/24")
	deny := mustCIDR(t, "203.0.113.0/24")
	require.NoError(t, server.AllowCIDR(id, allow, 0))
	require.NoError(t, server.DenyCIDR(id, deny, 0))
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	ff.setRemoveDeniedErr(syscall.EIO)

	err := server.ClearRules(id)
	require.ErrorIs(t, err, syscall.EIO)
	assert.NotErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Empty(t, row.PolicyDegradedReason)
	mode, allowed, denied, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	assert.Empty(t, allowed)
	assert.Contains(t, denied, deny.String())
}

func TestAllowRemovalFailureCommitsStableDegradation(t *testing.T) {
	server, st, id, ff, _ := newTestServerWithAttachment(t)
	cidr := mustCIDR(t, "198.51.100.0/24")
	require.NoError(t, server.AllowCIDR(id, cidr, 0))
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	ff.setRemoveAllowedErr(syscall.EIO)

	err := server.RemoveAllowedCIDR(id, cidr)
	require.ErrorIs(t, err, errProtectedPolicyDurablyDegraded)
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Equal(t, policyDegradedAllowRemove, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
}

func TestTTLJournalBeginFailureSkipsProtectedExpiryButContinuesDNSExpiry(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	clock := newFakeClock()
	server.now = clock.Now
	protectedCIDR := mustCIDR(t, "198.51.100.0/24")
	require.NoError(t, server.AllowCIDR(id, protectedCIDR, time.Second))
	require.NoError(t, dnsServer.addIPToFilter("expiring.example", netIP(t, "203.0.113.10"), 32, 60))
	require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
	clock.Advance(time.Minute)

	originalSave := server.saveAttachment
	var failed atomic.Bool
	server.saveAttachment = func(row *store.Attachment) error {
		if row.PolicyDegradedReason == policyMutationInProgress && failed.CompareAndSwap(false, true) {
			return syscall.EIO
		}
		return originalSave(row)
	}
	server.sweepExpiredTTLs(clock.Now())

	_, allowed, _, _ := ff.snapshot()
	assert.Contains(t, allowed, protectedCIDR.String(), "protected expiry must not start without its durable journal")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed, "independent DNS expiry continues under fail-closed protected degradation")
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, policyDegradedAllowRemove, row.PolicyDegradedReason)
}

func TestDNSOnlyMutationUnderProtectedDegradationPreservesMarkerAndBlockAll(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	ff.setDenyErr(syscall.EIO)
	require.ErrorIs(t, server.DenyCIDR(id, mustCIDR(t, "198.51.100.0/24"), 0), errProtectedPolicyDurablyDegraded)
	ff.setDenyErr(nil)

	require.NoError(t, server.ReplaceDNSRules(id,
		apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "allowed.example", IncludeSubdomains: true}},
		[]*apiv1.DomainEntry{{Domain: "blocked.example"}},
	))
	dnsServer.mu.RLock()
	assert.Equal(t, apiv1.DnsMode_DNS_MODE_ALLOWLIST, dnsServer.mode)
	assert.Equal(t, map[string]bool{"allowed.example": true}, dnsServer.allowedDomains)
	assert.Equal(t, map[string]bool{"blocked.example": false}, dnsServer.deniedDomains)
	dnsServer.mu.RUnlock()
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, policyDegradedDenyAdd, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
	mode, _, _, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	stats := server.GetAttachmentStats()
	require.Len(t, stats, 1)
	assert.True(t, stats[0].PolicyDegraded)
	assert.Equal(t, policyDegradedDenyAdd, stats[0].PolicyDegradedReason)
}

func TestProtectedIncrementalPhysicalNoOpsDoNotJournalOrTouchFilter(t *testing.T) {
	t.Run("duplicate deny lifetime updates", func(t *testing.T) {
		server, _, id, ff, _ := newTestServerWithAttachment(t)
		clock := newFakeClock()
		server.now = clock.Now
		cidr := mustCIDR(t, "198.51.100.0/24")
		require.NoError(t, server.DenyCIDR(id, cidr, time.Second))
		require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
		beforeDenyCalls := ff.denyCallCount()
		saves := 0
		originalSave := server.saveAttachment
		server.saveAttachment = func(row *store.Attachment) error {
			saves++
			return originalSave(row)
		}

		require.NoError(t, server.DenyCIDR(id, cidr, 2*time.Second), "TTL extension is bookkeeping-only")
		require.NoError(t, server.DenyCIDR(id, cidr, 0), "permanent promotion is bookkeeping-only")
		assert.Equal(t, beforeDenyCalls, ff.denyCallCount())
		assert.Zero(t, saves)
	})

	t.Run("missing allow removal", func(t *testing.T) {
		server, _, id, ff, _ := newTestServerWithAttachment(t)
		require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
		beforeEvents := ff.eventLog()
		saves := 0
		originalSave := server.saveAttachment
		server.saveAttachment = func(row *store.Attachment) error {
			saves++
			return originalSave(row)
		}

		require.NoError(t, server.RemoveAllowedCIDR(id, mustCIDR(t, "192.0.2.0/24")))
		assert.Equal(t, beforeEvents, ff.eventLog())
		assert.Zero(t, saves)
	})

	t.Run("system-owned allow alias removal", func(t *testing.T) {
		server, _, id, ff, _ := newTestServerWithAttachment(t)
		cidr := mustCIDR(t, testDNSBootstrapCIDR)
		server.mu.RLock()
		reg := server.attachments[id].ttls
		server.mu.RUnlock()
		require.NoError(t, reg.addSystem(ff, cidr, listAllow))
		require.NoError(t, server.AllowCIDR(id, cidr, 0))
		require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
		beforeEvents := ff.eventLog()
		saves := 0
		originalSave := server.saveAttachment
		server.saveAttachment = func(row *store.Attachment) error {
			saves++
			return originalSave(row)
		}

		require.NoError(t, server.RemoveAllowedCIDR(id, cidr))
		assert.Equal(t, beforeEvents, ff.eventLog())
		assert.Zero(t, saves)
		_, allowed, _, _ := ff.snapshot()
		assert.Contains(t, allowed, cidr.String())
	})

	t.Run("source-less failed allow retry", func(t *testing.T) {
		server, _, id, ff, _ := newTestServerWithAttachment(t)
		cidr := mustCIDR(t, "203.0.113.0/24")
		require.NoError(t, server.AllowCIDR(id, cidr, 0))
		require.NoError(t, server.SetFilterMode(id, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL))
		server.mu.RLock()
		reg := server.attachments[id].ttls
		server.mu.RUnlock()
		ff.setRemoveAllowedErr(syscall.EIO)
		require.Error(t, reg.clear(ff), "fixture creates source-less inFilter retry state")
		ff.setRemoveAllowedErr(nil)
		beforeRemoves, _ := ff.removeCalls()
		saves := 0
		originalSave := server.saveAttachment
		server.saveAttachment = func(row *store.Attachment) error {
			saves++
			return originalSave(row)
		}

		require.NoError(t, server.ClearRules(id))
		afterRemoves, _ := ff.removeCalls()
		assert.Len(t, afterRemoves, len(beforeRemoves)+1)
		assert.Equal(t, 2, saves, "physical retry persists and clears the transient journal")
	})
}

func TestIncrementalSameModeIsExactNoOp(t *testing.T) {
	for _, mode := range []apiv1.PolicyMode{
		apiv1.PolicyMode_POLICY_MODE_DISABLED,
		apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			server, _, id, ff, _ := newTestServerWithAttachment(t)
			require.NoError(t, server.SetFilterMode(id, mode))
			setBefore, getBefore := ff.modeCallCounts()
			ff.setSetModeErr(syscall.EIO)
			ff.setGetModeErr(syscall.EIO)
			saves := 0
			server.saveAttachment = func(*store.Attachment) error {
				saves++
				return syscall.EIO
			}

			require.NoError(t, server.SetFilterMode(id, mode))
			setAfter, getAfter := ff.modeCallCounts()
			assert.Equal(t, setBefore, setAfter)
			assert.Equal(t, getBefore, getAfter)
			assert.Zero(t, saves)
		})
	}
}

func TestRepeatedDegradedFailurePreservesReasonAndPersistenceButLogsNewAmbiguity(t *testing.T) {
	server, st, id, _, _ := newTestServerWithAttachment(t)
	var logs bytes.Buffer
	server.logger = zerolog.New(&logs)
	server.mu.RLock()
	state := server.attachments[id]
	server.mu.RUnlock()

	saves := 0
	originalSave := server.saveAttachment
	server.saveAttachment = func(row *store.Attachment) error {
		saves++
		return originalSave(row)
	}
	capacityErr := errors.Join(filter.ErrProtectedRuleCapacity, syscall.ENOSPC)
	require.ErrorIs(t, server.enterPolicyDegradedAdmitted(id, state, policyDegradedAuthoritative, capacityErr), errProtectedPolicyDurablyDegraded)
	assert.Equal(t, 1, saves)
	firstLogs := logs.String()
	assert.Equal(t, 1, bytes.Count([]byte(firstLogs), []byte("attachment protected policy degraded")))

	require.ErrorIs(t, server.enterPolicyDegradedAdmitted(id, state, policyDegradedAuthoritative, capacityErr), errProtectedPolicyDurablyDegraded)
	assert.Equal(t, 1, saves, "ordinary retries in the same stable degradation must not rewrite the row")
	assert.Equal(t, firstLogs, logs.String(), "ordinary pressure retry must remain log-suppressed")

	ambiguity := errors.Join(filter.ErrProtectedRuleRollback, filter.ErrProtectedRuleModeAmbiguous, syscall.EIO)
	require.ErrorIs(t, server.enterPolicyDegradedAdmitted(id, state, policyDegradedDenyAdd, ambiguity), errProtectedPolicyDurablyDegraded)
	assert.Equal(t, 1, saves, "later incidents preserve the already-durable row")
	row, err := st.GetAttachment(id)
	require.NoError(t, err)
	assert.Equal(t, policyDegradedAuthoritative, row.PolicyDegradedReason,
		"the first stable diagnosis remains operator-visible until full recovery")
	assert.Contains(t, logs.String(), "new protected-policy ambiguity while attachment was already degraded")
	assert.Contains(t, logs.String(), `"rollback_ambiguous":true`)
	assert.Contains(t, logs.String(), `"mode_ambiguous":true`)
}

func TestProtectedStatsExposeEveryMapAndRetainHighWater(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	ff.ruleCapacity4 = 5
	ff.ruleCapacity6 = 7
	allow4 := mustCIDR(t, "192.0.2.0/24")
	allow6 := mustCIDR(t, "2001:db8::/32")
	deny4 := mustCIDR(t, "198.51.100.0/24")
	deny6 := mustCIDR(t, "2001:db9::/32")
	require.NoError(t, server.AllowCIDR(id, allow4, 0))
	require.NoError(t, server.AllowCIDR(id, allow6, 0))
	require.NoError(t, server.DenyCIDR(id, deny4, 0))
	require.NoError(t, server.DenyCIDR(id, deny6, 0))

	stats := server.GetAttachmentStats()
	require.Len(t, stats, 1)
	got := stats[0]
	for _, entries := range []uint32{
		got.ProtectedAllowIpv4Entries, got.ProtectedAllowIpv6Entries,
		got.ProtectedDenyIpv4Entries, got.ProtectedDenyIpv6Entries,
	} {
		assert.Equal(t, uint32(1), entries)
	}
	assert.Equal(t, uint32(5), got.ProtectedAllowIpv4Capacity)
	assert.Equal(t, uint32(5), got.ProtectedDenyIpv4Capacity)
	assert.Equal(t, uint32(7), got.ProtectedAllowIpv6Capacity)
	assert.Equal(t, uint32(7), got.ProtectedDenyIpv6Capacity)

	require.NoError(t, server.RemoveAllowedCIDR(id, allow4))
	require.NoError(t, server.RemoveAllowedCIDR(id, allow6))
	require.NoError(t, server.RemoveDeniedCIDR(id, deny4))
	require.NoError(t, server.RemoveDeniedCIDR(id, deny6))
	stats = server.GetAttachmentStats()
	require.Len(t, stats, 1)
	got = stats[0]
	assert.Zero(t, got.ProtectedAllowIpv4Entries)
	assert.Zero(t, got.ProtectedAllowIpv6Entries)
	assert.Zero(t, got.ProtectedDenyIpv4Entries)
	assert.Zero(t, got.ProtectedDenyIpv6Entries)
	for _, highWater := range []uint32{
		got.ProtectedAllowIpv4HighWater, got.ProtectedAllowIpv6HighWater,
		got.ProtectedDenyIpv4HighWater, got.ProtectedDenyIpv6HighWater,
	} {
		assert.Equal(t, uint32(1), highWater)
	}
}

func TestProtectedStatsFailureUsesLastProvenSnapshotAndRateLimitsWarning(t *testing.T) {
	server, _, id, ff, _ := newTestServerWithAttachment(t)
	clock := newFakeClock()
	server.now = clock.Now
	var logs bytes.Buffer
	server.logger = zerolog.New(&logs)
	allow := mustCIDR(t, "192.0.2.0/24")
	deny := mustCIDR(t, "2001:db8::/32")
	require.NoError(t, server.AllowCIDR(id, allow, 0))
	require.NoError(t, server.DenyCIDR(id, deny, 0))
	proven := server.GetAttachmentStats()
	require.Len(t, proven, 1)
	require.NoError(t, server.RemoveAllowedCIDR(id, allow))
	require.NoError(t, server.RemoveDeniedCIDR(id, deny))
	ff.setProtectedOccupancyErr(syscall.EIO)

	for i := 0; i < 2; i++ {
		stats := server.GetAttachmentStats()
		require.Len(t, stats, 1)
		assert.Equal(t, proven[0].ProtectedAllowIpv4Entries, stats[0].ProtectedAllowIpv4Entries)
		assert.Equal(t, proven[0].ProtectedAllowIpv4Capacity, stats[0].ProtectedAllowIpv4Capacity)
		assert.Equal(t, proven[0].ProtectedDenyIpv6Entries, stats[0].ProtectedDenyIpv6Entries)
		assert.Equal(t, proven[0].ProtectedDenyIpv6Capacity, stats[0].ProtectedDenyIpv6Capacity)
	}
	assert.Equal(t, 1, bytes.Count(logs.Bytes(), []byte("failed to refresh protected LPM telemetry")))
	clock.Advance(30 * time.Second)
	_ = server.GetAttachmentStats()
	assert.Equal(t, 2, bytes.Count(logs.Bytes(), []byte("failed to refresh protected LPM telemetry")))
}

func TestProtectedStatsConcurrentWithRuleMutation(t *testing.T) {
	server, _, id, _, _ := newTestServerWithAttachment(t)
	var cidrs []*net.IPNet
	for i := 0; i < 24; i++ {
		cidrs = append(cidrs, mustCIDR(t, fmt.Sprintf("198.51.100.%d/32", i+1)))
	}
	errCh := make(chan error, len(cidrs)*4)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for _, cidr := range cidrs {
			if err := server.AllowCIDR(id, cidr, 0); err != nil {
				errCh <- err
			}
			if err := server.RemoveAllowedCIDR(id, cidr); err != nil {
				errCh <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		for _, cidr := range cidrs {
			if err := server.DenyCIDR(id, cidr, 0); err != nil {
				errCh <- err
			}
			if err := server.RemoveDeniedCIDR(id, cidr); err != nil {
				errCh <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range len(cidrs) * 2 {
			stats := server.GetAttachmentStats()
			if len(stats) != 1 {
				errCh <- fmt.Errorf("stats snapshot count %d, want 1", len(stats))
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent protected stats/mutation failed: %v", err)
	}
}

func TestAuthoritativeOverCapacityEveryProtectedMapIsAtomicAndDegrades(t *testing.T) {
	for _, overflowing := range []string{"allow_ipv4", "allow_ipv6", "deny_ipv4", "deny_ipv6"} {
		t.Run(overflowing, func(t *testing.T) {
			server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
			clock := newFakeClock()
			server.now = clock.Now
			allow4 := mustCIDR(t, "192.0.2.0/24")
			allow6 := mustCIDR(t, "2001:db8::/32")
			deny4 := mustCIDR(t, "198.51.100.0/24")
			deny6 := mustCIDR(t, "2001:db9::/32")
			require.NoError(t, server.AllowCIDR(id, allow4, 5*time.Minute))
			require.NoError(t, server.AllowCIDR(id, allow6, 6*time.Minute))
			require.NoError(t, server.DenyCIDR(id, deny4, 7*time.Minute))
			require.NoError(t, server.DenyCIDR(id, deny6, 8*time.Minute))
			require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_DENYLIST,
				nil, []*apiv1.DomainEntry{{Domain: "old.example"}}))
			ff.ruleCapacity4, ff.ruleCapacity6 = 1, 1
			server.mu.RLock()
			reg := server.attachments[id].ttls
			server.mu.RUnlock()
			beforeRegistry := snapshotProtectedRegistry(reg)
			beforeMode, beforeAllowed, beforeDenied, _ := ff.snapshot()
			dnsServer.mu.RLock()
			beforeDNSMode := dnsServer.mode
			beforeDNSDenied := cloneDomainRules(dnsServer.deniedDomains)
			dnsServer.mu.RUnlock()

			allow := []*apiv1.CIDREntry{{Cidr: allow4.String()}, {Cidr: allow6.String()}}
			deny := []*apiv1.CIDREntry{{Cidr: deny4.String()}, {Cidr: deny6.String()}}
			switch overflowing {
			case "allow_ipv4":
				allow = append(allow, &apiv1.CIDREntry{Cidr: "203.0.113.0/24"})
			case "allow_ipv6":
				allow = append(allow, &apiv1.CIDREntry{Cidr: "2001:dba::/32"})
			case "deny_ipv4":
				deny = append(deny, &apiv1.CIDREntry{Cidr: "10.0.0.0/8"})
			case "deny_ipv6":
				deny = append(deny, &apiv1.CIDREntry{Cidr: "2001:dbb::/32"})
			}
			client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)
			err := client.applyBulkUpdate(id, &apiv1.BulkUpdate{
				Mode:       apiv1.PolicyMode_POLICY_MODE_DENYLIST,
				AllowCidrs: allow,
				DenyCidrs:  deny,
				Dns: &apiv1.DnsConfig{
					Mode:         apiv1.DnsMode_DNS_MODE_ALLOWLIST,
					AllowDomains: []*apiv1.DomainEntry{{Domain: "new.example"}},
				},
			})
			require.ErrorIs(t, err, filter.ErrProtectedRuleCapacity)
			assert.Equal(t, beforeRegistry, snapshotProtectedRegistry(reg),
				"failed final-capacity preflight must preserve exact ownership and TTL deadlines")
			mode, allowed, denied, _ := ff.snapshot()
			assert.Equal(t, filter.ModeBlockAll, mode)
			assert.Equal(t, beforeAllowed, allowed)
			assert.Equal(t, beforeDenied, denied)
			assert.NotEqual(t, beforeMode, mode)
			dnsServer.mu.RLock()
			assert.Equal(t, beforeDNSMode, dnsServer.mode)
			assert.Equal(t, beforeDNSDenied, dnsServer.deniedDomains)
			dnsServer.mu.RUnlock()
			row, getErr := st.GetAttachment(id)
			require.NoError(t, getErr)
			assert.Equal(t, policyDegradedAuthoritative, row.PolicyDegradedReason)
			assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
			stats := server.GetAttachmentStats()
			require.Len(t, stats, 1)
			assert.True(t, stats[0].PolicyDegraded)
			assert.Equal(t, uint64(1), stats[0].MapFullDrops)
		})
	}
}

func TestDegradedFullRecoveryHoldsBlockAllAcrossDNSStageFailure(t *testing.T) {
	server, st, id, ff, dnsServer := newTestServerWithAttachment(t)
	require.NoError(t, server.ReplaceDNSRules(id, apiv1.DnsMode_DNS_MODE_ALLOWLIST,
		[]*apiv1.DomainEntry{{Domain: "cached.example"}}, nil))
	require.NoError(t, dnsServer.addIPToFilter("cached.example", netIP(t, "203.0.113.10"), 32, 60))
	ff.setDenyErr(syscall.ENOSPC)
	require.ErrorIs(t, server.DenyCIDR(id, mustCIDR(t, "192.0.2.0/24"), 0), errProtectedPolicyDurablyDegraded)
	ff.setDenyErr(nil)
	ff.dnsRemoveErr = syscall.EIO
	client := NewControlPlaneClient("", server, zerolog.Nop(), nil, 0, nil)
	update := &apiv1.BulkUpdate{
		Mode:      apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		DenyCidrs: []*apiv1.CIDREntry{{Cidr: "198.51.100.0/24"}},
		Dns:       &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_DISABLED},
	}

	err := client.applyBulkUpdate(id, update)
	require.ErrorIs(t, err, syscall.EIO)
	mode, _, denied, _ := ff.snapshot()
	assert.Equal(t, filter.ModeBlockAll, mode)
	assert.Equal(t, []string{"198.51.100.0/24"}, denied, "protected maps may stage while activation stays held")
	dnsAllowed, _ := ff.dnsSnapshot()
	assert.Equal(t, []string{"203.0.113.10"}, dnsAllowed, "failed DNS transaction preserves its exact working set")
	row, getErr := st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.NotEmpty(t, row.PolicyDegradedReason)
	assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)

	ff.dnsRemoveErr = nil
	require.NoError(t, client.applyBulkUpdate(id, update))
	mode, _, denied, _ = ff.snapshot()
	assert.Equal(t, filter.ModeDenylist, mode)
	assert.Equal(t, []string{"198.51.100.0/24"}, denied)
	dnsAllowed, _ = ff.dnsSnapshot()
	assert.Empty(t, dnsAllowed)
	row, getErr = st.GetAttachment(id)
	require.NoError(t, getErr)
	assert.Empty(t, row.PolicyDegradedReason)
}

func TestDegradationTerminalEdgesStopGlobalAdmission(t *testing.T) {
	t.Run("block_all_proof", func(t *testing.T) {
		server, st, id, ff, _ := newTestServerWithAttachment(t)
		ff.setDenyErr(syscall.ENOSPC)
		ff.setSetModeErr(syscall.EIO)
		ff.setGetModeErr(syscall.EIO)
		err := server.DenyCIDR(id, mustCIDR(t, "198.51.100.0/24"), 0)
		require.Error(t, err)
		server.mu.RLock()
		assert.True(t, server.stopping)
		server.mu.RUnlock()
		row, getErr := st.GetAttachment(id)
		require.NoError(t, getErr)
		assert.Equal(t, policyDegradedDenyAdd, row.PolicyDegradedReason,
			"durable restart intent is retained even when live BLOCK_ALL proof fails")
		assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL.String(), row.Mode)
		mode, _, _, _ := ff.snapshot()
		assert.Equal(t, filter.ModeDisabled, mode, "failed write/read proof leaves the live posture explicitly ambiguous")
		require.ErrorContains(t, server.AllowCIDR(id, mustCIDR(t, "203.0.113.0/24"), 0), "daemon is stopping")
	})

	t.Run("both_marker_saves", func(t *testing.T) {
		server, st, id, ff, _ := newTestServerWithAttachment(t)
		ff.setDenyErr(syscall.ENOSPC)
		saves := 0
		server.saveAttachment = func(*store.Attachment) error {
			saves++
			return syscall.EIO
		}
		err := server.DenyCIDR(id, mustCIDR(t, "198.51.100.0/24"), 0)
		require.Error(t, err)
		assert.Equal(t, 2, saves)
		server.mu.RLock()
		state := server.attachments[id]
		assert.True(t, server.stopping)
		assert.Empty(t, state.info.PolicyDegradedReason,
			"store-first publication must not expose an undurable stable marker")
		assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_DISABLED.String(), state.info.Mode)
		server.mu.RUnlock()
		row, getErr := st.GetAttachment(id)
		require.NoError(t, getErr)
		assert.Empty(t, row.PolicyDegradedReason)
		assert.Equal(t, apiv1.PolicyMode_POLICY_MODE_DISABLED.String(), row.Mode)
		mode, _, _, _ := ff.snapshot()
		assert.Equal(t, filter.ModeBlockAll, mode,
			"live fail-closed posture survives for restart inference despite unavailable durability")
		require.ErrorContains(t, server.RemoveDeniedCIDR(id, mustCIDR(t, "203.0.113.0/24")), "daemon is stopping")
	})
}
