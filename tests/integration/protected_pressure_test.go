//go:build linux

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

const protectedPressureDegradedReason = "authoritative_protected_policy_failed"

type protectedPressureTrafficFixture struct {
	env           *e2eTestEnv
	attachmentID  string
	oldIP         string
	spareIP       string
	newIP         string
	unrelatedIP   string
	oldPort       string
	newPort       string
	unrelatedPort string
	connect       func(ip, port string) bool
}

func protectedPressureInitialPolicy(oldIP, spareIP string) *apiv1.SubscribedAck {
	return &apiv1.SubscribedAck{
		Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "192.0.2.200/32"},
			{Cidr: "2001:db8:ca:fe::1/128"},
			{Cidr: "2001:db8:ca:fe::2/128"},
		},
		DenyCidrs: []*apiv1.CIDREntry{
			{Cidr: oldIP + "/32"},
			{Cidr: spareIP + "/32"},
			{Cidr: "2001:db8:de:ad::1/128"},
			{Cidr: "2001:db8:de:ad::2/128"},
		},
	}
}

func protectedPressureOversizedPolicy(oldIP, spareIP, newIP string) *apiv1.BulkUpdate {
	initial := protectedPressureInitialPolicy(oldIP, spareIP)
	return &apiv1.BulkUpdate{
		Mode:       initial.Mode,
		AllowCidrs: initial.AllowCidrs,
		DenyCidrs: append(initial.DenyCidrs,
			&apiv1.CIDREntry{Cidr: newIP + "/32"}),
	}
}

func protectedPressureRecoveryPolicy(newIP string) *apiv1.BulkUpdate {
	return &apiv1.BulkUpdate{
		Mode: apiv1.PolicyMode_POLICY_MODE_DENYLIST,
		AllowCidrs: []*apiv1.CIDREntry{
			{Cidr: "2001:db8:ca:fe::1/128"},
		},
		DenyCidrs: []*apiv1.CIDREntry{
			{Cidr: newIP + "/32"},
			{Cidr: "2001:db8:de:ad::1/128"},
		},
	}
}

func requireProtectedCommandResult(t *testing.T, fixture *protectedPressureTrafficFixture, commandID string, update *apiv1.BulkUpdate) *apiv1.CommandResult {
	t.Helper()
	require.NoError(t, fixture.env.controlPlane.SendCommand(fixture.attachmentID, &apiv1.ControlCommand{
		Id:        fixture.attachmentID,
		CommandId: commandID,
		Command:   &apiv1.ControlCommand_BulkUpdate{BulkUpdate: update},
	}))
	require.True(t, waitForCondition(5*time.Second, func() bool {
		return fixture.env.controlPlane.CommandResult(commandID) != nil
	}), "command result %s was not observed", commandID)
	return fixture.env.controlPlane.CommandResult(commandID)
}

func requireProtectedAttachmentStats(t testing.TB, fixture *protectedPressureTrafficFixture) *apiv1.AttachmentStats {
	t.Helper()
	for _, stats := range fixture.env.daemonServer.GetAttachmentStats() {
		if stats.Id == fixture.attachmentID {
			return stats
		}
	}
	t.Fatalf("attachment %s missing from stats", fixture.attachmentID)
	return nil
}

func assertProtectedMapsFull(t testing.TB, stats *apiv1.AttachmentStats) {
	t.Helper()
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv4Entries)
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv6Entries)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv4Entries)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv6Entries)
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv4Capacity)
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv6Capacity)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv4Capacity)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv6Capacity)
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv4HighWater)
	assert.Equal(t, uint32(2), stats.ProtectedAllowIpv6HighWater)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv4HighWater)
	assert.Equal(t, uint32(2), stats.ProtectedDenyIpv6HighWater)
	assert.Zero(t, stats.DnsExactIpv4Entries, "authoritative pressure must not spill into the DNS exact tier")
	assert.Zero(t, stats.DnsExactIpv6Entries, "authoritative pressure must not spill into the DNS exact tier")
}

func exerciseProtectedLPMPressureTraffic(t *testing.T, fixture *protectedPressureTrafficFixture, requireWireHeartbeat bool) {
	t.Helper()

	initialStats := requireProtectedAttachmentStats(t, fixture)
	assertProtectedMapsFull(t, initialStats)
	assert.False(t, initialStats.PolicyDegraded)
	assert.Zero(t, initialStats.MapFullDrops)

	assert.False(t, fixture.connect(fixture.oldIP, fixture.oldPort), "initial protected deny must be active")
	assert.True(t, fixture.connect(fixture.newIP, fixture.newPort), "future deny must start reachable")
	assert.True(t, fixture.connect(fixture.unrelatedIP, fixture.unrelatedPort), "unrelated traffic must start reachable")

	failure := requireProtectedCommandResult(t, fixture, "protected-over-cap-"+fixture.attachmentID,
		protectedPressureOversizedPolicy(fixture.oldIP, fixture.spareIP, fixture.newIP))
	assert.False(t, failure.Success)
	assert.Contains(t, failure.Error, "capacity")

	degraded := requireProtectedAttachmentStats(t, fixture)
	assertProtectedMapsFull(t, degraded)
	assert.True(t, degraded.PolicyDegraded)
	assert.Equal(t, protectedPressureDegradedReason, degraded.PolicyDegradedReason)
	assert.GreaterOrEqual(t, degraded.MapFullDrops, uint64(1))
	assert.False(t, fixture.connect(fixture.oldIP, fixture.oldPort), "degraded BLOCK_ALL must keep the old deny blocked")
	assert.False(t, fixture.connect(fixture.newIP, fixture.newPort), "degraded BLOCK_ALL must block the failed incoming deny too")
	assert.False(t, fixture.connect(fixture.unrelatedIP, fixture.unrelatedPort), "degraded BLOCK_ALL must not fail open for unrelated traffic")

	if requireWireHeartbeat {
		require.Eventually(t, func() bool {
			stats, _ := fixture.env.controlPlane.HeartbeatStats(fixture.attachmentID)
			return stats != nil && stats.PolicyDegraded && stats.MapFullDrops >= 1
		}, 40*time.Second, 100*time.Millisecond,
			"control plane did not observe protected degradation in an actual Heartbeat")
		wireStats, count := fixture.env.controlPlane.HeartbeatStats(fixture.attachmentID)
		require.NotNil(t, wireStats)
		assert.GreaterOrEqual(t, count, 1)
		assertProtectedMapsFull(t, wireStats)
		assert.True(t, wireStats.PolicyDegraded)
		assert.Equal(t, protectedPressureDegradedReason, wireStats.PolicyDegradedReason)
		assert.GreaterOrEqual(t, wireStats.MapFullDrops, uint64(1))
	}

	recovery := requireProtectedCommandResult(t, fixture, "protected-recover-"+fixture.attachmentID,
		protectedPressureRecoveryPolicy(fixture.newIP))
	assert.True(t, recovery.Success, recovery.Error)
	require.True(t, waitForCondition(5*time.Second, func() bool {
		stats := requireProtectedAttachmentStats(t, fixture)
		return !stats.PolicyDegraded &&
			stats.ProtectedAllowIpv4Entries == 1 &&
			stats.ProtectedAllowIpv6Entries == 1 &&
			stats.ProtectedDenyIpv4Entries == 1 &&
			stats.ProtectedDenyIpv6Entries == 1
	}), "complete BulkUpdate did not clear protected degradation")
	recovered := requireProtectedAttachmentStats(t, fixture)
	assert.False(t, recovered.PolicyDegraded)
	assert.Empty(t, recovered.PolicyDegradedReason)
	assert.Equal(t, uint32(1), recovered.ProtectedAllowIpv4Entries,
		"the protected IPv4 allow map must retain only the system DNS bootstrap")
	assert.Equal(t, uint32(1), recovered.ProtectedAllowIpv6Entries)
	assert.Equal(t, uint32(1), recovered.ProtectedDenyIpv4Entries)
	assert.Equal(t, uint32(1), recovered.ProtectedDenyIpv6Entries)
	assert.Equal(t, uint32(2), recovered.ProtectedAllowIpv4Capacity)
	assert.Equal(t, uint32(2), recovered.ProtectedAllowIpv6Capacity)
	assert.Equal(t, uint32(2), recovered.ProtectedDenyIpv4Capacity)
	assert.Equal(t, uint32(2), recovered.ProtectedDenyIpv6Capacity)
	assert.Equal(t, uint32(2), recovered.ProtectedAllowIpv4HighWater)
	assert.Equal(t, uint32(2), recovered.ProtectedAllowIpv6HighWater)
	assert.Equal(t, uint32(2), recovered.ProtectedDenyIpv4HighWater)
	assert.Equal(t, uint32(2), recovered.ProtectedDenyIpv6HighWater)
	assert.Zero(t, recovered.DnsExactIpv4Entries)
	assert.Zero(t, recovered.DnsExactIpv6Entries)
	assert.GreaterOrEqual(t, recovered.MapFullDrops, uint64(1), "pressure telemetry is cumulative")

	assert.True(t, fixture.connect(fixture.oldIP, fixture.oldPort), "successful full reconcile must remove the old deny")
	assert.False(t, fixture.connect(fixture.newIP, fixture.newPort), "successful full reconcile must activate the new deny")
	assert.True(t, fixture.connect(fixture.unrelatedIP, fixture.unrelatedPort), "successful full reconcile must restore unrelated traffic")
}

func newProtectedPressureE2EEnv(t *testing.T, port int) *e2eTestEnv {
	t.Helper()
	return newE2ETestEnvWithConfig(t, port, port, 5*time.Second, func(cfg *config.Config) {
		cfg.Filter.MaxRuleEntries = 2
	})
}

func TestCgroupProtectedLPMPressureFailsClosedAndRecoversTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	const (
		oldIP       = "198.18.2.1"
		spareIP     = "198.18.2.2"
		newIP       = "198.18.2.3"
		unrelatedIP = "198.18.2.4"
	)
	for _, ip := range []string{oldIP, spareIP, newIP, unrelatedIP} {
		_ = ipCmd("addr", "del", ip+"/32", "dev", "lo")
		require.NoError(t, ipCmd("addr", "add", ip+"/32", "dev", "lo"))
		ip := ip
		defer func() { _ = ipCmd("addr", "del", ip+"/32", "dev", "lo") }()
	}
	oldPort, closeOld := listenTCP(t, oldIP)
	defer closeOld()
	newPort, closeNew := listenTCP(t, newIP)
	defer closeNew()
	unrelatedPort, closeUnrelated := listenTCP(t, unrelatedIP)
	defer closeUnrelated()

	cgroupPath, cleanupCgroup := setupTestCgroup(t, "netfence-protected-pressure")
	defer cleanupCgroup()
	for ip, port := range map[string]string{oldIP: oldPort, newIP: newPort, unrelatedIP: unrelatedPort} {
		require.True(t, runInCgroup(cgroupPath, ip+" "+port), "cgroup pressure topology is broken for %s", ip)
	}

	env := newProtectedPressureE2EEnv(t, 33200)
	defer env.cleanup()
	env.controlPlane.SetConfig(cgroupPath, protectedPressureInitialPolicy(oldIP, spareIP))
	resp, err := env.daemonServer.Attach(context.Background(), &apiv1.AttachRequest{
		Target: &apiv1.AttachRequest_CgroupPath{CgroupPath: cgroupPath},
	})
	require.NoError(t, err)
	defer func() {
		_, _ = env.daemonServer.Detach(context.Background(), &apiv1.DetachRequest{Id: resp.Id})
	}()

	exerciseProtectedLPMPressureTraffic(t, &protectedPressureTrafficFixture{
		env:           env,
		attachmentID:  resp.Id,
		oldIP:         oldIP,
		spareIP:       spareIP,
		newIP:         newIP,
		unrelatedIP:   unrelatedIP,
		oldPort:       oldPort,
		newPort:       newPort,
		unrelatedPort: unrelatedPort,
		connect: func(ip, port string) bool {
			return runInCgroup(cgroupPath, ip+" "+port)
		},
	}, true)
}

func TestTCProtectedLPMPressureFailsClosedAndRecoversTraffic(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanupVeth := setupVethNetns(t)
	defer cleanupVeth()
	const (
		spareIP     = "10.199.0.6"
		unrelatedIP = "10.199.0.7"
	)
	require.NoError(t, ipCmd("addr", "add", spareIP+"/24", "dev", vethHostIf))
	require.NoError(t, ipCmd("addr", "add", unrelatedIP+"/24", "dev", vethHostIf))
	oldPort, closeOld := listenTCP(t, vethAllowedIP)
	defer closeOld()
	newPort, closeNew := listenTCP(t, vethBlockedIP)
	defer closeNew()
	unrelatedPort, closeUnrelated := listenTCP(t, unrelatedIP)
	defer closeUnrelated()
	for ip, port := range map[string]string{vethAllowedIP: oldPort, vethBlockedIP: newPort, unrelatedIP: unrelatedPort} {
		require.True(t, nsConnectTCP(ip, port), "TC pressure topology is broken for %s", ip)
	}

	env := newProtectedPressureE2EEnv(t, 33201)
	defer env.cleanup()
	env.controlPlane.SetConfig(vethHostIf, protectedPressureInitialPolicy(vethAllowedIP, spareIP))
	resp, err := env.daemonServer.Attach(context.Background(), &apiv1.AttachRequest{
		Target:      &apiv1.AttachRequest_InterfaceName{InterfaceName: vethHostIf},
		TcDirection: apiv1.TcDirection_TC_DIRECTION_INGRESS,
	})
	require.NoError(t, err)
	defer func() {
		_, _ = env.daemonServer.Detach(context.Background(), &apiv1.DetachRequest{Id: resp.Id})
	}()
	flushNeighbors(t, vethHostIf)

	exerciseProtectedLPMPressureTraffic(t, &protectedPressureTrafficFixture{
		env:           env,
		attachmentID:  resp.Id,
		oldIP:         vethAllowedIP,
		spareIP:       spareIP,
		newIP:         vethBlockedIP,
		unrelatedIP:   unrelatedIP,
		oldPort:       oldPort,
		newPort:       newPort,
		unrelatedPort: unrelatedPort,
		connect:       nsConnectTCP,
	}, false)
}

func TestProtectedPressureProjectionFixtureIsInternallyConsistent(t *testing.T) {
	initial := protectedPressureInitialPolicy("198.18.2.1", "198.18.2.2")
	require.Len(t, initial.AllowCidrs, 3)
	require.Len(t, initial.DenyCidrs, 4)
	over := protectedPressureOversizedPolicy("198.18.2.1", "198.18.2.2", "198.18.2.3")
	assert.Len(t, over.DenyCidrs, 5)
	recovery := protectedPressureRecoveryPolicy("198.18.2.3")
	assert.Len(t, recovery.AllowCidrs, 1)
	assert.Len(t, recovery.DenyCidrs, 2)
	assert.Equal(t, fmt.Sprintf("%s/32", "198.18.2.3"), recovery.DenyCidrs[0].Cidr)
}
