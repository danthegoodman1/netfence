package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
	"github.com/stretchr/testify/require"
)

func TestMappedCIDROwnershipSurvivesBulkRemovalExpiryAndAdoption(t *testing.T) {
	s, _, id, _, _ := newTestServerWithAttachment(t)
	v4 := mustCIDR(t, "192.0.2.1/32")
	v6 := mustCIDR(t, "::ffff:192.0.2.1/128")
	require.NoError(t, s.ApplyRules(id, &apiv1.BulkUpdate{Mode: apiv1.PolicyMode_POLICY_MODE_ALLOWLIST,
		AllowCidrs: []*apiv1.CIDREntry{{Cidr: filter.CIDRString(v4)}, {Cidr: filter.CIDRString(v6)}}}))
	reg := s.attachments[id].ttls
	require.Len(t, reg.snapshotRules(), 2)
	require.NoError(t, s.RemoveAllowedCIDR(id, v6))
	rules := reg.snapshotRules()
	require.Len(t, rules, 1)
	require.Equal(t, "192.0.2.1/32", rules[0].cidr)
	now := time.Now()
	require.NoError(t, reg.addCP(s.attachments[id].filter, v6, listAllow, time.Second, now))
	swept := reg.expire(s.attachments[id].filter, now.Add(2*time.Second))
	require.Len(t, swept, 1)
	require.Equal(t, "::ffff:192.0.2.1/128", swept[0].cidr)
	adopted := newTTLRegistry()
	require.NoError(t, adopted.seedAdopted([]*net.IPNet{v4, v6}, nil))
	require.Len(t, adopted.snapshotRules(), 2)
	require.NoError(t, adopted.remove(nil, v6, listAllow))
	require.Equal(t, "192.0.2.1/32", adopted.snapshotRules()[0].cidr)
}
