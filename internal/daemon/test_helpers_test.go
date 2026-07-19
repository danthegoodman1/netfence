package daemon

import (
	"math"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/store"
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

const testDNSBootstrapCIDR = "127.0.0.1/32"

type fakeFilter struct {
	mu                      sync.Mutex
	mode                    filter.PolicyMode
	allowed                 []string
	denied                  []string
	dnsAllowed              []string
	dnsAddCalls             int
	dnsRemoveCalls          int
	dnsReplaceCalls         int
	dnsAddErr               error
	dnsRemoveErr            error
	dnsReplaceErr           error
	dnsCapacity4            uint32
	dnsCapacity6            uint32
	dnsListOverride         []net.IP
	dnsOccupancyOverride    *filter.DNSAllowOccupancy
	dnsAddEntered           chan struct{}
	dnsAddRelease           <-chan struct{}
	dnsAddOnce              sync.Once
	clearCalls              int
	stats                   filter.Stats
	setModeCalls            int
	getModeCalls            int
	allowCalls              int
	denyCalls               int
	closeCalls              int
	detachCalls             int
	setModeErr              error
	getModeErr              error
	closeErr                error
	detachErr               error
	detachErrs              []error
	allowErr                error // when set, AllowIP fails with this error
	denyErr                 error
	rulesErr                error // when set, adopted-map inventory fails
	removeAllowErr          error
	removeDenyErr           error
	ruleCapacity4           uint32
	ruleCapacity6           uint32
	protectedReplaceErr     error
	protectedOccupancyErr   error
	protectedOccupancyCalls int
	setModeEntered          chan struct{}
	setModeRelease          <-chan struct{}
	setModeOnce             sync.Once
	mutationsAfterClose     int
	// removedAllowed/removedDenied record every Remove call (even for CIDRs
	// not present, mirroring the real filter's idempotent removes), so tests
	// can prove a surviving rule was NEVER removed during a transition.
	removedAllowed []string
	removedDenied  []string
	// events is a single sequenced log of every mutating filter call, in
	// call order ("allow <cidr>", "deny <cidr>", "remove-allow <cidr>",
	// "remove-deny <cidr>", "set-mode <mode>", "clear"), so tests can prove
	// ORDERING invariants — e.g. that a mode flip's target list is fully
	// reconciled before the SetMode lands.
	events []string
}

func (f *fakeFilter) SetMode(mode filter.PolicyMode) error {
	f.mu.Lock()
	entered, release := f.setModeEntered, f.setModeRelease
	f.mu.Unlock()
	if entered != nil {
		f.setModeOnce.Do(func() { close(entered) })
	}
	if release != nil {
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.setModeCalls++
	f.events = append(f.events, "set-mode "+mode.String())
	if f.setModeErr != nil {
		return f.setModeErr
	}
	f.mode = mode
	return nil
}

func (f *fakeFilter) setSetModeErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setModeErr = err
}

func (f *fakeFilter) setGetModeErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getModeErr = err
}

func (f *fakeFilter) blockSetMode(entered chan struct{}, release <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setModeEntered = entered
	f.setModeRelease = release
}

func (f *fakeFilter) AllowIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.allowCalls++
	f.events = append(f.events, "allow "+cidr.String())
	if f.allowErr != nil {
		return f.allowErr
	}
	// Upsert, matching the real BPF map's set semantics on re-add.
	f.allowed = appendUnique(f.allowed, cidr.String())
	return nil
}

func (f *fakeFilter) setAllowErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowErr = err
}

func (f *fakeFilter) setRulesErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rulesErr = err
}

func (f *fakeFilter) allowCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.allowCalls
}

func (f *fakeFilter) DenyIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.events = append(f.events, "deny "+cidr.String())
	f.denyCalls++
	if f.denyErr != nil {
		return f.denyErr
	}
	f.denied = appendUnique(f.denied, cidr.String())
	return nil
}

func (f *fakeFilter) denyCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.denyCalls
}

func (f *fakeFilter) setDenyErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denyErr = err
}

func (f *fakeFilter) RemoveAllowedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.events = append(f.events, "remove-allow "+cidr.String())
	f.removedAllowed = append(f.removedAllowed, cidr.String())
	if f.removeAllowErr != nil {
		return f.removeAllowErr
	}
	f.allowed = removeString(f.allowed, cidr.String())
	return nil
}

func (f *fakeFilter) RemoveDeniedIP(cidr *net.IPNet) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.events = append(f.events, "remove-deny "+cidr.String())
	f.removedDenied = append(f.removedDenied, cidr.String())
	if f.removeDenyErr != nil {
		return f.removeDenyErr
	}
	f.denied = removeString(f.denied, cidr.String())
	return nil
}

func (f *fakeFilter) ReplaceProtectedRules(allowed, denied []*net.IPNet, mode filter.PolicyMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.protectedReplaceErr != nil {
		return f.protectedReplaceErr
	}
	canonical := func(cidrs []*net.IPNet) []string {
		seen := make(map[string]struct{}, len(cidrs))
		for _, cidr := range cidrs {
			seen[cidr.String()] = struct{}{}
		}
		out := make([]string, 0, len(seen))
		for raw := range seen {
			out = append(out, raw)
		}
		sort.Strings(out)
		return out
	}
	wantAllowed, wantDenied := canonical(allowed), canonical(denied)
	cap4, cap6 := f.ruleCapacity4, f.ruleCapacity6
	if cap4 == 0 {
		cap4 = math.MaxUint32
	}
	if cap6 == 0 {
		cap6 = math.MaxUint32
	}
	count := func(values []string) (v4, v6 uint32) {
		for _, raw := range values {
			if strings.Contains(raw, ":") {
				v6++
			} else {
				v4++
			}
		}
		return
	}
	allow4, allow6 := count(wantAllowed)
	deny4, deny6 := count(wantDenied)
	if allow4 > cap4 || deny4 > cap4 || allow6 > cap6 || deny6 > cap6 {
		return filter.ErrProtectedRuleCapacity
	}
	beforeAllowed := append([]string(nil), f.allowed...)
	beforeDenied := append([]string(nil), f.denied...)
	beforeMode := f.mode
	contains := func(values []string, target string) bool {
		for _, value := range values {
			if value == target {
				return true
			}
		}
		return false
	}
	rollback := func(err error) error {
		f.allowed, f.denied, f.mode = beforeAllowed, beforeDenied, beforeMode
		return err
	}
	setMode := func(target filter.PolicyMode) error {
		if f.mode == target {
			return nil
		}
		entered, release := f.setModeEntered, f.setModeRelease
		f.mu.Unlock()
		if entered != nil {
			f.setModeOnce.Do(func() { close(entered) })
		}
		if release != nil {
			<-release
		}
		f.mu.Lock()
		f.events = append(f.events, "set-mode "+target.String())
		f.setModeCalls++
		if f.setModeErr != nil {
			return f.setModeErr
		}
		f.mode = target
		return nil
	}
	applyAllowed := func() error {
		for _, raw := range wantAllowed {
			if !contains(beforeAllowed, raw) {
				f.events = append(f.events, "allow "+raw)
				f.allowCalls++
				if f.allowErr != nil {
					return f.allowErr
				}
				f.allowed = appendUnique(f.allowed, raw)
			}
		}
		for _, raw := range beforeAllowed {
			if !contains(wantAllowed, raw) {
				f.events = append(f.events, "remove-allow "+raw)
				f.removedAllowed = append(f.removedAllowed, raw)
				if f.removeAllowErr != nil {
					return f.removeAllowErr
				}
				f.allowed = removeString(f.allowed, raw)
			}
		}
		return nil
	}
	applyDenied := func() error {
		for _, raw := range wantDenied {
			if !contains(beforeDenied, raw) {
				f.events = append(f.events, "deny "+raw)
				if f.denyErr != nil {
					return f.denyErr
				}
				f.denied = appendUnique(f.denied, raw)
			}
		}
		for _, raw := range beforeDenied {
			if !contains(wantDenied, raw) {
				f.events = append(f.events, "remove-deny "+raw)
				f.removedDenied = append(f.removedDenied, raw)
				if f.removeDenyErr != nil {
					return f.removeDenyErr
				}
				f.denied = removeString(f.denied, raw)
			}
		}
		return nil
	}
	applyOrRollback := func(apply func() error) error {
		if err := apply(); err != nil {
			return rollback(err)
		}
		return nil
	}
	switch {
	case beforeMode == mode && mode == filter.ModeAllowlist:
		if err := applyOrRollback(applyDenied); err != nil {
			return err
		}
		if err := applyOrRollback(applyAllowed); err != nil {
			return err
		}
	case beforeMode == mode && mode == filter.ModeDenylist:
		if err := applyOrRollback(applyAllowed); err != nil {
			return err
		}
		if err := applyOrRollback(applyDenied); err != nil {
			return err
		}
	case mode == filter.ModeAllowlist:
		if err := applyOrRollback(applyAllowed); err != nil {
			return err
		}
		if err := setMode(mode); err != nil {
			return rollback(err)
		}
		if err := applyOrRollback(applyDenied); err != nil {
			return err
		}
	case mode == filter.ModeDenylist:
		if err := applyOrRollback(applyDenied); err != nil {
			return err
		}
		if err := setMode(mode); err != nil {
			return rollback(err)
		}
		if err := applyOrRollback(applyAllowed); err != nil {
			return err
		}
	default:
		if err := setMode(mode); err != nil {
			return rollback(err)
		}
		if err := applyOrRollback(applyAllowed); err != nil {
			return err
		}
		if err := applyOrRollback(applyDenied); err != nil {
			return err
		}
	}
	f.allowed, f.denied = wantAllowed, wantDenied
	return nil
}

func (f *fakeFilter) ProtectedRuleOccupancy() (filter.ProtectedRuleOccupancy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protectedOccupancyCalls++
	if f.protectedOccupancyErr != nil {
		return filter.ProtectedRuleOccupancy{}, f.protectedOccupancyErr
	}
	cap4, cap6 := f.ruleCapacity4, f.ruleCapacity6
	if cap4 == 0 {
		cap4 = math.MaxUint32
	}
	if cap6 == 0 {
		cap6 = math.MaxUint32
	}
	var out filter.ProtectedRuleOccupancy
	out.AllowedIPv4.Capacity, out.DeniedIPv4.Capacity = cap4, cap4
	out.AllowedIPv6.Capacity, out.DeniedIPv6.Capacity = cap6, cap6
	for _, raw := range f.allowed {
		if strings.Contains(raw, ":") {
			out.AllowedIPv6.Entries++
		} else {
			out.AllowedIPv4.Entries++
		}
	}
	for _, raw := range f.denied {
		if strings.Contains(raw, ":") {
			out.DeniedIPv6.Entries++
		} else {
			out.DeniedIPv4.Entries++
		}
	}
	return out, nil
}

func (f *fakeFilter) protectedOccupancyCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.protectedOccupancyCalls
}

func (f *fakeFilter) setProtectedOccupancyErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protectedOccupancyErr = err
}

func (f *fakeFilter) AddDNSAllowedIPs(ips []net.IP) error {
	f.mu.Lock()
	entered, release := f.dnsAddEntered, f.dnsAddRelease
	f.mu.Unlock()
	if entered != nil {
		f.dnsAddOnce.Do(func() { close(entered) })
	}
	if release != nil {
		<-release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsAddCalls++
	if f.dnsAddErr != nil {
		return f.dnsAddErr
	}
	for _, ip := range ips {
		f.dnsAllowed = appendUnique(f.dnsAllowed, ip.String())
	}
	return nil
}

func (f *fakeFilter) dnsSnapshot() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dnsAllowed...), f.dnsAddCalls
}

// resetDNSAllowedForBenchmark clears only the fake kernel exact-map snapshot.
// It intentionally retains the backing allocation and cumulative call counts
// so cold-query benchmarks can reset physical state without measuring fixture
// reconstruction or weakening their one-add-per-query postcondition.
func (f *fakeFilter) resetDNSAllowedForBenchmark() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsAllowed = f.dnsAllowed[:0]
}

func (f *fakeFilter) RemoveDNSAllowedIPs(ips []net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsRemoveCalls++
	if f.dnsRemoveErr != nil {
		return f.dnsRemoveErr
	}
	for _, ip := range ips {
		f.dnsAllowed = removeString(f.dnsAllowed, ip.String())
	}
	return nil
}

func (f *fakeFilter) ReplaceDNSAllowedIPs(remove, add []net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsReplaceCalls++
	if f.dnsReplaceErr != nil {
		return f.dnsReplaceErr
	}
	for _, ip := range remove {
		f.dnsAllowed = removeString(f.dnsAllowed, ip.String())
	}
	for _, ip := range add {
		f.dnsAllowed = appendUnique(f.dnsAllowed, ip.String())
	}
	return nil
}

func (f *fakeFilter) dnsRemoveCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dnsRemoveCalls
}

func (f *fakeFilter) DNSAllowedIPs() ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dnsListOverride != nil {
		out := make([]net.IP, len(f.dnsListOverride))
		for i := range f.dnsListOverride {
			out[i] = append(net.IP(nil), f.dnsListOverride[i]...)
		}
		return out, nil
	}
	out := make([]net.IP, 0, len(f.dnsAllowed))
	for _, raw := range f.dnsAllowed {
		out = append(out, net.ParseIP(raw))
	}
	return out, nil
}

func (f *fakeFilter) DNSAllowOccupancy() (filter.DNSAllowOccupancy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dnsOccupancyOverride != nil {
		return *f.dnsOccupancyOverride, nil
	}
	var out filter.DNSAllowOccupancy
	for _, raw := range f.dnsAllowed {
		if net.ParseIP(raw).To4() != nil {
			out.IPv4Entries++
		} else {
			out.IPv6Entries++
		}
	}
	out.IPv4Capacity = f.dnsCapacity4
	if out.IPv4Capacity == 0 {
		out.IPv4Capacity = ^uint32(0)
	}
	out.IPv6Capacity = f.dnsCapacity6
	if out.IPv6Capacity == 0 {
		out.IPv6Capacity = ^uint32(0)
	}
	return out, nil
}

func (f *fakeFilter) setRemoveAllowedErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeAllowErr = err
}

func (f *fakeFilter) setRemoveDeniedErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeDenyErr = err
}

func (f *fakeFilter) removeCalls() (removedAllowed, removedDenied []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.removedAllowed...), append([]string(nil), f.removedDenied...)
}

// eventLog returns the sequenced mutating-call log (see the events field).
func (f *fakeFilter) eventLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeFilter) ClearRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closeCalls > 0 {
		f.mutationsAfterClose++
	}
	f.events = append(f.events, "clear")
	f.allowed = nil
	f.denied = nil
	f.dnsAllowed = nil
	f.clearCalls++
	return nil
}

func (f *fakeFilter) mutationAfterCloseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mutationsAfterClose
}

func (f *fakeFilter) GetStats() (filter.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, nil
}

func (f *fakeFilter) GetMode() (filter.PolicyMode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getModeCalls++
	if f.getModeErr != nil {
		return filter.ModeDisabled, f.getModeErr
	}
	return f.mode, nil
}

func (f *fakeFilter) modeCallCounts() (set, get int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.setModeCalls, f.getModeCalls
}

func (f *fakeFilter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCalls++
	return f.closeErr
}

func (f *fakeFilter) setCloseErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeErr = err
}

// Detach mirrors the real filters: it is Close plus pin removal. It bumps
// closeCalls too so the exactly-once-teardown assertions (closeCallCount)
// keep guarding double-frees regardless of which teardown path ran.
func (f *fakeFilter) Detach() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachCalls++
	if f.closeCalls == 0 {
		f.closeCalls++
	}
	f.events = append(f.events, "detach")
	if len(f.detachErrs) > 0 {
		err := f.detachErrs[0]
		f.detachErrs = f.detachErrs[1:]
		return err
	}
	return f.detachErr
}

func (f *fakeFilter) setDetachErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachErr = err
}

func (f *fakeFilter) setDetachErrors(errs ...error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachErrs = append([]error(nil), errs...)
}

// detachCallCount reports how many times Detach ran.
func (f *fakeFilter) detachCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.detachCalls
}

// Rules mirrors the real filters' rule listing (used by restore reseeding).
func (f *fakeFilter) Rules() (allowed, denied []*net.IPNet, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rulesErr != nil {
		return nil, nil, f.rulesErr
	}
	for _, s := range f.allowed {
		_, cidr, perr := net.ParseCIDR(s)
		if perr != nil {
			return nil, nil, perr
		}
		allowed = append(allowed, cidr)
	}
	for _, s := range f.denied {
		_, cidr, perr := net.ParseCIDR(s)
		if perr != nil {
			return nil, nil, perr
		}
		denied = append(denied, cidr)
	}
	return allowed, denied, nil
}

// closeCallCount reports how many times Close ran, so tests can prove
// exactly-once teardown (no double-close between a racing Detach and an
// Attach rollback).
func (f *fakeFilter) closeCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCalls
}

func (f *fakeFilter) snapshot() (filter.PolicyMode, []string, []string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mode, append([]string(nil), f.allowed...), append([]string(nil), f.denied...), f.clearCalls
}

func appendUnique(values []string, target string) []string {
	for _, value := range values {
		if value == target {
			return values
		}
	}
	return append(values, target)
}

func removeString(values []string, target string) []string {
	out := values[:0]
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func newTestServerWithAttachment(t testing.TB) (*Server, *store.Store, string, *fakeFilter, *DNSServer) {
	t.Helper()

	st, err := store.New(filepath.Join(t.TempDir(), "netfence.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = st.Close()
	})

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    12000,
			PortMax:    12010,
			Upstream:   "127.0.0.1:1",
		},
	}
	server, err := NewServer(cfg, st, zerolog.Nop(), "test")
	require.NoError(t, err)

	id := "att-1"
	attachment := &store.Attachment{
		ID:         id,
		Target:     "target-1",
		Type:       apiv1.AttachmentType_ATTACHMENT_TYPE_TC.String(),
		Mode:       apiv1.PolicyMode_POLICY_MODE_DISABLED.String(),
		DnsMode:    apiv1.DnsMode_DNS_MODE_DISABLED.String(),
		DnsAddress: net.JoinHostPort(cfg.DNS.ListenAddr, "12000"),
		Metadata:   map[string]string{"tenant": "test"},
		AttachedAt: time.Now().UTC(),
	}
	require.NoError(t, st.SaveAttachment(attachment))

	ff := &fakeFilter{}
	reg := newTTLRegistry()
	sink, err := server.newDNSFilterSink(id, ff)
	require.NoError(t, err)
	dnsServer := NewDNSServer(id, attachment.DnsAddress, cfg.DNS.Upstream, zerolog.Nop(), sink, nil, sink.LimitCeilings())
	server.mu.Lock()
	server.attachments[id] = &attachmentState{info: attachment, dns: dnsServer, dnsSink: sink, filter: ff, ttls: reg}
	server.targetIndex[attachment.Target] = id
	server.portPool[12000] = true
	server.mu.Unlock()

	return server, st, id, ff, dnsServer
}
