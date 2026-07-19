package filter

import (
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"
)

type fakeExactBackend struct {
	entries        map[exactIPKey]struct{}
	capacity4      uint32
	capacity6      uint32
	putCount       int
	deleteCount    int
	failPutAt      int
	failDeleteAt   int
	failDelete     map[exactIPKey]error
	mutateOnPut    bool
	mutateOnDelete bool
	ops            []string
}

func newFakeExactBackend(capacity uint32, initial ...net.IP) *fakeExactBackend {
	b := &fakeExactBackend{
		entries:    make(map[exactIPKey]struct{}),
		capacity4:  capacity,
		capacity6:  capacity,
		failDelete: make(map[exactIPKey]error),
	}
	keys, err := canonicalExactIPKeys(initial)
	if err != nil {
		panic(err)
	}
	for _, key := range keys {
		b.entries[key] = struct{}{}
	}
	return b
}

func (b *fakeExactBackend) keys(family exactIPFamily) ([]exactIPKey, error) {
	var out []exactIPKey
	for key := range b.entries {
		if key.family == family {
			out = append(out, key)
		}
	}
	sortExactIPKeys(out)
	return out, nil
}

func (b *fakeExactBackend) capacity(family exactIPFamily) (uint32, error) {
	if family == exactIPv4 {
		return b.capacity4, nil
	}
	return b.capacity6, nil
}

func (b *fakeExactBackend) put(key exactIPKey) error {
	b.putCount++
	b.ops = append(b.ops, "put "+key.ip().String())
	if b.failPutAt > 0 && b.putCount == b.failPutAt {
		if b.mutateOnPut {
			b.entries[key] = struct{}{}
		}
		return syscall.EIO
	}
	b.entries[key] = struct{}{}
	return nil
}

func (b *fakeExactBackend) delete(key exactIPKey) error {
	b.deleteCount++
	b.ops = append(b.ops, "delete "+key.ip().String())
	if b.failDeleteAt > 0 && b.deleteCount == b.failDeleteAt {
		if b.mutateOnDelete {
			delete(b.entries, key)
		}
		return syscall.EIO
	}
	if err := b.failDelete[key]; err != nil {
		return err
	}
	delete(b.entries, key)
	return nil
}

func exactIPStrings(t *testing.T, b exactDNSBackend) []string {
	t.Helper()
	ips, err := listExactDNSIPs(b)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func TestExactDNSBatchValidatesBeforeMutationAndPreflightsCapacity(t *testing.T) {
	b := newFakeExactBackend(1)
	if err := addExactDNSIPs(b, []net.IP{net.ParseIP("192.0.2.1"), nil}); err == nil {
		t.Fatal("nil IP must be rejected")
	}
	if len(b.ops) != 0 {
		t.Fatalf("validation failure mutated backend: %v", b.ops)
	}
	if err := addExactDNSIPs(b, []net.IP{{1, 2, 3}}); err == nil {
		t.Fatal("invalid-length IP must be rejected")
	}
	if len(b.ops) != 0 {
		t.Fatalf("invalid IP mutated backend: %v", b.ops)
	}

	err := addExactDNSIPs(b, []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")})
	if !errors.Is(err, ErrDNSAllowCapacity) {
		t.Fatalf("want capacity error, got %v", err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("capacity preflight must precede mutation: %v", b.ops)
	}
}

func TestExactDNSBatchCrossFamilyCapacityPreflightIsAtomic(t *testing.T) {
	initialV6 := net.ParseIP("2001:db8::1")
	b := newFakeExactBackend(1, initialV6)
	err := addExactDNSIPs(b, []net.IP{
		net.ParseIP("192.0.2.1"),   // IPv4 has room
		net.ParseIP("2001:db8::2"), // IPv6 is already full
	})
	if !errors.Is(err, ErrDNSAllowCapacity) {
		t.Fatalf("want cross-family capacity error, got %v", err)
	}
	if len(b.ops) != 0 {
		t.Fatalf("IPv6 preflight failure must precede every IPv4 put: %v", b.ops)
	}
	if got := exactIPStrings(t, b); !reflect.DeepEqual(got, []string{initialV6.String()}) {
		t.Fatalf("cross-family preflight changed contents: %v", got)
	}
}

func TestExactDNSBatchCanonicalDedupeAndSortedList(t *testing.T) {
	b := newFakeExactBackend(4)
	err := addExactDNSIPs(b, []net.IP{
		net.ParseIP("2001:db8::2"),
		net.IPv4(192, 0, 2, 2),
		net.ParseIP("192.0.2.1"),
		net.ParseIP("::ffff:192.0.2.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.1", "192.0.2.2", "2001:db8::2"}
	if got := exactIPStrings(t, b); !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	if b.putCount != 3 {
		t.Fatalf("deduped batch should perform 3 puts, got %d", b.putCount)
	}
}

func TestExactDNSBatchAmbiguousPutRollsBackToProvenSnapshot(t *testing.T) {
	initial := net.ParseIP("198.51.100.9")
	b := newFakeExactBackend(8, initial)
	b.failPutAt = 2
	b.mutateOnPut = true // syscall changed the map and then reported EIO
	err := addExactDNSIPs(b, []net.IP{net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.1")})
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("want original EIO, got %v", err)
	}
	if errors.Is(err, ErrDNSAllowRollback) {
		t.Fatalf("authoritative snapshot proved clean rollback: %v", err)
	}
	if got := exactIPStrings(t, b); !reflect.DeepEqual(got, []string{initial.String()}) {
		t.Fatalf("rollback did not restore exact pre-state: %v", got)
	}
	wantTail := []string{"delete 192.0.2.1", "delete 192.0.2.2"}
	if got := b.ops[len(b.ops)-2:]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("rollback order is nondeterministic: want %v, got %v (all %v)", wantTail, got, b.ops)
	}
}

func TestExactDNSBatchResidualIsTypedRollbackAmbiguity(t *testing.T) {
	b := newFakeExactBackend(8)
	b.failPutAt = 1
	b.mutateOnPut = true
	key, err := canonicalExactIPKeys([]net.IP{net.ParseIP("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	b.failDelete[key[0]] = syscall.EBUSY
	err = addExactDNSIPs(b, []net.IP{net.ParseIP("192.0.2.1")})
	if !errors.Is(err, ErrDNSAllowRollback) {
		t.Fatalf("residual key must force typed fail-closed ambiguity, got %v", err)
	}
	if got := exactIPStrings(t, b); !reflect.DeepEqual(got, []string{"192.0.2.1"}) {
		t.Fatalf("test must prove residual state, got %v", got)
	}
}

func TestExactDNSRemoveFailureRestoresInSortedOrder(t *testing.T) {
	b := newFakeExactBackend(8,
		net.ParseIP("2001:db8::2"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.1"),
	)
	// Fail the last initial delete after the two IPv4 keys were removed.
	v6Key, _ := canonicalExactIPKeys([]net.IP{net.ParseIP("2001:db8::2")})
	b.failDelete[v6Key[0]] = syscall.EIO
	err := removeExactDNSIPs(b, []net.IP{
		net.ParseIP("2001:db8::2"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.1"),
	})
	if !errors.Is(err, syscall.EIO) || errors.Is(err, ErrDNSAllowRollback) {
		t.Fatalf("want cleanly rolled-back original failure, got %v", err)
	}
	wantTail := []string{"put 192.0.2.1", "put 192.0.2.2"}
	if got := b.ops[len(b.ops)-2:]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("restore order is nondeterministic: want %v, got %v (all %v)", wantTail, got, b.ops)
	}
}

func TestExactDNSRemoveAmbiguousAppliedDeleteRestoresProvenSnapshot(t *testing.T) {
	initial := net.ParseIP("192.0.2.44")
	b := newFakeExactBackend(8, initial)
	b.failDeleteAt = 1
	b.mutateOnDelete = true // syscall deleted the key and then reported EIO
	err := removeExactDNSIPs(b, []net.IP{initial})
	if !errors.Is(err, syscall.EIO) {
		t.Fatalf("want original EIO, got %v", err)
	}
	if errors.Is(err, ErrDNSAllowRollback) {
		t.Fatalf("authoritative final snapshot proved remove rollback: %v", err)
	}
	if got := exactIPStrings(t, b); !reflect.DeepEqual(got, []string{initial.String()}) {
		t.Fatalf("ambiguous delete rollback did not restore exact pre-state: %v", got)
	}
	wantOps := []string{"delete 192.0.2.44", "put 192.0.2.44"}
	if !reflect.DeepEqual(b.ops, wantOps) {
		t.Fatalf("unexpected ambiguous-delete recovery operations: want %v, got %v", wantOps, b.ops)
	}
}
