package filter

import (
	"errors"
	"fmt"
	"net"
)

var (
	// ErrPinnedStateInvalid marks a pin set that is explicitly incomplete or
	// structurally incompatible with the filter that owns it. Callers may
	// discard that exact pin set and recreate the attachment.
	ErrPinnedStateInvalid = errors.New("pinned filter state is structurally invalid")
	// ErrPinnedTargetMismatch marks a successfully inspected pinned link whose
	// kernel target identity differs from the live object currently at the
	// persisted name/path. The old link is defunct and may be discarded.
	ErrPinnedTargetMismatch = errors.New("pinned filter target identity changed")
	// ErrPinnedStateCloseFailed marks an ambiguous attempt to close handles
	// opened during a failed pinned-state load. Even if the primary load error
	// is otherwise discardable, callers must preserve pins when this marker is
	// present because userspace no longer knows which references remain live.
	ErrPinnedStateCloseFailed = errors.New("closing partially loaded pinned filter state failed")
	// ErrPinnedSchemaUpgradeRequired means a legacy pin set needs a program
	// migration but the caller did not provide the original load-time
	// carve-outs. Guessing them could loosen enforcement, so callers must use
	// LoadPinned*Cgroup/TCFilterWithOptions and supply the known posture.
	ErrPinnedSchemaUpgradeRequired = errors.New("pinned filter schema upgrade requires explicit original carve-outs")
	// ErrPinnedSchemaIncompatible marks a pin set written by a newer or
	// otherwise unsupported schema. It is intentionally not discardable:
	// callers must preserve the pins and abort rather than replacing live,
	// potentially newer enforcement.
	ErrPinnedSchemaIncompatible = errors.New("pinned filter schema is incompatible")
	// ErrDNSAllowCapacity reports an exact DNS allow batch that cannot fit in
	// the independently bounded IPv4 or IPv6 exact map. Capacity is checked
	// before any key is inserted.
	ErrDNSAllowCapacity = errors.New("DNS exact allow map capacity exceeded")
	// ErrDNSAllowRollback marks the rare case where a batch mutation failed
	// and restoring its exact pre-call state also failed. The operation never
	// hides this ambiguity; callers must fail closed until reconciled.
	ErrDNSAllowRollback = errors.New("DNS exact allow batch rollback failed")
	// ErrProtectedRuleCapacity reports an authoritative protected-LPM
	// replacement whose final state cannot fit one of the four independent
	// allow/deny IPv4/IPv6 maps. The check happens before mutation.
	ErrProtectedRuleCapacity = errors.New("protected rule map capacity exceeded")
	// ErrProtectedRuleSnapshot means the filter could not prove the complete
	// pre-mutation contents/capacity of every protected LPM map. Callers must
	// fail closed because an authoritative deny replacement cannot safely be
	// inferred from partial inventory.
	ErrProtectedRuleSnapshot = errors.New("protected rule map snapshot is unprovable")
	// ErrProtectedRuleRollback marks a protected-LPM mutation failure whose
	// exact pre-call four-map inventory could not be restored and verified.
	// Even a successful map rollback proves the effective mode only as the old
	// mode or BLOCK_ALL (normally BLOCK_ALL), not necessarily the pre-call mode;
	// callers must keep the attachment fail closed until authoritative recovery.
	ErrProtectedRuleRollback = errors.New("protected rule map rollback failed")
	// ErrProtectedRuleModeAmbiguous marks a mode-map write/read sequence whose
	// effective enforcement posture cannot be proven. Callers must make a
	// separate BLOCK_ALL write/read-back attempt and stop admission if that
	// safety posture also cannot be proven.
	ErrProtectedRuleModeAmbiguous = errors.New("protected policy mode is ambiguous")
)

// PolicyMode defines the filtering behavior
type PolicyMode uint8

const (
	// ModeDisabled allows all traffic
	ModeDisabled PolicyMode = 0
	// ModeAllowlist only allows traffic to IPs in the allowlist
	ModeAllowlist PolicyMode = 1
	// ModeBlockAll blocks all outbound traffic
	ModeBlockAll PolicyMode = 2
	// ModeDenylist blocks traffic to IPs in the denylist, allows all others
	ModeDenylist PolicyMode = 3
)

func (m PolicyMode) String() string {
	switch m {
	case ModeDisabled:
		return "disabled"
	case ModeAllowlist:
		return "allowlist"
	case ModeBlockAll:
		return "block_all"
	case ModeDenylist:
		return "denylist"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// Carve-out flag bits. Must match the CARVEOUT_* macros in
// bpf/filter_cgroup.c and bpf/filter_tc.c.
const (
	carveoutLocalhostV4 uint32 = 1 << 0
	carveoutLocalhostV6 uint32 = 1 << 1
	carveoutLinkLocalV4 uint32 = 1 << 2
	carveoutLinkLocalV6 uint32 = 1 << 3
	carveoutMulticastV6 uint32 = 1 << 4
)

// Carveouts configures destination ranges that are always allowed regardless
// of allowlist/denylist policy (block-all mode still blocks everything).
// The flags are baked into the BPF program as a load-time constant, so they
// are per-attachment and have zero per-packet cost.
type Carveouts struct {
	// LocalhostV4 always allows 127.0.0.0/8.
	LocalhostV4 bool
	// LocalhostV6 always allows ::1.
	LocalhostV6 bool
	// LinkLocalV4 always allows 169.254.0.0/16. OFF by default: this range
	// includes 169.254.169.254, the cloud metadata service — a
	// credential-theft target that sandboxing policies must be able to
	// block. Workloads that need it can simply allowlist it.
	LinkLocalV4 bool
	// LinkLocalV6 always allows fe80::/10 (required for NDP; without it
	// IPv6 allowlist connectivity breaks).
	LinkLocalV6 bool
	// MulticastV6 always allows ff02::/16 (link-local scope multicast,
	// used by NDP neighbor/router solicitation).
	MulticastV6 bool
}

// DefaultCarveouts returns the default carve-out posture: localhost and the
// IPv6 neighbor-discovery ranges allowed, IPv4 link-local (metadata service)
// subject to policy.
func DefaultCarveouts() Carveouts {
	return Carveouts{
		LocalhostV4: true,
		LocalhostV6: true,
		LinkLocalV4: false,
		LinkLocalV6: true,
		MulticastV6: true,
	}
}

// flags encodes the carve-outs as the BPF-side bitmask.
func (c Carveouts) flags() uint32 {
	var f uint32
	if c.LocalhostV4 {
		f |= carveoutLocalhostV4
	}
	if c.LocalhostV6 {
		f |= carveoutLocalhostV6
	}
	if c.LinkLocalV4 {
		f |= carveoutLinkLocalV4
	}
	if c.LinkLocalV6 {
		f |= carveoutLinkLocalV6
	}
	if c.MulticastV6 {
		f |= carveoutMulticastV6
	}
	return f
}

// Options holds optional load-time filter tuning. The zero value keeps the
// compiled-in defaults.
type Options struct {
	// MaxRuleEntries sets max_entries for each of the four LPM rule maps
	// (allowed/denied, IPv4/IPv6) at program load time. 0 keeps the
	// compiled-in default (4096). This is pure map sizing: the BPF program
	// bytes and per-packet lookup cost are unchanged (LPM trie lookups are
	// bounded by key length, not capacity).
	MaxRuleEntries uint32

	// MaxDNSRuleEntries sets max_entries for each exact DNS-derived allow map
	// (IPv4 and IPv6) at program load time. 0 keeps the compiled-in default
	// (4096). This is intentionally independent from MaxRuleEntries: DNS
	// entries are regenerable and may later be reclaimed by deterministic
	// userspace LRU policy, while authoritative CIDRs and denies are protected.
	MaxDNSRuleEntries uint32

	// PinDir, when non-empty, pins the filter's links and maps to this
	// directory (which must live on a bpffs mount). Pinned state is held by
	// the kernel independent of the creating process: enforcement survives
	// Close() and process death, and LoadPinnedCgroupFilter /
	// LoadPinnedTCFilter re-adopt it without re-attaching. The directory must
	// not already exist: collisions fail before any BPF load or attachment and
	// existing state is never removed. Empty disables pinning (state dies with
	// the process, the pre-pinning behavior).
	PinDir string
}

// Stats holds the filter statistics
type Stats struct {
	Allowed uint64
	Blocked uint64
}

// DNSAllowOccupancy reports independent usage and hard capacity for the two
// exact DNS-derived allow maps. The authoritative LPM maps are intentionally
// not included.
type DNSAllowOccupancy struct {
	IPv4Entries  uint32
	IPv4Capacity uint32
	IPv6Entries  uint32
	IPv6Capacity uint32
}

// RuleMapUsage reports current entries and hard capacity for one protected
// LPM map. High-water values are daemon-generation telemetry and therefore
// live in the daemon's registry rather than this physical snapshot.
type RuleMapUsage struct {
	Entries  uint32
	Capacity uint32
}

// ProtectedRuleOccupancy reports each non-evictable authoritative/system LPM
// map independently. DNS exact-host maps are intentionally excluded.
type ProtectedRuleOccupancy struct {
	AllowedIPv4 RuleMapUsage
	AllowedIPv6 RuleMapUsage
	DeniedIPv4  RuleMapUsage
	DeniedIPv6  RuleMapUsage
}

// PinnedSchemaState is the read-only classification used by startup orphan
// handling. An absent/zero marker is an uncommitted create/migration and must
// be preserved; current means the commit-last marker and required exact pins
// are present.
type PinnedSchemaState uint8

const (
	PinnedSchemaUncommitted PinnedSchemaState = iota
	PinnedSchemaCurrent
)

// ParseCIDR is a helper that parses a CIDR string (or single IP)
func ParseCIDR(s string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR: %s", s)
		}
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	return cidr, nil
}
