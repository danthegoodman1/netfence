//go:build linux

package daemon

import (
	"fmt"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func createFilter(pinDir, target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection, maxRuleEntries uint32) (filter.Filter, error) {
	filterMode := apiModeToFilterMode(mode)

	// Default carve-out posture (localhost + IPv6 ND allowed, IPv4
	// link-local incl. the cloud metadata service subject to policy).
	// Per-attachment overrides via the control plane are a deferred
	// follow-up; allowlisting 169.254.169.254/32 is the override for
	// workloads that need the metadata service.
	carveouts := filter.DefaultCarveouts()
	opts := filter.Options{MaxRuleEntries: maxRuleEntries, PinDir: pinDir}

	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		// Direction is meaningless for cgroup filters and is ignored.
		return filter.NewCgroupFilterWithOptions(target, filterMode, carveouts, opts)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return filter.NewTCFilterWithOptions(target, filterMode, apiDirectionToFilterDirection(direction), carveouts, opts)
	default:
		return nil, fmt.Errorf("unsupported attachment type: %s", attachType)
	}
}

// loadPinnedFilter re-adopts an attachment's BPF state from its bpffs pin
// directory without re-attaching anything (see LoadPinned*Filter).
func loadPinnedFilter(pinDir, target string, attachType apiv1.AttachmentType, direction apiv1.TcDirection) (filter.Filter, error) {
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		f, err := filter.LoadPinnedCgroupFilter(target, pinDir)
		if err != nil {
			// Avoid converting a nil *CgroupFilter into a non-nil Filter
			// interface on the error path.
			return nil, err
		}
		return f, nil
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		f, err := filter.LoadPinnedTCFilter(target, apiDirectionToFilterDirection(direction), pinDir)
		if err != nil {
			// Avoid converting a nil *TCFilter into a non-nil Filter interface
			// on the error path.
			return nil, err
		}
		return f, nil
	default:
		return nil, fmt.Errorf("unsupported attachment type: %s", attachType)
	}
}

func apiDirectionToFilterDirection(direction apiv1.TcDirection) filter.TCDirection {
	if direction == apiv1.TcDirection_TC_DIRECTION_INGRESS {
		return filter.DirectionIngress
	}
	// UNSPECIFIED defaults to EGRESS (preserves pre-direction behavior).
	return filter.DirectionEgress
}

func apiModeToFilterMode(mode apiv1.PolicyMode) filter.PolicyMode {
	switch mode {
	case apiv1.PolicyMode_POLICY_MODE_ALLOWLIST:
		return filter.ModeAllowlist
	case apiv1.PolicyMode_POLICY_MODE_BLOCK_ALL:
		return filter.ModeBlockAll
	case apiv1.PolicyMode_POLICY_MODE_DENYLIST:
		return filter.ModeDenylist
	default:
		return filter.ModeDisabled
	}
}
