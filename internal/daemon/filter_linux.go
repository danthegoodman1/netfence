//go:build linux

package daemon

import (
	"fmt"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func createFilter(target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode, direction apiv1.TcDirection) (filter.Filter, error) {
	filterMode := apiModeToFilterMode(mode)

	// Default carve-out posture (localhost + IPv6 ND allowed, IPv4
	// link-local incl. the cloud metadata service subject to policy).
	// Per-attachment overrides via the control plane are a deferred
	// follow-up; allowlisting 169.254.169.254/32 is the override for
	// workloads that need the metadata service.
	carveouts := filter.DefaultCarveouts()

	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		// Direction is meaningless for cgroup filters and is ignored.
		return filter.NewCgroupFilter(target, filterMode, carveouts)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return filter.NewTCFilter(target, filterMode, apiDirectionToFilterDirection(direction), carveouts)
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
