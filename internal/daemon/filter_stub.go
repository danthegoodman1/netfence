//go:build !linux

package daemon

import (
	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func createFilter(_ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode) (filter.Filter, error) {
	return nil, nil
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
