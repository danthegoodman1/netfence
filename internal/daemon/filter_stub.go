//go:build !linux

package daemon

import (
	"fmt"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func createFilter(_, _ string, _ apiv1.AttachmentType, _ apiv1.PolicyMode, _ apiv1.TcDirection, _ uint32) (filter.Filter, error) {
	return nil, nil
}

func loadPinnedFilter(_, _ string, _ apiv1.AttachmentType, _ apiv1.TcDirection) (filter.Filter, error) {
	return nil, fmt.Errorf("pinned BPF filters are only supported on linux")
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
