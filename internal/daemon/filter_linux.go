//go:build linux

package daemon

import (
	"fmt"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func createFilter(target string, attachType apiv1.AttachmentType, mode apiv1.PolicyMode) (filter.Filter, error) {
	filterMode := apiModeToFilterMode(mode)

	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		return filter.NewCgroupFilter(target, filterMode)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return filter.NewTCFilter(target, filterMode)
	default:
		return nil, fmt.Errorf("unsupported attachment type: %s", attachType)
	}
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
