//go:build !linux

package daemon

import (
	"fmt"
	"net"
	"os"
	"syscall"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

func currentTargetIdentity(attachType apiv1.AttachmentType, target string) (uint64, error) {
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		iface, err := net.InterfaceByName(target)
		if err != nil {
			return 0, err
		}
		return uint64(iface.Index), nil
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		info, err := os.Stat(target)
		if err != nil {
			return 0, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, fmt.Errorf("stat for %s did not expose an inode", target)
		}
		return stat.Ino, nil
	default:
		return 0, fmt.Errorf("unsupported attachment type: %s", attachType)
	}
}
