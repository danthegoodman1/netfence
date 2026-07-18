//go:build linux

package daemon

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	apiv1 "github.com/danthegoodman1/netfence/v1"
)

// currentTargetIdentity returns the kernel object identity an attachment
// binds to, rather than the user-facing name/path that may later be reused.
func currentTargetIdentity(attachType apiv1.AttachmentType, target string) (uint64, error) {
	switch attachType {
	case apiv1.AttachmentType_ATTACHMENT_TYPE_TC:
		return currentInterfaceIdentity(target)
	case apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP:
		return currentCgroupIdentity(target)
	default:
		return 0, fmt.Errorf("unsupported attachment type: %s", attachType)
	}
}

func currentInterfaceIdentity(name string) (uint64, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint64(iface.Index), nil
}

// currentCgroupIdentity deliberately mirrors pkg/filter's pin validation:
// on cgroup v2 the name_to_handle_at payload is the cgroup id reported by a
// bpf_link, with the kernfs inode as the equivalent fallback.
func currentCgroupIdentity(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err == nil {
		if b := handle.Bytes(); len(b) >= 8 {
			return binary.LittleEndian.Uint64(b[:8]), nil
		}
	}
	var st unix.Stat_t
	if statErr := unix.Stat(path, &st); statErr != nil {
		return 0, fmt.Errorf("resolving cgroup identity of %s: name_to_handle_at: %v, stat: %w", path, err, statErr)
	}
	return st.Ino, nil
}
