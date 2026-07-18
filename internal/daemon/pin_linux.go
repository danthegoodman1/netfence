//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// bpffsMountpoint is the canonical bpffs mount location.
const bpffsMountpoint = "/sys/fs/bpf"

// ensureBPFPinRoot makes sure pinRoot exists and lives on a bpffs mount, so
// pinned links/maps actually survive the daemon process. If pinRoot is under
// /sys/fs/bpf and bpffs is not mounted there yet, it mounts it (requires
// privilege). Anything else fails with an actionable error rather than
// silently pinning to a filesystem that cannot hold BPF objects.
func ensureBPFPinRoot(pinRoot string) error {
	if err := os.MkdirAll(pinRoot, 0o700); err == nil {
		if ok, ferr := onBpffs(pinRoot); ferr == nil && ok {
			return nil
		}
	}
	// Either the mkdir failed (e.g. /sys/fs/bpf is a read-only sysfs
	// directory because bpffs is not mounted) or the directory is not on
	// bpffs. If the pin root lives under the canonical mountpoint, try
	// mounting bpffs there and re-check.
	if pinRoot == bpffsMountpoint || strings.HasPrefix(pinRoot, bpffsMountpoint+"/") {
		if err := unix.Mount("bpffs", bpffsMountpoint, "bpf", 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("bpffs is not mounted at %s and mounting it failed: %w; mount it manually (mount -t bpf bpffs %s) or set filter.bpf_pin_dir to an existing bpffs mount", bpffsMountpoint, err, bpffsMountpoint)
		}
	}
	if err := os.MkdirAll(pinRoot, 0o700); err != nil {
		return fmt.Errorf("creating BPF pin root %s: %w", pinRoot, err)
	}
	ok, err := onBpffs(pinRoot)
	if err != nil {
		return fmt.Errorf("checking filesystem of BPF pin root %s: %w", pinRoot, err)
	}
	if !ok {
		return fmt.Errorf("BPF pin root %s is not on a bpffs mount; mount bpffs (mount -t bpf bpffs %s) or point filter.bpf_pin_dir at a bpffs mount", pinRoot, bpffsMountpoint)
	}
	return nil
}

// onBpffs reports whether path lives on a bpffs filesystem.
func onBpffs(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return uint32(st.Type) == uint32(unix.BPF_FS_MAGIC), nil
}
