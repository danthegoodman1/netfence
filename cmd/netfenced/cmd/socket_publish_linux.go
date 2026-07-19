//go:build linux

package cmd

import "golang.org/x/sys/unix"

func publishSocketNoReplace(staged, target string) error {
	return unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
}
