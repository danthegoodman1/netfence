//go:build !linux

package cmd

import "os"

// Netfence's enforcement runtime is Linux-only. This fallback keeps host-side
// compile/unit sanity available; Linux production uses renameat2 NOREPLACE.
func publishSocketNoReplace(staged, target string) error {
	if _, err := os.Lstat(target); err == nil {
		return os.ErrExist
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Rename(staged, target)
}
