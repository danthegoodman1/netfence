//go:build linux

package cmd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Keep the lock inode on disk: unlinking it allows another daemon to lock a
// different inode while the first still holds this one. Closing releases flock.
func acquireDaemonLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening daemon lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquiring host daemon lock %s (only one daemon per host is supported): %w", path, err)
	}
	return f, nil
}
