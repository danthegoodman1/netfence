//go:build linux

package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonLockLifetime(t *testing.T) {
	if path := os.Getenv("NETFENCE_TEST_LOCK_PATH"); path != "" {
		lock, err := acquireDaemonLock(path)
		if err != nil {
			os.Exit(23)
		}
		lock.Close()
		return
	}
	path := filepath.Join(t.TempDir(), "daemon.lock")
	lock, err := acquireDaemonLock(path)
	require.NoError(t, err)
	t.Cleanup(func() { lock.Close() })
	run := func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonLockLifetime$")
		cmd.Env = append(os.Environ(), "NETFENCE_TEST_LOCK_PATH="+path)
		return cmd.Run()
	}
	var exit *exec.ExitError
	require.ErrorAs(t, run(), &exit)
	require.Equal(t, 23, exit.ExitCode())
	require.NoError(t, lock.Close())
	require.NoError(t, run())
	_, err = os.Stat(path)
	require.NoError(t, err, "lock inode remains stable across starts")
}

func TestDaemonLockRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "target"), path))
	_, err := acquireDaemonLock(path)
	require.Error(t, err)
}
