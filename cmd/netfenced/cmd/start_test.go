package cmd

import (
	"errors"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSocketGroup(t *testing.T) {
	lookupCalls := 0
	lookup := func(name string) (*user.Group, error) {
		lookupCalls++
		switch name {
		case "netfence":
			return &user.Group{Name: name, Gid: "4321"}, nil
		case "oversized":
			return &user.Group{Name: name, Gid: "4294967296"}, nil
		}
		return nil, errors.New("missing")
	}
	maxUsableGID := uint64(math.MaxUint32 - 1)
	tests := []struct {
		name, value string
		want        int
		wantErr     bool
	}{
		{"empty_uses_effective", "", 1234, false},
		{"numeric", "2345", 2345, false},
		{"numeric_max_usable", "4294967294", int(maxUsableGID), false},
		{"numeric_sentinel", "4294967295", 0, true},
		{"numeric_gid_t_overflow", "4294967296", 0, true},
		{"name", "netfence", 4321, false},
		{"name_gid_t_overflow", "oversized", 0, true},
		{"negative", "-1", 0, true},
		{"numeric_overflow", "999999999999999999999999", 0, true},
		{"numeric_malformed", "12bad", 0, true},
		{"missing_name", "missing", 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := lookupCalls
			got, err := resolveSocketGroup(test.value, 1234, lookup)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.want, got)
			}
			if strings.HasPrefix(test.name, "numeric") || test.name == "negative" {
				assert.Equal(t, before, lookupCalls, "numeric-looking values never fall through to name lookup")
			}
		})
	}
}

func TestPrepareDaemonSocketPublishesSecuredIdentity(t *testing.T) {
	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "netfence.sock")
	listener, gid, err := prepareDaemonSocket(path, strconv.Itoa(os.Getegid()), defaultSocketSetupOps())
	require.NoError(t, err)
	assert.Equal(t, os.Getegid(), gid)
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSocket)
	assert.Equal(t, os.FileMode(0660), info.Mode().Perm())
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, uint32(os.Getegid()), stat.Gid)

	// A replacement at the published pathname is never removed by cleanup.
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("replacement"), 0600))
	require.NoError(t, listener.Close())
	replacement, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(replacement))
}

func TestPrepareDaemonSocketPermissionFailuresLeaveNothingReachable(t *testing.T) {
	for _, stage := range []string{"chown", "chmod"} {
		t.Run(stage, func(t *testing.T) {
			dir := shortSocketTempDir(t)
			path := filepath.Join(dir, "netfence.sock")
			ops := defaultSocketSetupOps()
			if stage == "chown" {
				ops.chown = func(string, int, int) error { return errors.New("injected chown failure") }
			} else {
				ops.chmod = func(string, os.FileMode) error { return errors.New("injected chmod failure") }
			}
			listener, _, err := prepareDaemonSocket(path, "", ops)
			require.Error(t, err)
			assert.Nil(t, listener)
			_, statErr := os.Lstat(path)
			assert.True(t, os.IsNotExist(statErr))
			staging, globErr := filepath.Glob(filepath.Join(dir, ".nf-*"))
			require.NoError(t, globErr)
			assert.Empty(t, staging)
		})
	}
}

func TestPrepareDaemonSocketLookupFailsBeforeFilesystemMutation(t *testing.T) {
	dir := shortSocketTempDir(t)
	path := filepath.Join(dir, "netfence.sock")
	stale, err := net.Listen("unix", path)
	require.NoError(t, err)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, stale.Close())
	ops := defaultSocketSetupOps()
	removeCalls := 0
	ops.lookupGroup = func(string) (*user.Group, error) { return nil, errors.New("injected lookup failure") }
	ops.removeStale = func(string) error { removeCalls++; return nil }
	listener, _, err := prepareDaemonSocket(path, "missing-group", ops)
	require.Error(t, err)
	assert.Nil(t, listener)
	assert.Zero(t, removeCalls)
	info, statErr := os.Lstat(path)
	require.NoError(t, statErr)
	assert.NotZero(t, info.Mode()&os.ModeSocket, "pre-existing path is untouched")
}

func shortSocketTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nf-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestRemoveStaleSocketRemovesOnlyUnixSockets(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "netfence-socket-test-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	socketPath := filepath.Join(dir, "netfence.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	require.NoError(t, listener.Close())

	require.NoError(t, removeStaleSocket(socketPath))
	_, err = os.Lstat(socketPath)
	assert.True(t, os.IsNotExist(err))

	filePath := filepath.Join(dir, "regular")
	require.NoError(t, os.WriteFile(filePath, []byte("not a socket"), 0600))
	require.Error(t, removeStaleSocket(filePath))
	_, err = os.Lstat(filePath)
	assert.NoError(t, err)

	dirPath := filepath.Join(dir, "socket-dir")
	require.NoError(t, os.Mkdir(dirPath, 0700))
	require.Error(t, removeStaleSocket(dirPath))
	_, err = os.Lstat(dirPath)
	assert.NoError(t, err)

	assert.NoError(t, removeStaleSocket(filepath.Join(dir, "missing.sock")))
}
