package cmd

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
