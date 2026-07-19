//go:build linux

package filter

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgroupDetachClosesHandlesOnceAndRetriesUnpin(t *testing.T) {
	removeCalls, closeCalls := 0, 0
	f := &CgroupFilter{
		pinDir: "/sys/fs/bpf/netfence/test-cgroup",
		removePinDir: func(string) error {
			removeCalls++
			if removeCalls == 1 {
				return errors.New("injected unpin failure")
			}
			return nil
		},
		closeHandlesForTest: func() error {
			closeCalls++
			return nil
		},
	}

	require.Error(t, f.Detach())
	assert.Equal(t, 1, removeCalls)
	assert.Equal(t, 1, closeCalls, "first failed-unpin Detach still closes all handles")
	require.NoError(t, f.Detach())
	assert.Equal(t, 2, removeCalls, "retry repeats only the unpin primitive")
	assert.Equal(t, 1, closeCalls, "closed handles are never closed twice")
}

func TestTCDetachClosesHandlesOnceAndRetriesUnpin(t *testing.T) {
	removeCalls, closeCalls := 0, 0
	f := &TCFilter{
		pinDir: "/sys/fs/bpf/netfence/test-tc",
		removePinDir: func(string) error {
			removeCalls++
			if removeCalls == 1 {
				return errors.New("injected unpin failure")
			}
			return nil
		},
		closeHandlesForTest: func() error {
			closeCalls++
			return nil
		},
	}

	require.Error(t, f.Detach())
	assert.Equal(t, 1, removeCalls)
	assert.Equal(t, 1, closeCalls, "first failed-unpin Detach still closes all handles")
	require.NoError(t, f.Detach())
	assert.Equal(t, 2, removeCalls, "retry repeats only the unpin primitive")
	assert.Equal(t, 1, closeCalls, "closed handles are never closed twice")
}

func TestCgroupDetachPersistsAmbiguousCloseErrorAcrossRetries(t *testing.T) {
	closeCalls := 0
	f := &CgroupFilter{
		pinDir:       "/sys/fs/bpf/netfence/test-cgroup-close-error",
		removePinDir: func(string) error { return nil },
		closeHandlesForTest: func() error {
			closeCalls++
			return errors.New("injected ambiguous close failure")
		},
	}
	first := f.Detach()
	second := f.Detach()
	require.Error(t, first)
	require.Error(t, second)
	assert.Contains(t, second.Error(), "ambiguous close failure")
	assert.Equal(t, 1, closeCalls)
}

func TestTCDetachPersistsAmbiguousCloseErrorAcrossRetries(t *testing.T) {
	closeCalls := 0
	f := &TCFilter{
		pinDir:       "/sys/fs/bpf/netfence/test-tc-close-error",
		removePinDir: func(string) error { return nil },
		closeHandlesForTest: func() error {
			closeCalls++
			return errors.New("injected ambiguous close failure")
		},
	}
	first := f.Detach()
	second := f.Detach()
	require.Error(t, first)
	require.Error(t, second)
	assert.Contains(t, second.Error(), "ambiguous close failure")
	assert.Equal(t, 1, closeCalls)
}
