package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDurableDefaultAndExplicitEphemeralValidation(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	require.Equal(t, "/var/lib/netfence/netfence.db", cfg.DBPath())
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("data_dir: ''\n"), 0600))
	_, err = Load(path)
	require.ErrorContains(t, err, "data_dir must be durable")
	require.NoError(t, os.WriteFile(path, []byte("data_dir: ''\nfilter:\n  bpf_pin_dir: ''\n"), 0600))
	cfg, err = Load(path)
	require.NoError(t, err)
	require.Equal(t, ":memory:", cfg.DBPath())
}
