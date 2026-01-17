//go:build linux

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/danthegoodman1/netfence/pkg/filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testServerPort   = "18080"
	testServerAddrV4 = "127.0.0.1:" + testServerPort
	testServerAddrV6 = "[::1]:" + testServerPort
	// nc format (host port separately)
	testServerNcV4 = "127.0.0.1 " + testServerPort
	testServerNcV6 = "::1 " + testServerPort
)

// Well-known public DNS servers for testing (nc format: host port)
var (
	// IPv4 test targets
	googleDNSv4     = "8.8.8.8 53"
	cloudflareDNSv4 = "1.1.1.1 53"

	// IPv6 test targets
	googleDNSv6     = "2001:4860:4860::8888 53"
	cloudflareDNSv6 = "2606:4700:4700::1111 53"
)

// startTestServer starts a simple HTTP server for testing connections (dual-stack)
func startTestServer(t *testing.T) (cleanup func()) {
	// Start IPv4 listener
	listenerV4, err := net.Listen("tcp4", testServerAddrV4)
	require.NoError(t, err, "failed to start IPv4 test server")

	// Start IPv6 listener
	listenerV6, err := net.Listen("tcp6", testServerAddrV6)
	require.NoError(t, err, "failed to start IPv6 test server")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	serverV4 := &http.Server{Handler: handler}
	serverV6 := &http.Server{Handler: handler}

	go serverV4.Serve(listenerV4)
	go serverV6.Serve(listenerV6)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		serverV4.Shutdown(ctx)
		serverV6.Shutdown(ctx)
	}
}

// tryConnect attempts to connect to an address and returns whether it succeeded
func tryConnect(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// runInCgroup runs nc in a child process within the specified cgroup
// Returns true if the connection succeeded, false if blocked
func runInCgroup(cgroupPath, targetAddr string) bool {
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("echo $$ > %s/cgroup.procs && nc -z -w 2 %s", cgroupPath, targetAddr),
	)
	return cmd.Run() == nil
}

// setupTestCgroup creates a test cgroup and returns cleanup function
func setupTestCgroup(t *testing.T, name string) (cgroupPath string, cleanup func()) {
	cgroupPath = "/sys/fs/cgroup/" + name
	err := os.MkdirAll(cgroupPath, 0755)
	require.NoError(t, err, "failed to create test cgroup")
	return cgroupPath, func() { os.Remove(cgroupPath) }
}

// hasIPv6 checks if the system has IPv6 connectivity
func hasIPv6() bool {
	conn, err := net.DialTimeout("udp6", "[2001:4860:4860::8888]:53", 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func TestCgroupFilterLoad(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cgroupPath := "/sys/fs/cgroup"
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		t.Skipf("cgroup path %s does not exist", cgroupPath)
	}

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeDisabled)
	require.NoError(t, err)
	defer f.Close()

	mode, err := f.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeDisabled, mode)
}

func TestCgroupBlockAll(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-blockall-test")
	defer cgroupCleanup()

	// Verify connections work without filter
	require.True(t, tryConnect(testServerAddrV4, 2*time.Second), "IPv4 test server not reachable")
	require.True(t, tryConnect(testServerAddrV6, 2*time.Second), "IPv6 test server not reachable")

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeBlockAll)
	require.NoError(t, err)
	defer f.Close()

	t.Run("IPv4_blocked", func(t *testing.T) {
		assert.False(t, runInCgroup(cgroupPath, testServerNcV4),
			"expected IPv4 connection to be BLOCKED")
	})

	t.Run("IPv6_blocked", func(t *testing.T) {
		assert.False(t, runInCgroup(cgroupPath, testServerNcV6),
			"expected IPv6 connection to be BLOCKED")
	})

	stats, err := f.GetStats()
	require.NoError(t, err)
	assert.Greater(t, stats.Blocked, uint64(0), "expected blocked count > 0")
	t.Logf("Stats: allowed=%d, blocked=%d", stats.Allowed, stats.Blocked)
}

func TestCgroupDisabled(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-disabled-test")
	defer cgroupCleanup()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeDisabled)
	require.NoError(t, err)
	defer f.Close()

	t.Run("IPv4_allowed", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, testServerNcV4),
			"expected IPv4 connection to SUCCEED in disabled mode")
	})

	t.Run("IPv6_allowed", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, testServerNcV6),
			"expected IPv6 connection to SUCCEED in disabled mode")
	})
}

func TestCgroupAllowlist(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-allowlist-test")
	defer cgroupCleanup()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeAllowlist)
	require.NoError(t, err)
	defer f.Close()

	// IPv4 tests
	t.Run("IPv4/not_in_allowlist_blocked", func(t *testing.T) {
		assert.False(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to be BLOCKED (not in allowlist)")
	})

	t.Run("IPv4/in_allowlist_allowed", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("8.8.8.8/32")
		require.NoError(t, f.AllowIP(cidr))

		assert.True(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to SUCCEED (in allowlist)")
	})

	t.Run("IPv4/removed_from_allowlist_blocked", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("8.8.8.8/32")
		require.NoError(t, f.RemoveAllowedIP(cidr))

		assert.False(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to be BLOCKED (removed from allowlist)")
	})

	t.Run("IPv4/localhost_always_allowed", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, testServerNcV4),
			"expected IPv4 localhost to SUCCEED (always allowed)")
	})

	// IPv6 tests
	if hasIPv6() {
		t.Run("IPv6/not_in_allowlist_blocked", func(t *testing.T) {
			assert.False(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to be BLOCKED (not in allowlist)")
		})

		t.Run("IPv6/in_allowlist_allowed", func(t *testing.T) {
			cidr, _ := filter.ParseCIDR("2001:4860:4860::8888/128")
			require.NoError(t, f.AllowIP(cidr))

			assert.True(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to SUCCEED (in allowlist)")
		})

		t.Run("IPv6/removed_from_allowlist_blocked", func(t *testing.T) {
			cidr, _ := filter.ParseCIDR("2001:4860:4860::8888/128")
			require.NoError(t, f.RemoveAllowedIP(cidr))

			assert.False(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to be BLOCKED (removed from allowlist)")
		})
	} else {
		t.Log("Skipping IPv6 external tests - no IPv6 connectivity")
	}

	t.Run("IPv6/localhost_always_allowed", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, testServerNcV6),
			"expected IPv6 localhost to SUCCEED (always allowed)")
	})
}

func TestCgroupDenylist(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-denylist-test")
	defer cgroupCleanup()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeDenylist)
	require.NoError(t, err)
	defer f.Close()

	// IPv4 tests
	t.Run("IPv4/not_in_denylist_allowed", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to SUCCEED (not in denylist)")
	})

	t.Run("IPv4/in_denylist_blocked", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("8.8.8.8/32")
		require.NoError(t, f.DenyIP(cidr))

		assert.False(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to be BLOCKED (in denylist)")
	})

	t.Run("IPv4/removed_from_denylist_allowed", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("8.8.8.8/32")
		require.NoError(t, f.RemoveDeniedIP(cidr))

		assert.True(t, runInCgroup(cgroupPath, googleDNSv4),
			"expected IPv4 connection to SUCCEED (removed from denylist)")
	})

	// IPv6 tests
	if hasIPv6() {
		t.Run("IPv6/not_in_denylist_allowed", func(t *testing.T) {
			assert.True(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to SUCCEED (not in denylist)")
		})

		t.Run("IPv6/in_denylist_blocked", func(t *testing.T) {
			cidr, _ := filter.ParseCIDR("2001:4860:4860::8888/128")
			require.NoError(t, f.DenyIP(cidr))

			assert.False(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to be BLOCKED (in denylist)")
		})

		t.Run("IPv6/removed_from_denylist_allowed", func(t *testing.T) {
			cidr, _ := filter.ParseCIDR("2001:4860:4860::8888/128")
			require.NoError(t, f.RemoveDeniedIP(cidr))

			assert.True(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected IPv6 connection to SUCCEED (removed from denylist)")
		})
	} else {
		t.Log("Skipping IPv6 external tests - no IPv6 connectivity")
	}
}

func TestCgroupCIDR(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-cidr-test")
	defer cgroupCleanup()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeDenylist)
	require.NoError(t, err)
	defer f.Close()

	// IPv4 CIDR tests - deny 8.8.0.0/16
	t.Run("IPv4/deny_cidr", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("8.8.0.0/16")
		require.NoError(t, f.DenyIP(cidr))

		// Both 8.8.8.8 and 8.8.4.4 should be blocked
		assert.False(t, runInCgroup(cgroupPath, "8.8.8.8 53"),
			"expected 8.8.8.8 to be BLOCKED (in denied /16)")
		assert.False(t, runInCgroup(cgroupPath, "8.8.4.4 53"),
			"expected 8.8.4.4 to be BLOCKED (in denied /16)")

		// 1.1.1.1 should not be blocked
		assert.True(t, runInCgroup(cgroupPath, cloudflareDNSv4),
			"expected 1.1.1.1 to SUCCEED (not in denied range)")

		// Cleanup
		require.NoError(t, f.RemoveDeniedIP(cidr))
	})

	// IPv6 CIDR tests - deny 2001:4860::/32 (Google's range)
	if hasIPv6() {
		t.Run("IPv6/deny_cidr", func(t *testing.T) {
			cidr, _ := filter.ParseCIDR("2001:4860::/32")
			require.NoError(t, f.DenyIP(cidr))

			// Google DNS should be blocked
			assert.False(t, runInCgroup(cgroupPath, googleDNSv6),
				"expected Google IPv6 DNS to be BLOCKED (in denied /32)")

			// Cloudflare should not be blocked
			assert.True(t, runInCgroup(cgroupPath, cloudflareDNSv6),
				"expected Cloudflare IPv6 DNS to SUCCEED (not in denied range)")

			// Cleanup
			require.NoError(t, f.RemoveDeniedIP(cidr))
		})
	} else {
		t.Log("Skipping IPv6 CIDR tests - no IPv6 connectivity")
	}
}

func TestCgroupModeSwitch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	cleanup := startTestServer(t)
	defer cleanup()

	cgroupPath, cgroupCleanup := setupTestCgroup(t, "netfence-modeswitch-test")
	defer cgroupCleanup()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeDisabled)
	require.NoError(t, err)
	defer f.Close()

	t.Run("disabled_allows_both", func(t *testing.T) {
		assert.True(t, runInCgroup(cgroupPath, testServerNcV4), "IPv4 should succeed")
		assert.True(t, runInCgroup(cgroupPath, testServerNcV6), "IPv6 should succeed")
	})

	t.Run("block_all_blocks_both", func(t *testing.T) {
		require.NoError(t, f.SetMode(filter.ModeBlockAll))
		assert.False(t, runInCgroup(cgroupPath, testServerNcV4), "IPv4 should be blocked")
		assert.False(t, runInCgroup(cgroupPath, testServerNcV6), "IPv6 should be blocked")
	})

	t.Run("back_to_disabled_allows_both", func(t *testing.T) {
		require.NoError(t, f.SetMode(filter.ModeDisabled))
		assert.True(t, runInCgroup(cgroupPath, testServerNcV4), "IPv4 should succeed")
		assert.True(t, runInCgroup(cgroupPath, testServerNcV6), "IPv6 should succeed")
	})
}

func TestTCFilterLoad(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ifaceName := "netfence-test0"
	require.NoError(t, createDummyInterface(ifaceName))
	defer deleteDummyInterface(ifaceName)

	f, err := filter.NewTCFilter(ifaceName, filter.ModeDisabled)
	require.NoError(t, err)
	defer f.Close()

	mode, err := f.GetMode()
	require.NoError(t, err)
	assert.Equal(t, filter.ModeDisabled, mode)
}

func TestTCFilterModes(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ifaceName := "netfence-test0"
	require.NoError(t, createDummyInterface(ifaceName))
	defer deleteDummyInterface(ifaceName)

	f, err := filter.NewTCFilter(ifaceName, filter.ModeDisabled)
	require.NoError(t, err)
	defer f.Close()

	modes := []filter.PolicyMode{
		filter.ModeDisabled,
		filter.ModeAllowlist,
		filter.ModeBlockAll,
		filter.ModeDenylist,
	}

	for _, m := range modes {
		t.Run(m.String(), func(t *testing.T) {
			require.NoError(t, f.SetMode(m))
			got, err := f.GetMode()
			require.NoError(t, err)
			assert.Equal(t, m, got)
		})
	}
}

func TestTCFilterIPManagement(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	ifaceName := "netfence-test0"
	require.NoError(t, createDummyInterface(ifaceName))
	defer deleteDummyInterface(ifaceName)

	f, err := filter.NewTCFilter(ifaceName, filter.ModeAllowlist)
	require.NoError(t, err)
	defer f.Close()

	// Test IPv4
	t.Run("IPv4/allow_and_remove", func(t *testing.T) {
		cidr, _ := filter.ParseCIDR("192.168.1.0/24")
		require.NoError(t, f.AllowIP(cidr))
		require.NoError(t, f.RemoveAllowedIP(cidr))
	})

	t.Run("IPv4/deny_and_remove", func(t *testing.T) {
		require.NoError(t, f.SetMode(filter.ModeDenylist))
		cidr, _ := filter.ParseCIDR("10.0.0.0/8")
		require.NoError(t, f.DenyIP(cidr))
		require.NoError(t, f.RemoveDeniedIP(cidr))
	})

	// Test IPv6
	t.Run("IPv6/allow_and_remove", func(t *testing.T) {
		require.NoError(t, f.SetMode(filter.ModeAllowlist))
		cidr, _ := filter.ParseCIDR("2001:db8::/32")
		require.NoError(t, f.AllowIP(cidr))
		require.NoError(t, f.RemoveAllowedIP(cidr))
	})

	t.Run("IPv6/deny_and_remove", func(t *testing.T) {
		require.NoError(t, f.SetMode(filter.ModeDenylist))
		cidr, _ := filter.ParseCIDR("fd00::/8")
		require.NoError(t, f.DenyIP(cidr))
		require.NoError(t, f.RemoveDeniedIP(cidr))
	})
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		input   string
		wantLen int
		wantErr bool
	}{
		// IPv4
		{"192.168.1.0/24", 24, false},
		{"10.0.0.0/8", 8, false},
		{"1.2.3.4", 32, false},
		{"0.0.0.0/0", 0, false},
		// IPv6
		{"2001:db8::/32", 32, false},
		{"::1", 128, false},
		{"fe80::/10", 10, false},
		{"::/0", 0, false},
		// Invalid
		{"invalid", 0, true},
		{"256.1.1.1", 0, true},
		{"2001:db8::xyz", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cidr, err := filter.ParseCIDR(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			ones, _ := cidr.Mask.Size()
			assert.Equal(t, tt.wantLen, ones)
		})
	}
}

// Helper functions

func createDummyInterface(name string) error {
	cmd := exec.Command("ip", "link", "add", name, "type", "dummy")
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("ip", "link", "set", name, "up")
	return cmd.Run()
}

func deleteDummyInterface(name string) error {
	cmd := exec.Command("ip", "link", "del", name)
	return cmd.Run()
}
