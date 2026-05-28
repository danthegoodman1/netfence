//go:build linux

package integration

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/danthegoodman1/netfence/pkg/filter"
	"github.com/stretchr/testify/require"
)

func BenchmarkCgroupConnectBaseline(b *testing.B) {
	requireRootBenchmark(b)

	benchDialUDP(b, benchmarkSocketAddr)
}

func BenchmarkCgroupConnectWarmAllowlist(b *testing.B) {
	requireRootBenchmark(b)

	cgroupPath, restore := moveBenchmarkToCgroup(b, "netfence-connect-warm-bench")
	defer restore()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeAllowlist)
	require.NoError(b, err)
	defer f.Close()

	host, _, err := net.SplitHostPort(benchmarkSocketAddr)
	require.NoError(b, err)
	cidr, err := filter.ParseCIDR(host + "/32")
	require.NoError(b, err)
	require.NoError(b, f.AllowIP(cidr))

	benchDialUDP(b, benchmarkSocketAddr)
}

func BenchmarkCgroupConnectAllowlistMiss(b *testing.B) {
	requireRootBenchmark(b)

	cgroupPath, restore := moveBenchmarkToCgroup(b, "netfence-connect-miss-bench")
	defer restore()

	f, err := filter.NewCgroupFilter(cgroupPath, filter.ModeAllowlist)
	require.NoError(b, err)
	defer f.Close()

	var blocked int
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("udp4", benchmarkSocketAddr)
		if err == nil {
			conn.Close()
			b.Fatal("allowlist miss unexpectedly connected")
		}
		blocked++
	}
	b.StopTimer()
	if blocked != b.N {
		b.Fatalf("blocked %d of %d connects", blocked, b.N)
	}
}

const benchmarkSocketAddr = "198.51.100.10:53"

func benchDialUDP(b *testing.B, addr string) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.Dial("udp4", addr)
		if err != nil {
			b.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func moveBenchmarkToCgroup(b *testing.B, name string) (string, func()) {
	b.Helper()

	original, err := currentCgroupPath()
	require.NoError(b, err)

	cgroupPath := filepath.Join("/sys/fs/cgroup", name)
	require.NoError(b, os.MkdirAll(cgroupPath, 0755))

	pid := os.Getpid()
	require.NoError(b, writeCgroupProcs(cgroupPath, pid))

	return cgroupPath, func() {
		_ = writeCgroupProcs(original, pid)
		_ = os.Remove(cgroupPath)
	}
}

func currentCgroupPath() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(parts[2], "/")), nil
		}
	}
	return "", fmt.Errorf("cgroup v2 path not found")
}

func writeCgroupProcs(cgroupPath string, pid int) error {
	return os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)
}

func requireRootBenchmark(b *testing.B) {
	b.Helper()
	if os.Geteuid() != 0 {
		b.Skip("benchmark requires root")
	}
}
