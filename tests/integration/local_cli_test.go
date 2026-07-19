//go:build linux

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgroupStandaloneCompiledCLILifecycle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}
	root := repositoryRoot(t)
	dir, err := os.MkdirTemp("/tmp", "nf-cli-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	binary, socket := filepath.Join(dir, "netfenced"), filepath.Join(dir, "n.sock")
	build := exec.Command("go", "build", "-o", binary, "./cmd/netfenced")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building real CLI: %v: %s", err, output)
	}

	pinRoot := fmt.Sprintf("/sys/fs/bpf/nf-cli-%d", os.Getpid())
	t.Cleanup(func() { _ = os.Remove(pinRoot) })
	port := 32000 + os.Getpid()%1000
	configPath := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf("socket: %q\nsocket_group: %q\ndata_dir: %q\nlog_level: debug\ndns:\n  listen_addr: 127.0.0.1\n  port_min: %d\n  port_max: %d\n  upstream: 127.0.0.1:1\nfilter:\n  bpf_pin_dir: %q\n  detach_on_stop: true\n", socket, fmt.Sprint(os.Getegid()), dir, port, port, pinRoot)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))

	logFile, err := os.Create(filepath.Join(dir, "daemon.log"))
	require.NoError(t, err)
	daemonCmd := exec.Command(binary, "start", "--config", configPath)
	daemonCmd.Stdout, daemonCmd.Stderr = logFile, logFile
	require.NoError(t, daemonCmd.Start())
	waitCh := make(chan error, 1)
	go func() { waitCh <- daemonCmd.Wait() }()
	var stopOnce sync.Once
	var logOnce sync.Once
	stopDaemon := func() {
		stopOnce.Do(func() {
			_ = daemonCmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitCh:
			case <-time.After(5 * time.Second):
				_ = daemonCmd.Process.Kill()
				<-waitCh
			}
			_ = logFile.Close()
		})
	}
	logDaemon := func() {
		logOnce.Do(func() {
			logBytes, _ := os.ReadFile(filepath.Join(dir, "daemon.log"))
			t.Logf("standalone daemon log:\n%s", bytes.TrimSpace(logBytes))
		})
	}
	t.Cleanup(func() {
		stopDaemon()
		logDaemon()
	})

	runCLI := func(wantSuccess bool, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		fullArgs := append([]string{"--socket", socket}, args...)
		output, err := exec.CommandContext(ctx, binary, fullArgs...).CombinedOutput()
		if wantSuccess {
			require.NoError(t, err, "%s: %s", strings.Join(args, " "), output)
		} else {
			require.Error(t, err, "%s unexpectedly succeeded: %s", strings.Join(args, " "), output)
		}
		return string(output)
	}
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "--socket", socket, "status")
		return cmd.Run() == nil
	}, 10*time.Second, 100*time.Millisecond, "daemon never became ready")

	aliasIP := fmt.Sprintf("198.18.%d.1", 10+os.Getpid()%200)
	_ = ipCmd("addr", "del", aliasIP+"/32", "dev", "lo")
	require.NoError(t, ipCmd("addr", "add", aliasIP+"/32", "dev", "lo"))
	t.Cleanup(func() { _ = ipCmd("addr", "del", aliasIP+"/32", "dev", "lo") })
	portText, closeTarget := listenTCP(t, aliasIP)
	defer closeTarget()
	cgroupPath, removeCgroup := setupTestCgroup(t, fmt.Sprintf("netfence-cli-%d", os.Getpid()))
	defer removeCgroup()
	target := aliasIP + " " + portText
	require.True(t, runInCgroup(cgroupPath, target), "standalone target must be reachable before attach")

	attachOutput := runCLI(true, "attach", "--cgroup", cgroupPath)
	id := parseAttachedID(t, attachOutput)
	require.True(t, runInCgroup(cgroupPath, target), "fresh no-CP attachment starts disabled")
	runCLI(true, "set-mode", id, "allowlist")
	assert.False(t, runInCgroup(cgroupPath, target), "unlisted target must be blocked")

	beforeInvalid := runCLI(true, "rules", id)
	runCLI(false, "allow-cidr", id, "not-a-cidr")
	afterInvalid := runCLI(true, "rules", id)
	assert.JSONEq(t, beforeInvalid, afterInvalid, "failed CLI command must be a true policy no-op")

	runCLI(true, "allow-cidr", id, aliasIP+"/32")
	assert.True(t, runInCgroup(cgroupPath, target), "local allow must take effect")
	runCLI(true, "deny-cidr", id, aliasIP+"/32")
	runCLI(true, "set-mode", id, "denylist")
	assert.False(t, runInCgroup(cgroupPath, target), "denylist mode must enforce a matching deny")
	runCLI(true, "remove-cidr", id, aliasIP+"/32", "--list", "deny")
	assert.True(t, runInCgroup(cgroupPath, target), "targeted deny removal must allow in denylist mode")

	runCLI(true, "set-dns-mode", id, "denylist")
	runCLI(true, "allow-domain", id, "allowed.example", "--subdomains")
	runCLI(true, "deny-domain", id, "blocked.example")
	runCLI(true, "remove-domain", id, "blocked.example")
	inspection := runCLI(true, "rules", id)
	assert.Contains(t, inspection, aliasIP+"/32")
	assert.Contains(t, inspection, "allowed.example")
	assert.NotContains(t, inspection, "blocked.example")

	fullState := filepath.Join(dir, "rules.json")
	require.NoError(t, os.WriteFile(fullState, []byte(fmt.Sprintf(`{"mode":"POLICY_MODE_ALLOWLIST","allowCidrs":[{"cidr":%q}],"dns":{"mode":"DNS_MODE_DENYLIST","denyDomains":[{"domain":"full.example"}]}}`, aliasIP+"/32")), 0600))
	runCLI(true, "apply-rules", id, "--file", fullState)
	assert.Contains(t, runCLI(true, "rules", id), "full.example")
	runCLI(true, "remove-cidr", id, aliasIP+"/32", "--list", "allow")
	assert.False(t, runInCgroup(cgroupPath, target), "targeted allow removal must block")

	runCLI(true, "detach", "--id", id)
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return connect4ProgCount(t, cgroupPath) == 0
	}), "detach must release the cgroup filter")
	assert.True(t, waitForCondition(5*time.Second, func() bool {
		return runInCgroup(cgroupPath, target)
	}), "detach removes enforcement")
	stopDaemon()
	logDaemon()
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}

func parseAttachedID(t *testing.T, output string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ID:"); ok {
			id := strings.TrimSpace(value)
			require.NotEmpty(t, id)
			return id
		}
	}
	t.Fatalf("attach output did not contain ID: %s", output)
	return ""
}
