package cmd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/daemon"
	"github.com/danthegoodman1/netfence/internal/store"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var (
	configFile string
	Version    = "dev"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the netfence daemon",
	Long: `Start the netfence daemon which:
- Exposes a local gRPC API for attaching/detaching filters
- Connects to the control plane via bidirectional stream
- Manages eBPF programs and DNS servers per attachment`,
	RunE: runStart,
}

func init() {
	startCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}

	logger := setupLogger(cfg.LogLevel)

	logger.Info().
		Str("version", Version).
		Str("socket", cfg.Socket).
		Str("control_plane", cfg.ControlPlane.URL).
		Msg("starting netfence daemon")

	st, err := store.New(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()

	server, err := daemon.NewServer(cfg, st, logger, Version)
	if err != nil {
		return err
	}

	if err := server.Start(); err != nil {
		return err
	}
	defer server.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.ControlPlane.URL != "" {
		// Resolve TLS/mTLS/token credentials once at startup so cert/key/CA
		// problems fail the start with a clear error instead of surfacing on
		// every reconnect. There is no plaintext fallback: config.Validate
		// already required either control_plane.tls or an explicit
		// control_plane.insecure: true.
		creds, err := daemon.BuildControlPlaneCreds(cfg.ControlPlane)
		if err != nil {
			return fmt.Errorf("building control plane credentials: %w", err)
		}
		if cfg.ControlPlane.Insecure && cfg.ControlPlane.AuthToken != "" {
			logger.Warn().Msg("control_plane.auth_token is set with control_plane.insecure: true — the bearer token will be sent over an unencrypted connection")
		}
		cpClient := daemon.NewControlPlaneClient(cfg.ControlPlane.URL, server, logger, cfg.Metadata, cfg.ControlPlane.SubscribeAckTimeout, creds)
		cpClient.SetTransportTuning(cfg.ControlPlane.KeepaliveTime, cfg.ControlPlane.KeepaliveTimeout, cfg.ControlPlane.ReconnectBackoffMax)
		server.SetControlPlaneClient(cpClient)
		go cpClient.Run(ctx)
	}

	listener, socketGID, err := prepareDaemonSocket(cfg.Socket, cfg.SocketGroup, defaultSocketSetupOps())
	if err != nil {
		return err
	}
	defer listener.Close()

	grpcServer := grpc.NewServer()
	apiv1.RegisterDaemonServiceServer(grpcServer, server)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info().Msg("shutting down")
		cancel()
		grpcServer.GracefulStop()
	}()

	logger.Info().Str("socket", cfg.Socket).Int("socket_gid", socketGID).Msg("listening")
	return grpcServer.Serve(listener)
}

type socketSetupOps struct {
	effectiveGID func() int
	lookupGroup  func(string) (*user.Group, error)
	mkdirTemp    func(string, string) (string, error)
	removeStale  func(string) error
	listen       func(string, string) (net.Listener, error)
	chown        func(string, int, int) error
	chmod        func(string, os.FileMode) error
	lstat        func(string) (os.FileInfo, error)
	publish      func(string, string) error
	removeAll    func(string) error
}

func defaultSocketSetupOps() socketSetupOps {
	return socketSetupOps{
		effectiveGID: os.Getegid,
		lookupGroup:  user.LookupGroup,
		mkdirTemp:    os.MkdirTemp,
		removeStale:  removeStaleSocket,
		listen:       net.Listen,
		chown:        os.Chown,
		chmod:        os.Chmod,
		lstat:        os.Lstat,
		publish:      publishSocketNoReplace,
		removeAll:    os.RemoveAll,
	}
}

func resolveSocketGroup(value string, effectiveGID int, lookup func(string) (*user.Group, error)) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return effectiveGID, nil
	}
	numeric := value[0] == '+' || value[0] == '-' || (value[0] >= '0' && value[0] <= '9')
	if numeric {
		gid, ok := parseSocketGID(value)
		if !ok {
			return 0, fmt.Errorf("socket_group %q is not a usable numeric GID (must be 0..%d)", value, uint64(math.MaxUint32-1))
		}
		return gid, nil
	}
	group, err := lookup(value)
	if err != nil {
		return 0, fmt.Errorf("looking up socket_group %q: %w", value, err)
	}
	if group == nil {
		return 0, fmt.Errorf("socket_group %q lookup returned no group", value)
	}
	gid, ok := parseSocketGID(group.Gid)
	if !ok {
		return 0, fmt.Errorf("socket_group %q resolved to invalid GID %q", value, group.Gid)
	}
	return gid, nil
}

func parseSocketGID(value string) (int, bool) {
	gid, err := strconv.ParseUint(strings.TrimPrefix(value, "+"), 10, 32)
	if err != nil || gid == math.MaxUint32 { // -1 is chown's no-change sentinel.
		return 0, false
	}
	return int(gid), true
}

type publishedSocketListener struct {
	net.Listener
	path       string
	stageDir   string
	identity   os.FileInfo
	lstat      func(string) (os.FileInfo, error)
	removeAll  func(string) error
	closeOnce  sync.Once
	closeError error
}

func (l *publishedSocketListener) Close() error {
	l.closeOnce.Do(func() {
		closeErr := l.Listener.Close()
		var removeErr error
		if current, err := l.lstat(l.path); err == nil {
			if os.SameFile(l.identity, current) {
				removeErr = os.Remove(l.path)
			}
		} else if !os.IsNotExist(err) {
			removeErr = err
		}
		l.closeError = errors.Join(closeErr, removeErr, l.removeAll(l.stageDir))
	})
	return l.closeError
}

// prepareDaemonSocket binds inside a private staging directory, establishes
// ownership/mode while unreachable, then publishes with an atomic no-replace
// rename. Close removes the public path only if it is still the same inode.
func prepareDaemonSocket(path, group string, ops socketSetupOps) (net.Listener, int, error) {
	gid, err := resolveSocketGroup(group, ops.effectiveGID(), ops.lookupGroup)
	if err != nil {
		return nil, 0, err
	}
	stageDir, err := ops.mkdirTemp(filepath.Dir(path), ".nf-")
	if err != nil {
		return nil, 0, err
	}
	stagedPath := filepath.Join(stageDir, "s")
	listener, err := ops.listen("unix", stagedPath)
	if err != nil {
		_ = ops.removeAll(stageDir)
		return nil, 0, err
	}
	cleanupFailure := func(cause error) (net.Listener, int, error) {
		return nil, 0, errors.Join(cause, listener.Close(), ops.removeAll(stageDir))
	}
	if err := ops.chown(stagedPath, -1, gid); err != nil {
		return cleanupFailure(fmt.Errorf("setting local socket group to %d: %w", gid, err))
	}
	if err := ops.chmod(stagedPath, 0660); err != nil {
		return cleanupFailure(fmt.Errorf("setting local socket mode 0660: %w", err))
	}
	identity, err := ops.lstat(stagedPath)
	if err != nil {
		return cleanupFailure(fmt.Errorf("inspecting secured local socket: %w", err))
	}
	if identity.Mode()&os.ModeSocket == 0 {
		return cleanupFailure(fmt.Errorf("staged local control path is not a socket"))
	}
	if err := ops.removeStale(path); err != nil {
		return cleanupFailure(err)
	}
	if err := ops.publish(stagedPath, path); err != nil {
		return cleanupFailure(fmt.Errorf("publishing secured local socket: %w", err))
	}
	return &publishedSocketListener{
		Listener: listener, path: path, stageDir: stageDir, identity: identity,
		lstat: ops.lstat, removeAll: ops.removeAll,
	}, gid, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %q", path)
	}
	return os.Remove(path)
}

func setupLogger(level string) zerolog.Logger {
	var lvl zerolog.Level
	switch level {
	case "trace":
		lvl = zerolog.TraceLevel
	case "debug":
		lvl = zerolog.DebugLevel
	case "info":
		lvl = zerolog.InfoLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	default:
		lvl = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(lvl)

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if os.Getenv("PRETTY") == "1" {
		logger = logger.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	return logger
}
