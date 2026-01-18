package cmd

import (
	"context"
	"net"
	"os"
	"os/signal"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if cfg.ControlPlane.URL != "" {
		cpClient := daemon.NewControlPlaneClient(cfg.ControlPlane.URL, server, logger, cfg.Metadata)
		server.SetControlPlaneClient(cpClient)
		go cpClient.Run(ctx)
	}

	if err := os.RemoveAll(cfg.Socket); err != nil {
		return err
	}

	listener, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()

	if err := os.Chmod(cfg.Socket, 0660); err != nil {
		logger.Warn().Err(err).Msg("failed to set socket permissions")
	}

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

	logger.Info().Str("socket", cfg.Socket).Msg("listening")
	return grpcServer.Serve(listener)
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
