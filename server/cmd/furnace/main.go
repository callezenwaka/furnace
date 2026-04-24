package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"furnace/server/internal/app"
	"furnace/server/internal/config"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to YAML config file")

	var runtime config.RuntimeOverrides
	flag.StringVar(&runtime.HTTPAddr, "http-addr", "", "Override HTTP listen address")
	flag.StringVar(&runtime.ProtocolAddr, "protocol-addr", "", "Override protocol listen address")
	flag.StringVar(&runtime.SQLitePath, "sqlite-path", "", "Override SQLite path")
	flag.StringVar(&runtime.LogLevel, "log-level", "", "Override log level (debug|info|warn|error)")

	var persistenceEnabled string
	flag.StringVar(&persistenceEnabled, "persistence-enabled", "", "Override persistence enabled (true|false)")

	var cleanupInterval string
	flag.StringVar(&cleanupInterval, "cleanup-interval", "", "Override cleanup interval duration")

	flag.Parse()

	if persistenceEnabled != "" {
		enabled, err := config.ParseBool(persistenceEnabled)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -persistence-enabled: %v\n", err)
			os.Exit(1)
		}
		runtime.PersistenceEnabled = &enabled
	}

	if cleanupInterval != "" {
		dur, err := time.ParseDuration(cleanupInterval)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -cleanup-interval: %v\n", err)
			os.Exit(1)
		}
		runtime.CleanupInterval = &dur
	}

	cfg, err := config.Load(configPath, runtime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	logLevel := new(slog.LevelVar)
	logLevel.Set(config.ToSlogLevel(cfg.LogLevel))
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	application, err := app.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize app", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("furnace starting",
		"http_addr", cfg.HTTPAddr,
		"protocol_addr", cfg.ProtocolAddr,
		"persistence_enabled", cfg.Persistence.Enabled,
		"sqlite_path", cfg.Persistence.SQLitePath,
	)

	if err := application.Start(ctx); err != nil {
		logger.Error("application stopped with error", "error", err)
		os.Exit(1)
	}
}
