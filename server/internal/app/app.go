package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"authpilot/server/internal/config"
	"authpilot/server/internal/httpapi"
	"authpilot/server/internal/store"
	"authpilot/server/internal/store/memory"
	sqliteStore "authpilot/server/internal/store/sqlite"
)

type App struct {
	cfg    config.Config
	logger *slog.Logger

	users    store.UserStore
	groups   store.GroupStore
	flows    store.FlowStore
	sessions store.SessionStore

	httpServer  *http.Server
	closers     []func() error
	cleanupDone chan struct{}
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	var users store.UserStore
	var groups store.GroupStore
	closers := make([]func() error, 0)

	if cfg.Persistence.Enabled {
		sqlite, err := sqliteStore.New(cfg.Persistence.SQLitePath)
		if err != nil {
			return nil, fmt.Errorf("initialize sqlite persistence: %w", err)
		}
		users = sqlite.Users()
		groups = sqlite.Groups()
		closers = append(closers, sqlite.Close)
	} else {
		users = memory.NewUserStore()
		groups = memory.NewGroupStore()
	}

	flows := memory.NewFlowStore()
	sessions := memory.NewSessionStore()

	router := httpapi.NewRouter(httpapi.Dependencies{
		Users:    users,
		Groups:   groups,
		Flows:    flows,
		Sessions: sessions,
	})

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &App{
		cfg:         cfg,
		logger:      logger,
		users:       users,
		groups:      groups,
		flows:       flows,
		sessions:    sessions,
		httpServer:  httpServer,
		closers:     closers,
		cleanupDone: make(chan struct{}),
	}, nil
}

func (a *App) Start(ctx context.Context) error {
	a.startCleanupScheduler(ctx)

	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("http server listening", "addr", a.cfg.HTTPAddr)
		if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		a.logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
		<-a.cleanupDone
		for _, closeFn := range a.closers {
			if err := closeFn(); err != nil {
				a.logger.Warn("resource close failed", "error", err)
			}
		}
		return nil
	case err := <-errCh:
		if err == nil {
			return nil
		}
		return fmt.Errorf("http server: %w", err)
	}
}

func (a *App) startCleanupScheduler(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.Cleanup.Interval)
	go func() {
		defer ticker.Stop()
		defer close(a.cleanupDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				flowRemoved, flowErr := a.flows.DeleteExpired(now)
				sessionRemoved, sessionErr := a.sessions.DeleteExpired(now)
				if flowErr != nil {
					a.logger.Warn("flow cleanup failed", "error", flowErr)
				}
				if sessionErr != nil {
					a.logger.Warn("session cleanup failed", "error", sessionErr)
				}
				if flowRemoved > 0 || sessionRemoved > 0 {
					a.logger.Info("cleanup completed", "flows_removed", flowRemoved, "sessions_removed", sessionRemoved)
				}
			}
		}
	}()
}
