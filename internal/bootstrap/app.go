package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
	// Imports for App struct fields if defined here, but App struct is in providers.go
	// "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	// wsadapter "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	// "gitlab.com/timkado/api/daisi-ws-service/internal/application"
	// "gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// NOTE: The App struct and NewApp function are defined in providers.go for Wire.
// This file should only contain methods for the App struct, like Run().

// Run starts the application, listens for HTTP requests, and handles graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	version := "unknown"              // Default if not found
	serviceName := "daisi-ws-service" // Default service name
	if a.configProvider != nil && a.configProvider.Get() != nil {
		configApp := a.configProvider.Get().App
		if configApp.Version != "" {
			version = configApp.Version
		}
		if configApp.ServiceName != "" {
			serviceName = configApp.ServiceName
		}

	}
	a.logger.Info(ctx, "Starting application", "service_name", serviceName, "version", version)

	// Setup HTTP routes
	a.httpServeMux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Health check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"OK"}`)
	})
	a.httpServeMux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Readiness check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"READY"}`)
	})

	if a.wsRouter != nil {
		a.wsRouter.RegisterRoutes(ctx, a.httpServeMux)
	} else {
		a.logger.Warn(ctx, "WebSocket router is not initialized. WebSocket routes will not be available.")
	}

	// Register /generate-token endpoint
	// Assumes a.generateTokenHandler and a.tokenGenerationMiddleware are injected into App by Wire from providers.go
	if a.generateTokenHandler != nil && a.tokenGenerationMiddleware != nil {
		a.httpServeMux.Handle("POST /generate-token", a.tokenGenerationMiddleware(a.generateTokenHandler))
		a.logger.Info(ctx, "/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateTokenHandler or TokenGenerationMiddleware not initialized. /generate-token endpoint will not be available.")
	}

	if a.connectionManager != nil {
		safego.Execute(ctx, a.logger, "ConnectionManagerKillSwitchListener", func() {
			a.connectionManager.StartKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerSessionRenewalLoop", func() {
			a.connectionManager.StartSessionRenewalLoop(ctx)
		})
	} else {
		a.logger.Warn(ctx, "ConnectionManager not initialized. Session management features may be impaired.")
	}

	safego.Execute(ctx, a.logger, "SignalListenerAndGracefulShutdown", func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		select {
		case sig := <-quit:
			a.logger.Info(context.Background(), "Shutdown signal received, initiating graceful shutdown...", "signal", sig.String())
		case <-ctx.Done(): // Listen to the application context as well
			a.logger.Info(context.Background(), "Application context cancelled, initiating graceful shutdown...")
		}

		shutdownTimeout := 30 * time.Second // Default
		if a.configProvider != nil && a.configProvider.Get() != nil {
			configApp := a.configProvider.Get().App
			if configApp.ShutdownTimeoutSeconds > 0 {
				shutdownTimeout = time.Duration(configApp.ShutdownTimeoutSeconds) * time.Second
			}
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if a.connectionManager != nil {
			a.connectionManager.StopKillSwitchListener()
			a.connectionManager.StopSessionRenewalLoop()
		}

		if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
			a.logger.Error(context.Background(), "HTTP server graceful shutdown failed", "error", err.Error())
		}
		a.logger.Info(context.Background(), "HTTP server shut down.")
	})

	a.logger.Info(ctx, fmt.Sprintf("HTTP server listening on port %d", a.configProvider.Get().Server.HTTPPort))
	if err := a.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.logger.Error(ctx, "HTTP server ListenAndServe error", "error", err.Error())
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	a.logger.Info(ctx, "Application shut down gracefully or server closed.")
	return nil
}
