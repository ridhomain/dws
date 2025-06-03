package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
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
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Health check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"OK"}`)
	})
	a.httpServeMux.Handle("GET /health", middleware.RequestIDMiddleware(healthHandler))

	readyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.Info(r.Context(), "Readiness check endpoint hit")
		w.Header().Set("Content-Type", "application/json")

		ready := true
		dependenciesStatus := make(map[string]string)

		// Check NATS connection
		if a.natsConn != nil {
			if a.natsConn.Status() == nats.CONNECTED {
				dependenciesStatus["nats"] = "connected"
			} else {
				dependenciesStatus["nats"] = "disconnected"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: NATS disconnected", "status", a.natsConn.Status().String())
			}
		} else {
			dependenciesStatus["nats"] = "not_configured"
			ready = false
			a.logger.Warn(r.Context(), "Readiness check failed: NATS client not configured in App struct")
		}

		// Check Redis connection
		if a.redisClient != nil {
			if err := a.redisClient.Ping(r.Context()).Err(); err == nil {
				dependenciesStatus["redis"] = "connected"
			} else {
				dependenciesStatus["redis"] = "disconnected"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: Redis ping failed", "error", err.Error())
			}
		} else {
			dependenciesStatus["redis"] = "not_configured"
			ready = false
			a.logger.Warn(r.Context(), "Readiness check failed: Redis client not configured in App struct")
		}

		response := struct {
			Status       string            `json:"status"`
			Dependencies map[string]string `json:"dependencies"`
		}{
			Dependencies: dependenciesStatus,
		}

		if ready {
			response.Status = "READY"
			w.WriteHeader(http.StatusOK)
		} else {
			response.Status = "NOT_READY"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			a.logger.Error(r.Context(), "Failed to encode readiness response", "error", err)
		}
	})
	a.httpServeMux.Handle("GET /ready", middleware.RequestIDMiddleware(readyHandler))

	// Register Prometheus metrics handler
	a.httpServeMux.Handle("GET /metrics", middleware.RequestIDMiddleware(promhttp.Handler()))
	a.logger.Info(ctx, "Prometheus metrics endpoint registered at /metrics")

	if a.wsRouter != nil {
		a.wsRouter.RegisterRoutes(ctx, a.httpServeMux)
	} else {
		a.logger.Warn(ctx, "WebSocket router is not initialized. WebSocket routes will not be available.")
	}

	if a.generateTokenHandler != nil && a.clientApiKeyMiddleware != nil {
		handlerToWrap := http.HandlerFunc(a.generateTokenHandler)
		finalGenerateTokenHandler := middleware.RequestIDMiddleware(a.clientApiKeyMiddleware(handlerToWrap))
		a.httpServeMux.Handle("POST /generate-token", finalGenerateTokenHandler)
		a.logger.Info(ctx, "/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateTokenHandler or clientApiKeyMiddleware not initialized. /generate-token endpoint will not be available.")
	}

	// Register new /admin/generate-token endpoint
	if a.generateAdminTokenHandler != nil && a.adminAPIKeyMiddleware != nil { // Assuming same middleware for now
		adminHandlerToWrap := http.HandlerFunc(a.generateAdminTokenHandler)
		finalAdminGenerateTokenHandler := middleware.RequestIDMiddleware(a.adminAPIKeyMiddleware(adminHandlerToWrap))
		a.httpServeMux.Handle("POST /admin/generate-token", finalAdminGenerateTokenHandler)
		a.logger.Info(ctx, "/admin/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateAdminTokenHandler or adminAPIKeyMiddleware not initialized. /admin/generate-token endpoint will not be available.")
	}

	if a.adminWsHandler != nil && a.adminAuthMiddleware != nil && a.configProvider != nil { // Check configProvider for APIKeyAuth
		apiKeyAuth := middleware.APIKeyAuthMiddleware(a.configProvider, a.logger)
		adminAuthedHandler := a.adminAuthMiddleware(a.adminWsHandler)
		chainedAdminHandler := apiKeyAuth(adminAuthedHandler)
		finalAdminWsHandler := middleware.RequestIDMiddleware(chainedAdminHandler)
		a.httpServeMux.Handle("GET /ws/admin", finalAdminWsHandler)
		a.logger.Info(ctx, "/ws/admin endpoint registered")
	} else {
		a.logger.Error(ctx, "AdminWsHandler, AdminAuthMiddleware, or ConfigProvider not initialized. /ws/admin endpoint will not be available.")
	}

	// NATS related providers in `providers.go` were temporarily commented out to isolate and resolve DI issues for the HTTP endpoint. These will need to be revisited.

	if a.connectionManager != nil {
		// Start global NATS consumer BEFORE other background services
		if err := a.connectionManager.StartGlobalConsumer(ctx); err != nil {
			a.logger.Error(ctx, "Failed to start global NATS consumer", "error", err.Error())
			// Decide if this is fatal or if the service can run without it
			// For now, we'll treat it as non-fatal but log the error
			// return fmt.Errorf("failed to start global NATS consumer: %w", err)
		} else {
			a.logger.Info(ctx, "Global NATS consumer started successfully")
		}

		safego.Execute(ctx, a.logger, "ConnectionManagerKillSwitchListener", func() {
			a.connectionManager.StartKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerAdminKillSwitchListener", func() {
			a.connectionManager.StartAdminKillSwitchListener(ctx)
		})
		safego.Execute(ctx, a.logger, "ConnectionManagerResourceRenewalLoop", func() {
			a.connectionManager.StartResourceRenewalLoop(ctx)
		})
	} else {
		a.logger.Warn(ctx, "ConnectionManager not initialized. Session and route management features may be impaired.")
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
			// Stop global consumer FIRST during shutdown
			a.logger.Info(context.Background(), "Stopping global NATS consumer...")
			if err := a.connectionManager.StopGlobalConsumer(); err != nil {
				a.logger.Error(context.Background(), "Error stopping global NATS consumer", "error", err.Error())
			}

			a.logger.Info(context.Background(), "Closing all WebSocket connections gracefully...")
			a.connectionManager.GracefullyCloseAllConnections(domain.StatusGoingAway, "Server is shutting down")
			time.Sleep(1 * time.Second)

			a.connectionManager.StopKillSwitchListener()
			a.connectionManager.StopResourceRenewalLoop()
		}

		// Call NATS cleanup if available - This is now handled by Wire's aggregated cleanup.
		// if a.natsCleanup != nil { // natsCleanup is no longer part of App struct
		// 	a.logger.Info(context.Background(), "Calling NATS cleanup...")
		// 	a.natsCleanup()
		// } else {
		// 	a.logger.Info(context.Background(), "NATS cleanup function not available.")
		// }

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
