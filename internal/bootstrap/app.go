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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
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

		// Check gRPC server health
		if a.grpcServer != nil && a.configProvider.Get().Server.GRPCPort > 0 {
			grpcTarget := fmt.Sprintf("localhost:%d", a.configProvider.Get().Server.GRPCPort)
			conn, err := grpc.DialContext(r.Context(), grpcTarget, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
			if err != nil {
				dependenciesStatus["grpc"] = "dial_error"
				ready = false
				a.logger.Warn(r.Context(), "Readiness check failed: gRPC server dial error", "target", grpcTarget, "error", err.Error())
			} else {
				healthClient := grpc_health_v1.NewHealthClient(conn)
				healthResp, err := healthClient.Check(r.Context(), &grpc_health_v1.HealthCheckRequest{Service: ""}) // Check overall server health
				if err != nil {
					dependenciesStatus["grpc"] = "health_check_error"
					ready = false
					a.logger.Warn(r.Context(), "Readiness check failed: gRPC health check error", "target", grpcTarget, "error", err.Error())
				} else if healthResp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
					dependenciesStatus["grpc"] = "not_serving"
					ready = false
					a.logger.Warn(r.Context(), "Readiness check failed: gRPC server not serving", "target", grpcTarget, "status", healthResp.GetStatus().String())
				} else {
					dependenciesStatus["grpc"] = "serving"
				}
				conn.Close()
			}
		} else {
			dependenciesStatus["grpc"] = "not_configured_or_running"
			// If gRPC is optional or not started, it might not affect overall readiness
			// For now, let's assume if it's configured to run, it should be healthy.
			if a.configProvider.Get().Server.GRPCPort > 0 { // Only consider it a failure if it was supposed to run
				ready = false
				a.logger.Warn(r.Context(), "Readiness check: gRPC server not configured or not running but GRPCPort > 0")
			}
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

	if a.generateTokenHandler != nil && a.tokenGenerationMiddleware != nil {
		// Cast the specific handler type to http.HandlerFunc, which implements http.Handler
		handlerToWrap := http.HandlerFunc(a.generateTokenHandler)
		finalGenerateTokenHandler := middleware.RequestIDMiddleware(a.tokenGenerationMiddleware(handlerToWrap))
		a.httpServeMux.Handle("POST /generate-token", finalGenerateTokenHandler)
		a.logger.Info(ctx, "/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateTokenHandler or TokenGenerationMiddleware not initialized. /generate-token endpoint will not be available.")
	}

	// Register new /admin/generate-token endpoint
	if a.generateAdminTokenHandler != nil && a.tokenGenerationMiddleware != nil { // Assuming same middleware for now
		adminHandlerToWrap := http.HandlerFunc(a.generateAdminTokenHandler)
		finalAdminGenerateTokenHandler := middleware.RequestIDMiddleware(a.tokenGenerationMiddleware(adminHandlerToWrap))
		a.httpServeMux.Handle("POST /admin/generate-token", finalAdminGenerateTokenHandler)
		a.logger.Info(ctx, "/admin/generate-token endpoint registered")
	} else {
		a.logger.Error(ctx, "GenerateAdminTokenHandler or TokenGenerationMiddleware not initialized. /admin/generate-token endpoint will not be available.")
	}

	if a.adminWsHandler != nil && a.adminAuthMiddleware != nil && a.configProvider != nil { // Check configProvider for APIKeyAuth
		apiKeyAuth := middleware.APIKeyAuthMiddleware(a.configProvider, a.logger)
		adminAuthedHandler := a.adminAuthMiddleware(a.adminWsHandler)
		chainedAdminHandler := apiKeyAuth(adminAuthedHandler)
		finalAdminWsHandler := middleware.RequestIDMiddleware(chainedAdminHandler)
		a.httpServeMux.Handle("GET /ws/admin", finalAdminWsHandler)
		a.logger.Info(ctx, "Admin WebSocket endpoint /ws/admin registered")
	} else {
		a.logger.Error(ctx, "AdminWsHandler, AdminAuthMiddleware, or ConfigProvider not initialized. /ws/admin endpoint will not be available.")
	}

	// NATS related providers in `providers.go` were temporarily commented out to isolate and resolve DI issues for the HTTP endpoint. These will need to be revisited.

	// Start gRPC Server if available
	if a.grpcServer != nil {
		if err := a.grpcServer.Start(); err != nil {
			a.logger.Error(ctx, "Failed to start gRPC server", "error", err.Error())
			// Depending on policy, this might be a fatal error for the app
			// For now, log and continue HTTP server startup
		} else {
			a.logger.Info(ctx, "gRPC server started successfully.")
		}
	} else {
		a.logger.Warn(ctx, "gRPC server is not initialized. gRPC services will not be available.")
	}

	if a.connectionManager != nil {
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
		// gRPC server shutdown is handled by its own context watcher initiated in its Start method
		// or can be explicitly called if needed: if a.grpcServer != nil { a.grpcServer.GracefulStop() }
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
