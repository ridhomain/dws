package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"

	"go.uber.org/zap"
)

// App holds the main application components that are managed by DI (Wire).
type App struct {
	httpServer        *http.Server
	logger            domain.Logger
	wsRouter          *websocket.Router
	httpServeMux      *http.ServeMux
	connectionManager *application.ConnectionManager
	// Add other long-lived components here, e.g., NATS connection, gRPC server
}

// NewApp creates a new application instance.
// Dependencies are injected by Google Wire.
func NewApp(
	httpServer *http.Server,
	logger domain.Logger,
	wsRouter *websocket.Router,
	httpServeMux *http.ServeMux,
	connectionManager *application.ConnectionManager,
) *App {
	return &App{
		httpServer:        httpServer,
		logger:            logger,
		wsRouter:          wsRouter,
		httpServeMux:      httpServeMux,
		connectionManager: connectionManager,
	}
}

// Run starts the application, including the HTTP server, and handles graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	appCtx := ctx
	if appCtx.Value(contextkeys.RequestIDKey) == nil {
		appCtx = context.WithValue(appCtx, contextkeys.RequestIDKey, "app-lifecycle")
	}

	a.logger.Info(appCtx, "Application starting...")

	// Start ConnectionManager background services
	if a.connectionManager != nil {
		a.connectionManager.StartKillSwitchListener(appCtx)
		a.logger.Info(appCtx, "ConnectionManager KillSwitch listener started")
		a.connectionManager.StartSessionRenewalLoop(appCtx)
		a.logger.Info(appCtx, "ConnectionManager Session Renewal loop started")
	} else {
		a.logger.Warn(appCtx, "ConnectionManager is nil, background services (KillSwitch, SessionRenewal) not started.")
	}

	a.wsRouter.RegisterRoutes(appCtx, a.httpServeMux)
	a.logger.Info(appCtx, "WebSocket routes registered")

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		a.logger.Info(appCtx, fmt.Sprintf("HTTP server starting on %s", a.httpServer.Addr))
		if err := a.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Fatal(context.Background(), "HTTP server failed to start", zap.Error(err))
		}
	}()

	<-stopChan

	a.logger.Info(appCtx, "Shutting down application...")

	// Stop ConnectionManager background services first
	if a.connectionManager != nil {
		a.logger.Info(appCtx, "Stopping ConnectionManager background services...")
		// Stop renewal loop first, then kill switch listener
		a.connectionManager.StopSessionRenewalLoop()
		a.logger.Info(appCtx, "ConnectionManager Session Renewal loop stopped")

		if err := a.connectionManager.StopKillSwitchListener(); err != nil {
			a.logger.Error(appCtx, "Error stopping ConnectionManager KillSwitch listener", zap.Error(err))
		} else {
			a.logger.Info(appCtx, "ConnectionManager KillSwitch listener stopped")
		}
		a.logger.Info(appCtx, "ConnectionManager background services stopped.")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()

	if err := a.httpServer.Shutdown(shutdownCtx); err != nil {
		a.logger.Error(appCtx, "HTTP server graceful shutdown failed", zap.Error(err))
	} else {
		a.logger.Info(appCtx, "HTTP server shutdown complete")
	}

	a.logger.Info(appCtx, "Application shutdown complete")
	return nil
}
