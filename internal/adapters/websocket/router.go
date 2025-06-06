package websocket

import (
	"context"
	"net/http"

	// "strings" // Not strictly needed if using r.PathValue directly in handler

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// Router handles routing for WebSocket connections.
// It applies necessary middlewares and forwards requests to the appropriate WebSocket handler.
type Router struct {
	logger         domain.Logger
	configProvider config.Provider
	authService    *application.AuthService
	wsHandler      http.Handler // This will be the actual WebSocket upgrade handler
}

// NewRouter creates a new WebSocket router.
// It requires a logger, config provider, auth service, and the WebSocket handler.
func NewRouter(logger domain.Logger, cfgProvider config.Provider, authService *application.AuthService, wsHandler http.Handler) *Router {
	return &Router{
		logger:         logger,
		configProvider: cfgProvider,
		authService:    authService,
		wsHandler:      wsHandler,
	}
}

// RegisterRoutes sets up the WebSocket endpoint with the necessary middleware.
// It registers the handler for paths matching GET /ws/{company}/{agent}.
func (r *Router) RegisterRoutes(ctx context.Context, mux *http.ServeMux) {
	// Chain of middleware: APIKeyAuth -> CompanyTokenAuth -> wsHandler
	apiKeyAuthedHandler := middleware.APIKeyAuthMiddleware(r.configProvider, r.logger)(r.wsHandler)
	companyTokenAuthedHandler := middleware.CompanyTokenAuthMiddleware(r.authService, r.logger)(apiKeyAuthedHandler)
	finalHandlerWithRequestID := middleware.RequestIDMiddleware(companyTokenAuthedHandler)

	// Go 1.22+ http.ServeMux supports path parameters.
	// The pattern "GET /ws/{company}/{agent}" will match GET requests to /ws/somecompany/someagent
	// The path parameters {company} and {agent} can be accessed via r.PathValue("company") and r.PathValue("agent")
	// within the final handler (wsHandler) or an intermediate middleware if needed.
	mux.Handle("GET /ws/{company}/{agent}", finalHandlerWithRequestID)

	// Using context.Background() for general info log not tied to a specific request.
	r.logger.Info(ctx, "WebSocket endpoint registered with RequestID, API Key and Company Token authentication", "pattern", "GET /ws/{company}/{agent}")
}
