package bootstrap

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/wire"
	redisv9 "github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/logger"
	redisadapter "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
)

// ServiceName is a type for injecting the service name string
type ServiceName string

// Define distinct types for specific handlers to help Wire differentiate
type HealthCheck http.HandlerFunc
type ReadinessCheck http.HandlerFunc

// BootstrapLoggerProvider provides a basic Zap logger for initial bootstrap processes.
func BootstrapLoggerProvider() (*zap.Logger, func(), error) {
	// Using NewDevelopment for more verbose bootstrap logs, switch to NewProduction if desired
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize bootstrap logger: %w", err)
	}
	cleanup := func() { _ = logger.Sync() }
	return logger, cleanup, nil
}

// ConfigProvider provides the application configuration.
func ConfigProvider(bootstrapLogger *zap.Logger) (config.Provider, error) {
	cfgProvider, err := config.NewViperProvider(bootstrapLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize config provider: %w", err)
	}
	return cfgProvider, nil
}

// AppLoggerProvider provides the main application logger.
func AppLoggerProvider(cfgProvider config.Provider, serviceName ServiceName) (domain.Logger, func(), error) {
	appLogger, err := logger.NewZapAdapter(cfgProvider, string(serviceName)) // Use injected serviceName
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize application logger: %w", err)
	}
	// Assuming ZapAdapter's underlying *zap.Logger has a Sync method for cleanup
	// If logger.NewZapAdapter returns a concrete *logger.ZapAdapter, we can access its internal logger.Sync()
	// For now, we'll assume the domain.Logger doesn't expose Sync directly.
	// If the concrete type is known and has Sync():
	// if concreteLogger, ok := appLogger.(*logger.ZapAdapter); ok {
	//  cleanup := func() { _ = concreteLogger.ZapInstance().Sync() } // Assuming ZapInstance() returns *zap.Logger
	//  return appLogger, cleanup, nil
	// }
	// If not, a no-op cleanup for the domain.Logger interface.
	cleanup := func() {}
	return appLogger, cleanup, nil
}

// HealthCheckHandlerProvider provides the HTTP handler for the /health endpoint.
// Renamed to avoid conflict and to be more explicit for Wire.
func HealthCheckHandlerProvider(appLogger domain.Logger) HealthCheck {
	fn := func(w http.ResponseWriter, r *http.Request) {
		reqCtx := context.WithValue(r.Context(), contextkeys.RequestIDKey, "health-check-wire") // Placeholder ID
		appLogger.Info(reqCtx, "Health check endpoint hit via Wire")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"OK"}`)
	}
	return HealthCheck(fn)
}

// ReadinessCheckHandlerProvider provides the HTTP handler for the /ready endpoint.
// Renamed to avoid conflict and to be more explicit for Wire.
func ReadinessCheckHandlerProvider(appLogger domain.Logger) ReadinessCheck {
	fn := func(w http.ResponseWriter, r *http.Request) {
		reqCtx := context.WithValue(r.Context(), contextkeys.RequestIDKey, "readiness-check-wire") // Placeholder ID
		appLogger.Info(reqCtx, "Readiness check endpoint hit via Wire")
		// TODO: Implement actual readiness checks (e.g., NATS, Redis connections) later
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"READY"}`)
	}
	return ReadinessCheck(fn)
}

// HTTPServeMuxProvider provides the HTTP request multiplexer.
// It registers handlers provided by other providers.
func HTTPServeMuxProvider(healthHandler HealthCheck, readinessHandler ReadinessCheck) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", http.HandlerFunc(healthHandler))   // Cast back to http.HandlerFunc
	mux.HandleFunc("/ready", http.HandlerFunc(readinessHandler)) // Cast back to http.HandlerFunc
	return mux
}

// HTTPServerProvider provides the main HTTP server.
func HTTPServerProvider(mux *http.ServeMux, cfgProvider config.Provider, appLogger domain.Logger) *http.Server {
	appConfig := cfgProvider.Get()
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", appConfig.Server.HTTPPort),
		Handler: mux,
		// TODO: Add ReadTimeout, WriteTimeout, IdleTimeout later from config
	}
	appLogger.Info(context.Background(), fmt.Sprintf("HTTP server configured for port %d", appConfig.Server.HTTPPort))
	return httpServer
}

// AuthServiceProvider provides the application.AuthService.
func AuthServiceProvider(logger domain.Logger, cfgProvider config.Provider, tokenCache domain.TokenCacheStore) *application.AuthService {
	return application.NewAuthService(logger, cfgProvider, tokenCache)
}

// WebsocketHandlerProvider provides the WebSocket connection handler.
func WebsocketHandlerProvider(appLogger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager) *websocket.Handler {
	// Here, you might also inject other dependencies into the NewHandler if it evolves,
	// for example, a connection manager service.
	return websocket.NewHandler(appLogger, cfgProvider, connManager)
}

// WebsocketRouterProvider provides the WebSocket router.
// It depends on the WebsocketHandler to delegate connections to.
func WebsocketRouterProvider(wsHandler *websocket.Handler, appLogger domain.Logger, cfgProvider config.Provider) *websocket.Router {
	return websocket.NewRouter(appLogger, cfgProvider, wsHandler)
}

// RedisClientProvider provides a Redis client instance.
func RedisClientProvider(cfgProvider config.Provider, appLogger domain.Logger) (*redisv9.Client, func(), error) {
	cfg := cfgProvider.Get().Redis
	client := redisv9.NewClient(&redisv9.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Check connection
	statusCmd := client.Ping(context.Background())
	if err := statusCmd.Err(); err != nil {
		appLogger.Error(context.Background(), "Failed to connect to Redis", "address", cfg.Address, "error", err.Error())
		return nil, func() { _ = client.Close() }, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	appLogger.Info(context.Background(), "Successfully connected to Redis", "address", cfg.Address)

	cleanup := func() {
		if err := client.Close(); err != nil {
			appLogger.Error(context.Background(), "Failed to close Redis connection", "error", err.Error())
		}
	}
	return client, cleanup, nil
}

// TokenCacheStoreProvider provides an instance of domain.TokenCacheStore (Redis implementation).
// It seems NewTokenCacheAdapter was not created in previous tasks. This will be a placeholder.
// TODO: Implement redisadapter.NewTokenCacheAdapter in internal/adapters/redis/token_cache_adapter.go
func TokenCacheStoreProvider(redisClient *redisv9.Client, logger domain.Logger) domain.TokenCacheStore {
	// return redisadapter.NewTokenCacheAdapter(redisClient, logger)
	logger.Warn(context.Background(), "TokenCacheStoreProvider is using a nil placeholder because NewTokenCacheAdapter is not yet implemented.")
	return nil // Placeholder until NewTokenCacheAdapter is implemented
}

// SessionLockManagerProvider provides an instance of domain.SessionLockManager.
func SessionLockManagerProvider(redisClient *redisv9.Client, logger domain.Logger) domain.SessionLockManager {
	return redisadapter.NewSessionLockManagerAdapter(redisClient, logger)
}

// KillSwitchPubSubAdapterProvider provides an instance that implements both
// domain.KillSwitchPublisher and domain.KillSwitchSubscriber.
func KillSwitchPubSubAdapterProvider(redisClient *redisv9.Client, logger domain.Logger) *redisadapter.KillSwitchPubSubAdapter {
	return redisadapter.NewKillSwitchPubSubAdapter(redisClient, logger)
}

// ConnectionManagerProvider provides an instance of application.ConnectionManager.
func ConnectionManagerProvider(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher, // Will be the same instance as subscriber
	killSwitchSubscriber domain.KillSwitchSubscriber, // Will be the same instance as publisher
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, configProvider, sessionLocker, killSwitchPublisher, killSwitchSubscriber)
}

// ProviderSet is a Wire provider set that includes all the providers for the application.
var ProviderSet = wire.NewSet(
	BootstrapLoggerProvider,
	ConfigProvider,
	AppLoggerProvider,
	HealthCheckHandlerProvider,
	ReadinessCheckHandlerProvider,
	HTTPServeMuxProvider,
	HTTPServerProvider,
	// HTTPLogMiddlewareProvider, // Removed: not directly consumed by App
	// APIKeyAuthMiddlewareProvider,       // Removed: created and used internally by WebsocketRouter
	// CompanyTokenAuthMiddlewareProvider, // Removed: will be created and used internally by WebsocketRouter
	AuthServiceProvider,
	RedisClientProvider,
	TokenCacheStoreProvider,
	SessionLockManagerProvider,
	KillSwitchPubSubAdapterProvider,
	wire.Bind(new(domain.KillSwitchPublisher), new(*redisadapter.KillSwitchPubSubAdapter)),  // Bind adapter to publisher interface
	wire.Bind(new(domain.KillSwitchSubscriber), new(*redisadapter.KillSwitchPubSubAdapter)), // Bind adapter to subscriber interface
	WebsocketHandlerProvider,
	WebsocketRouterProvider,
	ConnectionManagerProvider,
	// wire.Struct(new(App), "*"), // Intentionally commented out to use NewApp provider for *App
)
