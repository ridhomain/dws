package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	// ws "github.com/coder/websocket" // Alias for the websocket library - Not directly used in this file after simplification
	// "github.com/nats-io/nats.go" // Temporarily commented out

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	apphttp "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/http"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/logger"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"

	// appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats" // Temporarily commented out
	appredis "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"
	wsadapter "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	// "gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys" // Not directly used in this file
)

// App struct is defined here for Wire to use.
// It should be the single definition of App in the bootstrap package.
type App struct {
	configProvider            config.Provider
	logger                    domain.Logger
	httpServeMux              *http.ServeMux
	httpServer                *http.Server
	generateTokenHandler      http.HandlerFunc
	tokenGenerationMiddleware func(http.Handler) http.Handler // Specific middleware for /generate-token
	wsRouter                  *wsadapter.Router
	connectionManager         *application.ConnectionManager
	// natsCleanup            func() // Temporarily commented out
}

// NewApp is the constructor for App, also for Wire.
// It should be the single definition of NewApp in the bootstrap package.
func NewApp(
	cfgProvider config.Provider,
	appLogger domain.Logger,
	mux *http.ServeMux,
	server *http.Server,
	genTokenHandler http.HandlerFunc,
	tokenGenMiddleware func(http.Handler) http.Handler,
	wsRouter *wsadapter.Router,
	connManager *application.ConnectionManager,
	// natsCleanup func(), // Temporarily commented out if NATS provider returns it
) (*App, func(), error) { // Assuming a top-level cleanup for App
	app := &App{
		configProvider:            cfgProvider,
		logger:                    appLogger,
		httpServeMux:              mux,
		httpServer:                server,
		generateTokenHandler:      genTokenHandler,
		tokenGenerationMiddleware: tokenGenMiddleware,
		wsRouter:                  wsRouter,
		connectionManager:         connManager,
		// natsCleanup:            natsCleanup,
	}

	// Consolidated cleanup function for the App
	cleanup := func() {
		app.logger.Info(context.Background(), "Running app cleanup...")
		// if app.natsCleanup != nil {
		// 	app.natsCleanup()
		// }
		if app.connectionManager != nil {
			app.connectionManager.StopKillSwitchListener()
			app.connectionManager.StopSessionRenewalLoop()
		}
		// Add other cleanup tasks from providers if they return them directly to NewApp
	}
	return app, cleanup, nil
}

// ConfigProvider provides the application configuration.
func ConfigProvider() (config.Provider, error) {
	// For NewViperProvider to log its own errors, we give it a basic logger.
	// This logger won't have the full app config (like log level from file) yet.
	basicLogger, _ := zap.NewProduction() // Or zap.NewDevelopment() or zap.NewExample()
	// In a real app, you might have a more sophisticated bootstrap logging setup.
	return config.NewViperProvider(basicLogger)
}

// LoggerProvider provides the application logger.
func LoggerProvider(cfgProvider config.Provider) (domain.Logger, error) {
	appCfg := cfgProvider.Get()
	return logger.NewZapAdapter(cfgProvider, appCfg.App.ServiceName) // Use ServiceName as Name is not available
}

// HTTPServeMuxProvider provides the main HTTP multiplexer.
func HTTPServeMuxProvider() *http.ServeMux {
	return http.NewServeMux()
}

// HTTPGracefulServerProvider provides a new HTTP server configured for graceful shutdown.
func HTTPGracefulServerProvider(cfgProvider config.Provider, mux *http.ServeMux) *http.Server {
	appCfg := cfgProvider.Get()

	// TODO: Add ReadTimeoutSeconds and IdleTimeoutSeconds to config.AppConfig and use them here.
	// Using hardcoded defaults for Read and Idle timeouts as they are not in AppConfig.
	// WriteTimeoutSeconds is available in AppConfig.
	readTimeout := 10 * time.Second  // Default read timeout
	writeTimeout := 10 * time.Second // Default write timeout (fallback)
	idleTimeout := 60 * time.Second  // Default idle timeout

	if appCfg.App.WriteTimeoutSeconds > 0 {
		writeTimeout = time.Duration(appCfg.App.WriteTimeoutSeconds) * time.Second
	}

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", appCfg.Server.HTTPPort), // Use HTTPPort from ServerConfig
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}

// GenerateTokenHandlerProvider provider
func GenerateTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return apphttp.GenerateTokenHandler(cfgProvider, logger)
}

// TokenGenerationAuthMiddlewareProvider Provider
func TokenGenerationAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) func(http.Handler) http.Handler {
	// Corrected: Pass the cfgProvider directly, the middleware will extract the key.
	return middleware.TokenGenerationAuthMiddleware(cfgProvider, logger)
}

// WebsocketHandlerProvider provides the websocket handler.
func WebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager) *wsadapter.Handler {
	return wsadapter.NewHandler(logger, cfgProvider, connManager)
}

// WebsocketRouterProvider provides the websocket router.
// Parameter wsHandler changed from http.Handler to *wsadapter.Handler
func WebsocketRouterProvider(logger domain.Logger, cfgProvider config.Provider, authService *application.AuthService, wsHandler *wsadapter.Handler) *wsadapter.Router {
	return wsadapter.NewRouter(logger, cfgProvider, authService, wsHandler)
}

// AuthServiceProvider provides the AuthService.
func AuthServiceProvider(logger domain.Logger, cfgProvider config.Provider, tokenCache domain.TokenCacheStore) *application.AuthService {
	return application.NewAuthService(logger, cfgProvider, tokenCache)
}

// RedisClientProvider provides a Redis client and a cleanup function.
func RedisClientProvider(cfgProvider config.Provider, appLogger domain.Logger) (*redis.Client, func(), error) {
	appCfg := cfgProvider.Get()
	client := redis.NewClient(&redis.Options{
		Addr:     appCfg.Redis.Address,
		Password: appCfg.Redis.Password,
		DB:       appCfg.Redis.DB,
	})
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		appLogger.Error(context.Background(), "Failed to connect to Redis", "error", err.Error(), "address", appCfg.Redis.Address)
		return nil, nil, fmt.Errorf("failed to connect to Redis at %s: %w", appCfg.Redis.Address, err)
	}
	cleanup := func() {
		client.Close()
		appLogger.Info(context.Background(), "Redis connection closed")
	}
	appLogger.Info(context.Background(), "Successfully connected to Redis", "address", appCfg.Redis.Address)
	return client, cleanup, nil
}

// SessionLockManagerProvider provides the session lock manager.
func SessionLockManagerProvider(redisClient *redis.Client, logger domain.Logger) domain.SessionLockManager {
	return appredis.NewSessionLockManagerAdapter(redisClient, logger)
}

// KillSwitchPubSubAdapterProvider provides the kill switch pub/sub adapter.
func KillSwitchPubSubAdapterProvider(redisClient *redis.Client, logger domain.Logger) *appredis.KillSwitchPubSubAdapter {
	return appredis.NewKillSwitchPubSubAdapter(redisClient, logger)
}

// ConnectionManagerProvider provides the connection manager.
func ConnectionManagerProvider(
	logger domain.Logger,
	cfgProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPub domain.KillSwitchPublisher,
	killSwitchSub domain.KillSwitchSubscriber,
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, cfgProvider, sessionLocker, killSwitchPub, killSwitchSub)
}

// TokenCacheStoreProvider provides a TokenCacheStore.
func TokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.TokenCacheStore {
	// TODO: Implement appredis.NewTokenCacheAdapter in internal/adapters/redis/token_cache_adapter.go
	logger.Warn(context.Background(), "TokenCacheStoreProvider is using a placeholder nil implementation. Actual Redis-backed cache store needs to be implemented.")
	return nil
}

// ProviderSet is the Wire provider set for the entire application.
var ProviderSet = wire.NewSet(
	ConfigProvider,
	LoggerProvider,
	HTTPServeMuxProvider,
	HTTPGracefulServerProvider,

	// HTTP Handlers and Middleware
	GenerateTokenHandlerProvider,
	TokenGenerationAuthMiddlewareProvider,

	// WebSocket Components
	WebsocketHandlerProvider,
	WebsocketRouterProvider,
	// AuthServiceProvide already here. No, it's AuthServiceProvider

	// Infrastructure Adapters
	RedisClientProvider,
	SessionLockManagerProvider,
	KillSwitchPubSubAdapterProvider,
	wire.Bind(new(domain.KillSwitchPublisher), new(*appredis.KillSwitchPubSubAdapter)),
	wire.Bind(new(domain.KillSwitchSubscriber), new(*appredis.KillSwitchPubSubAdapter)),
	TokenCacheStoreProvider, // Added TokenCacheStoreProvider as AuthService needs it

	// NATS - Currently commented out to isolate DI issues, will be re-enabled
	// NatsConnProvider,
	// NatsStreamProvider,
	// NatsEventPublisherProvider,
	// wire.Bind(new(domain.EventPublisher), new(*nats.EventPublisherAdapter)),
	// NatsEventSubscriberProvider,
	// wire.Bind(new(domain.EventSubscriber), new(*nats.EventSubscriberAdapter)),

	// Application Services
	AuthServiceProvider, // This is the one to keep
	ConnectionManagerProvider,

	NewApp,
)
