package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	// ws "github.com/coder/websocket" // Alias for the websocket library - Not directly used in this file after simplification
	// "github.com/nats-io/nats.go" // Temporarily commented out

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	appgrpc "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc" // Added for gRPC Server
	apphttp "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/http"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/logger"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/middleware"

	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	appredis "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/redis"
	wsadapter "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/websocket"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	// "gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys" // Not directly used in this file
)

// Define distinct types for middlewares to help Wire differentiate them
type TokenGenerationMiddleware func(http.Handler) http.Handler
type AdminAuthMiddleware func(http.Handler) http.Handler // New type for AdminAuthMiddleware

// InitialZapLoggerProvider provides a basic *zap.Logger instance, primarily for config initialization.
// It returns the logger, a cleanup function (for syncing), and an error if creation fails.
func InitialZapLoggerProvider() (*zap.Logger, func(), error) {
	// Using zap.NewProduction() for a realistic default.
	// Consider making this configurable via a simple ENV var if needed for dev vs. prod initial logging.
	logger, err := zap.NewProduction()
	if err != nil {
		// Try NewDevelopment if NewProduction fails
		logger, err = zap.NewDevelopment()
		if err != nil {
			// As a last resort, use NewExample, which does not return an error.
			// This is unlikely to be hit if NewProduction/NewDevelopment are available.
			logger = zap.NewExample()
			// We will proceed with NewExample, but log the original error to stderr for visibility
			fmt.Fprintf(os.Stderr, "Failed to create initial zap logger (production and development failed, falling back to example): %v\n", err)
		}
	}

	cleanup := func() {
		// Syncing flushes any buffered log entries.
		// It's good practice, especially before application exit.
		if syncErr := logger.Sync(); syncErr != nil {
			// Log to stderr if sync fails, as the logger itself might be compromised.
			fmt.Fprintf(os.Stderr, "Failed to sync initial zap logger: %v\n", syncErr)
		}
	}
	return logger, cleanup, nil
}

// App struct is defined here for Wire to use.
// It should be the single definition of App in the bootstrap package.
type App struct {
	configProvider            config.Provider
	logger                    domain.Logger
	httpServeMux              *http.ServeMux
	httpServer                *http.Server
	grpcServer                *appgrpc.Server // Added gRPC Server
	generateTokenHandler      http.HandlerFunc
	tokenGenerationMiddleware func(http.Handler) http.Handler // Specific middleware for /generate-token
	wsRouter                  *wsadapter.Router
	connectionManager         *application.ConnectionManager
	natsConsumerAdapter       *appnats.ConsumerAdapter // Added NATS Consumer Adapter
	adminAuthMiddleware       AdminAuthMiddleware      // Middleware for /ws/admin
	adminWsHandler            *wsadapter.AdminHandler  // Handler for /ws/admin
	// natsCleanup            func() // Temporarily commented out
}

// NewApp is the constructor for App, also for Wire.
// It should be the single definition of NewApp in the bootstrap package.
func NewApp(
	cfgProvider config.Provider,
	appLogger domain.Logger,
	mux *http.ServeMux,
	server *http.Server,
	grpcSrv *appgrpc.Server, // Added gRPC Server
	genTokenHandler http.HandlerFunc,
	tokenGenMiddleware TokenGenerationMiddleware,
	wsRouter *wsadapter.Router,
	connManager *application.ConnectionManager,
	natsAdapter *appnats.ConsumerAdapter, // Added NATS Consumer Adapter
	adminAuthMid AdminAuthMiddleware, // Added AdminAuthMiddleware
	adminHandler *wsadapter.AdminHandler, // Added AdminHandler
) (*App, func(), error) { // Assuming a top-level cleanup for App
	app := &App{
		configProvider:            cfgProvider,
		logger:                    appLogger,
		httpServeMux:              mux,
		httpServer:                server,
		grpcServer:                grpcSrv, // Added gRPC Server
		generateTokenHandler:      genTokenHandler,
		tokenGenerationMiddleware: tokenGenMiddleware,
		wsRouter:                  wsRouter,
		connectionManager:         connManager,
		natsConsumerAdapter:       natsAdapter,
		adminAuthMiddleware:       adminAuthMid,
		adminWsHandler:            adminHandler,
	}

	// Consolidated cleanup function for the App
	// Wire will aggregate cleanup functions from providers like NatsConsumerAdapterProvider.
	// This explicit cleanup can be simplified or removed if all cleanups are provider-based.
	cleanup := func() {
		app.logger.Info(context.Background(), "Running app cleanup...")
		if app.connectionManager != nil {
			app.connectionManager.StopKillSwitchListener()
			app.connectionManager.StopResourceRenewalLoop()
		}
		if app.grpcServer != nil {
			app.logger.Info(context.Background(), "Stopping gRPC server during app cleanup...")
			app.grpcServer.GracefulStop() // Or app.grpcServer.Stop() if immediate is needed
		}
	}
	return app, cleanup, nil
}

// ConfigProvider provides the application configuration.
// It now accepts appCtx to be passed to NewViperProvider for graceful goroutine shutdown.
func ConfigProvider(appCtx context.Context, logger *zap.Logger) (config.Provider, error) {
	// Pass the application context to the Viper provider constructor
	return config.NewViperProvider(appCtx, logger)
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
func TokenGenerationAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) TokenGenerationMiddleware {
	// Corrected: Pass the cfgProvider directly, the middleware will extract the key.
	return middleware.TokenGenerationAuthMiddleware(cfgProvider, logger)
}

// AdminAuthMiddlewareProvider provides the middleware for admin WebSocket authentication.
func AdminAuthMiddlewareProvider(authService *application.AuthService, logger domain.Logger) AdminAuthMiddleware {
	return middleware.AdminAuthMiddleware(authService, logger)
}

// AdminWebsocketHandlerProvider provides the admin websocket handler.
func AdminWebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *wsadapter.AdminHandler {
	return wsadapter.NewAdminHandler(logger, cfgProvider, connManager, natsAdapter)
}

// WebsocketHandlerProvider provides the websocket handler.
// Now also takes NatsConsumerAdapter as a dependency.
func WebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter *appnats.ConsumerAdapter) *wsadapter.Handler {
	return wsadapter.NewHandler(logger, cfgProvider, connManager, natsAdapter)
}

// WebsocketRouterProvider provides the websocket router.
// Parameter wsHandler changed from http.Handler to *wsadapter.Handler
func WebsocketRouterProvider(logger domain.Logger, cfgProvider config.Provider, authService *application.AuthService, wsHandler *wsadapter.Handler) *wsadapter.Router {
	return wsadapter.NewRouter(logger, cfgProvider, authService, wsHandler)
}

// AuthServiceProvider provides the AuthService.
func AuthServiceProvider(logger domain.Logger, cfgProvider config.Provider, tokenCache domain.TokenCacheStore, adminTokenCache domain.AdminTokenCacheStore) *application.AuthService {
	return application.NewAuthService(logger, cfgProvider, tokenCache, adminTokenCache)
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

// ConnectionManagerProvider provides a ConnectionManager.
func ConnectionManagerProvider(
	logger domain.Logger,
	cfgProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPub domain.KillSwitchPublisher,
	killSwitchSub domain.KillSwitchSubscriber,
	routeRegistry domain.RouteRegistry, // Added RouteRegistry dependency
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, cfgProvider, sessionLocker, killSwitchPub, killSwitchSub, routeRegistry) // Pass routeRegistry
}

// TokenCacheStoreProvider provides a TokenCacheStore.
func TokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.TokenCacheStore {
	logger.Warn(context.Background(), "TokenCacheStoreProvider is using a placeholder nil implementation. Actual Redis-backed cache store needs to be implemented.")
	// TODO: Replace with actual appredis.NewTokenCacheAdapter(redisClient, logger) once implemented
	return nil
}

// AdminTokenCacheStoreProvider provides an AdminTokenCacheStore.
func AdminTokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.AdminTokenCacheStore {
	return appredis.NewAdminTokenCacheAdapter(redisClient, logger)
}

// NatsConsumerAdapterProvider provides the NATS ConsumerAdapter.
func NatsConsumerAdapterProvider(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger, routeRegistry domain.RouteRegistry) (*appnats.ConsumerAdapter, func(), error) {
	return appnats.NewConsumerAdapter(ctx, cfgProvider, appLogger, routeRegistry)
}

// Provider for RouteRegistry
func RouteRegistryProvider(redisClient *redis.Client, logger domain.Logger) domain.RouteRegistry {
	return appredis.NewRouteRegistryAdapter(redisClient, logger)
}

// Provider for GRPCMessageHandler
func GRPCMessageHandlerProvider(logger domain.Logger, connManager *application.ConnectionManager) *application.GRPCMessageHandler {
	return application.NewGRPCMessageHandler(logger, connManager)
}

// Provider for gRPC Server
func GRPCServerProvider(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider, grpcHandler *application.GRPCMessageHandler) (*appgrpc.Server, error) {
	return appgrpc.NewServer(appCtx, logger, cfgProvider, grpcHandler)
}

// ProviderSet is the Wire provider set for the entire application.
var ProviderSet = wire.NewSet(
	ConfigProvider,
	LoggerProvider,
	HTTPServeMuxProvider,
	HTTPGracefulServerProvider,
	InitialZapLoggerProvider,

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
	GRPCMessageHandlerProvider,    // Added gRPC Message Handler Provider
	GRPCServerProvider,            // Added gRPC Server Provider
	AdminAuthMiddlewareProvider,   // Added for admin auth
	AdminWebsocketHandlerProvider, // Added for admin websocket
	AdminTokenCacheStoreProvider,  // Added for admin token caching
	RouteRegistryProvider,         // Added RouteRegistryProvider
	NewApp,
	NatsConsumerAdapterProvider,
)
