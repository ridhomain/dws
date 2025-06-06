package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/wire"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

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
)

// Define distinct types for middlewares to help Wire differentiate them
type AdminAPIKeyMiddleware func(http.Handler) http.Handler
type ClientAPIKeyMiddleware func(http.Handler) http.Handler
type AdminAuthMiddleware func(http.Handler) http.Handler // New type for AdminAuthMiddleware

// Define distinct types for specific http.HandlerFunc roles
type CompanyUserTokenGenerateHandler http.HandlerFunc
type AdminUserTokenGenerateHandler http.HandlerFunc

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
			// Ignore common containerized environment sync errors when syncing to /dev/stderr
			// These errors occur when stderr is closed/invalid during container shutdown
			errMsg := syncErr.Error()
			if strings.Contains(errMsg, "sync /dev/stderr:") &&
				(strings.Contains(errMsg, "invalid argument") || strings.Contains(errMsg, "bad file descriptor")) {
				// These errors commonly occur in containerized environments during shutdown
				// and can be safely ignored as they don't indicate a real problem
				return
			}
			// Only log unexpected sync errors that might indicate real issues
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
	grpcServer                *appgrpc.Server                 // Added gRPC Server
	generateTokenHandler      CompanyUserTokenGenerateHandler // Updated type
	generateAdminTokenHandler AdminUserTokenGenerateHandler   // Updated type
	adminAPIKeyMiddleware     AdminAPIKeyMiddleware           // This is a type alias already func(http.Handler) http.Handler
	clientApiKeyMiddleware    ClientAPIKeyMiddleware          // This is a type alias already func(http.Handler) http.Handler
	wsRouter                  *wsadapter.Router
	connectionManager         *application.ConnectionManager
	natsConsumerAdapter       domain.NatsConsumer     // Changed from *appnats.ConsumerAdapter
	adminAuthMiddleware       AdminAuthMiddleware     // Middleware for /ws/admin
	adminWsHandler            *wsadapter.AdminHandler // Handler for /ws/admin
	natsConn                  *nats.Conn              // Added for readiness check
	redisClient               *redis.Client           // Added for readiness check
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
	genTokenHandler CompanyUserTokenGenerateHandler, // Updated type
	genAdminTokenHandler AdminUserTokenGenerateHandler, // Updated type
	adminAPIKeyMiddleware AdminAPIKeyMiddleware,
	clientApiKeyMiddleware ClientAPIKeyMiddleware,
	wsRouter *wsadapter.Router,
	connManager *application.ConnectionManager,
	natsAdapter domain.NatsConsumer, // Changed from *appnats.ConsumerAdapter
	adminAuthMid AdminAuthMiddleware, // Added AdminAuthMiddleware
	adminHandler *wsadapter.AdminHandler, // Added AdminHandler
	natsConn *nats.Conn, // Added for readiness check
	redisClient *redis.Client, // Added for readiness check
) (*App, func(), error) { // Assuming a top-level cleanup for App
	app := &App{
		configProvider:            cfgProvider,
		logger:                    appLogger,
		httpServeMux:              mux,
		httpServer:                server,
		grpcServer:                grpcSrv,              // Added gRPC Server
		generateTokenHandler:      genTokenHandler,      // Use updated type
		generateAdminTokenHandler: genAdminTokenHandler, // Use updated type
		adminAPIKeyMiddleware:     adminAPIKeyMiddleware,
		clientApiKeyMiddleware:    clientApiKeyMiddleware,
		wsRouter:                  wsRouter,
		connectionManager:         connManager,
		natsConsumerAdapter:       natsAdapter,
		adminAuthMiddleware:       adminAuthMid,
		adminWsHandler:            adminHandler,
		natsConn:                  natsConn,    // Initialize
		redisClient:               redisClient, // Initialize
	}

	// Consolidated cleanup function for the App
	// Wire will aggregate cleanup functions from providers like NatsConsumerAdapterProvider.
	// This explicit cleanup can be simplified or removed if all cleanups are provider-based.
	cleanup := func() {
		app.logger.Info(context.Background(), "Running app cleanup...")
		if app.connectionManager != nil {
			app.connectionManager.StopKillSwitchListener()
			app.connectionManager.StopResourceRenewalLoop()

			// Brief pause to allow graceful shutdown - reduced since we now have proper synchronization
			// Redis client cleanup happens after this in Wire's cleanup chain
			time.Sleep(50 * time.Millisecond)
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
	appServerCfg := appCfg.App // Corrected to use App struct for these values

	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	idleTimeout := 60 * time.Second

	if appServerCfg.ReadTimeoutSeconds > 0 {
		readTimeout = time.Duration(appServerCfg.ReadTimeoutSeconds) * time.Second
	}
	if appServerCfg.WriteTimeoutSeconds > 0 {
		writeTimeout = time.Duration(appServerCfg.WriteTimeoutSeconds) * time.Second
	}
	if appServerCfg.IdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(appServerCfg.IdleTimeoutSeconds) * time.Second
	}

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", appCfg.Server.HTTPPort),
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}

// GenerateTokenHandlerProvider provider
func GenerateTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) CompanyUserTokenGenerateHandler {
	return CompanyUserTokenGenerateHandler(apphttp.GenerateTokenHandler(cfgProvider, logger))
}

// GenerateAdminTokenHandlerProvider provider
func GenerateAdminTokenHandlerProvider(cfgProvider config.Provider, logger domain.Logger) AdminUserTokenGenerateHandler {
	return AdminUserTokenGenerateHandler(apphttp.GenerateAdminTokenHandler(cfgProvider, logger))
}

// AdminAPIKeyAuthMiddlewareProvider Provider
func AdminAPIKeyAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) AdminAPIKeyMiddleware {
	// Corrected: Pass the cfgProvider directly, the middleware will extract the key.
	return middleware.AdminAPIKeyAuthMiddleware(cfgProvider, logger)
}

// ClientAPIKeyAuthMiddlewareProvider Provider
func ClientAPIKeyAuthMiddlewareProvider(cfgProvider config.Provider, logger domain.Logger) ClientAPIKeyMiddleware {
	// Corrected: Pass the cfgProvider directly, the middleware will extract the key.
	return middleware.APIKeyAuthMiddleware(cfgProvider, logger)
}

// AdminAuthMiddlewareProvider provides the middleware for admin WebSocket authentication.
func AdminAuthMiddlewareProvider(authService *application.AuthService, logger domain.Logger) AdminAuthMiddleware {
	return middleware.AdminAuthMiddleware(authService, logger)
}

// AdminWebsocketHandlerProvider provides the admin websocket handler.
func AdminWebsocketHandlerProvider(logger domain.Logger, cfgProvider config.Provider, connManager *application.ConnectionManager, natsAdapter domain.NatsConsumer) *wsadapter.AdminHandler {
	return wsadapter.NewAdminHandler(logger, cfgProvider, connManager, natsAdapter)
}

// WebsocketHandlerProvider provides the websocket handler.
// Now also takes NatsConsumerAdapter as a dependency.
// Update WebsocketHandlerProvider to remove NATS adapter dependency
func WebsocketHandlerProvider(
	logger domain.Logger,
	cfgProvider config.Provider,
	connManager *application.ConnectionManager,
	routeRegistry domain.RouteRegistry,
	messageForwarder domain.MessageForwarder,
	redisClient *redis.Client,
) *wsadapter.Handler {
	// All 7 parameters in correct order:
	return wsadapter.NewHandler(
		logger,
		cfgProvider,
		connManager,
		nil,
		routeRegistry,
		messageForwarder,
		redisClient,
	)
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
	routeRegistry domain.RouteRegistry,
	redisClient *redis.Client,
	globalConsumer *appnats.GlobalConsumerHandler, // Add this parameter
) *application.ConnectionManager {
	return application.NewConnectionManager(logger, cfgProvider, sessionLocker, killSwitchPub, killSwitchSub, routeRegistry, redisClient, globalConsumer)
}

// TokenCacheStoreProvider provides a TokenCacheStore.
func TokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.TokenCacheStore {
	return appredis.NewTokenCacheAdapter(redisClient, logger)
}

// AdminTokenCacheStoreProvider provides an AdminTokenCacheStore.
func AdminTokenCacheStoreProvider(redisClient *redis.Client, logger domain.Logger) domain.AdminTokenCacheStore {
	return appredis.NewAdminTokenCacheAdapter(redisClient, logger)
}

func GlobalConsumerProvider(logger domain.Logger, cfgProvider config.Provider, natsAdapter domain.NatsConsumer) *appnats.GlobalConsumerHandler {
	// Get JetStream context from the NATS adapter
	// We'll need to add a method to expose the JetStream context
	js := natsAdapter.(*appnats.ConsumerAdapter).JetStreamContext()

	return appnats.NewGlobalConsumerHandler(logger, cfgProvider, js)
}

// NatsConsumerAdapterProvider provides the NATS ConsumerAdapter.
func NatsConsumerAdapterProvider(ctx context.Context, cfgProvider config.Provider, appLogger domain.Logger) (domain.NatsConsumer, func(), error) {
	adapter, cleanup, err := appnats.NewConsumerAdapter(ctx, cfgProvider, appLogger)
	if err != nil {
		return nil, nil, err // Propagate the error
	}
	return adapter, cleanup, nil
}

// Provider for RouteRegistry
func RouteRegistryProvider(redisClient *redis.Client, logger domain.Logger) domain.RouteRegistry {
	return appredis.NewRouteRegistryAdapter(redisClient, logger)
}

// Provider for GRPCMessageHandler
func GRPCMessageHandlerProvider(logger domain.Logger, connManager *application.ConnectionManager, cfgProvider config.Provider) *application.GRPCMessageHandler {
	return application.NewGRPCMessageHandler(logger, connManager, cfgProvider)
}

// Provider for gRPC Server
func GRPCServerProvider(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider, grpcHandler *application.GRPCMessageHandler) (*appgrpc.Server, error) {
	return appgrpc.NewServer(appCtx, logger, cfgProvider, grpcHandler)
}

// Provider for *nats.Conn from NatsConsumerAdapter
func NatsConnectionProvider(adapter domain.NatsConsumer) *nats.Conn {
	if adapter == nil {
		return nil
	}
	return adapter.NatsConn()
}

func MessageForwarderProvider(appCtx context.Context, logger domain.Logger, cfgProvider config.Provider) domain.MessageForwarder {
	return appgrpc.NewForwarderAdapter(appCtx, logger, cfgProvider)
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
	GenerateAdminTokenHandlerProvider,
	AdminAPIKeyAuthMiddlewareProvider,
	ClientAPIKeyAuthMiddlewareProvider,

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
	MessageForwarderProvider,      // Added MessageForwarderProvider
	NewApp,
	GlobalConsumerProvider,
	NatsConsumerAdapterProvider,
	NatsConnectionProvider, // Added NatsConnectionProvider
)
