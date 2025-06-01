package application

import (
	"context"
	"sync"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	appnats "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/nats"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// ConnectionManager manages active WebSocket connections, session locking, and route registration.
// Updated to work with global NATS consumer instead of per-connection subscriptions.
type ConnectionManager struct {
	logger                 domain.Logger
	configProvider         config.Provider
	sessionLocker          domain.SessionLockManager
	killSwitchPublisher    domain.KillSwitchPublisher
	killSwitchSubscriber   domain.KillSwitchSubscriber
	routeRegistry          domain.RouteRegistry
	activeConnections      sync.Map // Stores [sessionKey string] -> domain.ManagedConnection
	activeAdminConnections sync.Map // Stores [adminSessionKey string] -> domain.ManagedConnection for admin connections

	// Global NATS consumer replaces per-connection subscriptions
	globalConsumer *appnats.GlobalConsumerHandler

	// For session renewal goroutine
	renewalStopChan  chan struct{}
	renewalWg        sync.WaitGroup
	renewalStopMutex sync.Mutex
	renewalStopped   bool
	redisClient      *redis.Client
}

// NewConnectionManager creates a new ConnectionManager with global consumer support
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
	routeRegistry domain.RouteRegistry,
	redisClient *redis.Client,
	globalConsumer *appnats.GlobalConsumerHandler, // Add global consumer
) *ConnectionManager {
	return &ConnectionManager{
		logger:                 logger,
		configProvider:         configProvider,
		sessionLocker:          sessionLocker,
		killSwitchPublisher:    killSwitchPublisher,
		killSwitchSubscriber:   killSwitchSubscriber,
		routeRegistry:          routeRegistry,
		activeConnections:      sync.Map{},
		activeAdminConnections: sync.Map{},
		globalConsumer:         globalConsumer,
		renewalStopChan:        make(chan struct{}),
		renewalWg:              sync.WaitGroup{},
		renewalStopMutex:       sync.Mutex{},
		renewalStopped:         false,
		redisClient:            redisClient,
	}
}

// RouteRegistrar returns the underlying route registry (keeping for compatibility)
func (cm *ConnectionManager) RouteRegistrar() domain.RouteRegistry {
	return cm.routeRegistry
}

// GlobalConsumer returns the global NATS consumer handler
func (cm *ConnectionManager) GlobalConsumer() *appnats.GlobalConsumerHandler {
	return cm.globalConsumer
}

// StartGlobalConsumer starts the global NATS consumer
func (cm *ConnectionManager) StartGlobalConsumer(ctx context.Context) error {
	if cm.globalConsumer == nil {
		cm.logger.Error(ctx, "Global consumer not initialized")
		return nil
	}

	return cm.globalConsumer.Start(ctx)
}

// StopGlobalConsumer stops the global NATS consumer
func (cm *ConnectionManager) StopGlobalConsumer() error {
	if cm.globalConsumer == nil {
		return nil
	}

	return cm.globalConsumer.Stop()
}
