package application

import (
	"sync"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	// Imports like "context", "fmt", "time", "strings", "github.com/coder/websocket", "gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	// will likely be needed by the methods now in separate files, but not directly by this core file anymore unless NewConnectionManager needs them.
	// The Go compiler will tell us if any are missing in the other files.
)

// ConnectionManager manages active WebSocket connections, session locking, and route registration.
// It ensures that only one session per user is active and handles the lifecycle of connections.
// It also uses a RouteRegistry to track which pod is responsible for which chat/message routes.
type ConnectionManager struct {
	logger               domain.Logger
	configProvider       config.Provider
	sessionLocker        domain.SessionLockManager
	killSwitchPublisher  domain.KillSwitchPublisher
	killSwitchSubscriber domain.KillSwitchSubscriber
	routeRegistry        domain.RouteRegistry
	activeConnections    sync.Map // Stores [sessionKey string] -> domain.ManagedConnection

	// For session renewal goroutine
	renewalStopChan chan struct{}
	renewalWg       sync.WaitGroup
}

// NewConnectionManager creates a new ConnectionManager.
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
	routeRegistry domain.RouteRegistry,
) *ConnectionManager {
	return &ConnectionManager{
		logger:               logger,
		configProvider:       configProvider,
		sessionLocker:        sessionLocker,
		killSwitchPublisher:  killSwitchPublisher,
		killSwitchSubscriber: killSwitchSubscriber,
		routeRegistry:        routeRegistry,
		activeConnections:    sync.Map{},
		renewalStopChan:      make(chan struct{}),
		// renewalWg is initialized by its zero value, which is fine for sync.WaitGroup
	}
}

func (cm *ConnectionManager) RouteRegistrar() domain.RouteRegistry {
	return cm.routeRegistry
}
