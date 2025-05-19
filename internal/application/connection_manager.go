package application

import (
	"sync"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	// Imports like "context", "fmt", "time", "strings", "github.com/coder/websocket", "gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	// will likely be needed by the methods now in separate files, but not directly by this core file anymore unless NewConnectionManager needs them.
	// The Go compiler will tell us if any are missing in the other files.
)

// ConnectionManager handles the business logic related to WebSocket connections,
// including session management, authentication, and message routing.
// For now, it will focus on session lock acquisition and local connection management.
type ConnectionManager struct {
	logger               domain.Logger
	configProvider       config.Provider
	sessionLocker        domain.SessionLockManager
	killSwitchPublisher  domain.KillSwitchPublisher
	killSwitchSubscriber domain.KillSwitchSubscriber
	activeConnections    sync.Map // Stores [sessionKey string] -> domain.ManagedConnection

	// For session renewal goroutine
	renewalStopChan chan struct{}
	renewalWg       sync.WaitGroup
}

// NewConnectionManager creates a new instance of ConnectionManager.
func NewConnectionManager(
	logger domain.Logger,
	configProvider config.Provider,
	sessionLocker domain.SessionLockManager,
	killSwitchPublisher domain.KillSwitchPublisher,
	killSwitchSubscriber domain.KillSwitchSubscriber,
) *ConnectionManager {
	return &ConnectionManager{
		logger:               logger,
		configProvider:       configProvider,
		sessionLocker:        sessionLocker,
		killSwitchPublisher:  killSwitchPublisher,
		killSwitchSubscriber: killSwitchSubscriber,
		activeConnections:    sync.Map{},
		renewalStopChan:      make(chan struct{}),
		// renewalWg is initialized by its zero value, which is fine for sync.WaitGroup
	}
}
