package application

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

// StartResourceRenewalLoop periodically refreshes session locks and route registrations for active connections.
func (cm *ConnectionManager) StartResourceRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	routeTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second
	podID := cfg.Server.PodID

	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Resource renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Resource renewal will not work correctly.")
		return
	}

	cm.logger.Info(appCtx, "Starting resource renewal loop",
		"renewalInterval", renewalInterval.String(),
		"sessionTTL", sessionTTL.String(),
		"routeTTL", routeTTL.String(),
		"podID", podID,
	)

	cm.renewalWg.Add(1)
	safego.Execute(appCtx, cm.logger, "ResourceRenewalLoop", func() {
		defer cm.renewalWg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cm.logger.Debug(appCtx, "Resource renewal tick: attempting to renew active session locks and routes")

				cm.activeConnections.Range(func(key, value interface{}) bool {
					sessionKey, okSessionKey := key.(string)
					conn, okConn := value.(domain.ManagedConnection)
					if !okSessionKey || !okConn {
						cm.logger.Error(appCtx, "Invalid type in activeConnections map during renewal", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
						return true // Continue to next item
					}

					connCtx := conn.Context()
					renewalOpCtx, cancelOp := context.WithTimeout(appCtx, 5*time.Second)
					defer cancelOp()

					// 1. Renew Session Lock
					if cm.sessionLocker != nil && sessionTTL > 0 {
						refreshed, err := cm.sessionLocker.RefreshLock(renewalOpCtx, sessionKey, podID, sessionTTL)
						if err != nil {
							cm.logger.Error(connCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
						} else if refreshed {
							cm.logger.Debug(connCtx, "Successfully refreshed session lock", "sessionKey", sessionKey, "podID", podID, "newTTL", sessionTTL.String())
						} else {
							cm.logger.Warn(connCtx, "Failed to refresh session lock (not owned or expired)", "sessionKey", sessionKey, "podID", podID)
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping session lock renewal (not configured or TTL is zero)", "sessionKey", sessionKey)
					}

					// 2. Renew Routes (Chat and Message if applicable)
					if cm.routeRegistry != nil && routeTTL > 0 {
						companyID, _ := connCtx.Value(contextkeys.CompanyIDKey).(string)
						agentID, _ := connCtx.Value(contextkeys.AgentIDKey).(string)

						if companyID == "" || agentID == "" {
							cm.logger.Error(connCtx, "Missing companyID or agentID in connection context, cannot renew routes", "sessionKey", sessionKey)
							return true
						}

						chatRouteKey := rediskeys.RouteKeyChats(companyID, agentID)
						refreshedChat, errChat := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, chatRouteKey, podID, routeTTL)
						if errChat != nil {
							cm.logger.Error(connCtx, "Error refreshing chat route TTL", "routeKey", chatRouteKey, "podID", podID, "error", errChat.Error())
						} else if refreshedChat {
							cm.logger.Debug(connCtx, "Successfully refreshed chat route TTL", "routeKey", chatRouteKey, "podID", podID, "newTTL", routeTTL.String())
						} else {
							cm.logger.Warn(connCtx, "Failed to refresh chat route TTL (pod not member or key expired)", "routeKey", chatRouteKey, "podID", podID)
						}

						currentChatID := conn.GetCurrentChatID()
						if currentChatID != "" {
							messageRouteKey := rediskeys.RouteKeyMessages(companyID, agentID, currentChatID)
							refreshedMsg, errMsg := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, messageRouteKey, podID, routeTTL)
							if errMsg != nil {
								cm.logger.Error(connCtx, "Error refreshing message route TTL", "routeKey", messageRouteKey, "podID", podID, "error", errMsg.Error())
							} else if refreshedMsg {
								cm.logger.Debug(connCtx, "Successfully refreshed message route TTL", "routeKey", messageRouteKey, "podID", podID, "newTTL", routeTTL.String())
							} else {
								cm.logger.Warn(connCtx, "Failed to refresh message route TTL (pod not member or key expired)", "routeKey", messageRouteKey, "podID", podID)
							}
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping route renewal (not configured or TTL is zero)", "sessionKey", sessionKey)
					}

					return true
				})

			case <-cm.renewalStopChan:
				cm.logger.Info(appCtx, "Resource renewal loop stopping as requested.")
				return
			case <-appCtx.Done():
				cm.logger.Info(appCtx, "Resource renewal loop stopping due to application context cancellation.")
				return
			}
		}
	})
}

// StopResourceRenewalLoop signals the resource renewal loop to stop and waits for it to finish.
func (cm *ConnectionManager) StopResourceRenewalLoop() {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	if renewalInterval <= 0 || cfg.Server.PodID == "" { // Check if loop was likely started
		cm.logger.Info(context.Background(), "Resource renewal loop was not started or podID not set, nothing to stop.")
		return
	}
	cm.logger.Info(context.Background(), "Attempting to stop resource renewal loop...")
	close(cm.renewalStopChan) // Signal the loop to stop
	cm.renewalWg.Wait()       // Wait for the goroutine to finish
	cm.logger.Info(context.Background(), "Resource renewal loop stopped.")
}
