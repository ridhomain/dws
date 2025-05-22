package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"
)

// StartResourceRenewalLoop periodically refreshes session locks and route registrations for active connections.
func (cm *ConnectionManager) StartResourceRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second

	// Default TTLs from main app config (used as fallbacks or if adaptive is off)
	defaultSessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	defaultRouteTTL := time.Duration(cfg.App.RouteTTLSeconds) * time.Second

	podID := cfg.Server.PodID

	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Resource renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Resource renewal will not work correctly.")
		return
	}
	if cm.redisClient == nil {
		cm.logger.Error(appCtx, "Redis client is nil in ConnectionManager. Adaptive TTL renewal cannot proceed.")
		return
	}

	cm.logger.Info(appCtx, "Starting resource renewal loop",
		"renewalInterval", renewalInterval.String(),
		"defaultSessionTTL", defaultSessionTTL.String(),
		"defaultRouteTTL", defaultRouteTTL.String(),
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
				// Count active connections for logging metrics
				var activeCount int32 = 0

				// Track successful/failed refresh stats for this tick for debug reporting
				sessionRefreshStats := struct {
					attempted    int
					succeeded    int
					failed       int
					notOwned     int
					errorOccured int
				}{}

				// Process each active connection for renewal
				cm.activeConnections.Range(func(key, value interface{}) bool {
					activeCount++
					sessionKey, okSessionKey := key.(string)
					conn, okConn := value.(domain.ManagedConnection)
					if !okSessionKey || !okConn {
						cm.logger.Error(appCtx, "Invalid type in activeConnections map during renewal", "key_type", fmt.Sprintf("%T", key), "value_type", fmt.Sprintf("%T", value))
						return true // continue to next item
					}

					connCtx := conn.Context()
					// Create a short-lived context for each connection's renewal operations
					renewalOpCtx, cancelOp := context.WithTimeout(appCtx, 10*time.Second) // Increased timeout slightly
					defer cancelOp()

					// --- Session Lock Renewal ---
					adaptiveSessionCfg := cfg.AdaptiveTTL.SessionLock
					actualSessionTTL := defaultSessionTTL // Fallback to original config TTL
					decisionSession := "default_ttl"

					// Determine userType for metrics, assuming "user" for activeConnections
					// This might need refinement if activeConnections can store different types of sessions
					// or if admin connections were also renewed in this loop (they are not currently).
					userMetricType := "user"
					// If sessionKey could indicate an admin session, userMetricType could be changed here.
					// For example: if strings.HasPrefix(sessionKey, "adminsession:") { userMetricType = "admin" }

					// Increment attempt metric before trying to refresh
					metrics.IncrementSessionLockRenewalAttempt(userMetricType)
					sessionRefreshStats.attempted++

					if adaptiveSessionCfg.Enabled && cm.sessionLocker != nil && defaultSessionTTL > 0 {
						activityKey := sessionKey + ":last_active"
						lastActiveUnix, err := cm.redisClient.Get(renewalOpCtx, activityKey).Int64()

						if err != nil && !errors.Is(err, redis.Nil) {
							cm.logger.Error(connCtx, "Error fetching session last_active time", "sessionKey", sessionKey, "activityKey", activityKey, "error", err)
							decisionSession = "error_fetching_activity"
						} else if errors.Is(err, redis.Nil) { // No activity recorded, treat as inactive
							actualSessionTTL = time.Duration(adaptiveSessionCfg.InactiveTTLSeconds) * time.Second
							decisionSession = "inactive_no_key"
							cm.logger.Debug(connCtx, "Session inactive (no last_active key)", "sessionKey", sessionKey, "using_ttl", actualSessionTTL.String())
						} else {
							lastActiveTime := time.Unix(lastActiveUnix, 0)
							activityAge := time.Since(lastActiveTime)
							metrics.ObserveRedisActivityAge("session_lock", activityAge.Seconds())
							if activityAge <= time.Duration(adaptiveSessionCfg.ActivityThresholdSeconds)*time.Second {
								actualSessionTTL = time.Duration(adaptiveSessionCfg.ActiveTTLSeconds) * time.Second
								decisionSession = "active"
								cm.logger.Debug(connCtx, "Session active", "sessionKey", sessionKey, "last_active", lastActiveTime.Format(time.RFC3339), "using_ttl", actualSessionTTL.String())
							} else {
								actualSessionTTL = time.Duration(adaptiveSessionCfg.InactiveTTLSeconds) * time.Second
								decisionSession = "inactive_threshold"
								cm.logger.Debug(connCtx, "Session inactive (threshold)", "sessionKey", sessionKey, "last_active", lastActiveTime.Format(time.RFC3339), "using_ttl", actualSessionTTL.String())
							}
						}

						// Clamp TTL
						minSessTTL := time.Duration(adaptiveSessionCfg.MinTTLSeconds) * time.Second
						maxSessTTL := time.Duration(adaptiveSessionCfg.MaxTTLSeconds) * time.Second
						if actualSessionTTL < minSessTTL {
							actualSessionTTL = minSessTTL
						}
						if actualSessionTTL > maxSessTTL {
							actualSessionTTL = maxSessTTL
						}
						cm.logger.Debug(connCtx, "Final session TTL after clamping", "sessionKey", sessionKey, "final_ttl", actualSessionTTL.String())
					} else {
						if !adaptiveSessionCfg.Enabled {
							decisionSession = "disabled_config"
						}
						cm.logger.Debug(connCtx, "Adaptive session TTL not applied or session locker not configured; using default.", "sessionKey", sessionKey, "default_ttl", defaultSessionTTL.String(), "enabled_config", adaptiveSessionCfg.Enabled)
					}
					metrics.IncrementRedisTTLDecision("session_lock", decisionSession)

					// Enhanced debug for session lock renewal
					cm.logger.Debug(connCtx, "Processing session lock renewal",
						"sessionKey", sessionKey,
						"podID", podID,
						"calculated_ttl", actualSessionTTL.String(),
						"decision_reason", decisionSession,
						"operation", "ResourceRenewalTick")

					if cm.sessionLocker != nil && actualSessionTTL > 0 { // Ensure actualSessionTTL is positive
						metrics.ObserveRedisTTLCalculated("session_lock", actualSessionTTL.Seconds())
						refreshed, err := cm.sessionLocker.RefreshLock(renewalOpCtx, sessionKey, podID, actualSessionTTL)
						if err != nil {
							sessionRefreshStats.errorOccured++
							cm.logger.Error(connCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
							metrics.IncrementSessionLockRenewalFailure(userMetricType, "error")
						} else if !refreshed {
							// This case means lock was not ours or disappeared before refresh.
							cm.logger.Warn(connCtx, "Failed to refresh session lock (e.g., not owned by this pod, or key disappeared)", "sessionKey", sessionKey, "podID", podID)
							// Use 'sessionRefreshStats.failed' to count these non-error refresh failures.
							// The existing 'notOwned' field in stats might be redundant if we simplify here or can be set based on more detailed future checks if available.
							sessionRefreshStats.failed++ // Consolidating into 'failed' for now.
							metrics.IncrementSessionLockRenewalFailure(userMetricType, "failed_to_renew")
						} else {
							cm.logger.Debug(connCtx, "Successfully renewed session lock", "sessionKey", sessionKey, "newTTL", actualSessionTTL.Seconds())
							sessionRefreshStats.succeeded++
							metrics.IncrementSessionLockRenewalSuccess(userMetricType)
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping session lock renewal (not configured, TTL is zero, or adaptive TTL resulted in zero)", "sessionKey", sessionKey)
					}

					// --- Route Renewal ---
					if cm.routeRegistry != nil && defaultRouteTTL > 0 {
						companyID, _ := connCtx.Value(contextkeys.CompanyIDKey).(string)
						agentID, _ := connCtx.Value(contextkeys.AgentIDKey).(string)

						if companyID == "" || agentID == "" {
							cm.logger.Error(connCtx, "Missing companyID or agentID in connection context, cannot renew routes", "sessionKey", sessionKey)
							return true // continue to next item
						}

						// Chat Route (route:<c>:<a>:chats) Renewal
						chatRouteKey := rediskeys.RouteKeyChats(companyID, agentID)
						adaptiveChatRouteCfg := cfg.AdaptiveTTL.ChatRoute // Using ChatRoute specific config
						actualChatRouteTTL := defaultRouteTTL
						decisionChatRoute := "default_ttl"

						if adaptiveChatRouteCfg.Enabled { // Check if adaptive TTL is enabled for chat routes
							activityKey := chatRouteKey + ":last_active"
							lastActiveUnix, err := cm.redisClient.Get(renewalOpCtx, activityKey).Int64()
							if err != nil && !errors.Is(err, redis.Nil) {
								cm.logger.Error(connCtx, "Error fetching chat route last_active time", "routeKey", chatRouteKey, "activityKey", activityKey, "error", err)
								decisionChatRoute = "error_fetching_activity"
							} else if errors.Is(err, redis.Nil) {
								actualChatRouteTTL = time.Duration(adaptiveChatRouteCfg.InactiveTTLSeconds) * time.Second
								decisionChatRoute = "inactive_no_key"
							} else {
								lastActiveTime := time.Unix(lastActiveUnix, 0)
								activityAge := time.Since(lastActiveTime)
								metrics.ObserveRedisActivityAge("chat_route", activityAge.Seconds())
								if activityAge <= time.Duration(adaptiveChatRouteCfg.ActivityThresholdSeconds)*time.Second {
									actualChatRouteTTL = time.Duration(adaptiveChatRouteCfg.ActiveTTLSeconds) * time.Second
									decisionChatRoute = "active"
								} else {
									actualChatRouteTTL = time.Duration(adaptiveChatRouteCfg.InactiveTTLSeconds) * time.Second
									decisionChatRoute = "inactive_threshold"
								}
							}
							minChatRouteTTL := time.Duration(adaptiveChatRouteCfg.MinTTLSeconds) * time.Second
							maxChatRouteTTL := time.Duration(adaptiveChatRouteCfg.MaxTTLSeconds) * time.Second
							if actualChatRouteTTL < minChatRouteTTL {
								actualChatRouteTTL = minChatRouteTTL
							}
							if actualChatRouteTTL > maxChatRouteTTL {
								actualChatRouteTTL = maxChatRouteTTL
							}
							cm.logger.Debug(connCtx, "Adaptive chat route TTL calculated", "routeKey", chatRouteKey, "final_ttl", actualChatRouteTTL.String())
						} else {
							if !adaptiveChatRouteCfg.Enabled {
								decisionChatRoute = "disabled_config"
							}
							cm.logger.Debug(connCtx, "Adaptive chat route TTL disabled; using default.", "routeKey", chatRouteKey, "default_ttl", defaultRouteTTL.String())
						}
						metrics.IncrementRedisTTLDecision("chat_route", decisionChatRoute)

						if actualChatRouteTTL > 0 {
							metrics.ObserveRedisTTLCalculated("chat_route", actualChatRouteTTL.Seconds())
							refreshedChat, errChat := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, chatRouteKey, podID, actualChatRouteTTL)
							if errChat != nil {
								cm.logger.Error(connCtx, "Error refreshing chat route TTL", "routeKey", chatRouteKey, "podID", podID, "error", errChat.Error())
							} else if refreshedChat {
								cm.logger.Debug(connCtx, "Successfully refreshed chat route TTL", "routeKey", chatRouteKey, "podID", podID, "newTTL", actualChatRouteTTL.String())
							} else {
								cm.logger.Warn(connCtx, "Failed to refresh chat route TTL (pod not member or key expired)", "routeKey", chatRouteKey, "podID", podID)
							}
						}

						// Message Route (route:<c>:<a>:messages:<chatID>) Renewal
						currentChatID := conn.GetCurrentChatID()
						if currentChatID != "" {
							messageRouteKey := rediskeys.RouteKeyMessages(companyID, agentID, currentChatID)
							adaptiveMsgRouteCfg := cfg.AdaptiveTTL.MessageRoute
							actualMsgRouteTTL := defaultRouteTTL // Fallback
							decisionMsgRoute := "default_ttl"

							if adaptiveMsgRouteCfg.Enabled {
								activityKey := messageRouteKey + ":last_active"
								lastActiveUnix, err := cm.redisClient.Get(renewalOpCtx, activityKey).Int64()
								if err != nil && !errors.Is(err, redis.Nil) {
									cm.logger.Error(connCtx, "Error fetching message route last_active time", "routeKey", messageRouteKey, "activityKey", activityKey, "error", err)
									decisionMsgRoute = "error_fetching_activity"
								} else if errors.Is(err, redis.Nil) {
									actualMsgRouteTTL = time.Duration(adaptiveMsgRouteCfg.InactiveTTLSeconds) * time.Second
									decisionMsgRoute = "inactive_no_key"
								} else {
									lastActiveTime := time.Unix(lastActiveUnix, 0)
									activityAge := time.Since(lastActiveTime)
									metrics.ObserveRedisActivityAge("message_route", activityAge.Seconds())
									if activityAge <= time.Duration(adaptiveMsgRouteCfg.ActivityThresholdSeconds)*time.Second {
										actualMsgRouteTTL = time.Duration(adaptiveMsgRouteCfg.ActiveTTLSeconds) * time.Second
										decisionMsgRoute = "active"
									} else {
										actualMsgRouteTTL = time.Duration(adaptiveMsgRouteCfg.InactiveTTLSeconds) * time.Second
										decisionMsgRoute = "inactive_threshold"
									}
								}
								minMsgRouteTTL := time.Duration(adaptiveMsgRouteCfg.MinTTLSeconds) * time.Second
								maxMsgRouteTTL := time.Duration(adaptiveMsgRouteCfg.MaxTTLSeconds) * time.Second
								if actualMsgRouteTTL < minMsgRouteTTL {
									actualMsgRouteTTL = minMsgRouteTTL
								}
								if actualMsgRouteTTL > maxMsgRouteTTL {
									actualMsgRouteTTL = maxMsgRouteTTL
								}
								cm.logger.Debug(connCtx, "Adaptive message route TTL calculated", "routeKey", messageRouteKey, "final_ttl", actualMsgRouteTTL.String())
							} else {
								if !adaptiveMsgRouteCfg.Enabled {
									decisionMsgRoute = "disabled_config"
								}
								cm.logger.Debug(connCtx, "Adaptive message route TTL disabled; using default.", "routeKey", messageRouteKey, "default_ttl", defaultRouteTTL.String())
							}
							metrics.IncrementRedisTTLDecision("message_route", decisionMsgRoute)

							if actualMsgRouteTTL > 0 {
								metrics.ObserveRedisTTLCalculated("message_route", actualMsgRouteTTL.Seconds())
								refreshedMsg, errMsg := cm.routeRegistry.RefreshRouteTTL(renewalOpCtx, messageRouteKey, podID, actualMsgRouteTTL)
								if errMsg != nil {
									cm.logger.Error(connCtx, "Error refreshing message route TTL", "routeKey", messageRouteKey, "podID", podID, "error", errMsg.Error())
								} else if refreshedMsg {
									cm.logger.Debug(connCtx, "Successfully refreshed message route TTL", "routeKey", messageRouteKey, "podID", podID, "newTTL", actualMsgRouteTTL.String())
								} else {
									cm.logger.Warn(connCtx, "Failed to refresh message route TTL (pod not member or key expired)", "routeKey", messageRouteKey, "podID", podID)
								}
							}
						}
					} else {
						cm.logger.Debug(connCtx, "Skipping route renewal (not configured or defaultRouteTTL is zero)", "sessionKey", sessionKey)
					}
					return true // continue to next item in sync.Map
				})

				// Log summary of renewal operations for this tick
				cm.logger.Debug(appCtx, "Resource renewal tick completed",
					"active_connections", activeCount,
					"session_renewal_attempts", sessionRefreshStats.attempted,
					"session_renewal_succeeded", sessionRefreshStats.succeeded,
					"session_renewal_failed_not_owned", sessionRefreshStats.failed,
					"session_renewal_errors", sessionRefreshStats.errorOccured,
					"operation", "ResourceRenewalTick")

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
	// Check if loop was likely started
	if renewalInterval <= 0 || cfg.Server.PodID == "" || cm.redisClient == nil {
		cm.logger.Info(context.Background(), "Resource renewal loop was not started or prerequisites missing, nothing to stop.")
		return
	}

	cm.logger.Info(context.Background(), "Attempting to stop resource renewal loop...")

	// Use mutex to prevent multiple goroutines from closing the channel
	cm.renewalStopMutex.Lock()
	defer cm.renewalStopMutex.Unlock()

	// Check if the renewal loop has already been stopped
	if cm.renewalStopped {
		cm.logger.Info(context.Background(), "Resource renewal loop was already stopped.")
		return
	}

	// Signal the loop to stop and mark as stopped
	close(cm.renewalStopChan)
	cm.renewalStopped = true

	// Wait for the goroutine to finish
	cm.renewalWg.Wait()
	cm.logger.Info(context.Background(), "Resource renewal loop stopped.")
}
