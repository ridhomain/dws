package application

import (
	"context"
	"time"
)

// StartSessionRenewalLoop starts a goroutine to periodically renew active session locks.
// appCtx is the main application context that can be used to signal shutdown.
func (cm *ConnectionManager) StartSessionRenewalLoop(appCtx context.Context) {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	sessionTTL := time.Duration(cfg.App.SessionTTLSeconds) * time.Second
	podID := cfg.Server.PodID

	if renewalInterval <= 0 {
		cm.logger.Warn(appCtx, "Session lock renewal interval is not configured or invalid; renewal loop will not start.", "intervalSeconds", cfg.App.TTLRefreshIntervalSeconds)
		return
	}
	if sessionTTL <= 0 {
		cm.logger.Warn(appCtx, "Session lock TTL is not configured or invalid; renewal logic might be ineffective.", "ttlSeconds", cfg.App.SessionTTLSeconds)
	}
	if podID == "" {
		cm.logger.Error(appCtx, "PodID is not configured. Session lock renewal will not work correctly.")
		return
	}

	cm.logger.Info(appCtx, "Starting session renewal loop", "renewalInterval", renewalInterval.String(), "sessionTTL", sessionTTL.String(), "podID", podID)
	cm.renewalWg.Add(1)

	go func() {
		defer cm.renewalWg.Done()
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cm.logger.Debug(appCtx, "Session renewal tick: attempting to renew active session locks")
				var keysToRenew []string
				cm.activeConnections.Range(func(key, value interface{}) bool {
					sessionKey, ok := key.(string)
					if ok {
						keysToRenew = append(keysToRenew, sessionKey)
					}
					return true
				})

				if len(keysToRenew) == 0 {
					cm.logger.Debug(appCtx, "No active session locks to renew this tick.")
					continue
				}

				cm.logger.Debug(appCtx, "Found active session locks to renew", "count", len(keysToRenew))

				for _, sessionKey := range keysToRenew {
					renewalCtx, cancel := context.WithTimeout(appCtx, 5*time.Second)

					refreshed, err := cm.sessionLocker.RefreshLock(renewalCtx, sessionKey, podID, sessionTTL)
					if err != nil {
						cm.logger.Error(renewalCtx, "Error refreshing session lock", "sessionKey", sessionKey, "podID", podID, "error", err.Error())
					} else if refreshed {
						cm.logger.Debug(renewalCtx, "Successfully refreshed session lock", "sessionKey", sessionKey, "podID", podID, "newTTL", sessionTTL.String())
					} else {
						cm.logger.Warn(renewalCtx, "Failed to refresh session lock (not owned or expired)", "sessionKey", sessionKey, "podID", podID)
					}
					cancel()
				}

			case <-cm.renewalStopChan:
				cm.logger.Info(appCtx, "Session renewal loop stopping as requested.")
				return
			case <-appCtx.Done():
				cm.logger.Info(appCtx, "Session renewal loop stopping due to application context cancellation.")
				return
			}
		}
	}()
}

// StopSessionRenewalLoop signals the session renewal loop to stop and waits for it to complete.
func (cm *ConnectionManager) StopSessionRenewalLoop() {
	cfg := cm.configProvider.Get()
	renewalInterval := time.Duration(cfg.App.TTLRefreshIntervalSeconds) * time.Second
	if renewalInterval <= 0 || cfg.Server.PodID == "" { // Check if loop was started
		cm.logger.Info(context.Background(), "Session renewal loop was not started or podID not set, nothing to stop.")
		return
	}

	cm.logger.Info(context.Background(), "Attempting to stop session renewal loop...")
	close(cm.renewalStopChan)
	cm.renewalWg.Wait()
	cm.logger.Info(context.Background(), "Session renewal loop stopped.")
}
