package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
)

var ErrNoOwningPod = errors.New("no owning pod found for the route")

type RouteRegistryAdapter struct {
	redisClient *redis.Client
	logger      domain.Logger
}

func NewRouteRegistryAdapter(redisClient *redis.Client, logger domain.Logger) *RouteRegistryAdapter {
	if redisClient == nil {
		panic("redisClient cannot be nil in NewRouteRegistryAdapter")
	}
	if logger == nil {
		panic("logger cannot be nil in NewRouteRegistryAdapter")
	}
	return &RouteRegistryAdapter{
		redisClient: redisClient,
		logger:      logger,
	}
}

func (a *RouteRegistryAdapter) RegisterChatRoute(ctx context.Context, companyID, agentID, podID string, ttl time.Duration) error {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	a.logger.Debug(ctx, "Registering chat route", "key", key, "podID", podID, "ttl", ttl.String())
	pipe := a.redisClient.Pipeline()
	pipe.SAdd(ctx, key, podID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		a.logger.Error(ctx, "Failed to register chat route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SADD/EXPIRE for chat route key '%s' failed: %w", key, err)
	}
	return nil
}

func (a *RouteRegistryAdapter) UnregisterChatRoute(ctx context.Context, companyID, agentID, podID string) error {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	a.logger.Debug(ctx, "Unregistering chat route", "key", key, "podID", podID)
	err := a.redisClient.SRem(ctx, key, podID).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to unregister chat route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SREM for chat route key '%s' failed: %w", key, err)
	}
	return nil
}

func (a *RouteRegistryAdapter) RegisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string, ttl time.Duration) error {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	a.logger.Debug(ctx, "Registering message route", "key", key, "podID", podID, "ttl", ttl.String())
	pipe := a.redisClient.Pipeline()
	pipe.SAdd(ctx, key, podID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		a.logger.Error(ctx, "Failed to register message route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SADD/EXPIRE for message route key '%s' failed: %w", key, err)
	}
	return nil
}

func (a *RouteRegistryAdapter) UnregisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string) error {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	a.logger.Debug(ctx, "Unregistering message route", "key", key, "podID", podID)
	err := a.redisClient.SRem(ctx, key, podID).Err()
	if err != nil {
		a.logger.Error(ctx, "Failed to unregister message route", "key", key, "podID", podID, "error", err.Error())
		return fmt.Errorf("redis SREM for message route key '%s' failed: %w", key, err)
	}
	return nil
}

func (a *RouteRegistryAdapter) GetOwningPodForMessageRoute(ctx context.Context, companyID, agentID, chatID string) (string, error) {
	key := rediskeys.RouteKeyMessages(companyID, agentID, chatID)
	members, err := a.redisClient.SMembers(ctx, key).Result()
	if err != nil {
		a.logger.Error(ctx, "Failed to get members for message route", "key", key, "error", err.Error())
		return "", fmt.Errorf("redis SMEMBERS for message route key '%s' failed: %w", key, err)
	}
	if len(members) == 0 {
		a.logger.Debug(ctx, "No owning pod found for message route", "key", key)
		return "", ErrNoOwningPod
	}
	if len(members) > 1 {
		a.logger.Warn(ctx, "Multiple owning pods found for message route, returning first", "key", key, "pods", members)
	}
	return members[0], nil
}

func (a *RouteRegistryAdapter) GetOwningPodsForChatRoute(ctx context.Context, companyID, agentID string) ([]string, error) {
	key := rediskeys.RouteKeyChats(companyID, agentID)
	members, err := a.redisClient.SMembers(ctx, key).Result()
	if err != nil {
		a.logger.Error(ctx, "Failed to get members for chat route", "key", key, "error", err.Error())
		return nil, fmt.Errorf("redis SMEMBERS for chat route key '%s' failed: %w", key, err)
	}
	if len(members) == 0 {
		a.logger.Debug(ctx, "No owning pods found for chat route", "key", key)
		// It's not necessarily an error for a chat route to have no pods if no one is connected for that company/agent
	}
	return members, nil
}

// RefreshRouteTTL refreshes the TTL of a route key if the podID is currently a member of the set.
// This implementation uses a Lua script for atomicity.
func (a *RouteRegistryAdapter) RefreshRouteTTL(ctx context.Context, routeKey, podID string, ttl time.Duration) (bool, error) {
	script := `
        if redis.call("sismember", KEYS[1], ARGV[1]) == 1 then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
    `
	ttlSeconds := int64(ttl.Seconds())
	result, err := a.redisClient.Eval(ctx, script, []string{routeKey}, podID, ttlSeconds).Int64()
	if err != nil && !errors.Is(err, redis.Nil) { // redis.Nil can be returned if key doesn't exist, which is fine if sismember is 0
		a.logger.Error(ctx, "Redis EVAL (RefreshRouteTTL script) failed", "key", routeKey, "podID", podID, "error", err.Error())
		return false, fmt.Errorf("redis EVAL for RefreshRouteTTL on key '%s' failed: %w", routeKey, err)
	}
	refreshed := result == 1
	a.logger.Debug(ctx, "Redis RefreshRouteTTL result", "key", routeKey, "podID", podID, "ttl_seconds", ttlSeconds, "refreshed_by_script", refreshed, "script_result_val", result)
	return refreshed, nil
}

func (a *RouteRegistryAdapter) RecordActivity(ctx context.Context, routeKey string, activityTTL time.Duration) error {
	activityKey := routeKey + ":last_active"
	now := time.Now().Unix()
	err := a.redisClient.Set(ctx, activityKey, now, activityTTL).Err()
	if err != nil {
		a.logger.Error(ctx, "Redis SET failed for RecordActivity on route key", "key", activityKey, "error", err.Error())
		return fmt.Errorf("redis SET for key '%s' in RecordActivity (route) failed: %w", activityKey, err)
	}
	a.logger.Debug(ctx, "Redis SET successful for RecordActivity on route key", "key", activityKey, "timestamp", now, "ttl", activityTTL)
	return nil
}
