package domain

import (
	"context"
	"time"
)

// RouteRegistry defines the interface for managing chat and message route registrations.
// It allows tracking which pod is responsible for handling events for specific routes.
type RouteRegistry interface {
	// RegisterChatRoute associates a pod with the general chat eventSADD route:<C>:<A>:chats <pod_id> EX <ttl>
	// for a given company and agent.
	RegisterChatRoute(ctx context.Context, companyID, agentID, podID string, ttl time.Duration) error

	// UnregisterChatRoute removes a pod's association from the general chat event SREM route:<C>:<A>:chats <pod_id>
	// for a given company and agent.
	UnregisterChatRoute(ctx context.Context, companyID, agentID, podID string) error

	// RegisterMessageRoute associates a pod with a specific chat message SADD route:<C>:<A>:messages:<chat_id> <pod_id> EX <ttl>
	// for a given company, agent, and chatID.
	RegisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string, ttl time.Duration) error

	// UnregisterMessageRoute removes a pod's association from a specific chat message SREM route:<C>:<A>:messages:<chat_id> <pod_id>
	// for a given company, agent, and chatID.
	UnregisterMessageRoute(ctx context.Context, companyID, agentID, chatID, podID string) error

	// UnregisterAllMessageRoutesForPod removes a pod's association from all specific chat message routes
	// it might be part of for a given company and agent. This is useful when a client disconnects or
	// switches to a generic chat view. It might involve iterating or using a pattern, depending on Redis capabilities.
	// For simplicity, we might initially require knowing the exact chat IDs to SREM or rely on TTLs for cleanup.
	// A more robust implementation might involve Lua scripting or keeping track of a pod's message routes.
	// For now, we'll focus on specific unregistration. If a wildcard SREM is needed, this signature may change.
	// This specific function might be tricky without Lua. Let's rethink if this exact signature is best
	// or if the caller should manage specific chat IDs to unregister.
	// The subtask details mention: "pod first SREMs itself from any previous specific message routes it owned for that session".
	// This implies the pod *knows* its previous chat_id.
	// So, this function may not be needed if unregistration is always specific.
	// Let's keep it simple for now and assume specific unregistrations.

	// GetOwningPodForMessageRoute retrieves the pod ID currently owning the route for a specific chat's messages.
	// This might return one pod ID or an error if none/multiple (though SADD implies single set members effectively).
	// SMEMBERS route:<C>:<A>:messages:<chat_id>
	GetOwningPodForMessageRoute(ctx context.Context, companyID, agentID, chatID string) (string, error)

	// GetOwningPodsForChatRoute retrieves all pod IDs associated with the general chat route for a company/agent.
	// SMEMBERS route:<C>:<A>:chats
	GetOwningPodsForChatRoute(ctx context.Context, companyID, agentID string) ([]string, error)

	// RefreshRouteTTL extends the expiration time for a given route key if the podID matches the value.
	// This is a generic refresh that could be used for both chat and message routes.
	// It should use a Lua script to ensure atomicity: check current value, then EXPIRE.
	RefreshRouteTTL(ctx context.Context, routeKey, podID string, ttl time.Duration) (bool, error)
}
