package domain

import (
	"context"
)

// MessageForwarder defines the interface for forwarding messages to other pods,
// typically via gRPC.
type MessageForwarder interface {
	// ForwardEvent sends an EnrichedEventPayload to a target pod.
	// targetPodAddress is the network address (e.g., "ip:port") of the target pod.
	ForwardEvent(ctx context.Context, targetPodAddress string, event *EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error
}
