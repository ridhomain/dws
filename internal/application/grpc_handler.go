package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/rediskeys"
	"google.golang.org/grpc/metadata"
)

// GRPCMessageHandler implements the gRPC MessageForwardingService.
type GRPCMessageHandler struct {
	pb.UnimplementedMessageForwardingServiceServer
	logger         domain.Logger
	connManager    *ConnectionManager
	configProvider config.Provider
}

// NewGRPCMessageHandler creates a new GRPCMessageHandler.
func NewGRPCMessageHandler(logger domain.Logger, connManager *ConnectionManager, configProvider config.Provider) *GRPCMessageHandler {
	return &GRPCMessageHandler{
		logger:         logger,
		connManager:    connManager,
		configProvider: configProvider,
	}
}

// PushEvent is the RPC handler for receiving forwarded messages.
func (h *GRPCMessageHandler) PushEvent(ctx context.Context, req *pb.PushEventRequest) (*pb.PushEventResponse, error) {
	// Extract request_id from incoming metadata and add to context for logging
	md, ok := metadata.FromIncomingContext(ctx)
	logCtx := ctx
	if ok {
		if reqIDValues := md.Get(string(contextkeys.RequestIDKey)); len(reqIDValues) > 0 {
			logCtx = context.WithValue(ctx, contextkeys.RequestIDKey, reqIDValues[0])
			h.logger.Debug(logCtx, "Extracted request_id from gRPC metadata", "request_id", reqIDValues[0])
		} else {
			h.logger.Debug(logCtx, "No request_id found in gRPC metadata")
		}
	} else {
		h.logger.Debug(logCtx, "No gRPC metadata found in incoming context")
	}

	metrics.IncrementGrpcMessagesReceived(req.SourcePodId)
	h.logger.Info(logCtx, "gRPC PushEvent received",
		"target_company_id", req.TargetCompanyId,
		"target_agent_id", req.TargetAgentId,
		"target_chat_id", req.TargetChatId,
		"source_event_id", req.Payload.EventId,
	)

	if req.Payload == nil {
		h.logger.Warn(logCtx, "gRPC PushEvent received nil payload")
		return &pb.PushEventResponse{Success: false, Message: "Nil payload received"}, fmt.Errorf("nil payload")
	}

	sessionKeyPrefix := fmt.Sprintf("session:%s:%s:", req.TargetCompanyId, req.TargetAgentId)
	var targetConn domain.ManagedConnection
	found := false

	h.connManager.activeConnections.Range(func(key, value interface{}) bool {
		sKey, okKey := key.(string)
		conn, okConn := value.(domain.ManagedConnection)
		if !okKey || !okConn {
			return true // continue iteration
		}
		if strings.HasPrefix(sKey, sessionKeyPrefix) {
			if conn.GetCurrentChatID() == req.TargetChatId {
				targetConn = conn
				found = true
				return false // stop iteration
			}
		}
		return true // continue iteration
	})

	if !found || targetConn == nil {
		h.logger.Warn(logCtx, "gRPC PushEvent: No active local WebSocket connection found for target chat_id on this pod",
			"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId)
		return &pb.PushEventResponse{Success: false, Message: "No active local connection for chat_id"}, nil
	}

	var rowDataMap map[string]interface{}
	if req.Payload.RowData != nil {
		rowDataMap = req.Payload.RowData.AsMap()
	}

	domainPayload := domain.EnrichedEventPayload{
		EventID:   req.Payload.EventId,
		CompanyID: req.Payload.CompanyId,
		AgentID:   req.Payload.AgentId,
		MessageID: req.Payload.MessageId,
		ChatID:    req.Payload.ChatId,
		EventTime: req.Payload.EventTime,
		RowData:   rowDataMap,
		EventType: req.Payload.EventType,
	}

	wsMessage := domain.NewEventMessage(domainPayload)

	if err := targetConn.WriteJSON(wsMessage); err != nil {
		h.logger.Error(targetConn.Context(), "gRPC PushEvent: Failed to write message to local WebSocket connection",
			"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId,
			"error", err.Error(),
		)
		return &pb.PushEventResponse{Success: false, Message: "Failed to write to local WebSocket"}, nil
	}

	// Record message route activity after successful local delivery by gRPC handler
	if h.connManager != nil && h.connManager.RouteRegistrar() != nil && h.configProvider != nil {
		messageRouteKey := rediskeys.RouteKeyMessages(req.TargetCompanyId, req.TargetAgentId, req.TargetChatId)
		adaptiveMsgRouteCfg := h.configProvider.Get().AdaptiveTTL.MessageRoute
		activityTTL := time.Duration(adaptiveMsgRouteCfg.MaxTTLSeconds) * time.Second
		if activityTTL <= 0 { // Fallback if MaxTTLSeconds is not set or zero
			activityTTL = time.Duration(h.configProvider.Get().App.RouteTTLSeconds) * time.Second * 2
		}
		if errAct := h.connManager.RouteRegistrar().RecordActivity(targetConn.Context(), messageRouteKey, activityTTL); errAct != nil {
			h.logger.Error(targetConn.Context(), "gRPC PushEvent: Failed to record message route activity after local delivery", "messageRouteKey", messageRouteKey, "error", errAct)
		} else {
			h.logger.Debug(targetConn.Context(), "gRPC PushEvent: Recorded message route activity after local delivery", "messageRouteKey", messageRouteKey, "activityTTL", activityTTL.String())
		}
	}

	h.logger.Info(targetConn.Context(), "gRPC PushEvent: Successfully delivered message to local WebSocket connection",
		"target_company_id", req.TargetCompanyId, "target_agent_id", req.TargetAgentId, "target_chat_id", req.TargetChatId,
	)

	return &pb.PushEventResponse{Success: true, Message: "Event delivered to local WebSocket"}, nil
}
