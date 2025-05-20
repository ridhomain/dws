package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	pb "gitlab.com/timkado/api/daisi-ws-service/internal/adapters/grpc/proto"
	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/metrics"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/contextkeys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type ForwarderAdapter struct {
	logger         domain.Logger
	configProvider config.Provider
	grpcClientPool *sync.Map // Map targetAddress (string) to *grpc.ClientConn
}

func NewForwarderAdapter(logger domain.Logger, configProvider config.Provider) *ForwarderAdapter {
	return &ForwarderAdapter{
		logger:         logger,
		configProvider: configProvider,
		grpcClientPool: &sync.Map{},
	}
}

func (fa *ForwarderAdapter) ForwardEvent(ctx context.Context, targetPodAddress string, event *domain.EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error {
	fa.logger.Info(ctx, "Attempting to forward message via gRPC using ForwarderAdapter", "target_address", targetPodAddress, "event_id", event.EventID)

	var grpcConn *grpc.ClientConn
	var errClient error
	var connFromPool bool

	if connVal, okPool := fa.grpcClientPool.Load(targetPodAddress); okPool {
		grpcConn, connFromPool = connVal.(*grpc.ClientConn)
		if !connFromPool {
			fa.logger.Error(ctx, "Invalid type in gRPC client pool, removing entry.", "target_address", targetPodAddress, "type", fmt.Sprintf("%T", connVal))
			fa.grpcClientPool.Delete(targetPodAddress)
			grpcConn = nil // Ensure it's nil so a new one is created
		} else {
			connState := grpcConn.GetState()
			if connState != connectivity.Ready && connState != connectivity.Idle {
				fa.logger.Warn(ctx, "Pooled gRPC connection is not Ready or Idle, discarding.", "target_address", targetPodAddress, "state", connState.String())
				fa.grpcClientPool.Delete(targetPodAddress)
				grpcConn.Close() // Close the unhealthy connection
				grpcConn = nil
				connFromPool = false // Treat as if not from pool for recreation
			} else {
				fa.logger.Debug(ctx, "Reusing gRPC client connection from pool", "target_address", targetPodAddress, "state", connState.String())
			}
		}
	}

	if grpcConn == nil {
		fa.logger.Info(ctx, "Creating new gRPC client connection via ForwarderAdapter", "target_address", targetPodAddress)
		// Consider adding grpc.WithBlock() if initial connection is critical, or manage connection state actively.
		connOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		newlyCreatedConn, newErrClient := grpc.NewClient(targetPodAddress, connOpts...)
		if newErrClient == nil {
			grpcConn = newlyCreatedConn
			fa.grpcClientPool.Store(targetPodAddress, grpcConn)
		} else {
			errClient = newErrClient
		}
	}

	if errClient != nil {
		fa.logger.Error(ctx, "Failed to establish gRPC connection to owner pod via ForwarderAdapter",
			"target_pod_address", targetPodAddress, "error", errClient.Error())
		return errClient
	}
	if grpcConn == nil { // Should not happen if errClient is nil, but defensive check
		fa.logger.Error(ctx, "gRPC connection is nil after creation attempt without error ForwarderAdapter", "target_pod_address", targetPodAddress)
		return fmt.Errorf("gRPC connection is nil for %s", targetPodAddress)
	}

	client := pb.NewMessageForwardingServiceClient(grpcConn)
	protoData, errProtoStruct := structpb.NewStruct(event.Data.(map[string]interface{}))
	if errProtoStruct != nil {
		fa.logger.Error(ctx, "Failed to convert event.Data to proto.Struct for gRPC via ForwarderAdapter", "error", errProtoStruct.Error())
		return errProtoStruct
	}

	grpcRequest := &pb.PushEventRequest{
		Payload: &pb.EnrichedEventPayloadMessage{
			EventId:   event.EventID,
			EventType: event.EventType,
			Timestamp: timestamppb.New(event.Timestamp),
			Source:    event.Source,
			Data:      protoData,
		},
		TargetCompanyId: targetCompanyID,
		TargetAgentId:   targetAgentID,
		TargetChatId:    targetChatID,
		SourcePodId:     sourcePodID,
	}

	mdOut := metadata.New(nil)
	if reqID, okCtxVal := ctx.Value(contextkeys.RequestIDKey).(string); okCtxVal && reqID != "" {
		mdOut.Set(string(contextkeys.RequestIDKey), reqID)
	}
	pushCtxWithMetadata := metadata.NewOutgoingContext(ctx, mdOut)

	grpcClientTimeoutSeconds := fa.configProvider.Get().App.GRPCCLientForwardTimeoutSeconds
	grpcClientTimeout := 5 * time.Second // Default timeout
	if grpcClientTimeoutSeconds > 0 {
		grpcClientTimeout = time.Duration(grpcClientTimeoutSeconds) * time.Second
	}

	var finalErr error
	for i := 0; i < 2; i++ { // 0: initial attempt, 1: retry attempt
		pushCtx, pushCancel := context.WithTimeout(pushCtxWithMetadata, grpcClientTimeout)
		resp, errPush := client.PushEvent(pushCtx, grpcRequest)
		pushCancel()

		if errPush == nil {
			if resp != nil && resp.Success {
				fa.logger.Info(ctx, "Successfully forwarded message via gRPC using ForwarderAdapter", "target_pod_address", targetPodAddress, "event_id", event.EventID, "attempt", i)
				metrics.IncrementGrpcMessagesSent(targetPodAddress) // Assuming targetPodAddress can be used as target_pod_id metric label
				if i > 0 {
					metrics.IncrementGrpcForwardRetrySuccess(targetPodAddress)
				}
				return nil // Success
			}
			finalErr = fmt.Errorf("gRPC PushEvent to %s was not successful via ForwarderAdapter: %s (attempt %d)", targetPodAddress, resp.Message, i)
			fa.logger.Warn(ctx, finalErr.Error())
			// if not successful, but no gRPC error, don't retry unless specifically designed for application-level retries
			break // Do not retry if server responded with success:false
		}

		finalErr = errPush // Store the error for potential return after retry logic
		st, ok := status.FromError(errPush)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) {
			fa.logger.Warn(ctx, "gRPC PushEvent to owner pod failed with retryable error via ForwarderAdapter", "target_pod_address", targetPodAddress, "error", errPush.Error(), "grpc_code", st.Code().String(), "is_pooled_conn", connFromPool, "attempt", i)
			if i == 0 { // Only log retry attempt metric on the first failure leading to a retry
				metrics.IncrementGrpcForwardRetryAttempts(targetPodAddress)
				time.Sleep(200 * time.Millisecond) // Wait before retry
				continue                           // Go to next iteration for retry
			}
		} else {
			fa.logger.Error(ctx, "gRPC PushEvent to owner pod failed with non-retryable error via ForwarderAdapter", "target_pod_address", targetPodAddress, "error", errPush.Error(), "is_pooled_conn", connFromPool, "attempt", i)
			// For non-retryable errors, break immediately.
			break
		}
	}

	// If loop finished, it means all attempts failed or a non-retryable error occurred.
	if finalErr != nil {
		metrics.IncrementGrpcForwardRetryFailure(targetPodAddress)
		if connFromPool && grpcConn != nil { // If the connection came from pool and failed, remove it
			fa.grpcClientPool.Delete(targetPodAddress)
			grpcConn.Close()
			fa.logger.Info(ctx, "Removed and closed failed gRPC connection from pool in ForwarderAdapter", "target_pod_address", targetPodAddress)
		}
		return finalErr
	}

	return nil // Should be covered by success path, but as a fallback
}
