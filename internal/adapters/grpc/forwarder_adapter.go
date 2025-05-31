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
	"gitlab.com/timkado/api/daisi-ws-service/pkg/safego"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultGRPCPoolIdleTimeout             = 300 * time.Second // 5 minutes
	defaultGRPCPoolHealthCheckInterval     = 60 * time.Second  // 1 minute
	defaultGRPCCircuitBreakerFailThreshold = 5
	defaultGRPCCircuitBreakerOpenDuration  = 30 * time.Second
)

type pooledConnection struct {
	conn         *grpc.ClientConn
	lastUsedTime time.Time
	mu           sync.Mutex // Protects conn if it needs to be replaced
}

type circuitBreakerState struct {
	failures    int
	lastFailure time.Time
	openUntil   time.Time
	targetPodID string
}

// ForwarderAdapter manages gRPC client connections and event forwarding.
type ForwarderAdapter struct {
	logger              domain.Logger
	configProvider      config.Provider
	grpcClientPool      *sync.Map // Stores map[string]*pooledConnection
	circuitBreakers     *sync.Map // Stores map[string]*circuitBreakerState
	appCtx              context.Context
	appCancel           context.CancelFunc
	idleTimeout         time.Duration
	healthCheckInterval time.Duration
	failThreshold       int
	openDuration        time.Duration
}

// NewForwarderAdapter creates a new ForwarderAdapter.
func NewForwarderAdapter(appCtx context.Context, logger domain.Logger, configProvider config.Provider) *ForwarderAdapter {
	appCfg := configProvider.Get().App

	idleTimeout := defaultGRPCPoolIdleTimeout
	if appCfg.GrpcPoolIdleTimeoutSeconds > 0 {
		idleTimeout = time.Duration(appCfg.GrpcPoolIdleTimeoutSeconds) * time.Second
	}

	healthCheckInterval := defaultGRPCPoolHealthCheckInterval
	if appCfg.GrpcPoolHealthCheckIntervalSeconds > 0 {
		healthCheckInterval = time.Duration(appCfg.GrpcPoolHealthCheckIntervalSeconds) * time.Second
	}

	failThreshold := defaultGRPCCircuitBreakerFailThreshold
	if appCfg.GrpcCircuitBreakerFailThreshold > 0 {
		failThreshold = appCfg.GrpcCircuitBreakerFailThreshold
	}

	openDuration := defaultGRPCCircuitBreakerOpenDuration
	if appCfg.GrpcCircuitBreakerOpenDurationSeconds > 0 {
		openDuration = time.Duration(appCfg.GrpcCircuitBreakerOpenDurationSeconds) * time.Second
	}

	adapterCtx, adapterCancel := context.WithCancel(appCtx)

	fa := &ForwarderAdapter{
		logger:              logger,
		configProvider:      configProvider,
		grpcClientPool:      &sync.Map{},
		circuitBreakers:     &sync.Map{},
		appCtx:              adapterCtx,
		appCancel:           adapterCancel,
		idleTimeout:         idleTimeout,
		healthCheckInterval: healthCheckInterval,
		failThreshold:       failThreshold,
		openDuration:        openDuration,
	}

	fa.startCleanupRoutine()
	return fa
}

func (fa *ForwarderAdapter) getCircuitBreaker(targetPodID string) *circuitBreakerState {
	cbVal, _ := fa.circuitBreakers.LoadOrStore(targetPodID, &circuitBreakerState{targetPodID: targetPodID})
	return cbVal.(*circuitBreakerState)
}

func (fa *ForwarderAdapter) isCircuitOpen(targetPodID string) bool {
	cb := fa.getCircuitBreaker(targetPodID)
	if cb.openUntil.IsZero() || time.Now().After(cb.openUntil) {
		return false // Circuit is closed or reset
	}
	return true // Circuit is open
}

func (fa *ForwarderAdapter) recordFailure(targetPodID string) {
	cb := fa.getCircuitBreaker(targetPodID)
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= fa.failThreshold {
		cb.openUntil = time.Now().Add(fa.openDuration)
		fa.logger.Warn(fa.appCtx, "Circuit breaker tripped for target pod", "target_pod_id", targetPodID, "open_until", cb.openUntil)
		metrics.IncrementGrpcCircuitBreakerTripped(targetPodID)
		// When circuit opens, we might want to proactively close the connection to this pod
		if connVal, okPool := fa.grpcClientPool.Load(targetPodID); okPool {
			pc := connVal.(*pooledConnection)
			pc.mu.Lock()
			if pc.conn != nil {
				pc.conn.Close()
				pc.conn = nil
				metrics.IncrementGrpcPoolConnectionsClosed("circuit_trip")
				fa.logger.Info(fa.appCtx, "Closed gRPC connection due to circuit breaker trip", "target_pod_id", targetPodID)
			}
			pc.mu.Unlock()
			fa.grpcClientPool.Delete(targetPodID) // Remove from pool
		}
	}
}

func (fa *ForwarderAdapter) recordSuccess(targetPodID string) {
	cb := fa.getCircuitBreaker(targetPodID)
	cb.failures = 0
	cb.openUntil = time.Time{} // Reset openUntil, effectively closing the circuit if it was open
}

func (fa *ForwarderAdapter) getConnection(ctx context.Context, targetPodAddress string) (*grpc.ClientConn, error) {
	if fa.isCircuitOpen(targetPodAddress) {
		fa.logger.Warn(ctx, "Circuit breaker is open for target, refusing connection attempt", "target_pod_address", targetPodAddress)
		return nil, fmt.Errorf("circuit breaker open for %s", targetPodAddress)
	}

	connVal, okPool := fa.grpcClientPool.Load(targetPodAddress)
	if okPool {
		pc := connVal.(*pooledConnection)
		pc.mu.Lock()
		defer pc.mu.Unlock()

		if pc.conn != nil {
			state := pc.conn.GetState()
			if state == connectivity.Ready || state == connectivity.Idle {
				pc.lastUsedTime = time.Now()
				fa.logger.Debug(ctx, "Reusing healthy gRPC connection from pool", "target_address", targetPodAddress, "state", state.String())
				return pc.conn, nil
			}
			// Connection is not healthy, close and remove it
			fa.logger.Warn(ctx, "Pooled gRPC connection is not healthy, closing and removing", "target_address", targetPodAddress, "state", state.String())
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("health_fail")
		}
	}

	// No valid connection in pool or it was unhealthy, create a new one
	fa.logger.Info(ctx, "Creating new gRPC client connection", "target_address", targetPodAddress)
	connOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	newlyCreatedConn, errClient := grpc.NewClient(targetPodAddress, connOpts...)
	if errClient != nil {
		fa.logger.Error(ctx, "Failed to establish new gRPC connection", "target_pod_address", targetPodAddress, "error", errClient.Error())
		metrics.IncrementGrpcPoolConnectionErrors(targetPodAddress)
		fa.recordFailure(targetPodAddress)
		return nil, errClient
	}

	pc := &pooledConnection{
		conn:         newlyCreatedConn,
		lastUsedTime: time.Now(),
	}
	fa.grpcClientPool.Store(targetPodAddress, pc)
	metrics.IncrementGrpcPoolConnectionsCreated()
	metrics.SetGrpcPoolSize(float64(getSyncMapLength(fa.grpcClientPool)))
	return newlyCreatedConn, nil
}

// ForwardEvent forwards an event to a target pod via gRPC.
func (fa *ForwarderAdapter) ForwardEvent(ctx context.Context, targetPodAddress string, event *domain.EnrichedEventPayload, targetCompanyID, targetAgentID, targetChatID, sourcePodID string) error {
	fa.logger.Info(ctx, "Attempting to forward message via gRPC", "target_address", targetPodAddress, "event_id", event.EventID)

	grpcConn, errClient := fa.getConnection(ctx, targetPodAddress)
	if errClient != nil {
		return fmt.Errorf("failed to get gRPC connection for %s: %w", targetPodAddress, errClient)
	}

	client := pb.NewMessageForwardingServiceClient(grpcConn)

	// Convert event.RowData to map[string]interface{} for structpb.NewStruct
	var rowDataMap map[string]interface{}
	if event.RowData != nil {
		var ok bool
		rowDataMap, ok = event.RowData.(map[string]interface{})
		if !ok {
			fa.logger.Error(ctx, "event.RowData is not a map[string]interface{}", "event_id", event.EventID, "type", fmt.Sprintf("%T", event.RowData))
			return fmt.Errorf("event.RowData is not a map[string]interface{}: %T", event.RowData)
		}
	}

	protoRowData, errProtoStruct := structpb.NewStruct(rowDataMap)
	if errProtoStruct != nil {
		fa.logger.Error(ctx, "Failed to convert event.RowData to proto.Struct for gRPC", "error", errProtoStruct.Error(), "event_id", event.EventID)
		return errProtoStruct
	}

	grpcRequest := &pb.PushEventRequest{
		Payload: &pb.EnrichedEventPayloadMessage{
			EventId:   event.EventID,
			CompanyId: event.CompanyID,
			AgentId:   event.AgentID,
			MessageId: event.MessageID,
			ChatId:    event.ChatID,
			RowData:   protoRowData,
			EventTime: event.EventTime, // Assuming event.EventTime is now string
			EventType: event.EventType,
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
				fa.logger.Info(ctx, "Successfully forwarded message via gRPC", "target_pod_address", targetPodAddress, "event_id", event.EventID, "attempt", i)
				metrics.IncrementGrpcMessagesSent(targetPodAddress)
				fa.recordSuccess(targetPodAddress)
				if i > 0 {
					metrics.IncrementGrpcForwardRetrySuccess(targetPodAddress)
				}
				// Update last used time on successful use
				if connVal, okPool := fa.grpcClientPool.Load(targetPodAddress); okPool {
					connVal.(*pooledConnection).lastUsedTime = time.Now()
				}
				return nil
			}
			finalErr = fmt.Errorf("gRPC PushEvent to %s was not successful: %s (attempt %d)", targetPodAddress, resp.Message, i)
			fa.logger.Warn(ctx, finalErr.Error())
			break // Non-retryable application error from target
		}

		finalErr = errPush
		metrics.IncrementGrpcPoolConnectionErrors(targetPodAddress)
		fa.recordFailure(targetPodAddress)

		st, ok := status.FromError(errPush)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) {
			fa.logger.Warn(ctx, "gRPC PushEvent to owner pod failed with retryable error", "target_pod_address", targetPodAddress, "error", errPush.Error(), "grpc_code", st.Code().String(), "attempt", i)
			if i == 0 {
				metrics.IncrementGrpcForwardRetryAttempts(targetPodAddress)
				time.Sleep(200 * time.Millisecond)
				// Get a potentially new connection for retry, as the old one might be bad
				grpcConn, errClient = fa.getConnection(ctx, targetPodAddress)
				if errClient != nil {
					return fmt.Errorf("failed to get gRPC connection for retry to %s: %w", targetPodAddress, errClient)
				}
				client = pb.NewMessageForwardingServiceClient(grpcConn) // Re-assign client with new conn
				continue
			}
		} else {
			fa.logger.Error(ctx, "gRPC PushEvent to owner pod failed with non-retryable error", "target_pod_address", targetPodAddress, "error", errPush.Error(), "attempt", i)
			break // Non-retryable gRPC error
		}
	}

	if finalErr != nil {
		metrics.IncrementGrpcForwardRetryFailure(targetPodAddress)
		return finalErr
	}
	return nil // Should be unreachable if loop completes due to success or break
}

func (fa *ForwarderAdapter) startCleanupRoutine() {
	ticker := time.NewTicker(fa.healthCheckInterval) // Use healthCheckInterval for periodic cleanup scan

	safego.Execute(fa.appCtx, fa.logger, "GRPCPoolCleanupRoutine", func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fa.cleanupIdleConnections()
			case <-fa.appCtx.Done():
				fa.logger.Info(fa.appCtx, "gRPC pool cleanup routine stopping.")
				fa.closeAllConnections()
				return
			}
		}
	})
}

func (fa *ForwarderAdapter) cleanupIdleConnections() {
	now := time.Now()
	cleanedCount := 0
	fa.grpcClientPool.Range(func(key, value interface{}) bool {
		targetPodAddress := key.(string)
		pc := value.(*pooledConnection)

		pc.mu.Lock()
		if pc.conn != nil && now.Sub(pc.lastUsedTime) > fa.idleTimeout {
			fa.logger.Info(fa.appCtx, "Closing idle gRPC connection", "target_address", targetPodAddress, "idle_duration_seconds", now.Sub(pc.lastUsedTime).Seconds())
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("idle")
			cleanedCount++
			fa.grpcClientPool.Delete(targetPodAddress) // Remove after closing
		}
		pc.mu.Unlock()
		return true
	})
	if cleanedCount > 0 {
		fa.logger.Info(fa.appCtx, "Cleaned up idle gRPC connections", "count", cleanedCount)
	}
	metrics.SetGrpcPoolSize(float64(getSyncMapLength(fa.grpcClientPool)))
}

func (fa *ForwarderAdapter) closeAllConnections() {
	fa.logger.Info(fa.appCtx, "Closing all gRPC client connections in pool...")
	closedCount := 0
	fa.grpcClientPool.Range(func(key, value interface{}) bool {
		targetPodAddress := key.(string)
		pc := value.(*pooledConnection)
		pc.mu.Lock()
		if pc.conn != nil {
			pc.conn.Close()
			pc.conn = nil
			metrics.IncrementGrpcPoolConnectionsClosed("shutdown")
			closedCount++
		}
		pc.mu.Unlock()
		fa.grpcClientPool.Delete(targetPodAddress)
		return true
	})
	fa.logger.Info(fa.appCtx, "All gRPC client connections closed.", "count", closedCount)
	metrics.SetGrpcPoolSize(0)
}

// Helper to get length of sync.Map, useful for metrics
func getSyncMapLength(m *sync.Map) int {
	length := 0
	m.Range(func(_, _ interface{}) bool {
		length++
		return true
	})
	return length
}

// Stop gracefully stops the ForwarderAdapter, cleaning up resources.
func (fa *ForwarderAdapter) Stop() {
	fa.logger.Info(fa.appCtx, "Stopping ForwarderAdapter...")
	fa.appCancel() // Signal cleanup routines to stop
	// Add wg.Wait() if cleanup routines are long-running and need to finish before Stop returns
}
