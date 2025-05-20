package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ActiveConnectionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "dws_active_connections",
			Help: "Number of active WebSocket connections.",
		},
	)

	ConnectionsTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_connections_total",
			Help: "Total WebSocket connections initiated (successful handshakes).",
		},
	)

	ConnectionDurationHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dws_connection_duration_seconds",
			Help:    "Duration of WebSocket connections.",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 15), // Example buckets: 0.1s to ~9hr (0.1, 0.2, 0.4 ... 2^14*0.1)
		},
	)

	MessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_messages_received_total",
			Help: "Total messages received from clients, partitioned by message type.",
		},
		[]string{"message_type"}, // e.g., "select_chat", "unknown_client_message"
	)

	MessagesSentCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_messages_sent_total",
			Help: "Total messages sent to clients, partitioned by message type.",
		},
		[]string{"message_type"}, // e.g., "ready", "event", "error"
	)

	AuthSuccessTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_auth_success_total",
			Help: "Successful token validations.",
		},
		[]string{"token_type"}, // "company", "admin"
	)

	AuthFailureTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_auth_failure_total",
			Help: "Failed token validations.",
		},
		[]string{"token_type", "reason"}, // token_type: "company", "admin"; reason: e.g., "expired", "invalid_format", "decryption_failed", "config_error"
	)

	SessionConflictsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_conflicts_total",
			Help: "Number of session conflicts detected.",
		},
		[]string{"user_type"}, // "user", "admin"
	)

	NatsMessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_nats_messages_received_total",
			Help: "Messages received from NATS, partitioned by NATS subject.",
		},
		[]string{"nats_subject"},
	)

	GrpcMessagesSentCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_messages_sent_total",
			Help: "Messages forwarded via gRPC, partitioned by target pod ID.",
		},
		[]string{"target_pod_id"},
	)

	GrpcMessagesReceivedCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_messages_received_total",
			Help: "Messages received via gRPC, partitioned by source pod ID.",
		},
		[]string{"source_pod_id"}, // This might require adding source_pod_id to gRPC request
	)

	GrpcForwardRetryAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_attempts_total",
			Help: "Total gRPC message forwarding retry attempts.",
		},
		[]string{"target_pod_id"},
	)
	GrpcForwardRetrySuccessCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_success_total",
			Help: "Total successful gRPC message forwarding retries.",
		},
		[]string{"target_pod_id"},
	)
	GrpcForwardRetryFailureCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_forward_retry_failure_total",
			Help: "Total failed gRPC message forwarding retries.",
		},
		[]string{"target_pod_id"},
	)

	SessionLockAttemptsCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_attempts_total",
			Help: "Total session lock acquisition attempts.",
		},
		[]string{"user_type", "lock_type"}, // lock_type: initial_setnx, retry_setnx, force_set
	)
	SessionLockSuccessCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_success_total",
			Help: "Total successful session lock acquisitions.",
		},
		[]string{"user_type", "lock_type"},
	)
	SessionLockFailureCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_session_lock_failure_total",
			Help: "Total failed session lock acquisitions.",
		},
		[]string{"user_type", "reason"}, // reason: conflict, redis_error, timeout
	)

	// gRPC Client Pool Metrics
	GrpcPoolSizeGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "dws_grpc_pool_size",
			Help: "Total number of connections in the gRPC client pool.",
		},
	)
	GrpcPoolConnectionsCreatedTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connections_created_total",
			Help: "Total new gRPC client connections established by the pool.",
		},
	)
	GrpcPoolConnectionsClosedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connections_closed_total",
			Help: "Total gRPC client connections closed by the pool, partitioned by reason.",
		},
		[]string{"reason"}, // e.g., "idle", "error", "health_fail"
	)
	GrpcPoolConnectionErrorsTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_pool_connection_errors_total",
			Help: "Total errors encountered with pooled gRPC client connections, partitioned by target pod.",
		},
		[]string{"target_pod_id"},
	)
	GrpcCircuitBreakerTrippedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_grpc_circuitbreaker_tripped_total",
			Help: "Total times the circuit breaker has tripped for a target pod.",
		},
		[]string{"target_pod_id"},
	)

	// WebSocket Buffer Metrics
	WebsocketBufferUsedGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dws_websocket_buffer_used_count",
			Help: "Current number of messages in the WebSocket send buffer.",
		},
		[]string{"session_key"}, // Or another relevant label like user_id
	)
	WebsocketBufferCapacityGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dws_websocket_buffer_capacity_count",
			Help: "Capacity of the WebSocket send buffer.",
		},
		[]string{"session_key"},
	)
	WebsocketMessagesDroppedTotalCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_websocket_messages_dropped_total",
			Help: "Total messages dropped due to WebSocket backpressure.",
		},
		[]string{"session_key", "reason"}, // e.g., reason: "buffer_full"
	)
	WebsocketSlowClientsDisconnectedTotalCounter = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dws_websocket_slow_clients_disconnected_total",
			Help: "Total slow WebSocket clients disconnected.",
		},
	)

	// Adaptive TTL Metrics
	RedisTTLCalculatedSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dws_redis_ttl_calculated_seconds",
			Help:    "Distribution of calculated TTL values for Redis keys, partitioned by key type.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16), // 1s to ~9hrs
		},
		[]string{"key_type"},
	)

	RedisTTLDecisionTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dws_redis_ttl_decision_total",
			Help: "Total adaptive TTL decisions made, partitioned by key type and decision outcome.",
		},
		[]string{"key_type", "decision"}, // decision: active, inactive, no_activity_key, error_fetching_activity, disabled, default
	)

	RedisActivityAgeSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dws_redis_activity_age_seconds",
			Help:    "Distribution of the age of the last activity timestamp when making TTL decisions.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16), // 1s to ~9hrs
		},
		[]string{"key_type"},
	)
)

// IncrementActiveConnections increments the active connections gauge.
func IncrementActiveConnections() {
	ActiveConnectionsGauge.Inc()
}

// DecrementActiveConnections decrements the active connections gauge.
func DecrementActiveConnections() {
	ActiveConnectionsGauge.Dec()
}

// IncrementConnectionsTotal increments the total connections counter.
func IncrementConnectionsTotal() {
	ConnectionsTotalCounter.Inc()
}

// ObserveConnectionDuration records the duration of a WebSocket connection.
func ObserveConnectionDuration(durationSeconds float64) {
	ConnectionDurationHistogram.Observe(durationSeconds)
}

// IncrementMessagesReceived increments the counter for messages received from clients.
func IncrementMessagesReceived(messageType string) {
	MessagesReceivedCounter.WithLabelValues(messageType).Inc()
}

// IncrementMessagesSent increments the counter for messages sent to clients.
func IncrementMessagesSent(messageType string) {
	MessagesSentCounter.WithLabelValues(messageType).Inc()
}

// IncrementAuthSuccess increments the successful authentication counter.
func IncrementAuthSuccess(tokenType string) {
	AuthSuccessTotalCounter.WithLabelValues(tokenType).Inc()
}

// IncrementAuthFailure increments the failed authentication counter.
func IncrementAuthFailure(tokenType string, reason string) {
	AuthFailureTotalCounter.WithLabelValues(tokenType, reason).Inc()
}

// IncrementSessionConflicts increments the session conflict counter.
func IncrementSessionConflicts(userType string) {
	SessionConflictsTotalCounter.WithLabelValues(userType).Inc()
}

// IncrementNatsMessagesReceived increments the counter for messages received from NATS.
func IncrementNatsMessagesReceived(natsSubject string) {
	NatsMessagesReceivedCounter.WithLabelValues(natsSubject).Inc()
}

// IncrementGrpcMessagesSent increments the counter for messages sent via gRPC.
func IncrementGrpcMessagesSent(targetPodID string) {
	GrpcMessagesSentCounter.WithLabelValues(targetPodID).Inc()
}

// IncrementGrpcMessagesReceived increments the counter for messages received via gRPC.
func IncrementGrpcMessagesReceived(sourcePodID string) {
	GrpcMessagesReceivedCounter.WithLabelValues(sourcePodID).Inc()
}

func IncrementGrpcForwardRetryAttempts(targetPodID string) {
	GrpcForwardRetryAttemptsCounter.WithLabelValues(targetPodID).Inc()
}

func IncrementGrpcForwardRetrySuccess(targetPodID string) {
	GrpcForwardRetrySuccessCounter.WithLabelValues(targetPodID).Inc()
}

func IncrementGrpcForwardRetryFailure(targetPodID string) {
	GrpcForwardRetryFailureCounter.WithLabelValues(targetPodID).Inc()
}

func IncrementSessionLockAttempts(userType, lockType string) {
	SessionLockAttemptsCounter.WithLabelValues(userType, lockType).Inc()
}

func IncrementSessionLockSuccess(userType, lockType string) {
	SessionLockSuccessCounter.WithLabelValues(userType, lockType).Inc()
}

func IncrementSessionLockFailure(userType, reason string) {
	SessionLockFailureCounter.WithLabelValues(userType, reason).Inc()
}

// Helper functions for gRPC Client Pool Metrics
func SetGrpcPoolSize(size float64) {
	GrpcPoolSizeGauge.Set(size)
}

func IncrementGrpcPoolConnectionsCreated() {
	GrpcPoolConnectionsCreatedTotalCounter.Inc()
}

func IncrementGrpcPoolConnectionsClosed(reason string) {
	GrpcPoolConnectionsClosedTotalCounter.WithLabelValues(reason).Inc()
}

func IncrementGrpcPoolConnectionErrors(targetPodID string) {
	GrpcPoolConnectionErrorsTotalCounter.WithLabelValues(targetPodID).Inc()
}

func IncrementGrpcCircuitBreakerTripped(targetPodID string) {
	GrpcCircuitBreakerTrippedTotalCounter.WithLabelValues(targetPodID).Inc()
}

// Helper functions for WebSocket Buffer Metrics
func SetWebsocketBufferUsed(sessionKey string, count float64) {
	WebsocketBufferUsedGauge.WithLabelValues(sessionKey).Set(count)
}

func SetWebsocketBufferCapacity(sessionKey string, capacity float64) {
	WebsocketBufferCapacityGauge.WithLabelValues(sessionKey).Set(capacity)
}

func IncrementWebsocketMessagesDropped(sessionKey, reason string) {
	WebsocketMessagesDroppedTotalCounter.WithLabelValues(sessionKey, reason).Inc()
}

func IncrementWebsocketSlowClientsDisconnected() {
	WebsocketSlowClientsDisconnectedTotalCounter.Inc()
}

func ObserveRedisTTLCalculated(keyType string, ttlSeconds float64) {
	RedisTTLCalculatedSeconds.WithLabelValues(keyType).Observe(ttlSeconds)
}

func IncrementRedisTTLDecision(keyType string, decision string) {
	RedisTTLDecisionTotal.WithLabelValues(keyType, decision).Inc()
}

func ObserveRedisActivityAge(keyType string, ageSeconds float64) {
	RedisActivityAgeSeconds.WithLabelValues(keyType).Observe(ageSeconds)
}
