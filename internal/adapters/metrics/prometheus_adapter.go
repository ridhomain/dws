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
