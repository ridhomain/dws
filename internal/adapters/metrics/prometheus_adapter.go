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
)

// IncrementActiveConnections increments the active connections gauge.
func IncrementActiveConnections() {
	ActiveConnectionsGauge.Inc()
}

// DecrementActiveConnections decrements the active connections gauge.
func DecrementActiveConnections() {
	ActiveConnectionsGauge.Dec()
}

// TODO: Add more metrics as per Task 10 (e.g., dws_nats_messages_received_total, dws_websocket_messages_sent_total)
// TODO: Add provider for these metrics if they need to be injected or managed via DI, for now, they are global.
