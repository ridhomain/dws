package domain

import "time"

// EnrichedEventPayload is a placeholder for the actual structure defined in
// daisi-cdc-consumer-service/cdc-service-docs/schemas.md.
// Please replace this with the actual struct definition.
type EnrichedEventPayload struct {
	EventID   string      `json:"event_id"`
	EventType string      `json:"event_type"`
	Timestamp time.Time   `json:"timestamp"`
	Source    string      `json:"source"`
	Data      interface{} `json:"data"` // This will likely be more specific
}
