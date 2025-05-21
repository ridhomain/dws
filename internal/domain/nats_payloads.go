package domain

// EnrichedEventPayload is the structure for messages received from NATS,
// reflecting the schema defined in upstream-schemas.md.
type EnrichedEventPayload struct {
	EventID   string      `json:"event_id"`
	EventTime string      `json:"event_time"`
	CompanyID string      `json:"company_id"`
	AgentID   string      `json:"agent_id,omitempty"`   // omitempty because it's not always present for all event types
	MessageID string      `json:"message_id,omitempty"` // omitempty as it's specific to 'messages' table
	ChatID    string      `json:"chat_id,omitempty"`    // omitempty as it's relevant for 'messages' and 'chats'
	RowData   interface{} `json:"row_data"`             // Contains the actual table row data
}
