// internal/domain/nats_payloads.go - Updated to match CDC-Consumer API

package domain

import "time"

// EventType represents specific types of events from CDC
type EventType string

const (
	// Contact Events (only update)
	EventContactUpdate EventType = "contact.update"

	// Chat Events (only insert and update)
	EventChatCreate EventType = "chat.create"
	EventChatUpdate EventType = "chat.update"

	// Message Events (only insert and update)
	EventMessageCreate EventType = "message.create"
	EventMessageUpdate EventType = "message.update"

	// Agent Events (all actions)
	EventAgentCreate EventType = "agent.create"
	EventAgentUpdate EventType = "agent.update"
	EventAgentDelete EventType = "agent.delete"
)

// EnrichedEventPayload updated to match CDC-Consumer API structure
type EnrichedEventPayload struct {
	EventID   string    `json:"event_id"`   // Unique identifier
	EventType EventType `json:"event_type"` // Specific event type (e.g., "message.create")
	EventTime string    `json:"event_time"` // RFC3339 timestamp

	// Routing information
	CompanyID string `json:"company_id"`
	AgentID   string `json:"agent_id"`

	// Entity-specific identifiers (only populated when relevant)
	ChatID    string `json:"chat_id,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	ContactID string `json:"contact_id,omitempty"`

	// Essential data fields only (replaces the old RowData interface{})
	Data EventData `json:"data"`

	// For updates, include what changed
	Changes map[string]interface{} `json:"changes,omitempty"`
}

// EventData contains only essential fields based on event type
type EventData struct {
	// Contact fields
	PhoneNumber string `json:"phone_number,omitempty"`
	CustomName  string `json:"custom_name,omitempty"`
	AssignedTo  string `json:"assigned_to,omitempty"`
	Origin      string `json:"origin,omitempty"`
	Tags        string `json:"tags,omitempty"`

	// Chat fields
	PushName              string      `json:"push_name,omitempty"`
	IsGroup               bool        `json:"is_group,omitempty"`
	UnreadCount           int32       `json:"unread_count,omitempty"`
	ConversationTimestamp int64       `json:"conversation_timestamp,omitempty"`
	Jid                   string      `json:"jid,omitempty"`
	GroupName             string      `json:"group_name,omitempty"`
	LastMessageObj        interface{} `json:"last_message,omitempty"`

	// Message fields
	FromPhone        string      `json:"from_phone,omitempty"`
	ToPhone          string      `json:"to_phone,omitempty"`
	MessageText      string      `json:"message_text,omitempty"`
	MessageUrl       string      `json:"message_url,omitempty"`
	MessageType      string      `json:"message_type,omitempty"`
	MessageObj       interface{} `json:"message_obj,omitempty"`
	EditedMessageObj interface{} `json:"edited_message_obj,omitempty"`
	Status           string      `json:"status,omitempty"`
	Flow             string      `json:"flow,omitempty"`
	MessageTimestamp int64       `json:"message_timestamp,omitempty"`
	IsDeleted        bool        `json:"is_deleted,omitempty"`
	Key              interface{} `json:"key,omitempty"`

	// Agent fields
	AgentName string `json:"agent_name,omitempty"`
	HostName  string `json:"host_name,omitempty"`
	Version   string `json:"version,omitempty"`
	QRCode    string `json:"qr_code,omitempty"`

	// General
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}
