package domain

import (
	// "time" // No longer needed here if EventTime is string throughout

	"github.com/coder/websocket"
)

// MessageType defines the type of a WebSocket message in the json.v1 subprotocol.
const (
	MessageTypeReady      = "ready"
	MessageTypeEvent      = "event"
	MessageTypeError      = "error"
	MessageTypeSelectChat = "select_chat"

	StatusGoingAway websocket.StatusCode = 1001 // Standard code for server going away
)

// BaseMessage is a generic structure for all messages in the json.v1 subprotocol.
// The Payload can be any of our specific message structs or the domain.ErrorResponse directly.
type BaseMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}

// SelectChatMessagePayload is the payload for a "select_chat" message from the client.
type SelectChatMessagePayload struct {
	ChatID string `json:"chat_id"`
}

// NewReadyMessage creates a new message of type "ready".
func NewReadyMessage() BaseMessage {
	return BaseMessage{
		Type: MessageTypeReady,
	}
}

// NewEventMessage creates a new message of type "event".
// It expects eventData to be the domain.EnrichedEventPayload (or any other desired payload struct for events).
func NewEventMessage(eventData interface{}) BaseMessage {
	return BaseMessage{
		Type:    MessageTypeEvent,
		Payload: eventData, // eventData (domain.EnrichedEventPayload) is passed directly
	}
}

// NewErrorMessage creates a new message of type "error".
func NewErrorMessage(errResp ErrorResponse) BaseMessage {
	return BaseMessage{
		Type:    MessageTypeError,
		Payload: errResp,
	}
}
