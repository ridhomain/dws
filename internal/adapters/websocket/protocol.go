package websocket

import (
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// MessageType defines the type of a WebSocket message in the json.v1 subprotocol.
const (
	MessageTypeReady      = "ready"
	MessageTypeEvent      = "event"
	MessageTypeError      = "error"
	MessageTypeSelectChat = "select_chat"
)

// BaseMessage is a generic structure for all messages in the json.v1 subprotocol.
// The Payload can be any of our specific message structs or the domain.ErrorResponse directly.
type BaseMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}

// EventMessagePayload was initially considered but the architecture specifies the EnrichedEventPayload
// directly as the payload for "event" messages. So, this specific struct might not be needed
// if we directly use the EnrichedEventPayload (as an interface{} or specific type) in BaseMessage.Payload.
// type EventMessagePayload struct {
// 	Data interface{} `json:"data"`
// }

// SelectChatMessagePayload is the payload for a "select_chat" message from the client.
type SelectChatMessagePayload struct {
	ChatID string `json:"chat_id"`
}

// --- Helper functions for creating server-to-client messages --- //

// NewReadyMessage creates a new message of type "ready".
// According to architecture.md, the ready message is just {"type": "ready"}.
func NewReadyMessage() BaseMessage {
	return BaseMessage{
		Type: MessageTypeReady,
		// Payload is omitted as per spec
	}
}

// NewEventMessage creates a new message of type "event".
// eventData is the EnrichedEventPayload.
func NewEventMessage(eventData interface{}) BaseMessage {
	// The architecture.md specifies: {"type": "event", "payload": { /* EnrichedEventPayload from schemas.md */ }}
	// This means the EnrichedEventPayload itself is the value of the "payload" key.
	return BaseMessage{
		Type:    MessageTypeEvent,
		Payload: eventData, // EnrichedEventPayload directly becomes the payload
	}
}

// NewErrorMessage creates a new message of type "error".
// errResp is the domain.ErrorResponse struct.
func NewErrorMessage(errResp domain.ErrorResponse) BaseMessage {
	// The architecture.md specifies: {"type": "error", "payload": {"code": "ErrorCode", "message": "...", "details": "..."}}
	// This matches the structure of domain.ErrorResponse.
	return BaseMessage{
		Type:    MessageTypeError,
		Payload: errResp, // domain.ErrorResponse directly becomes the payload
	}
}

/*
For client-to-server messages like "select_chat":
Example: {"type": "select_chat", "chat_id": "string_chat_id_value"}

The handler (`manageConnection` in handler.go) will need to:
1. Read the raw message bytes using `Connection.ReadMessage()`.
2. Unmarshal the bytes into a `BaseMessage` struct to inspect the `Type` field.
   var baseMsg BaseMessage
   if err := json.Unmarshal(rawMessageBytes, &baseMsg); err != nil {
       // handle unmarshal error, log, possibly close connection
       return
   }

3. Use a switch statement on `baseMsg.Type`:
   switch baseMsg.Type {
   case MessageTypeSelectChat:
       // If the type is "select_chat", the `baseMsg.Payload` will be a map[string]interface{}
       // due to `json.Unmarshal` into an interface{}. We need to convert it to the specific
       // `SelectChatMessagePayload` struct.
       var chatPayload SelectChatMessagePayload
       payloadBytes, err := json.Marshal(baseMsg.Payload) // Convert map back to JSON bytes
       if err != nil {
           // handle marshal error, log, close connection
           return
       }
       if err := json.Unmarshal(payloadBytes, &chatPayload); err != nil {
           // handle unmarshal error for the specific payload, log, close connection
           return
       }
       // Now you can use chatPayload.ChatID
       // h.logger.Info(connCtx, "Received select_chat", "chat_id", chatPayload.ChatID)
       // TODO: Implement logic for handling select_chat (e.g., update NATS subscriptions)

   // case OtherClientMessageType:
       // ... handle other client message types if any ...

   default:
       // h.logger.Warn(connCtx, "Received unknown message type from client", "type", baseMsg.Type)
       // Optionally, send an error message back to the client or close connection.
   }
*/
