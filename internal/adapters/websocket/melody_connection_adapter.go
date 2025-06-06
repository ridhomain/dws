package websocket

import (
	"context"
	"encoding/json"

	"github.com/coder/websocket"
	"github.com/olahol/melody"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// MelodyConnectionAdapter adapts a Melody session to implement domain.ManagedConnection
type MelodyConnectionAdapter struct {
	session *melody.Session
	handler *MelodyHandler
}

// Close implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) Close(statusCode websocket.StatusCode, reason string) error {
	// Melody doesn't expose close with status code directly
	// Just close the session
	return m.session.Close()
}

// CloseWithError implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) CloseWithError(errResp domain.ErrorResponse, reason string) error {
	// Try to send error message before closing
	errorMsg := domain.NewErrorMessage(errResp)
	data, _ := json.Marshal(errorMsg)
	m.session.Write(data)

	// Close connection
	return m.session.Close()
}

// WriteJSON implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.session.Write(data)
}

// RemoteAddr implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) RemoteAddr() string {
	if m.session.Request != nil {
		return m.session.Request.RemoteAddr
	}
	return "unknown"
}

// Context implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) Context() context.Context {
	return m.handler.buildContext(m.session)
}

// GetCurrentChatID implements domain.ManagedConnection
func (m *MelodyConnectionAdapter) GetCurrentChatID() string {
	data := m.handler.getSessionData(m.session)
	if data != nil {
		data.mu.Lock()
		defer data.mu.Unlock()
		return data.CurrentChatID
	}
	return ""
}
