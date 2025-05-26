# Daisi WebSocket Service: Schema and Frontend Integration Guide

## 1. System Overview

Daisi WebSocket Service is a real-time communication platform that facilitates:
- WebSocket connections for agents and administrators
- Event streaming through NATS JetStream messaging system
- Authentication and session management with single-tab enforcement
- Real-time message forwarding between agents and administrators
- Dynamic route registry for efficient message routing across pods

## 2. Data Schema

### Core Models

#### Authentication Models

```typescript
interface AuthenticatedUserContext {
  userID: string;
  companyID: string;
  agentID: string;
  expiresAt: Date;
}

interface AdminUserContext {
  adminID: string;
  expiresAt: Date;
}
```

#### Message Models

```typescript
interface EnrichedEventPayload {
  event_id: string;
  event_time: string;
  company_id: string;
  agent_id?: string;     // Optional: not present for all event types
  message_id?: string;   // Optional: specific to 'messages' table
  chat_id?: string;      // Optional: relevant for 'messages' and 'chats'
  row_data: any;         // Contains the actual table row data
}

interface BaseMessage {
  type: "ready" | "event" | "error" | "select_chat";
  payload?: any;
}

interface SelectChatMessagePayload {
  chat_id: string;
}

interface ErrorResponse {
  code: string;        // Machine-readable error code
  message: string;     // Human-readable error description
  details?: string;    // Optional additional context
}
```

## 3. API Endpoints

### HTTP Endpoints

| Endpoint | Method | Description | Authorization |
|----------|--------|-------------|--------------|
| `/health` | GET | Health check endpoint | None |
| `/ready` | GET | Readiness check endpoint | None |
| `/metrics` | GET | Prometheus metrics endpoint | None |
| `/generate-token` | POST | Generate user token | General API Key |
| `/admin/generate-token` | POST | Generate admin token | Admin API Key |

### WebSocket Endpoints

| Endpoint | Description | Authorization | Parameters |
|----------|-------------|---------------|------------|
| `/ws/{companyId}/{agentId}` | User WebSocket connection | API Key + User Token | `token` (query param), `x-api-key` (header or query param) |
| `/ws/admin` | Admin WebSocket connection | API Key + Admin Token | `token` (query param), `x-api-key` (header or query param) |

## 4. Authentication System

The service implements a dual authentication system with separate API keys for different purposes:

- **General API Key (`secret_token`)**: Used for generating user tokens and general WebSocket connections
- **Admin API Key (`admin_secret_token`)**: Used exclusively for generating admin tokens and administrative operations

This separation ensures better security isolation between user and admin operations.

## 5. Authentication Flow

1. **User Authentication**:
   ```javascript
   // Request a user token (using general API key)
   const response = await fetch('https://api.example.com/generate-token', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'X-API-Key': 'YOUR_GENERAL_API_KEY'
     },
     body: JSON.stringify({
       user_id: 'user123',
       company_id: 'company456',
       agent_id: 'agent789',
       expires_in_seconds: 3600 // Optional
     })
   });
   
   const data = await response.json();
   const token = data.token;
   ```

2. **Admin Authentication**:
   ```javascript
   // Request an admin token (using admin API key)
   const response = await fetch('https://api.example.com/admin/generate-token', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'X-API-Key': 'YOUR_ADMIN_API_KEY'
     },
     body: JSON.stringify({
       admin_user_id: 'admin123',
       expires_in_seconds: 1200 // Optional
     })
   });
   
   const data = await response.json();
   const adminToken = data.token;
   ```

## 6. WebSocket Communication Protocol

### Connection Establishment

**User Connection**:
```javascript
const companyId = 'company456';
const agentId = 'agent789';
const socket = new WebSocket(`wss://api.example.com/ws/${companyId}/${agentId}?token=${token}`);
```

**Admin Connection**:
```javascript
const socket = new WebSocket(`wss://api.example.com/ws/admin?token=${adminToken}`);
```

### Sub-protocol Details

The service uses the `json.v1` sub-protocol, indicating that all non-control frames exchanged over WebSocket contain UTF-8 encoded JSON payloads.

### Ping/Pong Heartbeat

The server sends ping frames every 20 seconds. Clients must respond with pong frames to maintain the connection. If a client fails to respond to 2 consecutive pings (~40-60 seconds), the connection will be closed.

### Message Types

1. **Ready Message**:
   - Sent by the server to indicate the connection is ready
   ```json
   {
     "type": "ready"
   }
   ```

2. **Event Message**:
   - Sent by the server to deliver event data
   ```json
   {
     "type": "event",
     "payload": {
       "event_id": "evt_123456",
       "event_time": "2025-05-24T15:30:45Z",
       "company_id": "company456",
       "agent_id": "agent789",
       "chat_id": "chat123",
       "row_data": {
         // Dynamic content based on the event type
       }
     }
   }
   ```

3. **Error Message**:
   - Sent by the server when an error occurs
   ```json
   {
     "type": "error",
     "payload": {
       "code": "InvalidAPIKey",
       "message": "The provided API key is invalid",
       "details": "Please check your credentials"
     }
   }
   ```

4. **Select Chat Message**:
   - Sent by the client to subscribe to a specific chat's messages
   ```json
   {
     "type": "select_chat",
     "payload": {
       "chat_id": "chat123"
     }
   }
   ```

### Session Management

The service enforces single-tab sessions, meaning only one active WebSocket connection is allowed per `(company, agent, user)` combination or per admin user. If a user attempts to connect from a different tab or device while an active session exists:

1. The new connection will be established
2. The old connection will receive a close frame with code 4402 and reason "session-replaced"
3. The old session will be terminated

### Error Codes

| Error Code | Description | HTTP Status | WebSocket Close Code |
|------------|-------------|------------|---------------------|
| `InvalidAPIKey` | Missing or invalid API key | 401 | 4401 |
| `InvalidToken` | Invalid token | 403 | 4403 |
| `SessionConflict` | Session conflict (already connected elsewhere) | 409 | 4402 |
| `SubscriptionFailure` | Failed to subscribe to message stream | 500 | 1011 |
| `RateLimitExceeded` | Rate limit exceeded | 429 | 4429 |
| `BadRequest` | Bad request format | 400 | 4400 |
| `InternalServerError` | Internal server error | 500 | 1011 |

## 7. Frontend Integration Guide

### Setting Up the Connection

```javascript
class DaisiWebSocketClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
    this.socket = null;
    this.token = null;
    this.eventHandlers = {};
    this.pingInterval = null;
    this.reconnectAttempts = 0;
  }

  async authenticateUser(userId, companyId, agentId) {
    try {
      const response = await fetch(`${this.baseUrl}/generate-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey
        },
        body: JSON.stringify({
          user_id: userId,
          company_id: companyId,
          agent_id: agentId
        })
      });
      
      if (!response.ok) {
        throw new Error(`Authentication failed: ${response.status}`);
      }
      
      const data = await response.json();
      this.token = data.token;
      return this.token;
    } catch (error) {
      console.error('Authentication error:', error);
      throw error;
    }
  }

  async authenticateAdmin(adminId) {
    try {
      const response = await fetch(`${this.baseUrl}/admin/generate-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey
        },
        body: JSON.stringify({
          admin_user_id: adminId
        })
      });
      
      if (!response.ok) {
        throw new Error(`Admin authentication failed: ${response.status}`);
      }
      
      const data = await response.json();
      this.token = data.token;
      return this.token;
    } catch (error) {
      console.error('Admin authentication error:', error);
      throw error;
    }
  }

  connect(isAdmin = false, companyId = null, agentId = null) {
    if (!this.token) {
      throw new Error('Token not available. Please authenticate first.');
    }
    
    let url;
    if (isAdmin) {
      url = `${this.baseUrl.replace('http', 'ws')}/ws/admin?token=${this.token}`;
    } else {
      if (!companyId || !agentId) {
        throw new Error('Company ID and Agent ID are required for user connections.');
      }
      url = `${this.baseUrl.replace('http', 'ws')}/ws/${companyId}/${agentId}?token=${this.token}`;
    }
    
    // Set protocol to json.v1 as required by the server
    this.socket = new WebSocket(url, ['json.v1']);
    
    this.socket.onopen = () => {
      console.log('WebSocket connection established');
      this.reconnectAttempts = 0;
      if (this.eventHandlers['open']) {
        this.eventHandlers['open']();
      }
    };
    
    this.socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (this.eventHandlers[message.type]) {
          this.eventHandlers[message.type](message.payload);
        }
        if (this.eventHandlers['message']) {
          this.eventHandlers['message'](message);
        }
      } catch (error) {
        console.error('Error processing message:', error);
      }
    };
    
    this.socket.onclose = (event) => {
      console.log('WebSocket connection closed:', event.code, event.reason);
      
      // Handle session conflict (code 4402)
      if (event.code === 4402) {
        console.warn('Session replaced by another connection');
        // Optionally inform the user their session was taken over
        if (this.eventHandlers['session-conflict']) {
          this.eventHandlers['session-conflict'](event);
        }
      }
      
      if (this.eventHandlers['close']) {
        this.eventHandlers['close'](event);
      }
      
      // Clear ping interval if it exists
      if (this.pingInterval) {
        clearInterval(this.pingInterval);
        this.pingInterval = null;
      }
    };
    
    this.socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (this.eventHandlers['error']) {
        this.eventHandlers['error'](error);
      }
    };
    
    return this.socket;
  }

  on(eventType, callback) {
    this.eventHandlers[eventType] = callback;
  }

  selectChat(chatId) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }
    
    this.socket.send(JSON.stringify({
      type: 'select_chat',
      payload: { chat_id: chatId }
    }));
  }

  disconnect() {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
  
  // Helper method to implement reconnection with exponential backoff
  reconnect(isAdmin = false, companyId = null, agentId = null) {
    const maxReconnectAttempts = 10;
    const baseDelay = 1000; // Start with 1 second
    
    if (this.reconnectAttempts >= maxReconnectAttempts) {
      console.error('Maximum reconnection attempts reached');
      if (this.eventHandlers['reconnect-failed']) {
        this.eventHandlers['reconnect-failed']();
      }
      return;
    }
    
    const delay = baseDelay * Math.pow(2, this.reconnectAttempts);
    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts + 1}/${maxReconnectAttempts})`);
    
    setTimeout(() => {
      this.reconnectAttempts++;
      this.connect(isAdmin, companyId, agentId);
    }, delay);
  }
}
```

### Using the Client in a React Application

```jsx
import React, { useState, useEffect } from 'react';
import { DaisiWebSocketClient } from './daisi-client';

// Initialize the client
const daisiClient = new DaisiWebSocketClient(
  'https://api.example.com',
  'YOUR_API_KEY'
);

function ChatComponent() {
  const [messages, setMessages] = useState([]);
  const [selectedChat, setSelectedChat] = useState(null);
  const [connected, setConnected] = useState(false);
  
  useEffect(() => {
    // Authenticate and connect when component mounts
    async function connectToWebSocket() {
      try {
        await daisiClient.authenticateUser(
          'user123',
          'company456',
          'agent789'
        );
        
        daisiClient.on('open', () => {
          setConnected(true);
        });
        
        daisiClient.on('ready', () => {
          console.log('Connection is ready to receive messages');
          // When we receive "ready", the connection is fully established
        });
        
        daisiClient.on('event', (payload) => {
          setMessages(prevMessages => [...prevMessages, payload]);
        });
        
        daisiClient.on('error', (error) => {
          console.error('WebSocket error:', error);
        });
        
        daisiClient.on('close', (event) => {
          setConnected(false);
          if (event.code !== 1000) { // Normal closure
            console.log('Connection closed unexpectedly:', event.reason);
            // Consider reconnect logic here
          }
        });
        
        daisiClient.on('session-conflict', () => {
          // Handle session conflict (e.g., show a message to the user)
          alert("Your account has been connected from another location.");
        });
        
        daisiClient.connect(false, 'company456', 'agent789');
      } catch (error) {
        console.error('Connection error:', error);
      }
    }
    
    connectToWebSocket();
    
    return () => {
      // Disconnect when component unmounts
      daisiClient.disconnect();
    };
  }, []);
  
  // Handle chat selection
  useEffect(() => {
    if (connected && selectedChat) {
      daisiClient.selectChat(selectedChat);
    }
  }, [selectedChat, connected]);
  
  return (
    <div className="chat-container">
      <div className="chat-sidebar">
        <h3>Chat Sessions</h3>
        <ul>
          <li onClick={() => setSelectedChat('chat123')}>Chat 1</li>
          <li onClick={() => setSelectedChat('chat456')}>Chat 2</li>
        </ul>
      </div>
      <div className="chat-messages">
        <h3>Messages {selectedChat ? `(${selectedChat})` : ''}</h3>
        {messages.map((msg, index) => (
          <div key={index} className="message">
            <div className="message-header">
              <span>Event ID: {msg.event_id}</span>
              <span>Time: {new Date(msg.event_time).toLocaleString()}</span>
            </div>
            <div className="message-body">
              <pre>{JSON.stringify(msg.row_data, null, 2)}</pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

### Admin Client Example

```jsx
import React, { useState, useEffect } from 'react';
import { DaisiWebSocketClient } from './daisi-client';

// Initialize the client
const adminClient = new DaisiWebSocketClient(
  'https://api.example.com',
  'YOUR_API_KEY'
);

function AdminDashboard() {
  const [agents, setAgents] = useState([]);
  const [connected, setConnected] = useState(false);
  
  useEffect(() => {
    async function connectAdminWebSocket() {
      try {
        await adminClient.authenticateAdmin('admin007');
        
        adminClient.on('open', () => {
          setConnected(true);
        });
        
        adminClient.on('ready', () => {
          console.log('Admin connection is ready');
        });
        
        adminClient.on('event', (payload) => {
          // For admin connections, payload contains agent table events
          if (payload.row_data && payload.row_data.agent_id) {
            setAgents(prevAgents => {
              // Update or add agent based on the event data
              const index = prevAgents.findIndex(a => a.agent_id === payload.row_data.agent_id);
              if (index >= 0) {
                const newAgents = [...prevAgents];
                newAgents[index] = payload.row_data;
                return newAgents;
              } else {
                return [...prevAgents, payload.row_data];
              }
            });
          }
        });
        
        adminClient.on('error', (error) => {
          console.error('Admin WebSocket error:', error);
        });
        
        adminClient.on('close', (event) => {
          setConnected(false);
        });
        
        // Connect as admin
        adminClient.connect(true);
      } catch (error) {
        console.error('Admin connection error:', error);
      }
    }
    
    connectAdminWebSocket();
    
    return () => {
      adminClient.disconnect();
    };
  }, []);
  
  return (
    <div className="admin-dashboard">
      <h2>Admin Dashboard {connected ? '(Connected)' : '(Disconnected)'}</h2>
      <h3>Agent List</h3>
      <table className="agent-table">
        <thead>
          <tr>
            <th>Agent ID</th>
            <th>Status</th>
            <th>Name</th>
            <th>Last Active</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.agent_id}>
              <td>{agent.agent_id}</td>
              <td>{agent.status}</td>
              <td>{agent.name}</td>
              <td>{agent.last_active ? new Date(agent.last_active).toLocaleString() : 'N/A'}</td>
            </tr>
          ))}
          {agents.length === 0 && (
            <tr>
              <td colSpan="4" className="no-agents">No agents available</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
```

## 8. Event Handling Best Practices

1. **Reconnection Strategy**:
   - Implement an exponential backoff strategy to handle reconnections
   - Monitor connection status and automatically reconnect when disconnected
   - Preserve message queue during disconnections
   - Consider a maximum reconnection limit to prevent excessive reconnection attempts

2. **Error Handling**:
   - Parse error messages and handle specific error codes appropriately
   - Handle session conflicts (code 4402) by notifying the user
   - Log errors with contextual information for debugging
   - Differentiate between connection errors and application errors

3. **Performance Optimization**:
   - Reuse WebSocket connections when possible
   - Implement client-side throttling for message sending
   - Be prepared to handle high message volumes (especially for admin connections)
   - Maintain a buffer of recent messages for recovery after disconnection

4. **Security Considerations**:
   - Always use TLS/SSL (wss:// protocol) for WebSocket connections
   - Store tokens securely (e.g., in memory only, not localStorage)
   - Implement token refresh mechanisms for long-lived connections
   - Include API key authentication in all requests
   - Handle session conflicts gracefully

## 9. Advanced Integration Features

### Real-time Notifications

```javascript
class NotificationService {
  constructor(daisiClient) {
    this.daisiClient = daisiClient;
    this.notifications = [];
    
    // Listen for events
    this.daisiClient.on('event', (payload) => {
      if (this.isNotificationEvent(payload)) {
        this.handleNotification(payload);
      }
    });
  }
  
  isNotificationEvent(payload) {
    // Custom logic to determine if an event is a notification
    return payload.row_data && payload.row_data.notification_type;
  }
  
  handleNotification(payload) {
    const notification = {
      id: payload.event_id,
      timestamp: payload.event_time,
      content: payload.row_data,
      read: false
    };
    
    this.notifications.push(notification);
    
    // Trigger notification display
    this.displayNotification(notification);
    
    return notification;
  }
  
  displayNotification(notification) {
    // Implementation for showing notifications to the user
    // Could use browser notifications, in-app toasts, etc.
    if (Notification && Notification.permission === "granted") {
      return new Notification("New Message", {
        body: this.formatNotificationBody(notification),
        tag: notification.id // Prevents duplicate notifications
      });
    } else if (Notification && Notification.permission !== "denied") {
      Notification.requestPermission().then(permission => {
        if (permission === "granted") {
          this.displayNotification(notification);
        }
      });
    }
  }
  
  formatNotificationBody(notification) {
    const content = notification.content;
    if (content.message_text) {
      return content.message_text;
    } else if (content.notification_text) {
      return content.notification_text;
    }
    return "You have a new notification";
  }
  
  markAsRead(notificationId) {
    const notification = this.notifications.find(n => n.id === notificationId);
    if (notification) {
      notification.read = true;
    }
  }
  
  getUnreadCount() {
    return this.notifications.filter(n => !n.read).length;
  }
  
  getAllNotifications() {
    return [...this.notifications];
  }
}
```

### Activity Monitoring

```javascript
class ActivityMonitor {
  constructor(daisiClient) {
    this.daisiClient = daisiClient;
    this.activeUsers = new Map(); // Map of user IDs to their last activity
    
    this.daisiClient.on('event', (payload) => {
      if (this.isUserActivityEvent(payload)) {
        this.updateUserActivity(payload);
      }
    });
    
    // Clean up stale activities
    setInterval(() => this.cleanupStaleActivities(), 60000);
  }
  
  isUserActivityEvent(payload) {
    return payload.row_data && (
      payload.row_data.activity_type || 
      payload.row_data.status || 
      payload.row_data.user_status
    );
  }
  
  updateUserActivity(payload) {
    const userId = payload.row_data.user_id || payload.row_data.agent_id;
    if (!userId) return;
    
    this.activeUsers.set(userId, {
      lastSeen: new Date(),
      status: payload.row_data.status || payload.row_data.user_status || 'active',
      activity: payload.row_data.activity_type || 'unknown',
      metadata: payload.row_data
    });
    
    // Trigger any registered callbacks
    if (this.activityUpdateCallback) {
      this.activityUpdateCallback(this.getActiveUsers());
    }
  }
  
  cleanupStaleActivities() {
    const now = new Date();
    this.activeUsers.forEach((data, userId) => {
      const timeDiff = now - data.lastSeen;
      if (timeDiff > 5 * 60 * 1000) { // 5 minutes
        this.activeUsers.delete(userId);
      }
    });
    
    // Trigger callback if registered
    if (this.activityUpdateCallback) {
      this.activityUpdateCallback(this.getActiveUsers());
    }
  }
  
  getActiveUsers() {
    return Array.from(this.activeUsers.entries()).map(([userId, data]) => ({
      userId,
      ...data
    }));
  }
  
  onActivityUpdate(callback) {
    this.activityUpdateCallback = callback;
  }
}
```

### Connection Status Indicator

```jsx
import React, { useEffect, useState } from 'react';
import { DaisiWebSocketClient } from './daisi-client';

function ConnectionStatusIndicator({ client }) {
  const [status, setStatus] = useState('disconnected');
  const [lastPing, setLastPing] = useState(null);
  
  useEffect(() => {
    // Set up event listeners for connection status
    client.on('open', () => {
      setStatus('connecting'); // Initially connecting until "ready" message
    });
    
    client.on('ready', () => {
      setStatus('connected');
    });
    
    client.on('close', () => {
      setStatus('disconnected');
    });
    
    client.on('error', () => {
      setStatus('error');
    });
    
    // Track pings for connection health
    const pingInterval = setInterval(() => {
      if (status === 'connected') {
        // Check time since last server response
        const now = Date.now();
        const lastActivity = lastPing || now;
        const inactiveTime = now - lastActivity;
        
        if (inactiveTime > 45000) { // No activity for 45 seconds
          setStatus('stale');
        }
      }
    }, 10000);
    
    // Update lastPing on any message from server
    client.on('message', () => {
      setLastPing(Date.now());
    });
    
    return () => {
      clearInterval(pingInterval);
    };
  }, [client, status, lastPing]);
  
  // Render appropriate indicator based on status
  const getStatusColor = () => {
    switch (status) {
      case 'connected': return 'green';
      case 'connecting': return 'yellow';
      case 'stale': return 'orange';
      case 'error':
      case 'disconnected': return 'red';
      default: return 'gray';
    }
  };
  
  return (
    <div className="connection-indicator">
      <span 
        className="status-dot"
        style={{ backgroundColor: getStatusColor() }}
      />
      <span className="status-text">
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
    </div>
  );
}
``` 