# Daisi WebSocket Service

A stateless Go WebSocket service for real-time event streaming between Daisi CDC Consumer Service and browser clients.

## Overview

Daisi WebSocket Service is a high-performance, scalable Go application designed to provide real-time WebSocket connectivity for agents and users in the Daisi platform. It serves as a critical communication gateway for real-time events, handling WebSocket connections, authentication, session management, and message routing.

### Key Features

- **WebSocket Connection Management**: Establishes, maintains, and gracefully closes WebSocket connections with clients
- **Single-session Enforcement**: Guarantees at most one active connection per (company, agent, user) tuple
- **Authentication**: Validates API keys and AES-GCM encrypted tokens
- **Dynamic Route Registry**: Uses Redis to track message routing across service instances
- **Message Routing**: Efficiently delivers messages to connected WebSocket clients
- **Cross-pod Communication**: Uses gRPC to forward events between service instances
- **NATS JetStream Integration**: Subscribes to subjects for real-time event delivery
- **Admin WebSocket**: Dedicated endpoint for admin UI clients with streaming system-level events
- **Observability**: Prometheus metrics, structured logging and optional tracing

## System Architecture

The service follows clean architecture principles with separation of concerns:

- **Domain Layer**: Core models and port interfaces
- **Application Layer**: Business logic and use cases
- **Adapters Layer**: Infrastructure integrations (Redis, NATS, WebSocket, gRPC)
- **Bootstrap Layer**: Dependency injection with Google Wire

### Core Components

- **WebSocket Handler**: Upgrades HTTP connections to WebSocket protocol
- **Connection Manager**: Manages WebSocket connections and routes
- **Auth Service**: Validates user and admin tokens
- **Session Lock Manager**: Ensures exclusive user sessions with Redis
- **Route Registry**: Maps users and chats to specific service pods
- **NATS Consumer**: Subscribes to event streams and routes messages
- **Message Forwarder**: Uses gRPC to forward messages between service pods

### Technical Stack

- **Language**: Go 1.23, clean architecture pattern
- **WebSocket**: github.com/coder/websocket v1.8.13
- **Messaging**: NATS JetStream for pub/sub
- **Session Management**: Redis for distributed locking and route registry
- **Service-to-Service**: gRPC for cross-pod communication
- **Configuration**: Viper for YAML/ENV configuration with hot reload
- **DI**: Google Wire for compile-time dependency injection
- **Observability**: Prometheus metrics, Zap structured logging, optional OpenTelemetry

## Getting Started

### Prerequisites

- Go 1.23+ (as specified in go.mod)
- Docker & Docker Compose
- Make (for using Makefile shortcuts)
- Protocol Buffers compiler (for generating gRPC code)

### Environment Setup

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd daisi-ws-service
   ```

2. **Install dependencies**:
   ```bash
   go mod tidy
   go mod download
   ```

3. **Generate the required security keys**:
   ```bash
   # Generate AES keys for token encryption (32-byte, 64-character hex strings)
   openssl rand -hex 32  # For TOKEN_AES_KEY
   openssl rand -hex 32  # For ADMIN_TOKEN_AES_KEY
   
   # Generate API secret tokens (32-character random strings)
   openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32  # For SECRET_TOKEN
   openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32  # For TOKEN_GENERATION_ADMIN_KEY
   ```

4. **Set environment variables** (or add to your .env file):
   ```bash
   export DAISI_WS_AUTH_SECRET_TOKEN=<generated_secret_token>
   export DAISI_WS_AUTH_TOKEN_AES_KEY=<generated_token_aes_key>
   export DAISI_WS_AUTH_ADMIN_TOKEN_AES_KEY=<generated_admin_token_aes_key>
   export DAISI_WS_AUTH_TOKEN_GENERATION_ADMIN_KEY=<generated_token_generation_admin_key>
   ```

### Running with Docker Compose

The easiest way to run the service with its dependencies is using Docker Compose:

```bash
# Start Redis, NATS, and the WebSocket service
make up

# View logs 
make logs

# Stop all services
make down
```

### Building and Development

```bash
# Build the Docker image
make build

# Format code
make format

# Run Go tests
make test

# Regenerate Protocol Buffer code
make proto

# Update Wire dependency injection
make wire
```

## API Endpoints

### HTTP Endpoints

| Endpoint | Method | Description | Authorization |
|----------|--------|-------------|--------------|
| `/health` | GET | Health check endpoint | None |
| `/ready` | GET | Readiness check endpoint | None |
| `/metrics` | GET | Prometheus metrics endpoint | None |
| `/generate-token` | POST | Generate user token | API Key |
| `/admin/generate-token` | POST | Generate admin token | API Key |

### WebSocket Endpoints

| Endpoint | Description | Authorization | Parameters |
|----------|-------------|---------------|------------|
| `/ws/{companyId}/{agentId}` | User WebSocket connection | API Key + User Token | `token` (query param), `x-api-key` (header or query param) |
| `/ws/admin` | Admin WebSocket connection | API Key + Admin Token | `token` (query param), `x-api-key` (header or query param) |

## Integration Guide

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

### Message Types

1. **Ready Message** - Sent by the server when connection is ready:
   ```json
   {
     "type": "ready"
   }
   ```

2. **Event Message** - Sent by the server to deliver event data:
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

3. **Select Chat Message** - Sent by the client to subscribe to a specific chat:
   ```json
   {
     "type": "select_chat",
     "payload": {
       "chat_id": "chat123"
     }
   }
   ```

4. **Error Message** - Sent by the server when an error occurs:
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

### Session Management

The service enforces single-tab sessions. If a user attempts to connect from a different tab or device while an active session exists:

1. The new connection will be established
2. The old connection will receive a close frame with code 4402 and reason "session-replaced"
3. The old session will be terminated

## Error Codes

| Error Code | Description | WebSocket Close Code |
|------------|-------------|---------------------|
| `InvalidAPIKey` | Missing or invalid API key | 4401 |
| `InvalidToken` | Invalid token | 4403 |
| `SessionConflict` | Session conflict (already connected elsewhere) | 4402 |
| `SubscriptionFailure` | Failed to subscribe to message stream | 1011 |
| `RateLimitExceeded` | Rate limit exceeded | 4429 |
| `BadRequest` | Bad request format | 4400 |
| `InternalServerError` | Internal server error | 1011 |

## Performance Requirements

| Aspect | Target |
|--------|--------|
| Connection fan-out latency (P95) | ≤ 100 ms (JetStream → browser) |
| End-to-end latency budget | ≤ 200 ms (CDC → browser) |
| Concurrent sockets per replica | ≥ 10,000 (combined user & admin) |
| Availability | ≥ 99.95% over 30 days |

## Development

See the [Developer Guide](docs/developer_guide.md) for detailed development information, including project structure, workflow, and best practices.

For integration details, refer to the [Schema and Integration Guide](docs/schema-and-integration-guide.md).

## License

[License information not provided]

