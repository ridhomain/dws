# Daisi WebSocket Service

A high-performance, scalable Go WebSocket service for real-time event streaming between NATS JetStream and browser clients in the Daisi platform.

## Overview

Daisi WebSocket Service is a sophisticated Go application designed to provide real-time WebSocket connectivity for agents and users in the Daisi platform. Built with Go 1.23 and clean architecture principles, it serves as a critical communication gateway for real-time events, handling WebSocket connections, authentication, session management, and intelligent message routing across multiple service instances.

### Key Features

- **Dual WebSocket Endpoints**: Separate endpoints for users (`/ws/{company}/{agent}`) and admins (`/ws/admin`)
- **Advanced Session Management**: Exclusive sessions with Redis-based distributed locking and automatic session migration
- **Dual Authentication System**: API key + AES-GCM encrypted tokens for users and admins
- **Intelligent Message Routing**: Redis-based route registry with automatic cross-pod message forwarding via gRPC
- **NATS JetStream Integration**: Durable consumers with queue groups for reliable message processing
- **Adaptive TTL Management**: Activity-based TTL optimization for session locks and routes
- **Advanced WebSocket Features**: Buffered sending, backpressure handling, compression support, ping/pong health checks
- **Circuit Breaker Pattern**: Fault-tolerant gRPC communication with connection pooling
- **Comprehensive Observability**: Prometheus metrics, structured Zap logging, health checks
- **Hot Configuration Reload**: File watching and SIGHUP signal support

## System Architecture

The service follows clean architecture principles with distinct layers:

- **Domain Layer**: Pure business logic with interface definitions
- **Application Layer**: Business orchestration and use cases
- **Adapters Layer**: Infrastructure integrations (Redis, NATS, WebSocket, gRPC)
- **Bootstrap Layer**: Dependency injection with Google Wire

### Core Components

- **Connection Manager**: Central orchestrator for WebSocket connections and routing
- **Auth Service**: Dual token validation with Redis caching
- **Session Lock Manager**: Distributed exclusive session management
- **Route Registry**: Intelligent message routing across service instances
- **NATS Consumer**: JetStream integration with fault-tolerant processing
- **Message Forwarder**: gRPC-based cross-pod communication with circuit breakers
- **Kill Switch**: Session migration system via Redis pub/sub

### Technical Stack

- **Language**: Go 1.23 with clean architecture
- **WebSocket**: github.com/coder/websocket v1.8.13 with advanced features
- **Messaging**: NATS JetStream with durable consumers and queue groups
- **Session Management**: Redis with distributed locking and adaptive TTL
- **Service Communication**: gRPC with Protocol Buffers and circuit breakers
- **Configuration**: Viper with YAML/ENV support and hot reload
- **Dependency Injection**: Google Wire for compile-time DI
- **Observability**: Prometheus metrics, Zap structured logging
- **Security**: AES-GCM token encryption with dual authentication

## Getting Started

### Prerequisites

- Go 1.23+ (as specified in go.mod)
- Docker & Docker Compose
- Make (for using Makefile shortcuts)
- Protocol Buffers compiler (for gRPC code generation)

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
   openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32  # For ADMIN_SECRET_TOKEN
   ```

4. **Set environment variables** (or add to your .env file):
   ```bash
   export DAISI_WS_AUTH_SECRET_TOKEN=<generated_secret_token>
   export DAISI_WS_AUTH_TOKEN_AES_KEY=<generated_token_aes_key>
   export DAISI_WS_AUTH_ADMIN_TOKEN_AES_KEY=<generated_admin_token_aes_key>
   export DAISI_WS_AUTH_ADMIN_SECRET_TOKEN=<generated_admin_secret_token>
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
| `/ready` | GET | Readiness check with dependency status | None |
| `/metrics` | GET | Prometheus metrics endpoint | None |
| `/generate-token` | POST | Generate user token | Admin API Key |
| `/admin/generate-token` | POST | Generate admin token | Admin API Key |

### WebSocket Endpoints

| Endpoint | Description | Authorization | Query Parameters |
|----------|-------------|---------------|------------------|
| `/ws/{company}/{agent}` | User WebSocket connection | API Key + User Token | `token`, `x-api-key` (header or query) |
| `/ws/admin` | Admin WebSocket connection | API Key + Admin Token | `token`, `x-api-key` (header or query) |

## Authentication System

The service implements a dual authentication system with separate API keys for different purposes:

- **General API Key (`secret_token`)**: Used for generating user tokens and general WebSocket connections
- **Admin API Key (`admin_secret_token`)**: Used exclusively for generating admin tokens and administrative operations

This separation ensures better security isolation between user and admin operations.

## Token Generation

### User Token Generation

```bash
curl -X POST http://localhost:8080/generate-token \
  -H "X-API-Key: your-general-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "company_id": "company123",
    "agent_id": "agent456", 
    "user_id": "user789",
    "expires_in_seconds": 3600
  }'
```

### Admin Token Generation

```bash
curl -X POST http://localhost:8080/admin/generate-token \
  -H "X-API-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "admin_id": "admin123",
    "expires_in_seconds": 7200,
    "subscribed_company_id": "company123",
    "subscribed_agent_id": "agent456",
    "company_id_restriction": "company123"
  }'
```

## WebSocket Integration

### User Connection Example

```javascript
const companyId = 'company456';
const agentId = 'agent789';
const token = 'your-encrypted-token';
const apiKey = 'your-api-key';

const socket = new WebSocket(
  `wss://api.example.com/ws/${companyId}/${agentId}?token=${token}&x-api-key=${apiKey}`
);

socket.onopen = function(event) {
  console.log('Connected to WebSocket');
};

socket.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
  
  if (message.type === 'ready') {
    // Connection is ready, can now select a chat
    socket.send(JSON.stringify({
      type: 'select_chat',
      payload: { chat_id: 'chat123' }
    }));
  }
};
```

### Admin Connection Example

```javascript
const adminToken = 'your-admin-token';
const apiKey = 'your-api-key';

const adminSocket = new WebSocket(
  `wss://api.example.com/ws/admin?token=${adminToken}&x-api-key=${apiKey}`
);

adminSocket.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Admin event:', message);
  
  // Receive system-wide events across all companies/agents
};
```

## Message Types

### Server-to-Client Messages

1. **Ready Message** - Connection established successfully:
   ```json
   {
     "type": "ready"
   }
   ```

2. **Event Message** - Real-time event data:
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
         // Dynamic content based on event type
       }
     }
   }
   ```

3. **Error Message** - Error notifications:
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

### Client-to-Server Messages

1. **Select Chat Message** - Subscribe to specific chat events:
   ```json
   {
     "type": "select_chat",
     "payload": {
       "chat_id": "chat123"
     }
   }
   ```

## Configuration

### Main Configuration File (`config/config.yaml`)

```yaml
server:
  http_port: 8080
  grpc_port: 50051
  pod_id: ""  # Set via environment variable
  enable_reflection: false

nats:
  url: "nats://nats:4222"
  stream_name: "wa_stream" 
  consumer_name: "ws_fanout"
  retry_on_failed_connect: true

redis:
  address: "redis:6379"
  
auth:
  secret_token: ""  # Set via environment
  token_aes_key: ""  # Set via environment
  admin_secret_token: ""  # Set via environment
  admin_token_aes_key: ""  # Set via environment
  token_cache_ttl_seconds: 30

app:
  session_ttl_seconds: 30
  route_ttl_seconds: 300
  ttl_refresh_interval_seconds: 10
  websocket_message_buffer_size: 100
  websocket_backpressure_drop_policy: "drop_oldest"  # or "block"
  ping_interval_seconds: 20
  pong_wait_seconds: 60

adaptive_ttl:
  session_lock:
    enabled: false
    min_ttl_seconds: 15
    max_ttl_seconds: 30
    activity_threshold_seconds: 120
  message_route:
    enabled: true
    min_ttl_seconds: 300
    max_ttl_seconds: 900
    activity_threshold_seconds: 600
```

### Environment Variables

All configuration values can be overridden using environment variables with the `DAISI_WS_` prefix:

```bash
DAISI_WS_SERVER_HTTP_PORT=8080
DAISI_WS_SERVER_GRPC_PORT=50051
DAISI_WS_SERVER_POD_ID=ws-service-1
DAISI_WS_NATS_URL=nats://localhost:4222
DAISI_WS_REDIS_ADDRESS=localhost:6379
DAISI_WS_AUTH_SECRET_TOKEN=your-secret-token
DAISI_WS_AUTH_TOKEN_AES_KEY=your-64-char-hex-key
DAISI_WS_AUTH_ADMIN_SECRET_TOKEN=your-admin-secret-token
```

## NATS Integration

### Subject Patterns

The service subscribes to hierarchical NATS subjects:

- **General Chat Events**: `websocket.{company}.{agent}.chats`
- **Specific Chat Messages**: `websocket.{company}.{agent}.messages.{chat_id}`
- **Admin Events**: `websocket.{company}.{agent}.agents`

### JetStream Configuration

- **Durable Consumers**: `ws_fanout` for reliability
- **Queue Groups**: Load balancing across replicas
- **Manual Acknowledgment**: Ensures reliable processing
- **Delivery Modes**: `DeliverAll` for chats, `DeliverLastPerSubject` for messages

## Session Management

### Exclusive Sessions

The service enforces single-session per user using Redis distributed locks:

- **Lock Key**: `session:{company}:{agent}:{user}`
- **Admin Lock Key**: `session:admin:{admin_id}`
- **Session Migration**: Automatic via kill switch pub/sub
- **Activity Tracking**: Adaptive TTL based on usage patterns

### Session Migration Process

1. New connection attempts to acquire session lock
2. If lock exists, publish kill switch message
3. Old connection receives termination signal
4. New connection acquires lock and establishes

## Error Codes and WebSocket Close Codes

| Error Code | Description | WebSocket Close Code |
|------------|-------------|---------------------|
| `InvalidAPIKey` | Missing/invalid API key | 4401 |
| `InvalidToken` | Invalid/expired token | 4403 |
| `SessionConflict` | Session already active | 4402 |
| `SubscriptionFailure` | NATS subscription failed | 1011 |
| `RateLimitExceeded` | Rate limit exceeded | 4429 |
| `BadRequest` | Malformed request | 4400 |
| `InternalServerError` | Server error | 1011 |

## Monitoring and Observability

### Prometheus Metrics

The service exposes comprehensive metrics at `/metrics`:

- **Connection Metrics**: `dws_active_connections`, `dws_connection_duration_seconds`
- **Message Metrics**: `dws_messages_sent_total`, `dws_messages_received_total`
- **Authentication Metrics**: `dws_auth_success_total`, `dws_auth_failure_total`
- **gRPC Metrics**: `dws_grpc_messages_sent_total`, `dws_grpc_forward_retry_attempts_total`
- **Session Lock Metrics**: `dws_session_lock_attempts_total`, `dws_session_lock_success_total`
- **Buffer Metrics**: `dws_websocket_buffer_used_count`, `dws_websocket_messages_dropped_total`

### Health Checks

- **`/health`**: Basic service health
- **`/ready`**: Comprehensive dependency checks (NATS, Redis, gRPC)

### Structured Logging

Contextual logging with fields:
- `request_id`: Request correlation
- `user_id`, `company_id`, `agent_id`: User context
- `event_id`: Event correlation
- `session_key`: Session identification

## Performance Targets

| Metric | Target |
|--------|--------|
| Concurrent connections per pod | ≥ 10,000 |
| Message delivery latency (P95) | ≤ 100ms |
| End-to-end latency | ≤ 200ms (CDC → browser) |
| Availability | ≥ 99.95% over 30 days |
| Cross-pod forwarding latency | ≤ 50ms |

## Development

### Project Structure

```
daisi-ws-service/
├── cmd/daisi-ws-service/     # Application entry point
├── internal/
│   ├── domain/               # Business logic interfaces
│   ├── application/          # Use cases and orchestration
│   ├── adapters/            # Infrastructure implementations
│   └── bootstrap/           # Dependency injection
├── pkg/                     # Shared utilities
├── config/                  # Configuration files
└── deploy/                  # Deployment configurations
```

### Development Workflow

1. **Make Changes**: Edit code in appropriate layers
2. **Generate Code**: Run `make wire` for DI, `make proto` for gRPC
3. **Test**: Run `make test` for unit tests
4. **Format**: Run `make format` for code formatting
5. **Build**: Run `make build` for Docker image

### Adding New Features

1. **Domain Layer**: Define interfaces in `internal/domain/`
2. **Application Layer**: Implement use cases in `internal/application/`
3. **Adapters Layer**: Add infrastructure in `internal/adapters/`
4. **Wire Integration**: Update `internal/bootstrap/providers.go`

## Deployment

### Docker Compose (Development)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f ws-service-1

# Scale replicas
docker-compose up -d --scale ws-service-1=2 --scale ws-service-2=2
```

### Kubernetes (Production)

The service is designed for Kubernetes deployment with:
- **Horizontal Pod Autoscaling**: Based on connection metrics
- **Service Mesh**: gRPC communication between pods
- **ConfigMaps/Secrets**: Configuration and security management
- **Network Policies**: Security isolation

## License

[License information to be provided]

