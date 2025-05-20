# Daisi WebSocket Service - Gaps Analysis

## Introduction

This document identifies gaps, missing features, and potential improvements in the current implementation of the daisi-ws-service when compared against the architectural requirements specified in `architecture.md`. The analysis is organized by category to provide a clear overview of areas that need attention.

## Missing Features

### Admin WebSocket Support (Phase 5) -- SKIP

While the code includes implementation for admin WebSocket functionality, there are a few incomplete areas:

1. **Admin Event Filtering**: The admin WebSocket handler doesn't implement filtering logic based on the admin user's company restriction or other potential permission boundaries. The architecture document mentions admin tokens might contain company-specific restrictions, but the implementation doesn't fully enforce this. -- SKIP, No need to filter and enforce, we don't use granular auth for now.

### Observability Improvements (FR-9B)

While basic observability is implemented, there are opportunities for more comprehensive metrics:

1. **Metric Naming Consistency**: Some metrics are prefixed with `dws_` as per the architecture doc, but others aren't using this consistent prefix.

2. **Connection Duration Histogram**: The architecture doc specifies a connection duration histogram with specific buckets (1m, 5m, 15m, 30m, 1h, 4h, 8h, 24h), but the implementation doesn't explicitly define these buckets.

3. **NATS Consumer Lag Metrics**: The architecture doc specifies monitoring JetStream consumer lag, but explicit metrics for tracking this don't appear to be implemented. -- SKIP, we plan to use nats metrics exporter, no need to handle in this service.

### WebSocket Compression Support -- SKIP, because in config, we plan to use disabled. 

While the codebase includes configuration options for WebSocket compression modes, the implementation might need further testing and validation:

```go
switch strings.ToLower(appSpecificConfig.WebsocketCompressionMode) {
case "context_takeover":
    opts.CompressionMode = websocket.CompressionContextTakeover
case "no_context_takeover":
    opts.CompressionMode = websocket.CompressionNoContextTakeover
case "disabled":
    opts.CompressionMode = websocket.CompressionDisabled
default:
    opts.CompressionMode = websocket.CompressionDisabled
}
```

## Potential Implementation Issues

### Error Handling and Recovery

1. **Inconsistent Error Response Format**: The architecture document defines a standard error format, but there might be inconsistencies in how errors are formatted and returned throughout the codebase.

2. **gRPC Message Forwarding Retry Logic**: The architecture document mentions that message forwarding failures should be retried once, but the implementation in `internal/adapters/websocket/handler.go` does not clearly implement this retry pattern.

3. **Panic Recovery**: While the `safego` package is used for goroutine execution with panic recovery, ensuring comprehensive recovery across all goroutines would improve stability.

### Session Management

1. **Session Lock Acquisition Retry Logic**: The acquisition retry logic in `AcquireSessionLockOrNotify` could be refined to better handle edge cases, particularly around timing of lock releases and acquisitions.

2. **Route Registry Management**: The architecture document emphasizes careful tracking of pod ownership for chat/message routes. The current implementation should be thoroughly tested to ensure it properly handles all edge cases during pod failures or network partitions. -- Should be included on testing phase

### Security Considerations

1. **AES Key Handling**: The code correctly handles AES key validation, but could benefit from additional logging that doesn't expose sensitive key material in case of configuration errors.

2. **Token Validation**: The token validation logic could include additional checks for token freshness, signature validity, and potential replay attacks.

## Implementation Improvements

### Code Structure

1. **Domain vs. Application Logic Separation**: The separation between domain and application logic could be refined in some areas to ensure better adherence to clean architecture principles.

2. **Explicit Dependency Injection**: While Google Wire is used for dependency injection, some components still have direct dependencies that could be better abstracted through interfaces.

### Performance Optimization

1. **gRPC Connection Pooling**: The implementation includes a basic gRPC connection pool, but it could be enhanced with more sophisticated connection management, timeouts, and circuit breaking.

2. **Message Buffering and Backpressure**: Additional logic for handling message backpressure when WebSocket clients are slow to receive messages would improve system resilience.

3. **Redis Key Expiration Strategy**: The current implementation uses fixed TTLs for Redis keys. A more sophisticated approach with variable TTLs based on activity patterns could improve efficiency.

### Resilience Enhancements

1. **Graceful Degradation**: Additional logic to handle partial system failures (e.g., Redis unavailability) could improve service resilience.

2. **Rate Limiting**: Implementing per-client rate limiting would protect the service from clients sending excessive message volumes.

## Compliance with Architecture Document

### Recommendations in Architecture Document 

1. **Redis Key Generation Helpers**: The architecture document recommends implementing helper functions in `pkg/rediskeys/keys.go` for consistent Redis key generation. This has been implemented correctly.

2. **Context-Aware Logging**: The architecture document emphasizes request_id propagation via context. The implementation includes this, but could possibly be enhanced to ensure consistent propagation across all boundaries.

3. **Config Hot-Reload**: The architecture document mentions config hot-reload on SIGHUP, which is implemented but could benefit from additional logging to confirm which specific configuration values were changed.

## Conclusion

While the daisi-ws-service implementation largely adheres to the architecture document, the identified gaps and potential improvements would enhance the service's robustness, maintainability, and adherence to the architectural vision. Addressing these items should be prioritized based on operational impact and alignment with business requirements.
