#!/bin/bash
set -e

echo "Running daisi-ws-service benchmarks..."

# Clean previous results
rm -rf benchmark-results/
mkdir -p benchmark-results/{profiles,individual-benchmarks}

# Set benchmark configuration
export BENCHMARK_CONFIG="config/benchmark-config.yaml"

echo "Starting benchmark execution with profiling..."

# Run all benchmarks with profiling
go test -bench=. -benchtime=10s -count=3 \
  -cpuprofile=benchmark-results/profiles/cpu.prof \
  -memprofile=benchmark-results/profiles/mem.prof \
  -blockprofile=benchmark-results/profiles/block.prof \
  ./benchmarks/... | tee benchmark-results/raw-output.txt

echo ""
echo "Benchmark execution completed!"
echo ""

# Generate individual benchmark reports
echo "Generating individual benchmark reports..."

# Extract auth benchmark results
grep -A 20 "BenchmarkUserTokenValidation\|BenchmarkAdminTokenValidation\|BenchmarkTokenValidationConcurrent" benchmark-results/raw-output.txt > benchmark-results/individual-benchmarks/auth-performance.txt 2>/dev/null || echo "No auth benchmarks found"

# Extract connection benchmark results  
grep -A 20 "BenchmarkConnectionRegistration\|BenchmarkConnectionDeregistration\|BenchmarkConnectionLookup" benchmark-results/raw-output.txt > benchmark-results/individual-benchmarks/connection-performance.txt 2>/dev/null || echo "No connection benchmarks found"

# Extract message benchmark results
grep -A 20 "BenchmarkNATSMessageProcessing\|BenchmarkWebSocketBroadcast\|BenchmarkClientMessageProcessing" benchmark-results/raw-output.txt > benchmark-results/individual-benchmarks/message-performance.txt 2>/dev/null || echo "No message benchmarks found"

# Extract session benchmark results
grep -A 20 "BenchmarkSessionLockAcquisition\|BenchmarkRouteRegistration" benchmark-results/raw-output.txt > benchmark-results/individual-benchmarks/session-performance.txt 2>/dev/null || echo "No session benchmarks found"

# Extract integration benchmark results
grep -A 20 "BenchmarkFullUserFlow\|BenchmarkMessageFlow\|BenchmarkSessionManagementFlow\|BenchmarkHighLoadScenario" benchmark-results/raw-output.txt > benchmark-results/individual-benchmarks/integration-performance.txt 2>/dev/null || echo "No integration benchmarks found"

echo "Individual reports generated in benchmark-results/individual-benchmarks/"

# Generate summary report
echo "Generating summary report..."
cat > benchmark-results/summary.md << 'EOF'
# Daisi WebSocket Service - Benchmark Results Summary

## Execution Details
- **Date:** $(date)
- **Go Version:** $(go version)
- **Benchmark Duration:** 10 seconds per test
- **Iterations:** 3 runs per benchmark

## Key Performance Metrics

### Authentication Performance
- Token validation latency
- Cache hit/miss ratios
- Concurrent authentication throughput

### Connection Management
- Connection registration/deregistration speed
- Lookup performance
- Memory overhead per connection

### Message Processing
- NATS message processing throughput
- WebSocket broadcast performance
- End-to-end message latency

### Session Management
- Session lock acquisition time
- Route registry performance
- Conflict resolution efficiency

### Integration Tests
- Full user flow performance
- High-load scenario results
- Memory pressure test outcomes

## Detailed Results
See individual benchmark files in `individual-benchmarks/` directory for detailed metrics.

## Profile Analysis
CPU, memory, and blocking profiles are available in `profiles/` directory.
Use `go tool pprof` to analyze:
```bash
go tool pprof benchmark-results/profiles/cpu.prof
go tool pprof benchmark-results/profiles/mem.prof
go tool pprof benchmark-results/profiles/block.prof
```

EOF

echo "Summary report generated: benchmark-results/summary.md"
echo ""
echo "Benchmark results saved to benchmark-results/"
echo "Use 'go tool pprof benchmark-results/profiles/cpu.prof' to analyze CPU profile"
echo "Use 'go tool pprof benchmark-results/profiles/mem.prof' to analyze memory profile" 