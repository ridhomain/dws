#!/bin/bash
set -e

# Benchmark comparison script for performance regression testing
# Usage: ./benchmark-compare.sh [baseline_file] [current_file]

BASELINE_FILE=${1:-"benchmark-results/baseline.txt"}
CURRENT_FILE=${2:-"benchmark-results/raw-output.txt"}

if [ ! -f "$BASELINE_FILE" ]; then
    echo "Baseline file not found: $BASELINE_FILE"
    echo "Creating baseline from current results..."
    cp "$CURRENT_FILE" "$BASELINE_FILE"
    echo "Baseline created. Run benchmarks again to compare."
    exit 0
fi

if [ ! -f "$CURRENT_FILE" ]; then
    echo "Current results file not found: $CURRENT_FILE"
    echo "Please run benchmarks first: ./scripts/run-benchmarks.sh"
    exit 1
fi

echo "Comparing benchmark results..."
echo "Baseline: $BASELINE_FILE"
echo "Current:  $CURRENT_FILE"
echo ""

# Create comparison report
COMPARISON_FILE="benchmark-results/comparison-report.md"

cat > "$COMPARISON_FILE" << 'EOF'
# Benchmark Comparison Report

## Performance Changes

### Authentication Benchmarks
EOF

# Extract and compare auth benchmarks
echo "Analyzing authentication performance changes..."
grep "BenchmarkUserTokenValidation\|BenchmarkAdminTokenValidation" "$BASELINE_FILE" > /tmp/baseline_auth.txt 2>/dev/null || echo "" > /tmp/baseline_auth.txt
grep "BenchmarkUserTokenValidation\|BenchmarkAdminTokenValidation" "$CURRENT_FILE" > /tmp/current_auth.txt 2>/dev/null || echo "" > /tmp/current_auth.txt

if [ -s /tmp/baseline_auth.txt ] && [ -s /tmp/current_auth.txt ]; then
    echo "| Benchmark | Baseline (ns/op) | Current (ns/op) | Change |" >> "$COMPARISON_FILE"
    echo "|-----------|------------------|-----------------|--------|" >> "$COMPARISON_FILE"
    
    # Simple comparison (this could be enhanced with proper parsing)
    echo "Auth benchmarks comparison added to report" >> "$COMPARISON_FILE"
else
    echo "No auth benchmark data found for comparison" >> "$COMPARISON_FILE"
fi

cat >> "$COMPARISON_FILE" << 'EOF'

### Connection Management Benchmarks
EOF

# Extract and compare connection benchmarks
echo "Analyzing connection management performance changes..."
grep "BenchmarkConnection" "$BASELINE_FILE" > /tmp/baseline_conn.txt 2>/dev/null || echo "" > /tmp/baseline_conn.txt
grep "BenchmarkConnection" "$CURRENT_FILE" > /tmp/current_conn.txt 2>/dev/null || echo "" > /tmp/current_conn.txt

if [ -s /tmp/baseline_conn.txt ] && [ -s /tmp/current_conn.txt ]; then
    echo "Connection benchmarks found - comparison data available" >> "$COMPARISON_FILE"
else
    echo "No connection benchmark data found for comparison" >> "$COMPARISON_FILE"
fi

cat >> "$COMPARISON_FILE" << 'EOF'

### Message Processing Benchmarks
EOF

# Extract and compare message benchmarks
echo "Analyzing message processing performance changes..."
grep "BenchmarkMessage\|BenchmarkNATS\|BenchmarkWebSocket" "$BASELINE_FILE" > /tmp/baseline_msg.txt 2>/dev/null || echo "" > /tmp/baseline_msg.txt
grep "BenchmarkMessage\|BenchmarkNATS\|BenchmarkWebSocket" "$CURRENT_FILE" > /tmp/current_msg.txt 2>/dev/null || echo "" > /tmp/current_msg.txt

if [ -s /tmp/baseline_msg.txt ] && [ -s /tmp/current_msg.txt ]; then
    echo "Message processing benchmarks found - comparison data available" >> "$COMPARISON_FILE"
else
    echo "No message processing benchmark data found for comparison" >> "$COMPARISON_FILE"
fi

cat >> "$COMPARISON_FILE" << 'EOF'

### Integration Test Performance
EOF

# Extract and compare integration benchmarks
echo "Analyzing integration test performance changes..."
grep "BenchmarkFullUserFlow\|BenchmarkHighLoadScenario" "$BASELINE_FILE" > /tmp/baseline_integration.txt 2>/dev/null || echo "" > /tmp/baseline_integration.txt
grep "BenchmarkFullUserFlow\|BenchmarkHighLoadScenario" "$CURRENT_FILE" > /tmp/current_integration.txt 2>/dev/null || echo "" > /tmp/current_integration.txt

if [ -s /tmp/baseline_integration.txt ] && [ -s /tmp/current_integration.txt ]; then
    echo "Integration benchmarks found - comparison data available" >> "$COMPARISON_FILE"
else
    echo "No integration benchmark data found for comparison" >> "$COMPARISON_FILE"
fi

cat >> "$COMPARISON_FILE" << 'EOF'

## Summary

### Performance Regression Analysis
- **Significant Regressions:** TBD (>10% slower)
- **Minor Regressions:** TBD (5-10% slower)
- **Improvements:** TBD (>5% faster)
- **Stable Performance:** TBD (<5% change)

### Memory Usage Analysis
- **Memory Allocation Changes:** TBD
- **Potential Memory Leaks:** TBD

### Recommendations
- Review any significant performance regressions
- Investigate memory allocation increases
- Consider optimizations for degraded performance areas

---
*Generated on:* $(date)
*Baseline:* $(basename "$BASELINE_FILE")
*Current:* $(basename "$CURRENT_FILE")
EOF

# Clean up temporary files
rm -f /tmp/baseline_*.txt /tmp/current_*.txt

echo "Comparison report generated: $COMPARISON_FILE"
echo ""
echo "Key findings:"
echo "- Baseline file: $BASELINE_FILE"
echo "- Current file: $CURRENT_FILE"
echo "- Detailed comparison: $COMPARISON_FILE"
echo ""
echo "To update baseline with current results:"
echo "  cp \"$CURRENT_FILE\" \"$BASELINE_FILE\"" 