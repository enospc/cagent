#!/bin/bash

# Test script to demonstrate enhanced logging functionality
echo "Testing enhanced logging functionality..."

# Test 1: Simple command with output
echo "=== Test 1: Running a simple command with output ==="
unset LD_PRELOAD LD_LIBRARY_PATH
SECURITY_MODE=medium cargo run -- -v --help 2>&1 | head -20

# Test 2: Check the log file to see real-time capture
echo ""
echo "=== Test 2: Latest log entries ==="
LATEST_LOG=$(ls -t ~/.config/cagent/logs/log-*.log 2>/dev/null | head -1)
if [ -f "$LATEST_LOG" ]; then
    echo "Latest log file: $LATEST_LOG"
    echo "--- Last 10 lines of log ---"
    tail -10 "$LATEST_LOG"
else
    echo "No log file found"
fi

echo ""
echo "Test completed. Check the output above to see:"
echo "1. Verbose command execution logging (prefixed with [EXEC])"
echo "2. Real-time output capture in log file with timestamps"
echo "3. Command completion status and timing"