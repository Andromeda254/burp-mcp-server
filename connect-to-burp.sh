#!/bin/bash

# BurpSuite Live Connection Script for Claude Desktop
# This script connects Claude Desktop directly to the BurpSuite extension

BURP_HOST="localhost"
BURP_PORT="5001"
MAX_RETRIES=30
RETRY_DELAY=1

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%H:%M:%S')] $1" >&2
}

check_burp_connection() {
    # Check if BurpSuite extension is running on port 1337
    if command -v nc &> /dev/null; then
        nc -z "$BURP_HOST" "$BURP_PORT" 2>/dev/null
        return $?
    elif command -v telnet &> /dev/null; then
        timeout 2 telnet "$BURP_HOST" "$BURP_PORT" </dev/null &>/dev/null
        return $?
    else
        # Fallback: try to connect with bash
        timeout 2 bash -c "exec 3<>/dev/tcp/$BURP_HOST/$BURP_PORT" &>/dev/null
        return $?
    fi
}

wait_for_burp_extension() {
    log "Waiting for BurpSuite extension on $BURP_HOST:$BURP_PORT..."
    
    for i in $(seq 1 $MAX_RETRIES); do
        if check_burp_connection; then
            log "✓ BurpSuite extension found on port $BURP_PORT"
            return 0
        fi
        
        if [ $i -eq 1 ]; then
            log "⚠ BurpSuite extension not found. Make sure:"
            log "  1. BurpSuite Professional is running"
            log "  2. MCP Extension is loaded (burp-mcp-server-1.0.0-burp-extension.jar)"
            log "  3. Extension started MCP server on port $BURP_PORT"
        fi
        
        log "Retry $i/$MAX_RETRIES..."
        sleep $RETRY_DELAY
    done
    
    log "✗ Failed to connect to BurpSuite extension after $MAX_RETRIES attempts"
    log "Please ensure BurpSuite extension is properly loaded"
    exit 1
}

connect_to_burp() {
    log "Establishing connection to BurpSuite extension..."
    
    # Use socat if available (best option)
    if command -v socat &> /dev/null; then
        log "Using socat for connection"
        exec socat - "TCP:$BURP_HOST:$BURP_PORT"
    
    # Use nc if available
    elif command -v nc &> /dev/null; then
        log "Using nc for connection"
        exec nc "$BURP_HOST" "$BURP_PORT"
    
    # Use telnet as fallback
    elif command -v telnet &> /dev/null; then
        log "Using telnet for connection"
        exec telnet "$BURP_HOST" "$BURP_PORT"
    
    # Bash TCP connection as last resort
    else
        log "Using bash TCP connection"
        exec 3<>"/dev/tcp/$BURP_HOST/$BURP_PORT"
        cat <&3 &
        cat >&3
        wait
    fi
}

# Main execution
log "BurpSuite Live Connection Script started"
wait_for_burp_extension
connect_to_burp
