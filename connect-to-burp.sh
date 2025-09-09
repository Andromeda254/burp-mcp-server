#!/bin/bash

# BurpSuite Live Connection Script for Claude Desktop
# This script connects Claude Desktop directly to the BurpSuite extension

BURP_HOST="localhost"
BURP_PORTS="5001 5002 5003 5004 5005"  # Try multiple ports
BURP_PORT="5001"  # Default for messages
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
    # Check if BurpSuite MCP extension is running on any of the ports
    # Test the actual MCP endpoint instead of just port connectivity
    for port in $BURP_PORTS; do
        # Test if the MCP endpoint responds correctly
        if command -v curl &> /dev/null; then
            # Send a simple MCP initialize request to test the endpoint
            local test_response=$(curl -s --max-time 3 \
                -X POST "http://$BURP_HOST:$port/mcp" \
                -H "Content-Type: application/json" \
                -d '{"jsonrpc":"2.0","id":999,"method":"initialize","params":{}}' \
                2>/dev/null)
            
            # Check if response contains MCP server identification
            if echo "$test_response" | grep -q '"name":"burp-mcp-server"'; then
                BURP_PORT="$port"  # Update the port we found
                log "✅ Found MCP server on port $port"
                return 0
            fi
        else
            # Fallback: basic port connectivity test
            if command -v nc &> /dev/null; then
                if nc -z "$BURP_HOST" "$port" 2>/dev/null; then
                    BURP_PORT="$port"
                    return 0
                fi
            fi
        fi
    done
    return 1
}

wait_for_burp_extension() {
    log "Waiting for BurpSuite extension on $BURP_HOST:$BURP_PORT..."
    
    for i in $(seq 1 $MAX_RETRIES); do
        if check_burp_connection; then
            log "✅ BurpSuite extension found on port $BURP_PORT"
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
    log "Establishing HTTP connection to BurpSuite MCP extension..."
    log "Connecting to http://$BURP_HOST:$BURP_PORT/mcp"
    
    # Create HTTP-to-stdio bridge for MCP protocol
    # This converts stdio MCP messages to HTTP POST requests
    python3 -c "
import sys
import json
import urllib.request
import urllib.parse

# MCP HTTP endpoint
url = 'http://$BURP_HOST:$BURP_PORT/mcp'

try:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
            
        line = line.strip()
        if not line:
            continue
            
        # Create HTTP request
        data = line.encode('utf-8')
        req = urllib.request.Request(url, data=data)
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        
        # Parse JSON to get request id for proper error responses
        try:
            request_data = json.loads(line)
            request_id = request_data.get('id', 0)  # Default to 0 if no id
        except:
            request_id = 0  # Fallback for malformed JSON
        
        # Send request and get response
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                result = response.read().decode('utf-8')
                print(result)
                sys.stdout.flush()
        except Exception as e:
            # Send proper JSON-RPC error response with id field
            error_resp = {
                'jsonrpc': '2.0',
                'id': request_id,
                'error': {'code': -32603, 'message': str(e)}
            }
            print(json.dumps(error_resp))
            sys.stdout.flush()
            
except KeyboardInterrupt:
    pass
except Exception as e:
    print(f'Connection error: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# Main execution
log "BurpSuite Live Connection Script started"
wait_for_burp_extension
connect_to_burp
