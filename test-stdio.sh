#!/bin/bash

# Test script for MCP Server stdio mode
# This script sends JSON-RPC messages to test the MCP protocol

echo "🧪 Testing MCP Server in stdio mode..."

# Start the server in stdio mode and pipe test messages
(
    echo "=== Test 1: Initialize Protocol ==="
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
    
    sleep 1
    
    echo "=== Test 2: List Available Tools ==="
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    
    sleep 1
    
    echo "=== Test 3: List Available Resources ==="  
    echo '{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}'
    
    sleep 1
    
    echo "=== Test 4: Call scan_target tool ==="
    echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_target","arguments":{"url":"https://example.com","scanType":"passive"}}}'
    
    sleep 1
    
    echo "=== Test 5: Call proxy_history tool ==="
    echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"proxy_history","arguments":{"limit":5}}}'
    
    sleep 2
    
    # Send EOF to close the connection
    echo "EOF"
    
) | timeout 10s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio

echo "✅ stdio mode test completed"
