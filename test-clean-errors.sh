#!/bin/bash

echo "🧪 Testing unsupported method error handling (clean test)..."

# Send only JSON-RPC messages without debug text
(
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}'
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"test"}}'
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":4,"method":"unknown/method","params":{}}'
    sleep 1
    
) | timeout 8s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio

echo -e "\n✅ Clean error handling test completed"
