#!/bin/bash

echo "🧪 Testing unsupported method error handling in stdio mode..."

# Send initialize first, then test unsupported methods
(
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
    sleep 0.5
    
    echo "=== Testing prompts/list (should return error) ==="
    echo '{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}'
    sleep 0.5
    
    echo "=== Testing prompts/get (should return error) ==="  
    echo '{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"test"}}'
    sleep 0.5
    
    echo "=== Testing unknown method (should return error) ==="
    echo '{"jsonrpc":"2.0","id":4,"method":"unknown/method","params":{}}'
    sleep 1
    
) | timeout 10s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio

echo -e "\n✅ Unsupported method error handling test completed"
