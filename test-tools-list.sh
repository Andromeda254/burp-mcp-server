#!/bin/bash

echo "🧪 Testing MCP Server tools/list in stdio mode..."

# Send initialize first, then tools/list
(
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
    sleep 1
) | timeout 8s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio

echo -e "\n✅ Tools list test completed"
