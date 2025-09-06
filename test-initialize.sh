#!/bin/bash

echo "🧪 Testing MCP Server initialize response in stdio mode..."

# Test initialize response
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}' | timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio

echo -e "\n✅ Initialize test completed"
