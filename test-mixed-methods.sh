#!/bin/bash

echo "🧪 Testing both valid and invalid methods..."

# Send initialize, valid method (tools/list), and invalid methods
(
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":false},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'  
    sleep 0.5
    echo '{"jsonrpc":"2.0","id":3,"method":"prompts/list","params":{}}'
    sleep 1
    
) | timeout 8s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio | jq -c .

echo -e "\n✅ Mixed method test completed"
