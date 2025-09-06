#!/bin/bash

echo "🧪 Testing JSON-RPC 2.0 compliance..."

# Test single error response and validate JSON structure
echo "Testing prompts/list error response:"
echo '{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
  grep '"error":' | \
  python3 -m json.tool

echo -e "\nTesting with null id:"
echo '{"jsonrpc":"2.0","id":null,"method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
  grep '"error":' | \
  python3 -m json.tool

echo -e "\nTesting with string id:"
echo '{"jsonrpc":"2.0","id":"test-123","method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
  grep '"error":' | \
  python3 -m json.tool

echo -e "\n✅ JSON-RPC compliance test completed"
