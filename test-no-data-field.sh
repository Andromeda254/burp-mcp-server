#!/bin/bash

echo "🧪 Testing that error responses do NOT include 'data' field..."

# Test error response and check for absence of data field
response=$(echo '{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
  grep '"error":')

echo "Raw response:"
echo "$response"

echo -e "\nChecking for absence of 'data' field:"
if echo "$response" | grep -q '"data"'; then
    echo "❌ ERROR: Found 'data' field in response"
    echo "$response" | grep -o '"data"[^,}]*'
    exit 1
else
    echo "✅ SUCCESS: No 'data' field found in response"
fi

echo -e "\nValidating minimal format:"
echo "$response" | python3 -c "
import json
import sys

data = json.load(sys.stdin)
error = data['error']

# Check that error object only has 'code' and 'message'
expected_keys = {'code', 'message'}
actual_keys = set(error.keys())

if actual_keys == expected_keys:
    print('✅ Error object contains exactly: code and message')
    print(f'   Keys: {sorted(actual_keys)}')
else:
    print('❌ Error object contains unexpected keys')
    print(f'   Expected: {expected_keys}')
    print(f'   Actual: {actual_keys}')
    exit(1)
"

echo -e "\n🎉 Minimal error format validation completed!"
