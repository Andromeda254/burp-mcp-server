#!/bin/bash

echo "🧪 Testing exact format specification..."

# Test the exact example from specification
response=$(echo '{"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
  grep '"error":')

echo "Expected format:"
echo '{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32601,
    "message": "Method not found: prompts/list"
  }
}'

echo -e "\nActual response:"
echo "$response" | python3 -m json.tool

echo -e "\nValidating structure matches specification:"
echo "$response" | python3 -c "
import json
import sys

try:
    data = json.load(sys.stdin)
    
    # Check exact structure
    expected_keys = {'jsonrpc', 'id', 'error'}
    actual_keys = set(data.keys())
    
    if actual_keys == expected_keys:
        print('✅ Top-level keys match specification')
    else:
        print(f'❌ Key mismatch. Expected: {expected_keys}, Got: {actual_keys}')
        exit(1)
    
    # Check values
    if data['jsonrpc'] == '2.0':
        print('✅ jsonrpc version correct')
    else:
        print('❌ jsonrpc version incorrect')
        exit(1)
        
    if data['id'] == 2:
        print('✅ id value preserved')
    else:
        print('❌ id value incorrect')
        exit(1)
    
    # Check error object
    error = data['error']
    expected_error_keys = {'code', 'message'}
    actual_error_keys = set(error.keys())
    
    if actual_error_keys == expected_error_keys:
        print('✅ Error object keys match specification (no extra fields)')
    else:
        print(f'❌ Error key mismatch. Expected: {expected_error_keys}, Got: {actual_error_keys}')
        exit(1)
        
    if error['code'] == -32601:
        print('✅ Error code correct')
    else:
        print('❌ Error code incorrect')
        exit(1)
        
    if error['message'] == 'Method not found: prompts/list':
        print('✅ Error message correct')
    else:
        print('❌ Error message incorrect')
        exit(1)
        
    print('\\n🎉 Response exactly matches specification!')
    
except Exception as e:
    print(f'❌ Error validating response: {e}')
    exit(1)
"
