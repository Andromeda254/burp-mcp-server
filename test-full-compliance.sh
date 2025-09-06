#!/bin/bash

echo "🧪 Comprehensive JSON-RPC 2.0 Compliance Test..."

# Function to validate JSON-RPC response structure
validate_response() {
    local response="$1"
    local test_name="$2"
    
    echo "Validating $test_name:"
    echo "$response" | python3 -c "
import json
import sys
try:
    data = json.load(sys.stdin)
    
    # Check required fields
    if 'jsonrpc' not in data:
        print('  ❌ Missing jsonrpc field')
        exit(1)
    if data['jsonrpc'] != '2.0':
        print('  ❌ Invalid jsonrpc version')
        exit(1)
    if 'id' not in data:
        print('  ❌ Missing id field (required in responses)')
        exit(1)
        
    # Check mutual exclusivity of result/error
    has_result = 'result' in data and data['result'] is not None
    has_error = 'error' in data and data['error'] is not None
    
    if has_result and has_error:
        print('  ❌ Both result and error present')
        exit(1)
    if not has_result and not has_error:
        print('  ❌ Neither result nor error present')
        exit(1)
        
    # If error, validate error object
    if has_error:
        error = data['error']
        if 'code' not in error:
            print('  ❌ Missing error code')
            exit(1)
        if 'message' not in error:
            print('  ❌ Missing error message')
            exit(1)
        if not isinstance(error['code'], int):
            print('  ❌ Error code must be integer')
            exit(1)
        if not isinstance(error['message'], str):
            print('  ❌ Error message must be string')
            exit(1)
    
    print('  ✅ JSON-RPC 2.0 compliant')
    
except Exception as e:
    print(f'  ❌ Invalid JSON or structure: {e}')
    exit(1)
"
}

echo -e "\n--- Testing Error Responses ---"

# Test 1: Numeric ID
response1=$(echo '{"jsonrpc":"2.0","id":123,"method":"prompts/list","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | grep '"error":')
validate_response "$response1" "Numeric ID error response"

# Test 2: String ID  
response2=$(echo '{"jsonrpc":"2.0","id":"test-456","method":"prompts/get","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | grep '"error":')
validate_response "$response2" "String ID error response"

# Test 3: Null ID
response3=$(echo '{"jsonrpc":"2.0","id":null,"method":"unknown/method","params":{}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | grep '"error":')
validate_response "$response3" "Null ID error response"

echo -e "\n--- Testing Success Responses ---"

# Test 4: Successful initialize
response4=$(echo '{"jsonrpc":"2.0","id":"init-test","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
  timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | grep '"result":')
validate_response "$response4" "Initialize success response"

echo -e "\n🎉 All JSON-RPC 2.0 compliance tests completed!"
