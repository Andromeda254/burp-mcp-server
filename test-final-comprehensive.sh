#!/bin/bash

echo "🧪 FINAL COMPREHENSIVE MCP SERVER TEST"
echo "======================================"

# Function to test and validate response
test_method() {
    local method="$1"
    local params="$2" 
    local test_name="$3"
    local expected_type="$4"  # "result" or "error"
    
    echo -e "\n--- Testing: $test_name ---"
    
    local response=$(echo "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"$method\",\"params\":$params}" | \
        timeout 5s java -jar build/libs/burp-mcp-server-1.0.0-all.jar --stdio 2>/dev/null | \
        grep -E '"result":|"error":')
    
    echo "Response: $response"
    
    # Validate JSON structure
    if echo "$response" | python3 -c "
import json
import sys
try:
    data = json.load(sys.stdin)
    
    # Basic validation
    if 'jsonrpc' not in data or data['jsonrpc'] != '2.0':
        print('❌ Invalid jsonrpc')
        exit(1)
    if 'id' not in data or data['id'] != 99:
        print('❌ Invalid id')
        exit(1)
        
    # Check expected response type
    if '$expected_type' == 'result':
        if 'result' not in data:
            print('❌ Missing result field')
            exit(1)
        if 'error' in data:
            print('❌ Unexpected error field')
            exit(1)
    elif '$expected_type' == 'error':
        if 'error' not in data:
            print('❌ Missing error field')
            exit(1)
        if 'result' in data:
            print('❌ Unexpected result field')
            exit(1)
        # Validate error structure
        error = data['error']
        if 'code' not in error or 'message' not in error:
            print('❌ Invalid error structure')
            exit(1)
        if 'data' in error:
            print('❌ Unwanted data field in error')
            exit(1)
    
    print('✅ Valid JSON-RPC 2.0 response')
    
except Exception as e:
    print(f'❌ JSON validation failed: {e}')
    exit(1)
" 2>/dev/null; then
        echo "✅ $test_name: PASSED"
    else
        echo "❌ $test_name: FAILED"
    fi
}

# Test 1: Initialize (should succeed)
test_method "initialize" '{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}' "Initialize Protocol" "result"

# Test 2: Tools List (should succeed)  
test_method "tools/list" '{}' "List Available Tools" "result"

# Test 3: Resources List (should succeed)
test_method "resources/list" '{}' "List Available Resources" "result"

# Test 4: Unsupported Method - prompts/list (should fail with clean error)
test_method "prompts/list" '{}' "Unsupported prompts/list" "error"

# Test 5: Unsupported Method - prompts/get (should fail with clean error)
test_method "prompts/get" '{"name":"test"}' "Unsupported prompts/get" "error"

# Test 6: Unknown Method (should fail with clean error)
test_method "unknown/method" '{}' "Unknown method" "error"

# Test 7: Tool Call - scan_target (should succeed)
test_method "tools/call" '{"name":"scan_target","arguments":{"url":"https://example.com","scanType":"passive"}}' "Scan Target Tool" "result"

# Test 8: Tool Call - burp_info (should succeed)
test_method "tools/call" '{"name":"burp_info","arguments":{}}' "Burp Info Tool" "result"

echo -e "\n======================================"
echo "🎉 FINAL COMPREHENSIVE TEST COMPLETED"
echo "======================================"
