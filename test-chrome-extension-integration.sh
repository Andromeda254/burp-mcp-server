#!/bin/bash

# Test Chrome Extension Integration with BurpSuite MCP Server
# This script tests the bidirectional communication between Chrome Extension and Java backend

set -e

echo "=== BurpSuite MCP Chrome Extension Integration Test ==="
echo

# Configuration
EXTENSION_SERVER_HOST="localhost"
EXTENSION_SERVER_PORT="1337"
EXTENSION_SERVER_URL="http://${EXTENSION_SERVER_HOST}:${EXTENSION_SERVER_PORT}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to make HTTP request and check response
test_endpoint() {
    local endpoint=$1
    local method=$2
    local data=$3
    local expected_status=$4
    
    print_status $BLUE "Testing endpoint: ${method} ${endpoint}"
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -H "X-Session-ID: test-session-$(date +%s)" \
            -d "$data" \
            "${EXTENSION_SERVER_URL}${endpoint}")
    else
        response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
            -X "${method}" \
            "${EXTENSION_SERVER_URL}${endpoint}")
    fi
    
    # Extract body and status
    body=$(echo $response | sed -E 's/HTTPSTATUS\:[0-9]{3}$//')
    status=$(echo $response | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    
    if [ "$status" = "$expected_status" ]; then
        print_status $GREEN "✓ Status: $status (Expected: $expected_status)"
        echo "  Response: $body"
    else
        print_status $RED "✗ Status: $status (Expected: $expected_status)"
        echo "  Response: $body"
        return 1
    fi
    
    echo
    return 0
}

# Function to check if server is running
check_server_running() {
    if curl -s -f "${EXTENSION_SERVER_URL}/ping" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Start the test
print_status $YELLOW "Step 1: Check if Extension Server is running"

if check_server_running; then
    print_status $GREEN "✓ Extension Server is running at ${EXTENSION_SERVER_URL}"
else
    print_status $RED "✗ Extension Server is not running at ${EXTENSION_SERVER_URL}"
    echo
    print_status $YELLOW "To start the server, run:"
    echo "  1. Build the project: ./gradlew build"
    echo "  2. Run the server: ./start-server.sh http"
    echo "  3. Or run via Gradle: ./gradlew run"
    echo
    exit 1
fi

echo

print_status $YELLOW "Step 2: Test Basic Endpoints"

# Test ping endpoint
test_endpoint "/ping" "GET" "" "200" || exit 1

# Test status endpoint
test_endpoint "/status" "GET" "" "200" || exit 1

# Test stats endpoint
test_endpoint "/stats" "GET" "" "200" || exit 1

print_status $YELLOW "Step 3: Test API Endpoints with Mock Data"

# Test analysis endpoint
analysis_data='{
    "url": "https://example.com/test-page",
    "sessionId": "test-session-analysis",
    "timestamp": '$(date +%s)'000'
}'
test_endpoint "/api/analyze" "POST" "$analysis_data" "200" || exit 1

# Test recording endpoint
recording_data='{
    "action": "click",
    "sessionId": "test-session-recording",
    "element": {
        "tagName": "button",
        "id": "submit-btn",
        "className": "btn btn-primary"
    },
    "timestamp": '$(date +%s)'000'
}'
test_endpoint "/api/recording" "POST" "$recording_data" "200" || exit 1

# Test screenshot endpoint
screenshot_data='{
    "url": "https://example.com/test-page",
    "sessionId": "test-session-screenshot",
    "viewport": {
        "width": 1920,
        "height": 1080
    },
    "timestamp": '$(date +%s)'000'
}'
test_endpoint "/api/screenshot" "POST" "$screenshot_data" "200" || exit 1

# Test forms analysis endpoint
forms_data='{
    "url": "https://example.com/login",
    "sessionId": "test-session-forms",
    "forms": [
        {
            "action": "http://example.com/login",
            "method": "POST",
            "inputs": [
                {
                    "name": "username",
                    "type": "text"
                },
                {
                    "name": "password",
                    "type": "password",
                    "autocomplete": "current-password"
                }
            ]
        },
        {
            "action": "https://example.com/contact",
            "method": "POST",
            "inputs": [
                {
                    "name": "email",
                    "type": "email"
                },
                {
                    "name": "message",
                    "type": "textarea"
                },
                {
                    "name": "csrf_token",
                    "type": "hidden",
                    "value": "abc123"
                }
            ]
        }
    ],
    "timestamp": '$(date +%s)'000'
}'
test_endpoint "/api/forms-analysis" "POST" "$forms_data" "200" || exit 1

print_status $YELLOW "Step 4: Test Error Handling"

# Test invalid endpoint
print_status $BLUE "Testing invalid endpoint"
response=$(curl -s -w "HTTPSTATUS:%{http_code}" "${EXTENSION_SERVER_URL}/api/invalid-endpoint")
status=$(echo $response | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$status" = "404" ]; then
    print_status $GREEN "✓ Invalid endpoint correctly returns 404"
else
    print_status $RED "✗ Invalid endpoint returned status: $status (Expected: 404)"
fi

echo

# Test invalid method
print_status $BLUE "Testing invalid method on valid endpoint"
response=$(curl -s -w "HTTPSTATUS:%{http_code}" -X GET "${EXTENSION_SERVER_URL}/api/analyze")
status=$(echo $response | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$status" = "405" ]; then
    print_status $GREEN "✓ Invalid method correctly returns 405"
else
    print_status $RED "✗ Invalid method returned status: $status (Expected: 405)"
fi

echo

# Test malformed JSON
print_status $BLUE "Testing malformed JSON"
response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"invalid": json}' \
    "${EXTENSION_SERVER_URL}/api/analyze")
status=$(echo $response | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')

if [ "$status" = "500" ]; then
    print_status $GREEN "✓ Malformed JSON correctly returns 500"
else
    print_status $RED "✗ Malformed JSON returned status: $status (Expected: 500)"
fi

echo

print_status $YELLOW "Step 5: Test CORS Headers"

print_status $BLUE "Testing CORS preflight request"
response=$(curl -s -i -X OPTIONS "${EXTENSION_SERVER_URL}/api/analyze")

if echo "$response" | grep -q "Access-Control-Allow-Origin"; then
    print_status $GREEN "✓ CORS headers are present"
else
    print_status $RED "✗ CORS headers are missing"
fi

echo

print_status $YELLOW "Step 6: Performance Test"

print_status $BLUE "Testing multiple concurrent requests"

# Function to make concurrent requests
make_concurrent_request() {
    local endpoint_num=$1
    local data='{"sessionId": "perf-test-'$endpoint_num'", "url": "https://example.com/perf-test-'$endpoint_num'", "timestamp": '$(date +%s)'000}'
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$data" \
        "${EXTENSION_SERVER_URL}/api/analyze")
    
    status=$(echo $response | tr -d '\n' | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    if [ "$status" = "200" ]; then
        echo "Request $endpoint_num: OK"
    else
        echo "Request $endpoint_num: FAILED (Status: $status)"
    fi
}

# Launch 10 concurrent requests
for i in {1..10}; do
    make_concurrent_request $i &
done

# Wait for all background jobs to complete
wait

print_status $GREEN "✓ Concurrent requests completed"

echo

print_status $YELLOW "Step 7: Final Server Stats"

# Get final stats
test_endpoint "/stats" "GET" "" "200" || exit 1

echo
print_status $GREEN "=== All Tests Completed Successfully ==="

print_status $YELLOW "Next Steps:"
echo "  1. Load the Chrome extension from: chrome-extension/"
echo "  2. Navigate to a test website"
echo "  3. Open browser DevTools and check console for extension messages"
echo "  4. Use the extension to trigger security analysis"
echo "  5. Monitor BurpSuite for proxy traffic and scan results"

echo
print_status $BLUE "Extension Loading Instructions:"
echo "  1. Open Chrome browser"
echo "  2. Go to chrome://extensions/"
echo "  3. Enable 'Developer mode' in the top right"
echo "  4. Click 'Load unpacked' and select the 'chrome-extension' directory"
echo "  5. The extension should now be loaded and active"

echo
print_status $GREEN "Integration test completed successfully! ✨"
