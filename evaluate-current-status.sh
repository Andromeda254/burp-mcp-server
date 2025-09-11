#!/bin/bash

# Comprehensive Implementation Status Evaluation Script
# Tests current functionality and identifies gaps for next phase

# set -e removed to allow script to continue on errors

echo "🔍 BURP MCP SERVER - CURRENT STATUS EVALUATION"
echo "============================================="
echo "Date: $(date)"
echo "Version: 1.0.0"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
PASSED=0
FAILED=0
WARNINGS=0

# Function to print test results
print_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    case $status in
        "PASS")
            echo -e "${GREEN}✅ PASS${NC}: $test_name"
            ((PASSED++))
            ;;
        "FAIL")
            echo -e "${RED}❌ FAIL${NC}: $test_name - $details"
            ((FAILED++))
            ;;
        "WARN")
            echo -e "${YELLOW}⚠️  WARN${NC}: $test_name - $details"
            ((WARNINGS++))
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  INFO${NC}: $test_name - $details"
            ;;
    esac
}

# Function to test HTTP server response
test_http_endpoint() {
    local endpoint="$1"
    local expected_status="$2"
    local timeout="${3:-5}"
    
    if curl -s --max-time $timeout "$endpoint" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to test MCP tool call
test_mcp_tool() {
    local tool_name="$1"
    local arguments="$2"
    local port="${3:-5001}"
    
    local payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool_name\",\"arguments\":$arguments}}"
    
    local response=$(curl -s --max-time 10 \
        -X POST "http://localhost:$port/mcp" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)
    
    if [[ -n "$response" ]] && echo "$response" | grep -q '"result"'; then
        return 0
    else
        return 1
    fi
}

echo "📋 PHASE 1: BUILD SYSTEM EVALUATION"
echo "------------------------------------"

# Test 1: Java version
if java -version 2>&1 | grep -q "17\|18\|19\|20\|21"; then
    print_result "Java 17+ availability" "PASS"
else
    print_result "Java 17+ availability" "FAIL" "Java 17+ required"
fi

# Test 2: Gradle build
if ./gradlew --version > /dev/null 2>&1; then
    print_result "Gradle availability" "PASS"
else
    print_result "Gradle availability" "FAIL" "Gradle wrapper not working"
fi

# Test 3: Project compilation
echo -n "Testing project compilation... "
if ./gradlew compileJava --quiet > /dev/null 2>&1; then
    print_result "Project compilation" "PASS"
else
    print_result "Project compilation" "FAIL" "Compilation errors detected"
fi

# Test 4: JAR generation
if [ -f "build/libs/burp-mcp-server-1.0.0-all.jar" ]; then
    print_result "Fat JAR generation" "PASS"
    
    # Check JAR size (should be substantial with all dependencies)
    jar_size=$(du -h "build/libs/burp-mcp-server-1.0.0-all.jar" | cut -f1)
    print_result "Fat JAR size check" "INFO" "Size: $jar_size"
else
    print_result "Fat JAR generation" "WARN" "Run './gradlew shadowJar' first"
fi

# Test 5: Extension JAR generation
if [ -f "build/libs/burp-mcp-server-1.0.0-burp-extension.jar" ]; then
    print_result "Extension JAR generation" "PASS"
else
    print_result "Extension JAR generation" "WARN" "Run './gradlew burpExtensionJar' first"
fi

echo ""
echo "📋 PHASE 2: CORE FUNCTIONALITY EVALUATION"
echo "----------------------------------------"

# Start HTTP server for testing (if not already running)
SERVER_PID=""
if ! test_http_endpoint "http://localhost:5001/health" 200; then
    echo "Starting HTTP server for testing..."
    java -jar build/libs/burp-mcp-server-1.0.0-all.jar --port 5001 > /tmp/mcp-server.log 2>&1 &
    SERVER_PID=$!
    sleep 3
fi

# Test MCP protocol endpoints
if test_http_endpoint "http://localhost:5001/mcp" 200; then
    print_result "MCP HTTP endpoint availability" "PASS"
    
    # Test initialize
    init_response=$(curl -s -X POST "http://localhost:5001/mcp" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' 2>/dev/null)
    
    if echo "$init_response" | grep -q '"capabilities"'; then
        print_result "MCP initialize method" "PASS"
    else
        print_result "MCP initialize method" "FAIL" "No capabilities returned"
    fi
    
    # Test tools list
    tools_response=$(curl -s -X POST "http://localhost:5001/mcp" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' 2>/dev/null)
    
    if echo "$tools_response" | grep -q '"tools"'; then
        tool_count=$(echo "$tools_response" | grep -o '"name"' | wc -l)
        print_result "MCP tools list" "PASS"
        print_result "Available tools count" "INFO" "$tool_count tools registered"
    else
        print_result "MCP tools list" "FAIL" "No tools returned"
    fi
    
else
    print_result "MCP HTTP endpoint availability" "FAIL" "Server not responding"
fi

echo ""
echo "📋 PHASE 3: TOOL FUNCTIONALITY EVALUATION"
echo "-----------------------------------------"

# Test core tools
if test_http_endpoint "http://localhost:5001/mcp" 200; then
    
    # Test burp_info tool
    if test_mcp_tool "burp_info" "{}"; then
        print_result "burp_info tool" "PASS"
    else
        print_result "burp_info tool" "FAIL" "Tool call failed"
    fi
    
    # Test scan_target tool
    if test_mcp_tool "scan_target" '{"url":"https://example.com","scanType":"passive"}'; then
        print_result "scan_target tool" "PASS"
    else
        print_result "scan_target tool" "FAIL" "Tool call failed"
    fi
    
    # Test SSL interception setup
    if test_mcp_tool "setup_ssl_interception" '{"caType":"USE_BURP_CA"}'; then
        print_result "setup_ssl_interception tool" "PASS"
    else
        print_result "setup_ssl_interception tool" "FAIL" "Tool call failed"
    fi
    
    # Test browser session management
    if test_mcp_tool "manage_browser_session" '{"action":"create","targetUrl":"https://example.com"}'; then
        print_result "manage_browser_session tool" "PASS"
    else
        print_result "manage_browser_session tool" "FAIL" "Tool call failed"
    fi
    
    # Test OWASP Top 10 scanner
    if test_mcp_tool "scan_owasp_top10" '{"target_url":"https://example.com","categories":["injection","xss"]}'; then
        print_result "scan_owasp_top10 tool" "PASS"
    else
        print_result "scan_owasp_top10 tool" "FAIL" "Tool call failed"
    fi
    
else
    print_result "Tool functionality tests" "FAIL" "Server not available for testing"
fi

echo ""
echo "📋 PHASE 4: ADVANCED FEATURE EVALUATION"  
echo "---------------------------------------"

# Check for WebDriver dependencies
if ./gradlew dependencies | grep -q "selenium"; then
    print_result "Selenium WebDriver dependencies" "PASS"
else
    print_result "Selenium WebDriver dependencies" "FAIL" "Missing WebDriver dependencies"
fi

# Check for Chrome extension files
if [ -d "chrome-extension" ]; then
    print_result "Chrome extension directory" "PASS"
    
    if [ -f "chrome-extension/manifest.json" ]; then
        print_result "Chrome extension manifest" "PASS"
    else
        print_result "Chrome extension manifest" "FAIL" "Missing manifest.json"
    fi
else
    print_result "Chrome extension directory" "FAIL" "Directory not found"
fi

# Check for ML/AI dependencies
if ./gradlew dependencies | grep -q -E "(weka|ml|tensorflow|pytorch)"; then
    print_result "ML/AI dependencies" "PASS"
else
    print_result "ML/AI dependencies" "FAIL" "No ML libraries found"
fi

# Check browser availability for automation
if command -v chromium-browser > /dev/null || command -v google-chrome > /dev/null; then
    print_result "Chrome browser availability" "PASS"
else
    print_result "Chrome browser availability" "WARN" "No Chrome browser found"
fi

if command -v firefox > /dev/null; then
    print_result "Firefox browser availability" "PASS"
else
    print_result "Firefox browser availability" "WARN" "No Firefox browser found"
fi

echo ""
echo "📋 PHASE 5: INTEGRATION EVALUATION"
echo "----------------------------------"

# Check Claude Desktop config
claude_config="$HOME/.config/claude-desktop/claude_desktop_config.json"
if [ -f "$claude_config" ]; then
    if grep -q "burp-mcp-server" "$claude_config"; then
        print_result "Claude Desktop integration" "PASS"
    else
        print_result "Claude Desktop integration" "WARN" "Config exists but MCP not configured"
    fi
else
    print_result "Claude Desktop integration" "FAIL" "No Claude Desktop config found"
fi

# Check for BurpSuite integration files
if [ -f "setup-burp-live-integration.sh" ]; then
    print_result "BurpSuite integration script" "PASS"
else
    print_result "BurpSuite integration script" "FAIL" "Setup script missing"
fi

# Cleanup test server
if [ -n "$SERVER_PID" ]; then
    kill $SERVER_PID 2>/dev/null || true
    echo "Test server stopped"
fi

echo ""
echo "📊 EVALUATION SUMMARY"
echo "===================="
echo -e "Tests Passed: ${GREEN}$PASSED${NC}"
echo -e "Tests Failed: ${RED}$FAILED${NC}"
echo -e "Warnings: ${YELLOW}$WARNINGS${NC}"
echo "Total Tests: $((PASSED + FAILED + WARNINGS))"
echo ""

# Calculate overall health score
total_tests=$((PASSED + FAILED + WARNINGS))
if [ $total_tests -gt 0 ]; then
    health_score=$(( (PASSED * 100) / total_tests ))
    if [ $health_score -ge 80 ]; then
        echo -e "Overall Health: ${GREEN}$health_score%${NC} - Excellent ✅"
    elif [ $health_score -ge 60 ]; then
        echo -e "Overall Health: ${YELLOW}$health_score%${NC} - Good ⚠️"
    else
        echo -e "Overall Health: ${RED}$health_score%${NC} - Needs Work ❌"
    fi
fi

echo ""
echo "🎯 NEXT PHASE RECOMMENDATIONS"
echo "=============================="

if [ $FAILED -gt 5 ]; then
    echo "❗ Priority: Fix critical failures before advancing"
    echo "   Focus on build system and core functionality"
elif [ $WARNINGS -gt 3 ]; then
    echo "⚠️  Priority: Address warnings and missing dependencies"
    echo "   Ready for Phase 1 advanced feature implementation"
else
    echo "🚀 Priority: Begin advanced feature implementation"
    echo "   System is stable and ready for enhancement"
fi

echo ""
echo "📋 Recommended immediate actions:"
if [ $FAILED -gt 0 ]; then
    echo "1. Fix failed tests identified above"
fi
if ./gradlew dependencies | grep -q "selenium"; then
    echo "2. ✅ WebDriver dependencies are ready"
else
    echo "2. Add Selenium WebDriver dependencies to build.gradle"
fi
if [ ! -f "chrome-extension/manifest.json" ]; then
    echo "3. Create Chrome extension manifest and scripts"
fi
if [ $WARNINGS -gt 2 ]; then
    echo "4. Install missing browsers and system dependencies"
fi

echo ""
echo "For detailed next steps, see: NEXT-PHASE-EVALUATION.md"
echo "============================================="
