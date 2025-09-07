#!/bin/bash

echo "🧪 Testing current Claude Desktop integration..."

# Check if Claude Desktop processes are running
echo "Checking Claude Desktop processes..."
if pgrep -f "claude-desktop" > /dev/null; then
    echo "✅ Claude Desktop is running"
else
    echo "❌ Claude Desktop is not running - please start it"
    exit 1
fi

# Check the latest MCP server log for recent entries
echo -e "\nChecking latest MCP server responses..."
latest_entry=$(tail -5 "/home/jojo/.config/Claude/logs/mcp-server-burp-mcp-server.log" | grep "prompts/list" | tail -1)

if echo "$latest_entry" | grep -q '"data":null'; then
    echo "❌ ISSUE: Latest log shows data:null field"
    echo "Latest entry: $latest_entry"
else
    echo "✅ SUCCESS: No data field found in latest error responses"
    if echo "$latest_entry" | grep -q "prompts/list"; then
        echo "Latest entry: $latest_entry"
    else
        echo "No recent prompts/list entries found (which is expected)"
    fi
fi

# Check JAR timestamp
echo -e "\nJAR file information:"
stat /home/jojo/dev/burp-mcp-server/build/libs/burp-mcp-server-1.0.0-all.jar | grep "Modify:"

echo -e "\n✅ Integration test completed"
echo "If Claude Desktop is running and showing the old error format,"
echo "try restarting Claude Desktop to pick up the latest JAR."
