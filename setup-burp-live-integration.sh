#!/bin/bash

# BurpSuite Professional Live Integration Setup Script
# This script helps you set up Claude Desktop with live BurpSuite Professional integration

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BURP_EXTENSION_JAR="$PROJECT_DIR/build/libs/burp-mcp-server-1.0.0-burp-extension.jar"
CLAUDE_CONFIG_DIR="$HOME/.config/claude-desktop"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}  BurpSuite Professional Live Integration Setup${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo ""
}

check_burp_extension_jar() {
    if [ ! -f "$BURP_EXTENSION_JAR" ]; then
        echo -e "${RED}Error: BurpSuite extension JAR not found!${NC}"
        echo -e "${YELLOW}Building the extension JAR...${NC}"
        ./gradlew burpExtensionJar
        
        if [ ! -f "$BURP_EXTENSION_JAR" ]; then
            echo -e "${RED}Failed to build BurpSuite extension JAR${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ BurpSuite extension JAR found: $BURP_EXTENSION_JAR${NC}"
}

setup_claude_desktop_config() {
    echo -e "${YELLOW}Setting up Claude Desktop configuration for live integration...${NC}"
    
    # Create Claude Desktop config directory if it doesn't exist
    mkdir -p "$CLAUDE_CONFIG_DIR"
    
    # Create the live integration configuration
    cat > "$CLAUDE_CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "burp-mcp-server": {
      "command": "java",
      "args": [
        "-jar", 
        "/home/jojo/dev/burp-mcp-server/build/libs/burp-mcp-server-1.0.0-all.jar",
        "stdio",
        "--live-mode"
      ],
      "env": {
        "BURP_MCP_LOG_LEVEL": "INFO",
        "BURP_INTEGRATION_MODE": "LIVE",
        "BURP_API_HOST": "localhost",
        "BURP_API_PORT": "1337"
      }
    }
  },
  "prompts": [
    {
      "name": "live-burp-security-audit",
      "description": "Live security audit using BurpSuite Professional",
      "arguments": [
        {
          "name": "target_url",
          "description": "Target web application URL",
          "required": true
        }
      ],
      "template": "I need to perform a live security audit on {{target_url}} using BurpSuite Professional. Please help me:\n\n1. **Verify Live Integration**\n   - Check BurpSuite connection status\n   - Confirm all tools are available\n   - Verify proxy configuration\n\n2. **Live Traffic Analysis**\n   - Analyze real proxy traffic\n   - Review live site map data\n   - Monitor ongoing requests\n\n3. **Live Vulnerability Scanning**\n   - Start live security scans\n   - Monitor scan progress in real-time\n   - Review findings as they are discovered\n\n4. **Interactive Testing**\n   - Send requests to Repeater for manual testing\n   - Configure Intruder attacks with live payloads\n   - Use live encoding/decoding tools\n\n5. **Real-time Reporting**\n   - Generate reports from live scan data\n   - Export findings from BurpSuite\n   - Document live exploitation attempts\n\nThis audit will use live BurpSuite Professional data and functionality."
    }
  ]
}
EOF

    echo -e "${GREEN}✓ Claude Desktop configuration updated for live integration${NC}"
    echo -e "${YELLOW}Config file: $CLAUDE_CONFIG_FILE${NC}"
}

print_burp_setup_instructions() {
    echo -e "\n${YELLOW}=== BurpSuite Professional Setup Instructions ===${NC}"
    echo -e "1. ${GREEN}Open BurpSuite Professional${NC}"
    echo -e "2. ${GREEN}Go to Extensions → Installed${NC}"
    echo -e "3. ${GREEN}Click 'Add' to add a new extension${NC}"
    echo -e "4. ${GREEN}Select 'Java' extension type${NC}"
    echo -e "5. ${GREEN}Browse and select this JAR file:${NC}"
    echo -e "   ${BLUE}$BURP_EXTENSION_JAR${NC}"
    echo -e "6. ${GREEN}Click 'Next' to load the extension${NC}"
    echo -e "7. ${GREEN}Verify the extension loads without errors${NC}"
    echo -e "8. ${GREEN}Check the 'Output' tab for MCP server startup messages${NC}"
    echo ""
    echo -e "${YELLOW}Expected output in BurpSuite Output tab:${NC}"
    echo -e "${GREEN}[BurpMcpExtension] Extension loaded successfully${NC}"
    echo -e "${GREEN}[BurpMcpExtension] Starting MCP Server on port 1337...${NC}"
    echo -e "${GREEN}[BurpMcpExtension] MCP Server ready for Claude Desktop connection${NC}"
    echo ""
}

print_testing_instructions() {
    echo -e "${YELLOW}=== Testing Live Integration ===${NC}"
    echo -e "1. ${GREEN}Ensure BurpSuite Professional is running with the extension loaded${NC}"
    echo -e "2. ${GREEN}Restart Claude Desktop to pick up the new configuration${NC}"
    echo -e "3. ${GREEN}In Claude Desktop, try this command:${NC}"
    echo -e "   ${BLUE}\"Get BurpSuite connection status and available tools\"${NC}"
    echo -e "4. ${GREEN}You should see live connection details instead of mock data${NC}"
    echo -e "5. ${GREEN}Test a live scan with:${NC}"
    echo -e "   ${BLUE}\"Scan https://example.com for vulnerabilities using live BurpSuite\"${NC}"
    echo ""
}

print_troubleshooting() {
    echo -e "${YELLOW}=== Troubleshooting ===${NC}"
    echo -e "${RED}If the integration doesn't work:${NC}"
    echo -e "• ${GREEN}Check BurpSuite Output tab for error messages${NC}"
    echo -e "• ${GREEN}Verify Java 17+ is being used by BurpSuite${NC}"
    echo -e "• ${GREEN}Ensure no firewall blocking localhost:1337${NC}"
    echo -e "• ${GREEN}Restart both BurpSuite and Claude Desktop${NC}"
    echo -e "• ${GREEN}Check the extension is loaded and active in BurpSuite${NC}"
    echo ""
    echo -e "${YELLOW}Debug mode:${NC}"
    echo -e "Set BURP_MCP_LOG_LEVEL=DEBUG in Claude Desktop config for verbose logging"
    echo ""
}

print_next_steps() {
    echo -e "${BLUE}=== Next Steps ===${NC}"
    echo -e "1. ${GREEN}Load the BurpSuite extension using the instructions above${NC}"
    echo -e "2. ${GREEN}Restart Claude Desktop${NC}"
    echo -e "3. ${GREEN}Test the live integration${NC}"
    echo -e "4. ${GREEN}Start using Claude Desktop with live BurpSuite Professional!${NC}"
    echo ""
    echo -e "${GREEN}You can now perform real security testing with live data from BurpSuite Pro!${NC}"
}

# Main execution
print_banner
check_burp_extension_jar
setup_claude_desktop_config
print_burp_setup_instructions
print_testing_instructions
print_troubleshooting
print_next_steps

echo -e "\n${GREEN}Setup complete! Follow the instructions above to enable live integration.${NC}"
