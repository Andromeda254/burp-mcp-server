#!/bin/bash

# Claude Desktop MCP Setup Script for Ubuntu Linux
# This script configures Claude Desktop to work with the BurpSuite MCP Server

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_CONFIG_DIR="$HOME/.config/claude-desktop"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"

print_header() {
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${BLUE}  Claude Desktop MCP Setup - Ubuntu    ${NC}"
    echo -e "${BLUE}=======================================${NC}"
    echo
}

check_claude_desktop() {
    if ! command -v claude-desktop &> /dev/null; then
        echo -e "${YELLOW}Claude Desktop not found in PATH.${NC}"
        echo -e "${YELLOW}Please make sure Claude Desktop is installed.${NC}"
        echo
        echo "To install Claude Desktop on Ubuntu:"
        echo "1. Download the .deb file from https://claude.ai/download"
        echo "2. Install with: sudo dpkg -i claude-desktop-*.deb"
        echo "3. Or use the AppImage version"
        echo
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        echo -e "${GREEN}✓ Claude Desktop found${NC}"
    fi
}

create_config_directory() {
    echo -e "${YELLOW}Creating Claude Desktop config directory...${NC}"
    mkdir -p "$CLAUDE_CONFIG_DIR"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Config directory created: $CLAUDE_CONFIG_DIR${NC}"
    else
        echo -e "${RED}✗ Failed to create config directory${NC}"
        exit 1
    fi
}

detect_java_home() {
    # Try to detect JAVA_HOME automatically
    local java_home=""
    
    if [ -n "$JAVA_HOME" ]; then
        java_home="$JAVA_HOME"
    elif [ -d "/usr/lib/jvm/java-17-openjdk-amd64" ]; then
        java_home="/usr/lib/jvm/java-17-openjdk-amd64"
    elif [ -d "/usr/lib/jvm/java-11-openjdk-amd64" ]; then
        java_home="/usr/lib/jvm/java-11-openjdk-amd64"
    elif command -v java &> /dev/null; then
        # Try to find java home from java command
        java_home=$(java -XshowSettings:properties 2>&1 | grep 'java.home' | sed 's/.*= //')
    fi
    
    echo "$java_home"
}

create_config_file() {
    local java_home=$(detect_java_home)
    local jar_path="$PROJECT_DIR/build/libs/burp-mcp-server-1.0.0-all.jar"
    
    echo -e "${YELLOW}Creating Claude Desktop MCP configuration...${NC}"
    
    # Show detected values
    echo -e "${BLUE}Configuration details:${NC}"
    echo "  JAR Path: $jar_path"
    echo "  Java Home: $java_home"
    echo
    
    # Create the configuration
    cat > "$CLAUDE_CONFIG_FILE" << EOF
{
  "mcpServers": {
    "burp-mcp-server": {
      "command": "java",
      "args": [
        "-jar",
        "$jar_path",
        "--stdio"
      ],
      "env": {
        "JAVA_HOME": "$java_home",
        "BURP_MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
EOF
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Configuration file created: $CLAUDE_CONFIG_FILE${NC}"
    else
        echo -e "${RED}✗ Failed to create configuration file${NC}"
        exit 1
    fi
}

build_project() {
    echo -e "${YELLOW}Building MCP server JAR file...${NC}"
    
    cd "$PROJECT_DIR"
    
    if [ -f "./gradlew" ]; then
        ./gradlew shadowJar
    else
        gradle shadowJar
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Project built successfully${NC}"
    else
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
}

show_next_steps() {
    echo
    echo -e "${BLUE}=======================================${NC}"
    echo -e "${GREEN}✓ Setup Complete!${NC}"
    echo -e "${BLUE}=======================================${NC}"
    echo
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. Restart Claude Desktop to load the new configuration"
    echo "2. In Claude Desktop, you should see 'burp-mcp-server' available"
    echo "3. Test the connection by asking Claude about BurpSuite functionality"
    echo
    echo -e "${YELLOW}Available MCP Tools:${NC}"
    echo "  • scan_target - Initiate security scans"
    echo "  • get_scan_results - Retrieve scan results"
    echo "  • proxy_history - Get HTTP proxy history"
    echo
    echo -e "${YELLOW}Configuration Files:${NC}"
    echo "  • Claude Config: $CLAUDE_CONFIG_FILE"
    echo "  • Server Logs: $PROJECT_DIR/burp-mcp-server.log"
    echo
    echo -e "${YELLOW}Manual Testing:${NC}"
    echo "  • HTTP Mode: ./start-server.sh http"
    echo "  • Stdio Mode: ./start-server.sh stdio"
    echo
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo "  • Check logs in Claude Desktop console"
    echo "  • Verify Java 17+ is installed: java -version"
    echo "  • Test server manually: ./start-server.sh http"
}

# Main execution
print_header
check_claude_desktop
create_config_directory
build_project
create_config_file
show_next_steps
