#!/bin/bash

# BurpSuite MCP Server Startup Script for Ubuntu Linux
# This script can run the server in different modes

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR_FILE="$PROJECT_DIR/build/libs/burp-mcp-server-1.0.0-all.jar"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [MODE]"
    echo "Modes:"
    echo "  stdio    - Run in stdio mode (for Claude Desktop)"
    echo "  http     - Run HTTP server on localhost:5001 (default)"
    echo "  build    - Build the project first, then run HTTP server"
    echo "  help     - Show this help message"
}

check_java() {
    if ! command -v java &> /dev/null; then
        echo -e "${RED}Error: Java is not installed or not in PATH${NC}"
        echo "Please install Java 17:"
        echo "  sudo apt update"
        echo "  sudo apt install openjdk-17-jdk"
        exit 1
    fi
    
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
    if [ "$JAVA_VERSION" -lt "17" ]; then
        echo -e "${YELLOW}Warning: Java version is $JAVA_VERSION, but Java 17 is recommended${NC}"
    fi
}

build_project() {
    echo -e "${GREEN}Building project...${NC}"
    if [ -f "$PROJECT_DIR/gradlew" ]; then
        "$PROJECT_DIR/gradlew" shadowJar
    else
        gradle shadowJar
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed!${NC}"
        exit 1
    fi
}

check_jar_exists() {
    if [ ! -f "$JAR_FILE" ]; then
        echo -e "${YELLOW}JAR file not found. Building project...${NC}"
        build_project
    fi
}

run_stdio_mode() {
    echo -e "${GREEN}Starting MCP Server in stdio mode (for Claude Desktop)${NC}"
    echo -e "${YELLOW}Note: This mode expects JSON-RPC messages on stdin${NC}"
    java -jar "$JAR_FILE" --stdio
}

run_http_mode() {
    echo -e "${GREEN}Starting MCP Server in HTTP mode on localhost:5001${NC}"
    echo -e "${YELLOW}Access the server at: http://localhost:5001/mcp${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
    java -jar "$JAR_FILE"
}

# Main script logic
check_java

MODE=${1:-http}

case $MODE in
    stdio)
        check_jar_exists
        run_stdio_mode
        ;;
    http)
        check_jar_exists
        run_http_mode
        ;;
    build)
        build_project
        run_http_mode
        ;;
    help)
        print_usage
        ;;
    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        print_usage
        exit 1
        ;;
esac
