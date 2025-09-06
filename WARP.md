# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a Model Context Protocol (MCP) server that bridges Claude Desktop with BurpSuite security scanning capabilities. It implements the MCP specification to provide security scanning tools through conversational AI.

## Build System & Common Commands

### Building the Project
```bash
# Clean and build the shadow JAR (creates executable JAR with all dependencies)
./gradlew clean shadowJar

# Just build without cleaning
./gradlew shadowJar

# Compile Java sources only
./gradlew compileJava

# Run tests
./gradlew test

# Run the application directly (HTTP mode)
./gradlew run
```

### Running the Server
```bash
# Build and run HTTP server (recommended for development)
./start-server.sh build

# Run in HTTP mode (testing/debugging)
./start-server.sh http

# Run in stdio mode (for Claude Desktop integration)
./start-server.sh stdio

# Show help
./start-server.sh help
```

### Setup Commands
```bash
# Configure Claude Desktop integration automatically
./setup-claude-desktop.sh

# Check Java version (requires Java 17+)
java -version

# Install Java 17 on Ubuntu
sudo apt update && sudo apt install openjdk-17-jdk
```

## Architecture Overview

### Core Components

**McpServer.java** - Main server class that handles dual transport modes:
- **stdio mode**: JSON-RPC over stdin/stdout for Claude Desktop integration
- **HTTP mode**: REST server on localhost:5001 for testing and debugging

**McpProtocolHandler.java** - Implements MCP specification:
- Handles protocol negotiation (`initialize`)
- Manages tool discovery (`tools/list`) 
- Executes tool calls (`tools/call`)
- Provides resource access (`resources/list`, `resources/read`)

**BurpIntegration.java** - Security scanning interface:
- Currently provides mock data for development
- Designed to integrate with BurpSuite Montoya API
- Manages scan tasks, results, and proxy history

### Transport Architecture

The server implements a dual-transport pattern:

1. **stdio transport**: Direct JSON-RPC communication for Claude Desktop
2. **HTTP transport**: RESTful JSON-RPC over HTTP for testing

Both transports use identical message handling through the protocol handler.

### MCP Tools Available

- `scan_target`: Initiates security scans (passive/active/full)
- `get_scan_results`: Retrieves scan findings and vulnerabilities
- `proxy_history`: Accesses HTTP request/response history

### MCP Resources Available

- `burp://scan-queue`: Current scan queue status
- `burp://issues`: Discovered security issues

### Configuration System

The server uses environment variables for configuration:
- `BURP_MCP_LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARN, ERROR)
- `JAVA_HOME`: Java installation path

Claude Desktop configuration is managed via `~/.config/claude-desktop/claude_desktop_config.json`

## Development Patterns

### Error Handling
- Uses JSON-RPC 2.0 error codes consistently
- All exceptions are caught and converted to MCP error responses
- Comprehensive logging at appropriate levels

### Concurrency
- HTTP server uses fixed thread pool (4 threads)
- Thread-safe task storage using ConcurrentHashMap
- Proper resource cleanup with shutdown hooks

### JSON Processing
- Jackson ObjectMapper for all JSON serialization/deserialization
- Type-safe conversion between MCP message types
- Schema validation for tool parameters

### Protocol Compliance
- Implements MCP protocol version 2024-11-05
- Supports required capabilities (tools, resources)
- Proper initialization handshake

## Testing & Debugging

### Manual Testing HTTP Mode
```bash
# Start HTTP server
./start-server.sh http

# Test initialize
curl -X POST http://localhost:5001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# List available tools
curl -X POST http://localhost:5001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

### Debug Logging
```bash
# Enable debug logging
BURP_MCP_LOG_LEVEL=DEBUG ./start-server.sh stdio
```

### Testing with Claude Desktop
1. Run setup script: `./setup-claude-desktop.sh`
2. Restart Claude Desktop
3. Verify MCP server appears in available tools
4. Test with prompts like: "Please scan https://example.com for vulnerabilities"

## Deployment Considerations

### Java Runtime Requirements
- Requires OpenJDK 17 or later
- Uses Java 17+ features (switch expressions, var inference)
- Gradle toolchain ensures proper Java version

### Ubuntu Linux Specific
- All scripts are bash-based for Ubuntu/Linux environments
- Uses standard Ubuntu OpenJDK package paths
- Claude Desktop config follows Linux XDG standards

### JAR Packaging
- Shadow JAR includes all dependencies in single executable
- Main class: `com.burp.mcp.McpServer`
- Output: `build/libs/burp-mcp-server-1.0.0-all.jar`

## Security Integration Notes

### BurpSuite Integration
- Designed for BurpSuite Professional/Community Edition
- Uses Montoya API for deep integration (JAR in `libs/` directory)
- Current implementation provides mock data for development
- Production version would integrate with live BurpSuite instance

### MCP Security Model
- Server runs on localhost only (no external network access)
- All communication via secure JSON-RPC protocol
- No persistent storage of sensitive data
- Logs may contain request URLs (review log retention)

### Development vs Production
- Mock integration allows development without BurpSuite running
- Switch to live integration requires BurpSuite extension deployment
- HTTP mode enables testing without Claude Desktop dependency
