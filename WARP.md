# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is a comprehensive Model Context Protocol (MCP) server that provides full integration between Claude Desktop and BurpSuite Pro security testing tools. It implements the complete MCP specification to expose all major BurpSuite functionality through conversational AI, enabling natural language security testing workflows.

**Key Features:**
- Full BurpSuite Pro tool integration (Scanner, Proxy, Repeater, Intruder, Decoder, SiteMap)
- Dual deployment modes: Standalone server + BurpSuite extension
- Claude Desktop prompt templates for security testing workflows
- Java 17+ modern language features and best practices
- Gradle 8.1+ build system with advanced configurations

## Build System & Common Commands

### Building the Project
```bash
# Clean and build all JARs (standalone + BurpSuite extension)
./gradlew clean build

# Build shadow JAR for standalone use (includes all dependencies)
./gradlew shadowJar

# Build BurpSuite extension JAR specifically
./gradlew burpExtensionJar

# Compile with Java 17+ features enabled
./gradlew compileJava

# Run comprehensive test suite
./gradlew test

# Run the application directly (HTTP mode for testing)
./gradlew run

# Build with sources and javadoc JARs
./gradlew build -x test
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

**BurpIntegration.java** - Comprehensive BurpSuite Pro integration:
- Implements BurpExtension interface for native BurpSuite loading
- Full Montoya API integration with all BurpSuite Pro tools
- Manages Scanner, Proxy, Repeater, Intruder, Decoder, and SiteMap
- Dual mode: Mock data for standalone testing + Live BurpSuite integration
- Thread-safe operations with CompletableFuture async patterns

**BurpMcpExtension.java** - BurpSuite extension entry point:
- Native BurpSuite extension for direct plugin loading
- Async MCP server initialization within BurpSuite
- Real-time security event monitoring and callbacks
- Java 17+ record patterns for configuration management

### Transport Architecture

The server implements a dual-transport pattern:

1. **stdio transport**: Direct JSON-RPC communication for Claude Desktop
2. **HTTP transport**: RESTful JSON-RPC over HTTP for testing

Both transports use identical message handling through the protocol handler.

### MCP Tools Available

**Scanner Tools:**
- `scan_target`: Comprehensive security scans (passive/active/full)
- `get_scan_results`: Detailed vulnerability reports with remediation

**Proxy Tools:**
- `proxy_history`: HTTP traffic analysis with headers and content

**Repeater Tools:**
- `send_to_repeater`: Manual request testing and modification

**Intruder Tools:**
- `start_intruder_attack`: Automated attacks (sniper, battering ram, pitchfork, cluster bomb)

**Decoder Tools:**
- `decode_data`: Multi-format decoding (Base64, URL, HTML)
- `encode_data`: Multi-format encoding (Base64, URL, HTML)

**SiteMap Tools:**
- `get_site_map`: Complete application structure discovery

**Utility Tools:**
- `burp_info`: Integration status and feature availability

### MCP Resources Available

- `burp://scan-queue`: Current scan queue status
- `burp://issues`: Discovered security issues

### Configuration System

The server uses environment variables for configuration:
- `BURP_MCP_LOG_LEVEL`: Logging verbosity (DEBUG, INFO, WARN, ERROR)
- `JAVA_HOME`: Java installation path

Claude Desktop configuration is managed via `~/.config/claude-desktop/claude_desktop_config.json`

### Claude Desktop Prompt Templates

The project includes specialized prompt templates for security testing workflows:

- `web-security-audit`: Comprehensive web application security audit
- `api-security-test`: Specialized REST API security testing
- `quick-vulnerability-scan`: Fast vulnerability identification
- `manual-penetration-test`: Guided manual security testing
- `security-issue-analysis`: Detailed vulnerability analysis and reporting
- `burp-workflow-automation`: Automated security testing workflows

Use the enhanced configuration: `claude-desktop-config-enhanced.json`

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
