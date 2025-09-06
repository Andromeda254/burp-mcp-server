# BurpSuite MCP Server Extension

A Model Context Protocol (MCP) server extension for BurpSuite that enables Claude Desktop to interact with BurpSuite security scanning capabilities using the Montoya API.

## Overview

This project provides a bridge between Claude Desktop and BurpSuite, allowing you to:
- Initiate security scans through Claude Desktop
- Retrieve scan results and security findings
- Access proxy history and HTTP traffic analysis
- Manage scanning tasks through conversational AI

## Features

- **MCP Protocol Support**: Full compliance with MCP specification
- **Dual Transport Modes**: 
  - stdio mode for Claude Desktop integration
  - HTTP server mode for standalone testing
- **BurpSuite Integration**: Uses Montoya API for deep integration
- **Security Tools**:
  - `scan_target`: Launch passive, active, or full security scans
  - `get_scan_results`: Retrieve detailed scan results
  - `proxy_history`: Access HTTP request/response history
- **Resource Access**: Real-time access to scan queues and security issues

## Requirements

### System Requirements
- **Operating System**: Ubuntu 24.04 LTS (or compatible Linux)
- **Java**: OpenJDK 17 or later
- **BurpSuite**: Professional or Community Edition
- **Claude Desktop**: Latest version

### Dependencies
- Gradle 8.1+
- BurpSuite Montoya API
- Jackson JSON processing
- SLF4J logging

## Installation

### 1. Clone and Build

```bash
# Clone the repository
git clone <your-repo-url>
cd burp-mcp-server

# Build the project
./gradlew shadowJar
```

### 2. Install Java 17 (if not already installed)

```bash
sudo apt update
sudo apt install openjdk-17-jdk
```

### 3. Configure Claude Desktop

Run the automated setup script:

```bash
./setup-claude-desktop.sh
```

Or manually configure by editing `~/.config/claude-desktop/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "burp-mcp-server": {
      "command": "java",
      "args": [
        "-jar",
        "/home/jojo/dev/burp-mcp-server/build/libs/burp-mcp-server-1.0.0-all.jar",
        "--stdio"
      ],
      "env": {
        "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
        "BURP_MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## Usage

### Running the Server

#### For Claude Desktop (stdio mode)
```bash
./start-server.sh stdio
```

#### For Testing (HTTP mode)
```bash
./start-server.sh http
# Server will be available at http://localhost:5001/mcp
```

#### Build and Run
```bash
./start-server.sh build
```

### Available MCP Tools

#### 1. scan_target
Initiate a security scan on a target URL.

**Parameters:**
- `url` (required): Target URL to scan
- `scanType` (optional): Type of scan (`passive`, `active`, `full`)

**Example Claude Desktop usage:**
> "Please scan https://example.com for security vulnerabilities using a full scan"

#### 2. get_scan_results
Retrieve results from previous scans.

**Parameters:**
- `taskId` (optional): Specific scan task ID

**Example:**
> "Show me the results from my recent security scans"

#### 3. proxy_history
Get HTTP request/response history from BurpSuite proxy.

**Parameters:**
- `limit` (optional): Maximum number of entries (default: 100)
- `filter` (optional): URL filter pattern

**Example:**
> "Show me the last 50 HTTP requests that went through the proxy"

### Available Resources

#### burp://scan-queue
Access current scan queue status and active tasks.

#### burp://issues
Access discovered security issues and vulnerabilities.

## BurpSuite Integration

### As a BurpSuite Extension

1. Open BurpSuite Professional
2. Go to Extensions → Installed
3. Add → Select JAR file → Choose the built JAR file
4. The extension will integrate with BurpSuite's scanning engine

### Standalone Mode

The server can run independently and provide mock data for testing purposes when BurpSuite is not available.

## Configuration

### Logging Configuration

Edit `src/main/resources/logback.xml` to adjust logging levels:

```xml
<root level="INFO">
    <appender-ref ref="CONSOLE"/>
    <appender-ref ref="FILE"/>
</root>
```

### Server Configuration

Environment variables:
- `BURP_MCP_LOG_LEVEL`: Set logging level (DEBUG, INFO, WARN, ERROR)
- `JAVA_HOME`: Java installation directory

## Development

### Project Structure

```
burp-mcp-server/
├── src/main/java/com/burp/mcp/
│   ├── McpServer.java              # Main server class
│   ├── model/
│   │   └── McpMessage.java         # MCP message models
│   └── protocol/
│       ├── McpProtocolHandler.java # Protocol implementation
│       └── BurpIntegration.java    # BurpSuite integration
├── src/main/resources/
│   └── logback.xml                 # Logging configuration
├── build.gradle                    # Gradle build configuration
├── start-server.sh                 # Server startup script
└── setup-claude-desktop.sh        # Claude Desktop setup script
```

### Building from Source

```bash
# Clean build
./gradlew clean

# Compile only
./gradlew compileJava

# Run tests
./gradlew test

# Build shadow JAR
./gradlew shadowJar

# Build and run
./gradlew run
```

### Java 17 Best Practices

This project follows Java 17 best practices:
- Uses modern switch expressions
- Leverages var for type inference where appropriate
- Implements proper resource management with try-with-resources
- Uses the latest Jackson features for JSON processing

## Troubleshooting

### Common Issues

#### Java Version Issues
```bash
# Check Java version
java -version

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```

#### Claude Desktop Connection Issues
1. Check Claude Desktop logs
2. Verify the configuration file path
3. Test server manually: `./start-server.sh http`
4. Check server logs: `tail -f burp-mcp-server.log`

#### Build Issues
```bash
# Clean and rebuild
./gradlew clean shadowJar

# Check Gradle version
./gradlew --version
```

### Debug Mode

Run with debug logging:
```bash
BURP_MCP_LOG_LEVEL=DEBUG ./start-server.sh stdio
```

### Testing MCP Protocol

You can test the MCP protocol manually using curl:

```bash
# Start HTTP server
./start-server.sh http

# Test initialize
curl -X POST http://localhost:5001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# Test tools list
curl -X POST http://localhost:5001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Security Considerations

- The server runs on localhost only by default
- All communication uses JSON-RPC 2.0 protocol
- BurpSuite integration follows security best practices
- Logs may contain sensitive information - review log retention policies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes following Java 17 best practices
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review server logs
3. Test with HTTP mode for debugging
4. Open an issue with detailed information

## Version History

- **1.0.0**: Initial release with MCP protocol support and BurpSuite integration
  - stdio and HTTP transport modes
  - Basic scanning tools
  - Claude Desktop integration
  - Ubuntu Linux support
