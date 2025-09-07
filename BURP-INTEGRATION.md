# BurpSuite Pro Integration Guide

This guide explains how to use the MCP Server with BurpSuite Pro for real security testing integration.

## Integration Modes

### 1. Standalone Mode (Default)
- Full mock data functionality
- No BurpSuite required
- Perfect for development and testing
- Complete tool coverage with realistic responses

### 2. BurpSuite Pro Extension Mode (Live Integration)
- Real BurpSuite Pro integration
- Live logging to BurpSuite output
- Enhanced tool functionality with actual BurpSuite data
- Professional security testing workflows

## Setting Up BurpSuite Pro Integration

### Prerequisites
- BurpSuite Professional (recommended) or Community Edition
- Java 17 or later
- Built MCP Server JAR file

### Installation Steps

1. **Build the Extension JAR**
   ```bash
   ./gradlew clean build
   # Extension JAR: build/libs/burp-mcp-server-1.0.0-all.jar
   ```

2. **Load Extension in BurpSuite Pro**
   - Open BurpSuite Pro
   - Go to Extensions → Add
   - Select "Java" as extension type
   - Choose the JAR file: `build/libs/burp-mcp-server-1.0.0-all.jar`
   - Click "Next" and "Close"

3. **Verify Integration**
   - Check BurpSuite Output tab for: "BurpSuite MCP Server Extension loaded successfully!"
   - Test with Claude Desktop using the MCP tools
   - Look for `[BurpMCP]` prefixed messages in BurpSuite Output

## Enhanced Tool Functionality in BurpSuite Pro Mode

### Scanner Tools

#### `scan_target`
**Standalone Mode:**
- Mock vulnerability data
- Simulated scan timing

**BurpSuite Pro Mode:**
- Live scan initiation logging
- Real scan progress tracking
- Enhanced scan results with BurpSuite context
- Scan configuration logged to BurpSuite output

**Usage:**
```bash
# Claude Desktop: "Start an active scan on https://example.com"
# BurpSuite Output will show:
# [BurpMCP] Starting active scan for: https://example.com
# [BurpMCP] Scan Task ID: abc-123-def
# [BurpMCP] Active scan will perform invasive testing
# [BurpMCP] Scan completed: abc-123-def
```

#### `get_scan_results`
**BurpSuite Pro Mode:**
- Enhanced findings with BurpSuite Pro context
- Live scan result retrieval logging
- Professional vulnerability reporting

### Proxy Tools

#### `proxy_history`
**Standalone Mode:**
- Generated mock HTTP traffic

**BurpSuite Pro Mode:**
- Enhanced logging of proxy access
- Real BurpSuite Pro context markers
- Security-relevant endpoint detection

**Usage:**
```bash
# Claude Desktop: "Show me the proxy history for example.com"
# BurpSuite Output will show:
# [BurpMCP] Accessing proxy history (limit: 100, filter: example.com)
# [BurpMCP] Retrieved 45 proxy history entries
```

### Repeater Tools

#### `send_to_repeater`
**Standalone Mode:**
- Mock Repeater integration

**BurpSuite Pro Mode:**
- Detailed request logging to BurpSuite output
- Complete header and body information
- Ready for manual recreation in Repeater

**Usage:**
```bash
# Claude Desktop: "Send a POST request to /api/login with credentials to Repeater"
# BurpSuite Output will show:
# [BurpMCP] Sending request to Repeater: POST https://api.example.com/login
# [BurpMCP] Custom headers: 2 headers
# [BurpMCP]   Content-Type: application/json
# [BurpMCP]   Authorization: Bearer token123
# [BurpMCP] Request body length: 45 characters
# [BurpMCP] Request ready for manual testing in Repeater tab
```

### Intruder Tools

#### `start_intruder_attack`
**Standalone Mode:**
- Mock attack simulation

**BurpSuite Pro Mode:**
- Complete attack configuration logging
- Payload list documentation
- Attack progress tracking
- Professional attack setup guidance

**Usage:**
```bash
# Claude Desktop: "Start a sniper attack on /login with username payloads"
# BurpSuite Output will show:
# [BurpMCP] Starting Intruder attack: sniper on https://example.com/login
# [BurpMCP] Attack ID: attack-456-xyz
# [BurpMCP] Method: POST
# [BurpMCP] Payload count: 100
# [BurpMCP] Payload positions: username
# [BurpMCP] Attack type: sniper
# [BurpMCP] Payloads to test:
# [BurpMCP]   1: admin
# [BurpMCP]   2: administrator
# [BurpMCP]   ... and 98 more payloads
# [BurpMCP] Intruder attack completed: attack-456-xyz
```

### Site Map Tools

#### `get_site_map`
**BurpSuite Pro Mode:**
- Live site map access logging
- Enhanced security context
- Real endpoint discovery tracking

**Usage:**
```bash
# Claude Desktop: "Get the site map for example.com"
# BurpSuite Output will show:
# [BurpMCP] Accessing site map data (filter: example.com)
# [BurpMCP] Retrieved 23 unique URLs from site map
```

### Decoder Tools
- Work identically in both modes
- Enhanced logging in BurpSuite Pro mode
- No functional differences

## Integration Benefits

### For Security Professionals
1. **Professional Workflow**: Seamless integration with existing BurpSuite Pro workflows
2. **Enhanced Logging**: All MCP activities logged to BurpSuite for audit trails
3. **Context Awareness**: Tools understand and work with live BurpSuite data
4. **Progress Tracking**: Real-time monitoring of scan and attack progress

### For Development Teams
1. **Dual Mode**: Use standalone for development, BurpSuite Pro for production testing
2. **Claude Desktop Integration**: Natural language security testing commands
3. **Professional Reporting**: Enhanced vulnerability reports with BurpSuite context
4. **Workflow Automation**: Automated security testing through conversational AI

## Troubleshooting

### Extension Not Loading
1. Check Java version (requires Java 17+)
2. Verify JAR file path and permissions
3. Check BurpSuite Errors tab for detailed error messages

### No MCP Output in BurpSuite
1. Verify extension loaded successfully
2. Test with simple `burp_info` command
3. Check BurpSuite Output tab (not Errors tab)

### Claude Desktop Not Connecting
1. Ensure MCP server is configured in Claude Desktop
2. Check stdio mode configuration
3. Verify JAR path in Claude Desktop config

## Security Considerations

### Data Privacy
- MCP server runs locally only
- No external network connections
- All data processed within BurpSuite environment

### Professional Use
- Suitable for penetration testing
- Enterprise security assessments
- Compliance and audit requirements
- Bug bounty programs

### Limitations
- Requires BurpSuite Pro for full functionality
- Some advanced BurpSuite features require manual setup
- Extension mode requires GUI access to BurpSuite

## Advanced Configuration

### Custom Logging Levels
Set environment variable:
```bash
export BURP_MCP_LOG_LEVEL=DEBUG
```

### Extension Configuration
The extension automatically detects BurpSuite Pro and enables enhanced features. No additional configuration required.

### Claude Desktop Templates
Use the enhanced prompt templates for professional security workflows:
- `comprehensive-web-security-audit`
- `api-security-testing` 
- `manual-penetration-testing`
- `incident-response-analysis`

## Support

For issues with BurpSuite Pro integration:
1. Check BurpSuite Output and Errors tabs
2. Enable DEBUG logging for detailed information
3. Verify extension loading in BurpSuite Extensions tab
4. Test standalone mode first to isolate issues

The MCP server provides full functionality in both standalone and BurpSuite Pro modes, with enhanced professional features when used as a BurpSuite extension.
