package com.burp.mcp.protocol;

import com.burp.mcp.model.McpMessage;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * Handles MCP protocol messages and integrates with BurpSuite functionality
 */
public class McpProtocolHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(McpProtocolHandler.class);
    private final ObjectMapper objectMapper;
    private final BurpIntegration burpIntegration;
    
    public McpProtocolHandler(BurpIntegration burpIntegration) {
        // Configure ObjectMapper to exclude null values for minimal JSON responses
        this.objectMapper = new ObjectMapper();
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        this.burpIntegration = burpIntegration;
    }
    
    public McpMessage handleRequest(McpMessage request) {
        if (request.getMethod() == null) {
            return createErrorResponse(request.getId(), -32600, "Invalid Request");
        }
        
        // Handle explicitly unsupported methods with proper error responses
        if (isUnsupportedMethod(request.getMethod())) {
            return createMethodNotFoundError(request.getId(), request.getMethod());
        }
        
        try {
            return switch (request.getMethod()) {
                case "initialize" -> handleInitialize(request);
                case "tools/list" -> handleToolsList(request);
                case "tools/call" -> handleToolsCall(request);
                case "resources/list" -> handleResourcesList(request);
                case "resources/read" -> handleResourcesRead(request);
                default -> createErrorResponse(request.getId(), -32601, 
                    "Method not found: " + request.getMethod());
            };
        } catch (Exception e) {
            logger.error("Error handling request: {}", request.getMethod(), e);
            return createErrorResponse(request.getId(), -32603, 
                "Internal error: " + e.getMessage());
        }
    }
    
    private McpMessage handleInitialize(McpMessage request) {
        Map<String, Object> result = new HashMap<>();
        result.put("protocolVersion", "2024-11-05");
        
        // Only declare tools and resources capabilities, omit prompts
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("tools", Map.of("listChanged", true));
        capabilities.put("resources", Map.of("subscribe", true, "listChanged", true));
        result.put("capabilities", capabilities);
        
        Map<String, Object> serverInfo = new HashMap<>();
        serverInfo.put("name", "burp-mcp-server");
        serverInfo.put("version", "1.0.0");
        result.put("serverInfo", serverInfo);
        
        return createSuccessResponse(request.getId(), result);
    }
    
    private McpMessage handleToolsList(McpMessage request) {
        List<Map<String, Object>> tools = List.of(
            // UTILITY TOOLS
            Map.of(
                "name", "burp_info",
                "description", "Get information about the BurpSuite connection and current status",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of()
                )
            ),
            
            // SCANNER TOOLS
            Map.of(
                "name", "scan_target",
                "description", "Initiate a comprehensive security scan on a target URL with advanced options",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of(
                            "type", "string", 
                            "description", "Target URL to scan (e.g., https://example.com or https://example.com/path)"
                        ),
                        "scanType", Map.of(
                            "type", "string",
                            "description", "Type of scan to perform",
                            "enum", List.of("passive", "active", "full", "targeted", "light", "comprehensive"),
                            "default", "active"
                        ),
                        "scope", Map.of(
                            "type", "string",
                            "description", "Scan scope limitation",
                            "enum", List.of("single_page", "directory", "subdomain", "domain", "unlimited"),
                            "default", "directory"
                        ),
                        "maxDepth", Map.of(
                            "type", "integer",
                            "description", "Maximum crawl depth (1-10)",
                            "minimum", 1,
                            "maximum", 10,
                            "default", 3
                        ),
                        "includeStatic", Map.of(
                            "type", "boolean",
                            "description", "Include static resources (CSS, JS, images) in scan",
                            "default", false
                        ),
                        "aggressive", Map.of(
                            "type", "boolean",
                            "description", "Enable aggressive scanning modes (may be more detectable)",
                            "default", false
                        ),
                        "skipSlowChecks", Map.of(
                            "type", "boolean",
                            "description", "Skip time-intensive vulnerability checks for faster results",
                            "default", false
                        ),
                        "authentication", Map.of(
                            "type", "object",
                            "description", "Authentication credentials for authenticated scanning",
                            "properties", Map.of(
                                "type", Map.of(
                                    "type", "string",
                                    "enum", List.of("basic", "cookie", "bearer", "custom")
                                ),
                                "username", Map.of(
                                    "type", "string"
                                ),
                                "password", Map.of(
                                    "type", "string"
                                ),
                                "cookieName", Map.of(
                                    "type", "string"
                                ),
                                "cookieValue", Map.of(
                                    "type", "string"
                                ),
                                "bearerToken", Map.of(
                                    "type", "string"
                                ),
                                "customHeader", Map.of(
                                    "type", "string",
                                    "description", "Custom header in format 'Header-Name: Value'"
                                )
                            )
                        )
                    ),
                    "required", List.of("url")
                )
            ),
            
            // PROXY TOOLS
            Map.of(
                "name", "proxy_history",
                "description", "Retrieve HTTP traffic history from BurpSuite proxy",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "limit", Map.of(
                            "type", "integer",
                            "description", "Maximum number of requests to return",
                            "minimum", 1,
                            "maximum", 500,
                            "default", 100
                        ),
                        "filter", Map.of(
                            "type", "string",
                            "description", "URL filter pattern (optional)"
                        )
                    )
                )
            ),
            
            // REPEATER TOOLS
            Map.of(
                "name", "send_to_repeater",
                "description", "Send a custom HTTP request to BurpSuite Repeater for manual testing",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of(
                            "type", "string",
                            "description", "Target URL for the request"
                        ),
                        "method", Map.of(
                            "type", "string",
                            "description", "HTTP method",
                            "enum", List.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
                        ),
                        "headers", Map.of(
                            "type", "object",
                            "description", "HTTP headers as key-value pairs",
                            "additionalProperties", Map.of("type", "string")
                        ),
                        "body", Map.of(
                            "type", "string",
                            "description", "Request body content (for POST, PUT, etc.)"
                        )
                    ),
                    "required", List.of("url", "method")
                )
            ),
            
            // DECODER TOOLS
            Map.of(
                "name", "decode_data",
                "description", "Decode data using various encoding formats",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "data", Map.of(
                            "type", "string",
                            "description", "Data to decode"
                        ),
                        "encoding", Map.of(
                            "type", "string",
                            "description", "Encoding format to decode from",
                            "enum", List.of("base64", "url", "html", "ascii_hex", "gzip", "utf8")
                        )
                    ),
                    "required", List.of("data", "encoding")
                )
            ),
            Map.of(
                "name", "encode_data",
                "description", "Encode data using various encoding formats",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "data", Map.of(
                            "type", "string",
                            "description", "Data to encode"
                        ),
                        "encoding", Map.of(
                            "type", "string",
                            "description", "Encoding format to encode to",
                            "enum", List.of("base64", "url", "html", "ascii_hex", "gzip", "utf8")
                        )
                    ),
                    "required", List.of("data", "encoding")
                )
            ),
            
            // SCANNER TOOLS (Additional)
            Map.of(
                "name", "get_scan_results",
                "description", "Retrieve and analyze results from a previous security scan with filtering options",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "taskId", Map.of(
                            "type", "string",
                            "description", "Scan task ID (optional - returns all if omitted)"
                        ),
                        "severityFilter", Map.of(
                            "type", "array",
                            "description", "Filter by severity levels",
                            "items", Map.of(
                                "type", "string",
                                "enum", List.of("Critical", "High", "Medium", "Low", "Info")
                            )
                        ),
                        "vulnerabilityType", Map.of(
                            "type", "array",
                            "description", "Filter by vulnerability types",
                            "items", Map.of(
                                "type", "string",
                                "enum", List.of("XSS", "SQLi", "IDOR", "CSRF", "XXE", "LFI", "RFI", "Command Injection", "Authentication", "Authorization", "Session", "Cryptography")
                            )
                        ),
                        "includeRemediation", Map.of(
                            "type", "boolean",
                            "description", "Include detailed remediation advice",
                            "default", true
                        ),
                        "includeEvidence", Map.of(
                            "type", "boolean",
                            "description", "Include proof-of-concept evidence",
                            "default", true
                        ),
                        "sortBy", Map.of(
                            "type", "string",
                            "description", "Sort results by field",
                            "enum", List.of("severity", "confidence", "name", "url"),
                            "default", "severity"
                        ),
                        "format", Map.of(
                            "type", "string",
                            "description", "Output format for results",
                            "enum", List.of("detailed", "summary", "csv", "json"),
                            "default", "detailed"
                        ),
                        "limit", Map.of(
                            "type", "integer",
                            "description", "Maximum number of results to return",
                            "minimum", 1,
                            "maximum", 1000,
                            "default", 100
                        )
                    )
                )
            ),
            
            // INTRUDER TOOLS
            Map.of(
                "name", "start_intruder_attack",
                "description", "Launch an automated Intruder attack with customizable payloads",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of(
                            "type", "string",
                            "description", "Target URL for the attack"
                        ),
                        "method", Map.of(
                            "type", "string",
                            "description", "HTTP method",
                            "enum", List.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
                        ),
                        "body", Map.of(
                            "type", "string",
                            "description", "Request body (optional)"
                        ),
                        "headers", Map.of(
                            "type", "object",
                            "description", "HTTP headers as key-value pairs",
                            "additionalProperties", Map.of("type", "string")
                        ),
                        "attackType", Map.of(
                            "type", "string",
                            "description", "Type of Intruder attack",
                            "enum", List.of("sniper", "battering_ram", "pitchfork", "cluster_bomb")
                        ),
                        "payloadPositions", Map.of(
                            "type", "array",
                            "description", "Positions to insert payloads (e.g., parameter names)",
                            "items", Map.of("type", "string")
                        ),
                        "payloads", Map.of(
                            "type", "array",
                            "description", "List of payload values to test",
                            "items", Map.of("type", "string")
                        )
                    ),
                    "required", List.of("url", "method", "attackType", "payloads")
                )
            ),
            
            // SITEMAP TOOLS
            Map.of(
                "name", "get_site_map",
                "description", "Retrieve the discovered site map showing all application endpoints",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "urlFilter", Map.of(
                            "type", "string",
                            "description", "Filter results by URL pattern (optional)"
                        )
                    )
                )
            )
        );
        
        return createSuccessResponse(request.getId(), Map.of("tools", tools));
    }
    
    private McpMessage handleToolsCall(McpMessage request) {
        var params = objectMapper.convertValue(request.getParams(), JsonNode.class);
        var toolName = params.get("name").asText();
        var arguments = params.get("arguments");
        
        return switch (toolName) {
            // UTILITY TOOLS
            case "burp_info" -> handleBurpInfo(request.getId(), arguments);
            
            // SCANNER TOOLS
            case "scan_target" -> handleScanTarget(request.getId(), arguments);
            case "get_scan_results" -> handleGetScanResults(request.getId(), arguments);
            
            // PROXY TOOLS
            case "proxy_history" -> handleProxyHistory(request.getId(), arguments);
            
            // REPEATER TOOLS
            case "send_to_repeater" -> handleSendToRepeater(request.getId(), arguments);
            
            // INTRUDER TOOLS
            case "start_intruder_attack" -> handleStartIntruderAttack(request.getId(), arguments);
            
            // DECODER TOOLS
            case "decode_data" -> handleDecodeData(request.getId(), arguments);
            case "encode_data" -> handleEncodeData(request.getId(), arguments);
            
            // SITEMAP TOOLS
            case "get_site_map" -> handleGetSiteMap(request.getId(), arguments);
            
            default -> createErrorResponse(request.getId(), -32602, 
                "Unknown tool: " + toolName);
        };
    }
    
    // ===== SCANNER TOOL HANDLERS =====
    
    private McpMessage handleScanTarget(Object id, JsonNode arguments) {
        var url = arguments.get("url").asText();
        var scanType = arguments.has("scanType") ? arguments.get("scanType").asText() : "active";
        
        // Parse advanced scan configuration
        var scanConfig = new HashMap<String, Object>();
        scanConfig.put("url", url);
        scanConfig.put("scanType", scanType);
        scanConfig.put("scope", arguments.has("scope") ? arguments.get("scope").asText() : "directory");
        scanConfig.put("maxDepth", arguments.has("maxDepth") ? arguments.get("maxDepth").asInt() : 3);
        scanConfig.put("includeStatic", arguments.has("includeStatic") ? arguments.get("includeStatic").asBoolean() : false);
        scanConfig.put("aggressive", arguments.has("aggressive") ? arguments.get("aggressive").asBoolean() : false);
        scanConfig.put("skipSlowChecks", arguments.has("skipSlowChecks") ? arguments.get("skipSlowChecks").asBoolean() : false);
        
        // Parse authentication if provided
        Map<String, String> authConfig = null;
        if (arguments.has("authentication") && arguments.get("authentication").isObject()) {
            authConfig = new HashMap<>();
            var authNode = arguments.get("authentication");
            if (authNode.has("type")) authConfig.put("type", authNode.get("type").asText());
            if (authNode.has("username")) authConfig.put("username", authNode.get("username").asText());
            if (authNode.has("password")) authConfig.put("password", authNode.get("password").asText());
            if (authNode.has("cookieName")) authConfig.put("cookieName", authNode.get("cookieName").asText());
            if (authNode.has("cookieValue")) authConfig.put("cookieValue", authNode.get("cookieValue").asText());
            if (authNode.has("bearerToken")) authConfig.put("bearerToken", authNode.get("bearerToken").asText());
            if (authNode.has("customHeader")) authConfig.put("customHeader", authNode.get("customHeader").asText());
            scanConfig.put("authentication", authConfig);
        }
        
        try {
            var taskId = burpIntegration.startAdvancedScan(scanConfig);
            
            var responseText = buildScanStartResponse(scanConfig, taskId);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", responseText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to start {} scan for {}", scanType, url, e);
            return createErrorResponse(id, -32603, "Failed to start scan: " + e.getMessage());
        }
    }
    
    private String buildScanStartResponse(Map<String, Object> scanConfig, String taskId) {
        var sb = new StringBuilder();
        sb.append("🚀 Advanced Security Scan Started\n");
        sb.append("=".repeat(40)).append("\n\n");
        
        sb.append("📋 Scan Configuration:\n");
        sb.append("   URL: %s\n".formatted(scanConfig.get("url")));
        sb.append("   Type: %s\n".formatted(scanConfig.get("scanType")));
        sb.append("   Scope: %s\n".formatted(scanConfig.get("scope")));
        sb.append("   Max Depth: %s\n".formatted(scanConfig.get("maxDepth")));
        sb.append("   Include Static: %s\n".formatted(scanConfig.get("includeStatic")));
        sb.append("   Aggressive Mode: %s\n".formatted(scanConfig.get("aggressive")));
        sb.append("   Skip Slow Checks: %s\n".formatted(scanConfig.get("skipSlowChecks")));
        
        if (scanConfig.containsKey("authentication")) {
            @SuppressWarnings("unchecked")
            var auth = (Map<String, String>) scanConfig.get("authentication");
            sb.append("   Authentication: %s\n".formatted(auth.get("type")));
        }
        
        sb.append("\n🎯 Task ID: %s\n\n".formatted(taskId));
        
        // Add scan type specific information
        switch (scanConfig.get("scanType").toString()) {
            case "passive" -> sb.append("📊 Passive scan will analyze existing proxy traffic without sending new requests.\n");
            case "active" -> sb.append("🔍 Active scan will probe for vulnerabilities by sending test requests.\n");
            case "full" -> sb.append("🔍 Full scan combines crawling, passive analysis, and active vulnerability testing.\n");
            case "targeted" -> sb.append("🎯 Targeted scan focuses on specific vulnerability classes for faster results.\n");
            case "light" -> sb.append("⚡ Light scan performs essential checks with minimal impact.\n");
            case "comprehensive" -> sb.append("🔬 Comprehensive scan includes all available security tests (may take longer).\n");
        }
        
        sb.append("\n✅ The scan is now running in BurpSuite. Check the Dashboard > Tasks for progress.\n");
        sb.append("💡 Use 'get_scan_results' with task ID %s to retrieve results when complete.".formatted(taskId));
        
        return sb.toString();
    }
    
    private McpMessage handleGetScanResults(Object id, JsonNode arguments) {
        var taskId = arguments.has("taskId") ? arguments.get("taskId").asText() : null;
        
        // Parse filtering and formatting options
        var filterConfig = new HashMap<String, Object>();
        filterConfig.put("taskId", taskId);
        
        if (arguments.has("severityFilter") && arguments.get("severityFilter").isArray()) {
            var severities = new ArrayList<String>();
            arguments.get("severityFilter").forEach(node -> severities.add(node.asText()));
            filterConfig.put("severityFilter", severities);
        }
        
        if (arguments.has("vulnerabilityType") && arguments.get("vulnerabilityType").isArray()) {
            var vulnTypes = new ArrayList<String>();
            arguments.get("vulnerabilityType").forEach(node -> vulnTypes.add(node.asText()));
            filterConfig.put("vulnerabilityType", vulnTypes);
        }
        
        filterConfig.put("includeRemediation", arguments.has("includeRemediation") ? arguments.get("includeRemediation").asBoolean() : true);
        filterConfig.put("includeEvidence", arguments.has("includeEvidence") ? arguments.get("includeEvidence").asBoolean() : true);
        filterConfig.put("sortBy", arguments.has("sortBy") ? arguments.get("sortBy").asText() : "severity");
        filterConfig.put("format", arguments.has("format") ? arguments.get("format").asText() : "detailed");
        filterConfig.put("limit", arguments.has("limit") ? arguments.get("limit").asInt() : 100);
        
        try {
            var results = burpIntegration.getFilteredScanResults(filterConfig);
            var resultText = formatEnhancedScanResults(results, filterConfig);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", resultText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to get scan results for task {}", taskId, e);
            return createErrorResponse(id, -32603, "Failed to retrieve scan results: " + e.getMessage());
        }
    }
    
    // ===== PROXY TOOL HANDLERS =====
    
    private McpMessage handleProxyHistory(Object id, JsonNode arguments) {
        var limit = arguments.has("limit") ? arguments.get("limit").asInt() : 100;
        var filter = arguments.has("filter") ? arguments.get("filter").asText() : null;
        
        try {
            var history = burpIntegration.getProxyHistory(limit, filter);
            var historyText = formatProxyHistory(history, limit, filter);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", historyText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to get proxy history", e);
            return createErrorResponse(id, -32603, "Failed to retrieve proxy history: " + e.getMessage());
        }
    }
    
    // ===== REPEATER TOOL HANDLERS =====
    
    private McpMessage handleSendToRepeater(Object id, JsonNode arguments) {
        var url = arguments.get("url").asText();
        var method = arguments.get("method").asText();
        var body = arguments.has("body") ? arguments.get("body").asText() : null;
        
        Map<String, String> headers = null;
        if (arguments.has("headers") && arguments.get("headers").isObject()) {
            headers = new HashMap<>();
            var headersNode = arguments.get("headers");
            final var finalHeaders = headers; // Make effectively final for lambda
            headersNode.fieldNames().forEachRemaining(fieldName -> 
                finalHeaders.put(fieldName, headersNode.get(fieldName).asText())
            );
        }
        
        try {
            var result = burpIntegration.sendToRepeater(url, method, body, headers);
            var responseText = """
                Request sent to BurpSuite Repeater successfully!
                URL: %s
                Method: %s
                Status: %s
                %s
                You can now manually test and modify the request in BurpSuite Repeater.
                """.formatted(url, method, result.get("status"), result.get("message"));
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", responseText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to send request to Repeater", e);
            return createErrorResponse(id, -32603, "Failed to send to Repeater: " + e.getMessage());
        }
    }
    
    // ===== INTRUDER TOOL HANDLERS =====
    
    private McpMessage handleStartIntruderAttack(Object id, JsonNode arguments) {
        var url = arguments.get("url").asText();
        var method = arguments.get("method").asText();
        var body = arguments.has("body") ? arguments.get("body").asText() : null;
        var attackType = arguments.get("attackType").asText();
        
        // Parse headers
        Map<String, String> headers = null;
        if (arguments.has("headers") && arguments.get("headers").isObject()) {
            headers = new HashMap<>();
            var headersNode = arguments.get("headers");
            final var finalHeaders = headers; // Make effectively final for lambda
            headersNode.fieldNames().forEachRemaining(fieldName -> 
                finalHeaders.put(fieldName, headersNode.get(fieldName).asText())
            );
        }
        
        // Parse payload positions
        var payloadPositions = new ArrayList<String>();
        if (arguments.has("payloadPositions") && arguments.get("payloadPositions").isArray()) {
            arguments.get("payloadPositions").forEach(node -> payloadPositions.add(node.asText()));
        }
        
        // Parse payloads
        var payloads = new ArrayList<String>();
        arguments.get("payloads").forEach(node -> payloads.add(node.asText()));
        
        try {
            var attackId = burpIntegration.startIntruderAttack(url, method, body, headers, payloadPositions, payloads, attackType);
            var responseText = """
                Intruder attack launched successfully!
                URL: %s
                Method: %s
                Attack Type: %s
                Payloads: %d items
                Attack ID: %s
                The attack is now running in BurpSuite Intruder. Check the Intruder tab for results.
                """.formatted(url, method, attackType, payloads.size(), attackId);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", responseText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to start Intruder attack", e);
            return createErrorResponse(id, -32603, "Failed to start Intruder attack: " + e.getMessage());
        }
    }
    
    // ===== DECODER TOOL HANDLERS =====
    
    private McpMessage handleDecodeData(Object id, JsonNode arguments) {
        var data = arguments.get("data").asText();
        var encoding = arguments.get("encoding").asText();
        
        try {
            var result = burpIntegration.decodeData(data, encoding);
            var responseText = formatDecoderResult(result, "Decoded");
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", responseText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to decode data with encoding {}", encoding, e);
            return createErrorResponse(id, -32603, "Failed to decode data: " + e.getMessage());
        }
    }
    
    private McpMessage handleEncodeData(Object id, JsonNode arguments) {
        var data = arguments.get("data").asText();
        var encoding = arguments.get("encoding").asText();
        
        try {
            var result = burpIntegration.encodeData(data, encoding);
            var responseText = formatDecoderResult(result, "Encoded");
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", responseText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to encode data with encoding {}", encoding, e);
            return createErrorResponse(id, -32603, "Failed to encode data: " + e.getMessage());
        }
    }
    
    // ===== SITEMAP TOOL HANDLERS =====
    
    private McpMessage handleGetSiteMap(Object id, JsonNode arguments) {
        var urlFilter = arguments.has("urlFilter") ? arguments.get("urlFilter").asText() : null;
        
        try {
            var siteMap = burpIntegration.getSiteMap(urlFilter);
            var siteMapText = formatSiteMap(siteMap, urlFilter);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", siteMapText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to get site map", e);
            return createErrorResponse(id, -32603, "Failed to retrieve site map: " + e.getMessage());
        }
    }
    
    // ===== UTILITY TOOL HANDLERS =====
    
    private McpMessage handleBurpInfo(Object id, JsonNode arguments) {
        try {
            var info = burpIntegration.getBurpInfo();
            var infoText = formatBurpInfo(info);
            
            return createSuccessResponse(id, Map.of(
                "content", List.of(Map.of(
                    "type", "text",
                    "text", infoText
                ))
            ));
        } catch (Exception e) {
            logger.error("Failed to get BurpSuite info", e);
            return createErrorResponse(id, -32603, "Failed to get BurpSuite info: " + e.getMessage());
        }
    }
    
    private McpMessage handleResourcesList(McpMessage request) {
        var resources = List.of(
            Map.of(
                "uri", "burp://scan-queue",
                "name", "Scan Queue Status",
                "description", "Real-time scan queue status with active tasks and recent findings",
                "mimeType", "application/json"
            ),
            Map.of(
                "uri", "burp://issues",
                "name", "Security Issues",
                "description", "Complete list of discovered security vulnerabilities and findings",
                "mimeType", "application/json"
            ),
            Map.of(
                "uri", "burp://proxy-history",
                "name", "Proxy Traffic",
                "description", "Recent HTTP requests and responses captured by the proxy",
                "mimeType", "application/json"
            ),
            Map.of(
                "uri", "burp://site-map",
                "name", "Site Map",
                "description", "Complete application structure and discovered endpoints",
                "mimeType", "application/json"
            )
        );
        
        return createSuccessResponse(request.getId(), Map.of("resources", resources));
    }
    
    private McpMessage handleResourcesRead(McpMessage request) {
        var params = objectMapper.convertValue(request.getParams(), JsonNode.class);
        var uri = params.get("uri").asText();
        
        try {
            var content = switch (uri) {
                case "burp://scan-queue" -> burpIntegration.getScanQueue();
                case "burp://issues" -> burpIntegration.getSecurityIssues();
                case "burp://proxy-history" -> burpIntegration.getProxyHistory(50, null);
                case "burp://site-map" -> burpIntegration.getSiteMap(null);
                default -> Map.of("error", "Resource not found: " + uri);
            };
            
            return createSuccessResponse(request.getId(), List.of(Map.of(
                "uri", uri,
                "mimeType", "application/json",
                "text", objectMapper.valueToTree(content).toString()
            )));
        } catch (Exception e) {
            logger.error("Failed to read resource {}", uri, e);
            return createErrorResponse(request.getId(), -32603, 
                "Failed to read resource: " + e.getMessage());
        }
    }
    
    // ===== FORMATTING HELPER METHODS =====
    
    private String formatScanResults(List<Map<String, Object>> results, String taskId) {
        if (results.isEmpty()) {
            return taskId != null ? 
                "No results found for task ID: " + taskId :
                "No scan results available.";
        }
        
        var sb = new StringBuilder();
        sb.append(taskId != null ? 
            "Scan Results for Task ID: %s\n".formatted(taskId) :
            "Recent Scan Results:\n");
        sb.append("=" .repeat(50)).append("\n");
        
        for (var result : results) {
            if (result.containsKey("findings")) {
                @SuppressWarnings("unchecked")
                var findings = (List<Map<String, Object>>) result.get("findings");
                sb.append("Found %d security findings:\n\n".formatted(findings.size()));
                
                for (var finding : findings) {
                    sb.append("🔍 %s\n".formatted(finding.get("name")));
                    sb.append("   Severity: %s\n".formatted(finding.get("severity")));
                    if (finding.containsKey("confidence")) {
                        sb.append("   Confidence: %s\n".formatted(finding.get("confidence")));
                    }
                    if (finding.containsKey("url")) {
                        sb.append("   URL: %s\n".formatted(finding.get("url")));
                    }
                    sb.append("   Description: %s\n\n".formatted(finding.get("description")));
                }
            } else {
                sb.append("Result: %s\n".formatted(result));
            }
        }
        
        return sb.toString();
    }
    
    private String formatProxyHistory(List<Map<String, Object>> history, int limit, String filter) {
        var sb = new StringBuilder();
        sb.append("Proxy History\n");
        sb.append("=" .repeat(30)).append("\n");
        
        if (filter != null) {
            sb.append("Filter: %s\n".formatted(filter));
        }
        sb.append("Showing %d entries (limit: %d)\n\n".formatted(history.size(), limit));
        
        for (var entry : history) {
            sb.append("🌐 %s %s\n".formatted(entry.get("method"), entry.get("url")));
            sb.append("   Status: %s | Length: %s | Type: %s\n"
                .formatted(entry.get("status"), entry.get("length"), entry.get("mimeType")));
            
            if (entry.containsKey("requestHeaders")) {
                @SuppressWarnings("unchecked")
                var headers = (List<String>) entry.get("requestHeaders");
                sb.append("   Request Headers: %d\n".formatted(headers.size()));
            }
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    private String formatDecoderResult(Map<String, String> result, String operation) {
        var sb = new StringBuilder();
        sb.append("%s Result\n".formatted(operation));
        sb.append("=" .repeat(20)).append("\n");
        
        sb.append("Encoding: %s\n".formatted(result.get("encoding")));
        sb.append("Status: %s\n\n".formatted(result.get("status")));
        
        sb.append("Original:\n%s\n\n".formatted(result.get("original")));
        
        if ("success".equals(result.get("status"))) {
            var resultKey = "Decoded".equals(operation) ? "decoded" : "encoded";
            sb.append("%s:\n%s\n".formatted(operation, result.get(resultKey)));
        } else if (result.containsKey("message")) {
            sb.append("Error: %s\n".formatted(result.get("message")));
        }
        
        return sb.toString();
    }
    
    private String formatSiteMap(List<Map<String, Object>> siteMap, String urlFilter) {
        var sb = new StringBuilder();
        sb.append("Site Map\n");
        sb.append("=" .repeat(20)).append("\n");
        
        if (urlFilter != null) {
            sb.append("Filter: %s\n".formatted(urlFilter));
        }
        sb.append("Total URLs: %d\n\n".formatted(siteMap.size()));
        
        // Group by domain for better organization
        var domainGroups = siteMap.stream()
            .collect(Collectors.groupingBy(entry -> {
                var url = entry.get("url").toString();
                try {
                    return new java.net.URL(url).getHost();
                } catch (Exception e) {
                    return "unknown";
                }
            }));
        
        for (var domain : domainGroups.keySet()) {
            sb.append("📍 %s\n".formatted(domain));
            var entries = domainGroups.get(domain);
            
            for (var entry : entries) {
                sb.append("   %s %s [%s]\n"
                    .formatted(entry.get("method"), entry.get("url"), entry.get("status")));
            }
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    private String formatEnhancedScanResults(List<Map<String, Object>> results, Map<String, Object> filterConfig) {
        if (results.isEmpty()) {
            var taskId = filterConfig.get("taskId");
            return taskId != null ? 
                "No results found for task ID: " + taskId :
                "No scan results available matching the specified filters.";
        }
        
        var format = filterConfig.get("format").toString();
        var includeRemediation = (Boolean) filterConfig.get("includeRemediation");
        var includeEvidence = (Boolean) filterConfig.get("includeEvidence");
        
        return switch (format) {
            case "summary" -> formatScanResultsSummary(results);
            case "csv" -> formatScanResultsCsv(results);
            case "json" -> formatScanResultsJson(results);
            default -> formatScanResultsDetailed(results, includeRemediation, includeEvidence);
        };
    }
    
    private String formatScanResultsDetailed(List<Map<String, Object>> results, boolean includeRemediation, boolean includeEvidence) {
        var sb = new StringBuilder();
        sb.append("📋 Enhanced Scan Results Analysis\n");
        sb.append("=".repeat(50)).append("\n\n");
        
        // Calculate statistics
        var stats = calculateScanStatistics(results);
        sb.append("📊 Security Assessment Summary:\n");
        sb.append("   Total Findings: %d\n".formatted(stats.get("total")));
        sb.append("   Critical: %d | High: %d | Medium: %d | Low: %d\n\n"
            .formatted(stats.get("critical"), stats.get("high"), stats.get("medium"), stats.get("low")));
        
        // Risk assessment
        var riskLevel = assessOverallRisk(stats);
        sb.append("🎯 Overall Risk Level: %s\n\n".formatted(riskLevel));
        
        sb.append("🔍 Detailed Findings:\n");
        sb.append("-".repeat(30)).append("\n\n");
        
        for (var result : results) {
            if (result.containsKey("findings")) {
                @SuppressWarnings("unchecked")
                var findings = (List<Map<String, Object>>) result.get("findings");
                
                for (int i = 0; i < findings.size(); i++) {
                    var finding = findings.get(i);
                    var severity = finding.get("severity").toString();
                    var severityIcon = getSeverityIcon(severity);
                    
                    sb.append("%s [%d/%d] %s\n".formatted(severityIcon, i + 1, findings.size(), finding.get("name")));
                    sb.append("   🎯 Severity: %s".formatted(severity));
                    if (finding.containsKey("confidence")) {
                        sb.append(" | Confidence: %s".formatted(finding.get("confidence")));
                    }
                    sb.append("\n");
                    
                    if (finding.containsKey("url")) {
                        sb.append("   🔗 URL: %s\n".formatted(finding.get("url")));
                    }
                    if (finding.containsKey("parameter")) {
                        sb.append("   🔑 Parameter: %s\n".formatted(finding.get("parameter")));
                    }
                    
                    sb.append("   📄 Description: %s\n".formatted(finding.get("description")));
                    
                    if (includeEvidence && finding.containsKey("evidence")) {
                        sb.append("   🔍 Evidence: %s\n".formatted(finding.get("evidence")));
                    }
                    
                    if (includeRemediation && finding.containsKey("remediation")) {
                        sb.append("   ⚙️ Remediation: %s\n".formatted(finding.get("remediation")));
                    }
                    
                    if (finding.containsKey("cweId")) {
                        sb.append("   📚 CWE-%s: https://cwe.mitre.org/data/definitions/%s.html\n"
                            .formatted(finding.get("cweId"), finding.get("cweId")));
                    }
                    
                    sb.append("\n");
                }
            }
        }
        
        // Add recommendations
        sb.append(addSecurityRecommendations(stats));
        
        return sb.toString();
    }
    
    private String formatScanResultsSummary(List<Map<String, Object>> results) {
        var sb = new StringBuilder();
        sb.append("📈 Scan Results Summary\n");
        sb.append("=".repeat(30)).append("\n\n");
        
        var stats = calculateScanStatistics(results);
        var total = (Integer) stats.get("total");
        
        sb.append("Total Findings: %d\n".formatted(total));
        sb.append("Risk Distribution:\n");
        sb.append("  ❌ Critical: %d (%.1f%%)\n".formatted(stats.get("critical"), (stats.get("critical") * 100.0 / total)));
        sb.append("  ⚠️ High: %d (%.1f%%)\n".formatted(stats.get("high"), (stats.get("high") * 100.0 / total)));
        sb.append("  🟡 Medium: %d (%.1f%%)\n".formatted(stats.get("medium"), (stats.get("medium") * 100.0 / total)));
        sb.append("  🟢 Low: %d (%.1f%%)\n\n".formatted(stats.get("low"), (stats.get("low") * 100.0 / total)));
        
        sb.append("Overall Risk: %s\n".formatted(assessOverallRisk(stats)));
        
        return sb.toString();
    }
    
    private String formatScanResultsCsv(List<Map<String, Object>> results) {
        var sb = new StringBuilder();
        sb.append("Name,Severity,Confidence,URL,Parameter,Description,CWE\n");
        
        for (var result : results) {
            if (result.containsKey("findings")) {
                @SuppressWarnings("unchecked")
                var findings = (List<Map<String, Object>>) result.get("findings");
                
                for (var finding : findings) {
                    sb.append("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n"
                        .formatted(
                            finding.getOrDefault("name", ""),
                            finding.getOrDefault("severity", ""),
                            finding.getOrDefault("confidence", ""),
                            finding.getOrDefault("url", ""),
                            finding.getOrDefault("parameter", ""),
                            finding.getOrDefault("description", "").toString().replace("\"", "\\\""),
                            finding.getOrDefault("cweId", "")
                        ));
                }
            }
        }
        
        return sb.toString();
    }
    
    private String formatScanResultsJson(List<Map<String, Object>> results) {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(results);
        } catch (Exception e) {
            return "{\"error\": \"Failed to format as JSON: " + e.getMessage() + "\"}";
        }
    }
    
    private Map<String, Integer> calculateScanStatistics(List<Map<String, Object>> results) {
        var stats = new HashMap<String, Integer>();
        stats.put("total", 0);
        stats.put("critical", 0);
        stats.put("high", 0);
        stats.put("medium", 0);
        stats.put("low", 0);
        
        for (var result : results) {
            if (result.containsKey("findings")) {
                @SuppressWarnings("unchecked")
                var findings = (List<Map<String, Object>>) result.get("findings");
                
                for (var finding : findings) {
                    stats.put("total", stats.get("total") + 1);
                    var severity = finding.get("severity").toString().toLowerCase();
                    stats.put(severity, stats.getOrDefault(severity, 0) + 1);
                }
            }
        }
        
        return stats;
    }
    
    private String assessOverallRisk(Map<String, Integer> stats) {
        if (stats.get("critical") > 0) return "CRITICAL ❌";
        if (stats.get("high") > 2) return "HIGH ⚠️";
        if (stats.get("high") > 0 || stats.get("medium") > 5) return "MODERATE 🟡";
        if (stats.get("medium") > 0 || stats.get("low") > 10) return "LOW 🟢";
        return "MINIMAL ✅";
    }
    
    private String getSeverityIcon(String severity) {
        return switch (severity.toLowerCase()) {
            case "critical" -> "❌";
            case "high" -> "⚠️";
            case "medium" -> "🟡";
            case "low" -> "🟢";
            default -> "🔵";
        };
    }
    
    private String addSecurityRecommendations(Map<String, Integer> stats) {
        var sb = new StringBuilder();
        sb.append("💡 Security Recommendations:\n");
        sb.append("-".repeat(30)).append("\n");
        
        if (stats.get("critical") > 0) {
            sb.append("⚠️  URGENT: Address all Critical vulnerabilities immediately\n");
            sb.append("   - These pose immediate risk to application security\n");
            sb.append("   - Consider taking the application offline until fixed\n\n");
        }
        
        if (stats.get("high") > 0) {
            sb.append("🔴 HIGH PRIORITY: Fix High-severity issues within 24-48 hours\n");
            sb.append("   - Focus on authentication and injection vulnerabilities\n\n");
        }
        
        if (stats.get("medium") > 0) {
            sb.append("🟡 MEDIUM: Plan fixes for Medium-severity issues within 1-2 weeks\n");
            sb.append("   - Include in next development sprint\n\n");
        }
        
        sb.append("🔒 General Security Measures:\n");
        sb.append("   - Implement regular security scanning\n");
        sb.append("   - Use security headers (HSTS, CSP, X-Frame-Options)\n");
        sb.append("   - Keep frameworks and dependencies updated\n");
        sb.append("   - Implement proper input validation and output encoding\n\n");
        
        return sb.toString();
    }
    
    private String formatBurpInfo(Map<String, Object> info) {
        var sb = new StringBuilder();
        sb.append("BurpSuite Integration Status\n");
        sb.append("=" .repeat(35)).append("\n");
        
        sb.append("Extension Mode: %s\n".formatted(info.get("extensionMode")));
        sb.append("Connected to Burp: %s\n".formatted(info.get("connected")));
        
        if (info.containsKey("burpVersion")) {
            sb.append("Burp Version: %s\n".formatted(info.get("burpVersion")));
        }
        if (info.containsKey("apiVersion")) {
            sb.append("API Version: %s\n".formatted(info.get("apiVersion")));
        }
        
        sb.append("\nAvailable Features:\n");
        if ((Boolean) info.get("connected")) {
            sb.append("✅ Live BurpSuite integration\n");
            sb.append("✅ Real-time scanning\n");
            sb.append("✅ Proxy interception\n");
            sb.append("✅ Intruder attacks\n");
            sb.append("✅ Repeater requests\n");
            sb.append("✅ Complete tool suite\n");
        } else {
            sb.append("⚠️ Running in mock mode\n");
            sb.append("⚠️ Limited functionality\n");
            sb.append("💡 Load as BurpSuite extension for full features\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Check if the method is explicitly unsupported (e.g., prompts/list)
     */
    private boolean isUnsupportedMethod(String method) {
        return switch (method) {
            case "prompts/list", "prompts/get" -> true;
            default -> false;
        };
    }
    
    /**
     * Create a minimal JSON-RPC error response for unsupported methods
     * Returns: {"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found: prompts/list"}}
     */
    private McpMessage createMethodNotFoundError(Object requestId, String methodName) {
        logger.warn("Method not supported: {}", methodName);
        
        // Create minimal JSON error object - no 'data' field due to @JsonInclude(NON_NULL)
        McpMessage response = new McpMessage();
        // Claude Desktop requires ID field - use 0 if null
        response.setId(requestId != null ? requestId : 0);
        response.setError(new McpMessage.McpError(-32601, "Method not found: " + methodName));
        
        return response;
    }
    
    private McpMessage createSuccessResponse(Object id, Object result) {
        McpMessage response = new McpMessage();
        response.setId(id != null ? id : 0);
        response.setResult(result);
        return response;
    }
    
    private McpMessage createErrorResponse(Object id, int code, String message) {
        McpMessage response = new McpMessage();
        response.setId(id != null ? id : 0);
        response.setError(new McpMessage.McpError(code, message));
        return response;
    }
}
