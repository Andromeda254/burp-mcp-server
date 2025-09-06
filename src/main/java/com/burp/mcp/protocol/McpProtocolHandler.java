package com.burp.mcp.protocol;

import com.burp.mcp.model.McpMessage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final BurpIntegration burpIntegration;
    
    public McpProtocolHandler(BurpIntegration burpIntegration) {
        this.burpIntegration = burpIntegration;
    }
    
    public McpMessage handleRequest(McpMessage request) {
        if (request.getMethod() == null) {
            return createErrorResponse(request.getId(), -32600, "Invalid Request");
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
            // SCANNER TOOLS
            Map.of(
                "name", "scan_target",
                "description", "Initiate a comprehensive security scan on a target URL using BurpSuite Scanner",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of("type", "string", "description", "Target URL to scan"),
                        "scanType", Map.of("type", "string", 
                            "enum", List.of("passive", "active", "full"),
                            "description", "Type of scan: passive (safe), active (intrusive), full (crawl+audit)")
                    ),
                    "required", List.of("url")
                )
            ),
            Map.of(
                "name", "get_scan_results",
                "description", "Retrieve detailed results from security scans including vulnerabilities and findings",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "taskId", Map.of("type", "string", "description", "Specific scan task ID (optional)")
                    )
                )
            ),
            
            // PROXY TOOLS
            Map.of(
                "name", "proxy_history",
                "description", "Get HTTP request/response history from BurpSuite Proxy with detailed headers and content",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "limit", Map.of("type", "integer", "description", "Maximum number of entries (default: 100)"),
                        "filter", Map.of("type", "string", "description", "URL filter pattern to match specific requests")
                    )
                )
            ),
            
            // REPEATER TOOLS
            Map.of(
                "name", "send_to_repeater",
                "description", "Send an HTTP request to BurpSuite Repeater for manual testing and analysis",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of("type", "string", "description", "Target URL"),
                        "method", Map.of("type", "string", "enum", List.of("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"), "description", "HTTP method"),
                        "body", Map.of("type", "string", "description", "Request body content (optional)"),
                        "headers", Map.of("type", "object", "description", "Additional headers as key-value pairs (optional)")
                    ),
                    "required", List.of("url", "method")
                )
            ),
            
            // INTRUDER TOOLS
            Map.of(
                "name", "start_intruder_attack",
                "description", "Launch an automated attack using BurpSuite Intruder with custom payloads",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of("type", "string", "description", "Target URL"),
                        "method", Map.of("type", "string", "enum", List.of("GET", "POST", "PUT", "DELETE"), "description", "HTTP method"),
                        "body", Map.of("type", "string", "description", "Request body with payload positions marked"),
                        "headers", Map.of("type", "object", "description", "HTTP headers as key-value pairs"),
                        "payloadPositions", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Positions where payloads will be inserted"),
                        "payloads", Map.of("type", "array", "items", Map.of("type", "string"), "description", "List of payloads to use in the attack"),
                        "attackType", Map.of("type", "string", "enum", List.of("sniper", "battering_ram", "pitchfork", "cluster_bomb"), "description", "Intruder attack type")
                    ),
                    "required", List.of("url", "method", "payloads", "attackType")
                )
            ),
            
            // DECODER TOOLS
            Map.of(
                "name", "decode_data",
                "description", "Decode data using various encoding schemes (Base64, URL, HTML)",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "data", Map.of("type", "string", "description", "Data to decode"),
                        "encoding", Map.of("type", "string", "enum", List.of("base64", "url", "html"), "description", "Encoding scheme to use")
                    ),
                    "required", List.of("data", "encoding")
                )
            ),
            Map.of(
                "name", "encode_data",
                "description", "Encode data using various encoding schemes (Base64, URL, HTML)",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "data", Map.of("type", "string", "description", "Data to encode"),
                        "encoding", Map.of("type", "string", "enum", List.of("base64", "url", "html"), "description", "Encoding scheme to use")
                    ),
                    "required", List.of("data", "encoding")
                )
            ),
            
            // SITEMAP TOOLS
            Map.of(
                "name", "get_site_map",
                "description", "Retrieve the complete site map from BurpSuite showing all discovered URLs and endpoints",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "urlFilter", Map.of("type", "string", "description", "Filter results by URL pattern (optional)")
                    )
                )
            ),
            
            // UTILITY TOOLS
            Map.of(
                "name", "burp_info",
                "description", "Get information about the BurpSuite connection and current status",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of()
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
            // Scanner tools
            case "scan_target" -> handleScanTarget(request.getId(), arguments);
            case "get_scan_results" -> handleGetScanResults(request.getId(), arguments);
            
            // Proxy tools
            case "proxy_history" -> handleProxyHistory(request.getId(), arguments);
            
            // Repeater tools
            case "send_to_repeater" -> handleSendToRepeater(request.getId(), arguments);
            
            // Intruder tools
            case "start_intruder_attack" -> handleStartIntruderAttack(request.getId(), arguments);
            
            // Decoder tools
            case "decode_data" -> handleDecodeData(request.getId(), arguments);
            case "encode_data" -> handleEncodeData(request.getId(), arguments);
            
            // Sitemap tools
            case "get_site_map" -> handleGetSiteMap(request.getId(), arguments);
            
            // Utility tools
            case "burp_info" -> handleBurpInfo(request.getId(), arguments);
            
            default -> createErrorResponse(request.getId(), -32602, 
                "Unknown tool: " + toolName);
        };
    }
    
    // ===== SCANNER TOOL HANDLERS =====
    
    private McpMessage handleScanTarget(Object id, JsonNode arguments) {
        var url = arguments.get("url").asText();
        var scanType = arguments.has("scanType") ? 
            arguments.get("scanType").asText() : "passive";
        
        try {
            var taskId = burpIntegration.startScan(url, scanType);
            var responseText = """
                Started %s scan for %s.
                Task ID: %s
                The scan will analyze the target for security vulnerabilities.
                Use 'get_scan_results' with this task ID to retrieve findings.
                """.formatted(scanType, url, taskId);
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", responseText
            )));
        } catch (Exception e) {
            logger.error("Failed to start scan for {}", url, e);
            return createErrorResponse(id, -32603, "Failed to start scan: " + e.getMessage());
        }
    }
    
    private McpMessage handleGetScanResults(Object id, JsonNode arguments) {
        var taskId = arguments.has("taskId") ? arguments.get("taskId").asText() : null;
        
        try {
            var results = burpIntegration.getScanResults(taskId);
            var resultText = formatScanResults(results, taskId);
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", resultText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", historyText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", responseText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", responseText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", responseText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", responseText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", siteMapText
            )));
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
            
            return createSuccessResponse(id, List.of(Map.of(
                "type", "text",
                "text", infoText
            )));
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
    
    private McpMessage createSuccessResponse(Object id, Object result) {
        McpMessage response = new McpMessage();
        response.setId(id);
        response.setResult(result);
        return response;
    }
    
    private McpMessage createErrorResponse(Object id, int code, String message) {
        McpMessage response = new McpMessage();
        response.setId(id);
        response.setError(new McpMessage.McpError(code, message));
        return response;
    }
}
