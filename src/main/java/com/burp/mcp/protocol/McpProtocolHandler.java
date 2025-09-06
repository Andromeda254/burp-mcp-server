package com.burp.mcp.protocol;

import com.burp.mcp.model.McpMessage;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
            Map.of(
                "name", "scan_target",
                "description", "Initiate a security scan on a target URL using BurpSuite",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "url", Map.of("type", "string", "description", "Target URL to scan"),
                        "scanType", Map.of("type", "string", 
                            "enum", List.of("passive", "active", "full"),
                            "description", "Type of scan to perform")
                    ),
                    "required", List.of("url")
                )
            ),
            Map.of(
                "name", "get_scan_results",
                "description", "Retrieve results from previous scans",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "taskId", Map.of("type", "string", "description", "Scan task ID")
                    )
                )
            ),
            Map.of(
                "name", "proxy_history",
                "description", "Get HTTP request/response history from BurpSuite proxy",
                "inputSchema", Map.of(
                    "type", "object",
                    "properties", Map.of(
                        "limit", Map.of("type", "integer", "description", "Maximum number of entries"),
                        "filter", Map.of("type", "string", "description", "URL filter pattern")
                    )
                )
            )
        );
        
        return createSuccessResponse(request.getId(), Map.of("tools", tools));
    }
    
    private McpMessage handleToolsCall(McpMessage request) {
        JsonNode params = objectMapper.convertValue(request.getParams(), JsonNode.class);
        String toolName = params.get("name").asText();
        JsonNode arguments = params.get("arguments");
        
        return switch (toolName) {
            case "scan_target" -> handleScanTarget(request.getId(), arguments);
            case "get_scan_results" -> handleGetScanResults(request.getId(), arguments);
            case "proxy_history" -> handleProxyHistory(request.getId(), arguments);
            default -> createErrorResponse(request.getId(), -32602, 
                "Unknown tool: " + toolName);
        };
    }
    
    private McpMessage handleScanTarget(Object id, JsonNode arguments) {
        String url = arguments.get("url").asText();
        String scanType = arguments.has("scanType") ? 
            arguments.get("scanType").asText() : "passive";
        
        String taskId = burpIntegration.startScan(url, scanType);
        
        return createSuccessResponse(id, List.of(Map.of(
            "type", "text",
            "text", String.format("Started %s scan for %s. Task ID: %s", scanType, url, taskId)
        )));
    }
    
    private McpMessage handleGetScanResults(Object id, JsonNode arguments) {
        String taskId = arguments.has("taskId") ? arguments.get("taskId").asText() : null;
        
        List<Map<String, Object>> results = burpIntegration.getScanResults(taskId);
        
        return createSuccessResponse(id, List.of(Map.of(
            "type", "text",
            "text", String.format("Found %d scan results", results.size())
        )));
    }
    
    private McpMessage handleProxyHistory(Object id, JsonNode arguments) {
        int limit = arguments.has("limit") ? arguments.get("limit").asInt() : 100;
        String filter = arguments.has("filter") ? arguments.get("filter").asText() : null;
        
        List<Map<String, Object>> history = burpIntegration.getProxyHistory(limit, filter);
        
        return createSuccessResponse(id, List.of(Map.of(
            "type", "text",
            "text", String.format("Retrieved %d proxy history entries", history.size())
        )));
    }
    
    private McpMessage handleResourcesList(McpMessage request) {
        List<Map<String, Object>> resources = List.of(
            Map.of(
                "uri", "burp://scan-queue",
                "name", "Scan Queue",
                "description", "Current scan queue status",
                "mimeType", "application/json"
            ),
            Map.of(
                "uri", "burp://issues",
                "name", "Security Issues",
                "description", "Discovered security issues",
                "mimeType", "application/json"
            )
        );
        
        return createSuccessResponse(request.getId(), Map.of("resources", resources));
    }
    
    private McpMessage handleResourcesRead(McpMessage request) {
        JsonNode params = objectMapper.convertValue(request.getParams(), JsonNode.class);
        String uri = params.get("uri").asText();
        
        Object content = switch (uri) {
            case "burp://scan-queue" -> burpIntegration.getScanQueue();
            case "burp://issues" -> burpIntegration.getSecurityIssues();
            default -> Map.of("error", "Resource not found: " + uri);
        };
        
        return createSuccessResponse(request.getId(), List.of(Map.of(
            "uri", uri,
            "mimeType", "application/json",
            "text", objectMapper.valueToTree(content).toString()
        )));
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
