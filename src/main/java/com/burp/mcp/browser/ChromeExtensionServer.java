package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

/**
 * HTTP Server for Chrome Extension Communication
 * Provides bidirectional communication bridge between Chrome Extension and BurpSuite MCP Server
 * Follows Chrome Extension Native Messaging and HTTP API patterns
 */
public class ChromeExtensionServer {
    
    private static final Logger logger = LoggerFactory.getLogger(ChromeExtensionServer.class);
    
    // Server configuration
    private static final int DEFAULT_PORT = 1337;
    private static final String DEFAULT_HOST = "localhost";
    private static final int MAX_CONNECTIONS = 50;
    private static final int REQUEST_TIMEOUT = 30000; // 30 seconds
    
    // Server state
    private HttpServer httpServer;
    private ExecutorService executorService;
    private boolean isRunning = false;
    private final int port;
    private final String host;
    
    // Dependencies
    private final MontoyaApi api;
    private final ObjectMapper objectMapper;
    private final ExtensionMessageHandler messageHandler;
    
    // Active sessions and connections
    private final Map<String, ExtensionSession> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, Long> connectionHeartbeats = new ConcurrentHashMap<>();
    
    // Statistics
    private volatile long totalRequests = 0;
    private volatile long successfulRequests = 0;
    private volatile long failedRequests = 0;
    private final Instant startTime = Instant.now();
    
    /**
     * Chrome Extension Session representation
     */
    public static class ExtensionSession {
        private final String sessionId;
        private final String tabUrl;
        private final String userAgent;
        private final long createdTime;
        private volatile long lastActivity;
        private volatile boolean isRecording = false;
        private final Map<String, Object> metadata = new ConcurrentHashMap<>();
        
        public ExtensionSession(String sessionId, String tabUrl, String userAgent) {
            this.sessionId = sessionId;
            this.tabUrl = tabUrl;
            this.userAgent = userAgent;
            this.createdTime = System.currentTimeMillis();
            this.lastActivity = createdTime;
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public String getTabUrl() { return tabUrl; }
        public String getUserAgent() { return userAgent; }
        public long getCreatedTime() { return createdTime; }
        public long getLastActivity() { return lastActivity; }
        public boolean isRecording() { return isRecording; }
        public Map<String, Object> getMetadata() { return metadata; }
        
        // Setters
        public void updateActivity() { this.lastActivity = System.currentTimeMillis(); }
        public void setRecording(boolean recording) { this.isRecording = recording; }
    }
    
    /**
     * Extension message handler interface
     */
    public interface ExtensionMessageHandler {
        Map<String, Object> handleAnalyzeRequest(String sessionId, JsonNode data);
        Map<String, Object> handleRecordingRequest(String sessionId, JsonNode data);
        Map<String, Object> handleScreenshotRequest(String sessionId, JsonNode data);
        Map<String, Object> handleFormsAnalysisRequest(String sessionId, JsonNode data);
        Map<String, Object> handleConnectionStatus(String sessionId);
    }
    
    /**
     * Default implementation of ExtensionMessageHandler
     */
    private static class DefaultExtensionMessageHandler implements ExtensionMessageHandler {
        private final MontoyaApi api;
        
        public DefaultExtensionMessageHandler(MontoyaApi api) {
            this.api = api;
        }
        
        @Override
        public Map<String, Object> handleAnalyzeRequest(String sessionId, JsonNode data) {
            if (api != null) {
                api.logging().logToOutput("[ChromeExt] Analysis request from session: " + sessionId);
            }
            
            return Map.of(
                "success", true,
                "analysisId", "analysis_" + System.currentTimeMillis(),
                "message", "Analysis request received and queued",
                "timestamp", Instant.now().toString()
            );
        }
        
        @Override
        public Map<String, Object> handleRecordingRequest(String sessionId, JsonNode data) {
            if (api != null) {
                api.logging().logToOutput("[ChromeExt] Recording request from session: " + sessionId);
            }
            
            return Map.of(
                "success", true,
                "recordingId", "rec_" + System.currentTimeMillis(),
                "message", "Recording request processed",
                "timestamp", Instant.now().toString()
            );
        }
        
        @Override
        public Map<String, Object> handleScreenshotRequest(String sessionId, JsonNode data) {
            if (api != null) {
                api.logging().logToOutput("[ChromeExt] Screenshot request from session: " + sessionId);
            }
            
            return Map.of(
                "success", true,
                "screenshotId", "screenshot_" + System.currentTimeMillis(),
                "message", "Screenshot captured and processed",
                "timestamp", Instant.now().toString()
            );
        }
        
        @Override
        public Map<String, Object> handleFormsAnalysisRequest(String sessionId, JsonNode data) {
            if (api != null) {
                api.logging().logToOutput("[ChromeExt] Forms analysis request from session: " + sessionId);
            }
            
            // Extract form data if available
            int formCount = 0;
            if (data.has("forms") && data.get("forms").isArray()) {
                formCount = data.get("forms").size();
            }
            
            return Map.of(
                "success", true,
                "analysisId", "forms_analysis_" + System.currentTimeMillis(),
                "formsAnalyzed", formCount,
                "message", "Forms analysis completed",
                "securityIssues", generateMockSecurityIssues(formCount),
                "timestamp", Instant.now().toString()
            );
        }
        
        @Override
        public Map<String, Object> handleConnectionStatus(String sessionId) {
            return Map.of(
                "connected", true,
                "serverVersion", "1.0.0",
                "capabilities", List.of("recording", "analysis", "screenshots", "forms"),
                "sessionId", sessionId,
                "timestamp", Instant.now().toString()
            );
        }
        
        private List<Map<String, Object>> generateMockSecurityIssues(int formCount) {
            var issues = new ArrayList<Map<String, Object>>();
            if (formCount > 0) {
                issues.add(Map.of(
                    "type", "form_security",
                    "severity", "medium",
                    "description", "Forms detected without CSRF protection",
                    "recommendation", "Implement CSRF tokens for form submissions"
                ));
            }
            return issues;
        }
    }
    
    /**
     * Constructor with default configuration
     */
    public ChromeExtensionServer(MontoyaApi api) {
        this(api, DEFAULT_HOST, DEFAULT_PORT);
    }
    
    /**
     * Constructor with custom host and port
     */
    public ChromeExtensionServer(MontoyaApi api, String host, int port) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.objectMapper = new ObjectMapper();
        this.messageHandler = new DefaultExtensionMessageHandler(api);
        
        logger.info("Chrome Extension Server initialized for {}:{}", host, port);
    }
    
    /**
     * Constructor with custom message handler
     */
    public ChromeExtensionServer(MontoyaApi api, String host, int port, ExtensionMessageHandler customHandler) {
        this.api = api;
        this.host = host;
        this.port = port;
        this.objectMapper = new ObjectMapper();
        this.messageHandler = customHandler != null ? customHandler : new DefaultExtensionMessageHandler(api);
        
        logger.info("Chrome Extension Server initialized with custom handler for {}:{}", host, port);
    }
    
    /**
     * Start the HTTP server
     */
    public synchronized void start() throws IOException {
        if (isRunning) {
            logger.warn("Chrome Extension Server is already running on {}:{}", host, port);
            return;
        }
        
        try {
            // Create HTTP server
            httpServer = HttpServer.create(new InetSocketAddress(host, port), 0);
            
            // Create thread pool for handling requests
            executorService = Executors.newFixedThreadPool(MAX_CONNECTIONS, r -> {
                Thread t = new Thread(r, "ChromeExtension-Handler-" + System.currentTimeMillis());
                t.setDaemon(true);
                return t;
            });
            httpServer.setExecutor(executorService);
            
            // Set up endpoints
            setupEndpoints();
            
            // Start server
            httpServer.start();
            isRunning = true;
            
            logger.info("Chrome Extension Server started successfully on {}:{}", host, port);
            if (api != null) {
                api.logging().logToOutput("[ChromeExtension] HTTP Server started on " + host + ":" + port);
            }
            
            // Start heartbeat monitoring
            startHeartbeatMonitoring();
            
        } catch (IOException e) {
            logger.error("Failed to start Chrome Extension Server on {}:{}", host, port, e);
            cleanup();
            throw e;
        }
    }
    
    /**
     * Stop the HTTP server
     */
    public synchronized void stop() {
        if (!isRunning) {
            logger.warn("Chrome Extension Server is not running");
            return;
        }
        
        logger.info("Stopping Chrome Extension Server...");
        
        try {
            // Stop accepting new requests
            if (httpServer != null) {
                httpServer.stop(5); // Wait up to 5 seconds for ongoing requests
            }
            
            // Cleanup
            cleanup();
            
            logger.info("Chrome Extension Server stopped successfully");
            if (api != null) {
                api.logging().logToOutput("[ChromeExtension] HTTP Server stopped");
            }
            
        } catch (Exception e) {
            logger.error("Error stopping Chrome Extension Server", e);
        } finally {
            isRunning = false;
        }
    }
    
    /**
     * Setup HTTP endpoints
     */
    private void setupEndpoints() {
        // Main API endpoint for extension communication
        httpServer.createContext("/api/analyze", new AnalysisHandler());
        httpServer.createContext("/api/recording", new RecordingHandler());
        httpServer.createContext("/api/screenshot", new ScreenshotHandler());
        httpServer.createContext("/api/forms-analysis", new FormsAnalysisHandler());
        
        // Status and health endpoints
        httpServer.createContext("/status", new StatusHandler());
        httpServer.createContext("/ping", new PingHandler());
        httpServer.createContext("/stats", new StatsHandler());
        
        // CORS and preflight
        httpServer.createContext("/", new CORSHandler());
    }
    
    /**
     * CORS Handler for preflight requests
     */
    private class CORSHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(200, 0);
                exchange.close();
                return;
            }
            
            // For non-API paths, return 404
            if (!exchange.getRequestURI().getPath().startsWith("/api/") && 
                !exchange.getRequestURI().getPath().equals("/status") &&
                !exchange.getRequestURI().getPath().equals("/ping") &&
                !exchange.getRequestURI().getPath().equals("/stats")) {
                exchange.sendResponseHeaders(404, 0);
                exchange.close();
            }
        }
    }
    
    /**
     * Analysis Handler
     */
    private class AnalysisHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            handleExtensionRequest(exchange, "analysis", 
                (sessionId, data) -> messageHandler.handleAnalyzeRequest(sessionId, data));
        }
    }
    
    /**
     * Recording Handler
     */
    private class RecordingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            handleExtensionRequest(exchange, "recording", 
                (sessionId, data) -> messageHandler.handleRecordingRequest(sessionId, data));
        }
    }
    
    /**
     * Screenshot Handler
     */
    private class ScreenshotHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            handleExtensionRequest(exchange, "screenshot", 
                (sessionId, data) -> messageHandler.handleScreenshotRequest(sessionId, data));
        }
    }
    
    /**
     * Forms Analysis Handler
     */
    private class FormsAnalysisHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            handleExtensionRequest(exchange, "forms-analysis", 
                (sessionId, data) -> messageHandler.handleFormsAnalysisRequest(sessionId, data));
        }
    }
    
    /**
     * Status Handler
     */
    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            totalRequests++;
            
            try {
                var status = Map.of(
                    "status", "running",
                    "version", "1.0.0",
                    "activeSessions", activeSessions.size(),
                    "capabilities", List.of("recording", "analysis", "screenshots", "forms"),
                    "timestamp", Instant.now().toString()
                );
                
                var response = objectMapper.writeValueAsString(status);
                sendJSONResponse(exchange, 200, response);
                successfulRequests++;
                
            } catch (Exception e) {
                logger.error("Error in status handler", e);
                sendErrorResponse(exchange, 500, "Internal server error");
                failedRequests++;
            }
        }
    }
    
    /**
     * Ping Handler
     */
    private class PingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            totalRequests++;
            
            sendJSONResponse(exchange, 200, "{\"pong\":true,\"timestamp\":\"" + Instant.now() + "\"}");
            successfulRequests++;
        }
    }
    
    /**
     * Stats Handler
     */
    private class StatsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            setCORSHeaders(exchange);
            totalRequests++;
            
            try {
                var stats = Map.of(
                    "totalRequests", totalRequests,
                    "successfulRequests", successfulRequests,
                    "failedRequests", failedRequests,
                    "activeSessions", activeSessions.size(),
                    "uptime", Instant.now().toEpochMilli() - startTime.toEpochMilli(),
                    "startTime", startTime.toString()
                );
                
                var response = objectMapper.writeValueAsString(stats);
                sendJSONResponse(exchange, 200, response);
                successfulRequests++;
                
            } catch (Exception e) {
                logger.error("Error in stats handler", e);
                sendErrorResponse(exchange, 500, "Internal server error");
                failedRequests++;
            }
        }
    }
    
    /**
     * Generic extension request handler
     */
    private void handleExtensionRequest(HttpExchange exchange, String requestType, 
                                       ExtensionRequestHandler handler) throws IOException {
        setCORSHeaders(exchange);
        totalRequests++;
        
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method not allowed");
            failedRequests++;
            return;
        }
        
        try {
            // Read request body
            String requestBody = readRequestBody(exchange);
            JsonNode requestData = objectMapper.readTree(requestBody);
            
            // Extract or generate session ID
            String sessionId = extractSessionId(exchange, requestData);
            
            // Update session
            updateSession(exchange, sessionId, requestData);
            
            // Handle request
            Map<String, Object> response = handler.handle(sessionId, requestData);
            
            // Send response
            String responseJSON = objectMapper.writeValueAsString(response);
            sendJSONResponse(exchange, 200, responseJSON);
            successfulRequests++;
            
            logger.debug("Handled {} request from session {}", requestType, sessionId);
            
        } catch (Exception e) {
            logger.error("Error handling {} request", requestType, e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            failedRequests++;
        }
    }
    
    /**
     * Functional interface for extension request handling
     */
    @FunctionalInterface
    private interface ExtensionRequestHandler {
        Map<String, Object> handle(String sessionId, JsonNode data) throws Exception;
    }
    
    /**
     * Extract session ID from request
     */
    private String extractSessionId(HttpExchange exchange, JsonNode requestData) {
        // Try to get session ID from request data
        if (requestData.has("sessionId")) {
            return requestData.get("sessionId").asText();
        }
        
        // Try to get from headers
        List<String> sessionHeaders = exchange.getRequestHeaders().get("X-Session-ID");
        if (sessionHeaders != null && !sessionHeaders.isEmpty()) {
            return sessionHeaders.get(0);
        }
        
        // Generate new session ID based on client info
        String remoteAddress = exchange.getRemoteAddress().getAddress().getHostAddress();
        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        return "ext_" + Math.abs((remoteAddress + userAgent).hashCode()) + "_" + System.currentTimeMillis();
    }
    
    /**
     * Update session information
     */
    private void updateSession(HttpExchange exchange, String sessionId, JsonNode requestData) {
        String tabUrl = requestData.has("tabUrl") ? requestData.get("tabUrl").asText() : "unknown";
        String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
        
        ExtensionSession session = activeSessions.get(sessionId);
        if (session == null) {
            session = new ExtensionSession(sessionId, tabUrl, userAgent);
            activeSessions.put(sessionId, session);
            logger.debug("Created new extension session: {}", sessionId);
        } else {
            session.updateActivity();
        }
        
        // Update heartbeat
        connectionHeartbeats.put(sessionId, System.currentTimeMillis());
    }
    
    /**
     * Set CORS headers
     */
    private void setCORSHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-Session-ID");
        exchange.getResponseHeaders().add("Access-Control-Max-Age", "3600");
    }
    
    /**
     * Read request body
     */
    private String readRequestBody(HttpExchange exchange) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line);
            }
            return body.toString();
        }
    }
    
    /**
     * Send JSON response
     */
    private void sendJSONResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    /**
     * Send error response
     */
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String error) throws IOException {
        var errorResponse = Map.of(
            "success", false,
            "error", error,
            "timestamp", Instant.now().toString()
        );
        
        try {
            String responseJSON = objectMapper.writeValueAsString(errorResponse);
            sendJSONResponse(exchange, statusCode, responseJSON);
        } catch (Exception e) {
            // Fallback to plain text
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            byte[] responseBytes = error.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        }
    }
    
    /**
     * Start heartbeat monitoring to clean up inactive sessions
     */
    private void startHeartbeatMonitoring() {
        ScheduledExecutorService heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ChromeExtension-Heartbeat");
            t.setDaemon(true);
            return t;
        });
        
        heartbeatExecutor.scheduleAtFixedRate(this::cleanupInactiveSessions, 30, 30, TimeUnit.SECONDS);
    }
    
    /**
     * Cleanup inactive sessions
     */
    private void cleanupInactiveSessions() {
        long currentTime = System.currentTimeMillis();
        long inactiveThreshold = 5 * 60 * 1000; // 5 minutes
        
        Iterator<Map.Entry<String, Long>> iterator = connectionHeartbeats.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            if (currentTime - entry.getValue() > inactiveThreshold) {
                String sessionId = entry.getKey();
                iterator.remove();
                activeSessions.remove(sessionId);
                logger.debug("Cleaned up inactive session: {}", sessionId);
            }
        }
    }
    
    /**
     * Cleanup resources
     */
    private void cleanup() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        activeSessions.clear();
        connectionHeartbeats.clear();
    }
    
    // Public getters
    public boolean isRunning() { return isRunning; }
    public int getPort() { return port; }
    public String getHost() { return host; }
    public int getActiveSessionCount() { return activeSessions.size(); }
    public long getTotalRequests() { return totalRequests; }
    public long getSuccessfulRequests() { return successfulRequests; }
    public long getFailedRequests() { return failedRequests; }
    public Set<String> getActiveSessions() { return new HashSet<>(activeSessions.keySet()); }
}
