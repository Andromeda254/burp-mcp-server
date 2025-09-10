package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Chrome Extension Server for Burp MCP Integration
 * 
 * Provides HTTP server endpoints for Chrome extension communication,
 * enabling browser automation and live integration with BurpSuite.
 */
public class ChromeExtensionServer {
    
    private static final Logger logger = LoggerFactory.getLogger(ChromeExtensionServer.class);
    
    private final MontoyaApi api;
    private final BrowserManager browserManager;
    private final ObjectMapper objectMapper;
    private final AtomicBoolean serverRunning = new AtomicBoolean(false);
    private final Map<String, ExtensionSession> activeSessions = new ConcurrentHashMap<>();
    
    private HttpServer httpServer;
    private CollaboratorClient collaborator;
    private int serverPort = 1337; // Default port for Chrome extension communication
    
    public ChromeExtensionServer(MontoyaApi api, BrowserManager browserManager) {
        this.api = api;
        this.browserManager = browserManager;
        this.objectMapper = new ObjectMapper();
        
        if (api != null) {
            this.collaborator = api.collaborator().createClient();
        }
        
        logger.info("ChromeExtensionServer initialized");
    }
    
    /**
     * Start the Chrome extension communication server
     */
    public boolean startServer() {
        return startServer(serverPort);
    }
    
    /**
     * Start the server on a specific port
     */
    public boolean startServer(int port) {
        if (serverRunning.get()) {
            logger.warn("Chrome extension server is already running on port {}", port);
            return true;
        }
        
        try {
            httpServer = HttpServer.create(new InetSocketAddress(port), 0);
            setupEndpoints();
            
            // Use thread pool for handling requests
            httpServer.setExecutor(Executors.newFixedThreadPool(4));
            httpServer.start();
            
            serverRunning.set(true);
            this.serverPort = port;
            
            logger.info("Chrome extension server started on port {}", port);
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[CHROME-EXT] Extension server started on http://localhost:%d", port
                ));
            }
            
            return true;
            
        } catch (IOException e) {
            logger.error("Failed to start Chrome extension server on port {}: {}", port, e.getMessage(), e);
            
            if (api != null) {
                api.logging().logToError(String.format(
                    "[ERROR] Failed to start Chrome extension server: %s", e.getMessage()
                ));
            }
            
            return false;
        }
    }
    
    /**
     * Stop the server
     */
    public void stopServer() {
        if (httpServer != null && serverRunning.get()) {
            httpServer.stop(2);
            serverRunning.set(false);
            logger.info("Chrome extension server stopped");
            
            if (api != null) {
                api.logging().logToOutput("[CHROME-EXT] Extension server stopped");
            }
        }
    }
    
    /**
     * Setup HTTP endpoints for Chrome extension communication
     */
    private void setupEndpoints() {
        // Main extension communication endpoint
        httpServer.createContext("/chrome-extension", new ExtensionHandler());
        
        // Health check endpoint
        httpServer.createContext("/health", new HealthHandler());
        
        // Session management endpoints
        httpServer.createContext("/session", new SessionHandler());
        
        // Automation endpoints
        httpServer.createContext("/automation", new AutomationHandler());
        
        // Static file serving for extension installation
        httpServer.createContext("/extension-files", new ExtensionFileHandler());
        
        logger.info("Chrome extension endpoints configured");
    }
    
    /**
     * Main handler for Chrome extension communication
     */
    private class ExtensionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Enable CORS for Chrome extension
            enableCORS(exchange);
            
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 200, "OK");
                return;
            }
            
            try {
                String method = exchange.getRequestMethod();
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                
                logger.debug("Extension request: {} - {}", method, requestBody);
                
                if ("POST".equals(method)) {
                    handleExtensionMessage(exchange, requestBody);
                } else {
                    sendErrorResponse(exchange, 405, "Method not allowed");
                }
                
            } catch (Exception e) {
                logger.error("Error handling extension request: {}", e.getMessage(), e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
            }
        }
    }
    
    /**
     * Handle messages from Chrome extension
     */
    private void handleExtensionMessage(HttpExchange exchange, String requestBody) throws IOException {
        try {
            JsonNode message = objectMapper.readTree(requestBody);
            String type = message.get("type").asText();
            String sessionId = message.has("sessionId") ? message.get("sessionId").asText() : "default";
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("timestamp", System.currentTimeMillis());
            
            switch (type) {
                case "connect":
                    handleConnect(sessionId, message, response);
                    break;
                    
                case "page_loaded":
                    handlePageLoaded(sessionId, message, response);
                    break;
                    
                case "form_detected":
                    handleFormDetected(sessionId, message, response);
                    break;
                    
                case "login_attempt":
                    handleLoginAttempt(sessionId, message, response);
                    break;
                    
                case "auth_state_change":
                    handleAuthStateChange(sessionId, message, response);
                    break;
                    
                case "screenshot":
                    handleScreenshot(sessionId, message, response);
                    break;
                    
                case "dom_analysis":
                    handleDOMAnalysis(sessionId, message, response);
                    break;
                    
                default:
                    response.put("success", false);
                    response.put("error", "Unknown message type: " + type);
                    logger.warn("Unknown extension message type: {}", type);
            }
            
            sendJsonResponse(exchange, 200, response);
            
        } catch (Exception e) {
            logger.error("Failed to process extension message: {}", e.getMessage(), e);
            Map<String, Object> errorResponse = Map.of(
                "success", false,
                "error", e.getMessage(),
                "timestamp", System.currentTimeMillis()
            );
            sendJsonResponse(exchange, 500, errorResponse);
        }
    }
    
    /**
     * Handle Chrome extension connection
     */
    private void handleConnect(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            String extensionVersion = message.has("version") ? message.get("version").asText() : "unknown";
            String tabUrl = message.has("url") ? message.get("url").asText() : "";
            
            ExtensionSession session = new ExtensionSession(sessionId, tabUrl, extensionVersion);
            activeSessions.put(sessionId, session);
            
            // Register session with browser manager
            if (browserManager != null) {
                browserManager.registerExtensionSession(sessionId, session);
            }
            
            response.put("sessionId", sessionId);
            response.put("serverVersion", "1.0.0");
            response.put("burpConnected", api != null);
            response.put("message", "Chrome extension connected successfully");
            
            logger.info("Chrome extension connected - Session: {}, Version: {}, URL: {}", 
                sessionId, extensionVersion, tabUrl);
                
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[CHROME-EXT] Extension connected - Session: %s, URL: %s", sessionId, tabUrl
                ));
            }
            
        } catch (Exception e) {
            logger.error("Failed to handle extension connection: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle page loaded event from extension
     */
    private void handlePageLoaded(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            String url = message.get("url").asText();
            String title = message.has("title") ? message.get("title").asText() : "";
            
            ExtensionSession session = activeSessions.get(sessionId);
            if (session != null) {
                session.updateCurrentUrl(url);
                session.setPageTitle(title);
            }
            
            // Notify browser manager of page change
            if (browserManager != null) {
                browserManager.handlePageLoaded(sessionId, url, title);
            }
            
            response.put("message", "Page loaded event processed");
            
            logger.debug("Page loaded - Session: {}, URL: {}, Title: {}", sessionId, url, title);
            
        } catch (Exception e) {
            logger.error("Failed to handle page loaded event: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle form detection from extension
     */
    private void handleFormDetected(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            JsonNode formData = message.get("form");
            String formId = formData.has("id") ? formData.get("id").asText() : "unknown";
            String action = formData.has("action") ? formData.get("action").asText() : "";
            
            // Process form with browser manager
            if (browserManager != null) {
                browserManager.handleFormDetected(sessionId, formData);
            }
            
            response.put("message", "Form detection processed");
            response.put("formId", formId);
            
            logger.debug("Form detected - Session: {}, FormID: {}, Action: {}", sessionId, formId, action);
            
        } catch (Exception e) {
            logger.error("Failed to handle form detection: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle login attempt from extension
     */
    private void handleLoginAttempt(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            JsonNode loginData = message.get("loginData");
            
            // Process login attempt with browser manager
            if (browserManager != null) {
                boolean success = browserManager.handleLoginAttempt(sessionId, loginData);
                response.put("loginProcessed", success);
            }
            
            response.put("message", "Login attempt processed");
            
            logger.info("Login attempt processed - Session: {}", sessionId);
            
        } catch (Exception e) {
            logger.error("Failed to handle login attempt: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle authentication state change
     */
    private void handleAuthStateChange(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            String newState = message.get("state").asText();
            String previousState = message.has("previousState") ? message.get("previousState").asText() : "unknown";
            
            // Update browser manager with auth state change
            if (browserManager != null) {
                browserManager.handleAuthStateChange(sessionId, previousState, newState);
            }
            
            response.put("message", "Authentication state change processed");
            
            logger.info("Auth state change - Session: {}, {} -> {}", sessionId, previousState, newState);
            
        } catch (Exception e) {
            logger.error("Failed to handle auth state change: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle screenshot from extension
     */
    private void handleScreenshot(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            String screenshotData = message.get("screenshot").asText();
            String context = message.has("context") ? message.get("context").asText() : "general";
            
            // Process screenshot with browser manager
            if (browserManager != null) {
                String screenshotId = browserManager.handleScreenshot(sessionId, screenshotData, context);
                response.put("screenshotId", screenshotId);
            }
            
            response.put("message", "Screenshot processed");
            
            logger.debug("Screenshot received - Session: {}, Context: {}", sessionId, context);
            
        } catch (Exception e) {
            logger.error("Failed to handle screenshot: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Handle DOM analysis from extension
     */
    private void handleDOMAnalysis(String sessionId, JsonNode message, Map<String, Object> response) {
        try {
            JsonNode domData = message.get("domAnalysis");
            
            // Process DOM analysis with browser manager
            if (browserManager != null) {
                browserManager.handleDOMAnalysis(sessionId, domData);
            }
            
            response.put("message", "DOM analysis processed");
            
            logger.debug("DOM analysis received - Session: {}", sessionId);
            
        } catch (Exception e) {
            logger.error("Failed to handle DOM analysis: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("error", e.getMessage());
        }
    }
    
    /**
     * Health check handler
     */
    private class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            
            Map<String, Object> health = Map.of(
                "status", "healthy",
                "timestamp", System.currentTimeMillis(),
                "activeSessions", activeSessions.size(),
                "serverPort", serverPort,
                "burpConnected", api != null
            );
            
            sendJsonResponse(exchange, 200, health);
        }
    }
    
    /**
     * Session management handler
     */
    private class SessionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            
            if ("GET".equals(exchange.getRequestMethod())) {
                // Return active sessions
                Map<String, Object> sessions = new HashMap<>();
                activeSessions.forEach((id, session) -> {
                    sessions.put(id, session.toMap());
                });
                
                sendJsonResponse(exchange, 200, sessions);
            } else {
                sendErrorResponse(exchange, 405, "Method not allowed");
            }
        }
    }
    
    /**
     * Automation handler for extension automation requests
     */
    private class AutomationHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            
            if ("POST".equals(exchange.getRequestMethod())) {
                String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                
                try {
                    JsonNode request = objectMapper.readTree(requestBody);
                    String action = request.get("action").asText();
                    String sessionId = request.has("sessionId") ? request.get("sessionId").asText() : "default";
                    
                    Map<String, Object> result = processAutomationRequest(sessionId, action, request);
                    sendJsonResponse(exchange, 200, result);
                    
                } catch (Exception e) {
                    logger.error("Automation request failed: {}", e.getMessage(), e);
                    sendErrorResponse(exchange, 500, "Automation failed: " + e.getMessage());
                }
            } else {
                sendErrorResponse(exchange, 405, "Method not allowed");
            }
        }
    }
    
    /**
     * Process automation requests from extension
     */
    private Map<String, Object> processAutomationRequest(String sessionId, String action, JsonNode request) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("action", action);
        result.put("sessionId", sessionId);
        
        try {
            if (browserManager != null) {
                switch (action) {
                    case "fill_form":
                        result = browserManager.automateFormFill(sessionId, request);
                        break;
                    case "click_element":
                        result = browserManager.automateClick(sessionId, request);
                        break;
                    case "navigate":
                        result = browserManager.automateNavigation(sessionId, request);
                        break;
                    case "wait_for_element":
                        result = browserManager.automateWait(sessionId, request);
                        break;
                    default:
                        result.put("success", false);
                        result.put("error", "Unknown automation action: " + action);
                }
            } else {
                result.put("success", false);
                result.put("error", "Browser manager not available");
            }
            
        } catch (Exception e) {
            logger.error("Automation action {} failed for session {}: {}", action, sessionId, e.getMessage(), e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Extension file handler for serving extension files
     */
    private class ExtensionFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            enableCORS(exchange);
            
            // Serve basic extension installation info
            Map<String, Object> info = Map.of(
                "message", "Chrome extension files endpoint",
                "installationUrl", "http://localhost:" + serverPort + "/extension-files/",
                "status", "Extension server running"
            );
            
            sendJsonResponse(exchange, 200, info);
        }
    }
    
    // Utility methods
    
    private void enableCORS(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, X-Burp-MCP-Extension");
    }
    
    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, responseBytes.length);
        
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(responseBytes);
        }
    }
    
    private void sendJsonResponse(HttpExchange exchange, int statusCode, Object data) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        String json = objectMapper.writeValueAsString(data);
        sendResponse(exchange, statusCode, json);
    }
    
    private void sendErrorResponse(HttpExchange exchange, int statusCode, String error) throws IOException {
        Map<String, Object> errorResponse = Map.of(
            "success", false,
            "error", error,
            "timestamp", System.currentTimeMillis()
        );
        sendJsonResponse(exchange, statusCode, errorResponse);
    }
    
    // Getters and state methods
    
    public boolean isRunning() {
        return serverRunning.get();
    }
    
    public int getServerPort() {
        return serverPort;
    }
    
    public int getActiveSessionCount() {
        return activeSessions.size();
    }
    
    public ExtensionSession getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    public Map<String, ExtensionSession> getAllSessions() {
        return new HashMap<>(activeSessions);
    }
    
    /**
     * Extension session data
     */
    public static class ExtensionSession {
        private final String sessionId;
        private final String initialUrl;
        private final String extensionVersion;
        private final long createdAt;
        
        private String currentUrl;
        private String pageTitle;
        private long lastActivity;
        private boolean isActive = true;
        
        public ExtensionSession(String sessionId, String initialUrl, String extensionVersion) {
            this.sessionId = sessionId;
            this.initialUrl = initialUrl;
            this.extensionVersion = extensionVersion;
            this.createdAt = System.currentTimeMillis();
            this.currentUrl = initialUrl;
            this.lastActivity = createdAt;
        }
        
        public void updateCurrentUrl(String url) {
            this.currentUrl = url;
            this.lastActivity = System.currentTimeMillis();
        }
        
        public void setPageTitle(String title) {
            this.pageTitle = title;
            this.lastActivity = System.currentTimeMillis();
        }
        
        public Map<String, Object> toMap() {
            return Map.of(
                "sessionId", sessionId,
                "initialUrl", initialUrl,
                "currentUrl", currentUrl != null ? currentUrl : initialUrl,
                "pageTitle", pageTitle != null ? pageTitle : "",
                "extensionVersion", extensionVersion,
                "createdAt", createdAt,
                "lastActivity", lastActivity,
                "isActive", isActive
            );
        }
        
        // Getters
        public String getSessionId() { return sessionId; }
        public String getInitialUrl() { return initialUrl; }
        public String getCurrentUrl() { return currentUrl; }
        public String getPageTitle() { return pageTitle; }
        public String getExtensionVersion() { return extensionVersion; }
        public long getCreatedAt() { return createdAt; }
        public long getLastActivity() { return lastActivity; }
        public boolean isActive() { return isActive; }
        public void setActive(boolean active) { this.isActive = active; }
    }
}