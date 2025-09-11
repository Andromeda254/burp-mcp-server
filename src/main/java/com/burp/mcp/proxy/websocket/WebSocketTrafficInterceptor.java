package com.burp.mcp.proxy.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.burp.mcp.proxy.websocket.rules.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Comprehensive WebSocket traffic interceptor for live BurpSuite Professional integration
 * Implements classical Java design patterns: Strategy, Observer, Chain of Responsibility
 * 
 * Features:
 * - Real-time WebSocket message interception and modification
 * - Bi-directional traffic analysis with security scanning
 * - Message filtering and transformation
 * - Protocol-specific message handling (JSON, XML, binary protocols)
 * - Security vulnerability detection in WebSocket communications
 * - Traffic replay and session management
 */
public class WebSocketTrafficInterceptor implements WebSocketCreatedHandler, MessageHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketTrafficInterceptor.class);
    
    private final MontoyaApi api;
    private final WebSocketMessageAnalyzer analyzer;
    private final WebSocketMessageModifier modifier;
    private final WebSocketSessionManager sessionManager;
    private final List<WebSocketMessageInterceptorRule> interceptorRules;
    private final ExecutorService messageProcessingExecutor;
    
    // Statistics and monitoring
    private final AtomicLong totalConnectionsCreated = new AtomicLong(0);
    private final AtomicLong totalMessagesProcessed = new AtomicLong(0);
    private final Map<String, WebSocketConnectionStats> connectionStats = new ConcurrentHashMap<>();
    
    // Configuration
    private boolean interceptionEnabled = true;
    private boolean securityAnalysisEnabled = true;
    private boolean messageModificationEnabled = true;
    private int maxConcurrentConnections = 100;
    private int messageProcessingThreads = 4;
    
    // Security patterns for WebSocket messages
    private final List<Pattern> injectionPatterns = List.of(
        Pattern.compile("(?i)(<script[^>]*>.*?</script>)", Pattern.DOTALL),
        Pattern.compile("(?i)(javascript:)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)('|(\\\\-\\\\-)|(;)|(\\\\||\\\\|))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(union(.*)select)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(eval\\s*\\(|exec\\s*\\(|system\\s*\\()", Pattern.CASE_INSENSITIVE)
    );
    
    public WebSocketTrafficInterceptor(MontoyaApi api) {
        this.api = api;
        this.analyzer = new WebSocketMessageAnalyzer();
        this.modifier = new WebSocketMessageModifier();
        this.sessionManager = new WebSocketSessionManager();
        this.interceptorRules = new ArrayList<>();
        this.messageProcessingExecutor = Executors.newFixedThreadPool(messageProcessingThreads);
        
        initializeDefaultRules();
        registerWithBurpSuite();
        
        logger.info("WebSocket traffic interceptor initialized for live BurpSuite integration");
    }
    
    private void initializeDefaultRules() {
        // Add default WebSocket message interception rules
        addInterceptorRule(new WebSocketSecurityScanningRule());
        addInterceptorRule(new WebSocketAuthenticationRule());
        addInterceptorRule(new WebSocketDataValidationRule());
        addInterceptorRule(new WebSocketRateLimitingRule());
        addInterceptorRule(new WebSocketLoggingRule());
        
        logger.info("Initialized {} WebSocket interceptor rules", interceptorRules.size());
    }
    
    private void registerWithBurpSuite() {
        if (api != null) {
            api.websockets().registerWebSocketCreatedHandler(this);
            api.logging().logToOutput("[WEBSOCKET-INTERCEPTOR] WebSocket traffic interception enabled");
            logger.info("Registered WebSocket handler with BurpSuite proxy");
        }
    }
    
    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        if (!interceptionEnabled) {
            return;
        }
        
        try {
            var webSocket = webSocketCreated.webSocket();
            var upgradeRequest = webSocketCreated.upgradeRequest();
            var connectionId = generateConnectionId(upgradeRequest);
            
            var totalConnections = totalConnectionsCreated.incrementAndGet();
            
            // Check connection limits
            if (sessionManager.getActiveConnectionCount() >= maxConcurrentConnections) {
                logger.warn("Maximum WebSocket connections limit reached: {}", maxConcurrentConnections);
                if (api != null) {
                    api.logging().logToOutput("[WEBSOCKET-LIMIT] Maximum connections limit reached, monitoring only");
                }
            }
            
            // Create session for this WebSocket connection
            var session = sessionManager.createSession(connectionId, upgradeRequest, webSocket);
            connectionStats.put(connectionId, new WebSocketConnectionStats(connectionId, upgradeRequest.url()));
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[WEBSOCKET-CREATED] Connection #%d to %s (ID: %s)",
                    totalConnections, upgradeRequest.url(), connectionId
                ));
            }
            
            logger.info("WebSocket connection created: {} to {}", connectionId, upgradeRequest.url());
            
            // Analyze WebSocket handshake for security issues
            if (securityAnalysisEnabled) {
                analyzeWebSocketHandshake(upgradeRequest, connectionId);
            }
            
            // Register message handler for this WebSocket
            webSocket.registerMessageHandler(this);
            
        } catch (Exception e) {
            logger.error("Error handling WebSocket creation: {}", e.getMessage(), e);
            if (api != null) {
                api.logging().logToError("[WEBSOCKET-ERROR] Failed to handle WebSocket creation: " + e.getMessage());
            }
        }
    }
    
    @Override
    public TextMessageAction handleTextMessage(TextMessage textMessage) {
        if (!interceptionEnabled) {
            return TextMessageAction.continueWith(textMessage);
        }
        
        return processTextMessage(textMessage);
    }
    
    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
        if (!interceptionEnabled) {
            return BinaryMessageAction.continueWith(binaryMessage);
        }
        
        return processBinaryMessage(binaryMessage);
    }
    
    private TextMessageAction processTextMessage(TextMessage textMessage) {
        var messageId = totalMessagesProcessed.incrementAndGet();
        
        try {
            var payload = textMessage.payload();
            var direction = textMessage.direction();
            var connectionId = "ws_" + System.currentTimeMillis(); // Generate connection ID
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[WEBSOCKET-TEXT] Message #%d [%s] Length: %d chars (Connection: %s)",
                    messageId, direction, payload.length(), connectionId
                ));
            }
            
            logger.debug("Processing WebSocket text message: {} chars, direction: {}", 
                payload.length(), direction);
            
            // Update connection statistics
            updateConnectionStats(connectionId, true, direction, payload.length());
            
            // Process message asynchronously to avoid blocking
            var processingFuture = CompletableFuture.supplyAsync(() -> {
                return processWebSocketTextMessage(textMessage, connectionId, messageId);
            }, messageProcessingExecutor);
            
            // Get result with timeout to prevent blocking
            try {
                var result = processingFuture.get(5, TimeUnit.SECONDS);
                return result != null ? result : TextMessageAction.continueWith(textMessage);
            } catch (TimeoutException e) {
                logger.warn("WebSocket text message processing timeout for message #{}", messageId);
                return TextMessageAction.continueWith(textMessage);
            }
            
        } catch (Exception e) {
            logger.error("Error processing WebSocket text message #{}: {}", messageId, e.getMessage(), e);
            if (api != null) {
                api.logging().logToError("[WEBSOCKET-ERROR] Text message processing failed: " + e.getMessage());
            }
            return TextMessageAction.continueWith(textMessage);
        }
    }
    
    private BinaryMessageAction processBinaryMessage(BinaryMessage binaryMessage) {
        var messageId = totalMessagesProcessed.incrementAndGet();
        
        try {
            var payload = binaryMessage.payload();
            var direction = binaryMessage.direction();
            var connectionId = "ws_" + System.currentTimeMillis(); // Generate connection ID
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[WEBSOCKET-BINARY] Message #%d [%s] Length: %d bytes (Connection: %s)",
                    messageId, direction, payload.length(), connectionId
                ));
            }
            
            logger.debug("Processing WebSocket binary message: {} bytes, direction: {}", 
                payload.length(), direction);
            
            // Update connection statistics
            updateConnectionStats(connectionId, false, direction, payload.length());
            
            // Process message asynchronously
            var processingFuture = CompletableFuture.supplyAsync(() -> {
                return processWebSocketBinaryMessage(binaryMessage, connectionId, messageId);
            }, messageProcessingExecutor);
            
            // Get result with timeout
            try {
                var result = processingFuture.get(5, TimeUnit.SECONDS);
                return result != null ? result : BinaryMessageAction.continueWith(binaryMessage);
            } catch (TimeoutException e) {
                logger.warn("WebSocket binary message processing timeout for message #{}", messageId);
                return BinaryMessageAction.continueWith(binaryMessage);
            }
            
        } catch (Exception e) {
            logger.error("Error processing WebSocket binary message #{}: {}", messageId, e.getMessage(), e);
            if (api != null) {
                api.logging().logToError("[WEBSOCKET-ERROR] Binary message processing failed: " + e.getMessage());
            }
            return BinaryMessageAction.continueWith(binaryMessage);
        }
    }
    
    private TextMessageAction processWebSocketTextMessage(TextMessage textMessage, String connectionId, long messageId) {
        var payload = textMessage.payload();
        var direction = textMessage.direction();
        
        // Create message context for rule processing
        var context = new WebSocketMessageContext(connectionId, messageId, direction, 
            WebSocketMessageContext.MessageType.TEXT, Instant.now());
        context.setTextPayload(payload);
        
        // Apply interception rules using Chain of Responsibility pattern
        TextMessage modifiedMessage = textMessage;
        boolean messageModified = false;
        
        for (var rule : interceptorRules) {
            try {
                if (rule.shouldApply(context)) {
                    var result = rule.applyToTextMessage(modifiedMessage, context);
                    if (result.isModified()) {
                        modifiedMessage = result.getModifiedTextMessage();
                        messageModified = true;
                        context.addAppliedRule(rule.getClass().getSimpleName());
                        
                        logger.debug("Applied rule {} to WebSocket text message #{}", 
                            rule.getClass().getSimpleName(), messageId);
                    }
                    
                    if (result.shouldBlock()) {
                        if (api != null) {
                            api.logging().logToOutput(String.format(
                                "[WEBSOCKET-BLOCKED] Message #%d blocked by rule: %s",
                                messageId, rule.getClass().getSimpleName()
                            ));
                        }
                        return TextMessageAction.drop();
                    }
                }
            } catch (Exception e) {
                logger.error("Error applying WebSocket rule {}: {}", 
                    rule.getClass().getSimpleName(), e.getMessage());
            }
        }
        
        // Log modification summary
        if (messageModified && api != null) {
            api.logging().logToOutput(String.format(
                "[WEBSOCKET-MODIFIED] Message #%d modified by %d rules (Connection: %s)",
                messageId, context.getAppliedRules().size(), connectionId
            ));
        }
        
        return TextMessageAction.continueWith(modifiedMessage);
    }
    
    private BinaryMessageAction processWebSocketBinaryMessage(BinaryMessage binaryMessage, String connectionId, long messageId) {
        var payload = binaryMessage.payload();
        var direction = binaryMessage.direction();
        
        // Create message context for rule processing
        var context = new WebSocketMessageContext(connectionId, messageId, direction, 
            WebSocketMessageContext.MessageType.BINARY, Instant.now());
        context.setBinaryPayload(payload.getBytes());
        
        // Apply interception rules
        BinaryMessage modifiedMessage = binaryMessage;
        boolean messageModified = false;
        
        for (var rule : interceptorRules) {
            try {
                if (rule.shouldApply(context)) {
                    var result = rule.applyToBinaryMessage(modifiedMessage, context);
                    if (result.isModified()) {
                        modifiedMessage = result.getModifiedBinaryMessage();
                        messageModified = true;
                        context.addAppliedRule(rule.getClass().getSimpleName());
                        
                        logger.debug("Applied rule {} to WebSocket binary message #{}", 
                            rule.getClass().getSimpleName(), messageId);
                    }
                    
                    if (result.shouldBlock()) {
                        if (api != null) {
                            api.logging().logToOutput(String.format(
                                "[WEBSOCKET-BLOCKED] Binary message #%d blocked by rule: %s",
                                messageId, rule.getClass().getSimpleName()
                            ));
                        }
                        return BinaryMessageAction.drop();
                    }
                }
            } catch (Exception e) {
                logger.error("Error applying WebSocket binary rule {}: {}", 
                    rule.getClass().getSimpleName(), e.getMessage());
            }
        }
        
        // Log modification summary
        if (messageModified && api != null) {
            api.logging().logToOutput(String.format(
                "[WEBSOCKET-MODIFIED] Binary message #%d modified by %d rules (Connection: %s)",
                messageId, context.getAppliedRules().size(), connectionId
            ));
        }
        
        return BinaryMessageAction.continueWith(modifiedMessage);
    }
    
    private void analyzeWebSocketHandshake(HttpRequest upgradeRequest, String connectionId) {
        try {
            var analysis = analyzer.analyzeHandshake(upgradeRequest);
            
            if (analysis.hasSecurityIssues()) {
                var issues = analysis.getSecurityIssues();
                logger.warn("WebSocket handshake security issues for {}: {}", 
                    connectionId, issues);
                
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[WEBSOCKET-SECURITY] Handshake issues for %s: %s",
                        connectionId, String.join(", ", issues)
                    ));
                }
            }
            
            if (analysis.containsSensitiveData()) {
                logger.warn("Sensitive data detected in WebSocket handshake for {}", connectionId);
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[WEBSOCKET-SENSITIVE] Sensitive data in handshake for %s", connectionId
                    ));
                }
            }
            
        } catch (Exception e) {
            logger.error("Error analyzing WebSocket handshake for {}: {}", connectionId, e.getMessage());
        }
    }
    
    private void updateConnectionStats(String connectionId, boolean isText, Direction direction, int messageSize) {
        var stats = connectionStats.get(connectionId);
        if (stats != null) {
            if (direction == Direction.CLIENT_TO_SERVER) {
                if (isText) {
                    stats.incrementClientTextMessages();
                    stats.addClientTextBytes(messageSize);
                } else {
                    stats.incrementClientBinaryMessages();
                    stats.addClientBinaryBytes(messageSize);
                }
            } else {
                if (isText) {
                    stats.incrementServerTextMessages();
                    stats.addServerTextBytes(messageSize);
                } else {
                    stats.incrementServerBinaryMessages();
                    stats.addServerBinaryBytes(messageSize);
                }
            }
        }
    }
    
    private String generateConnectionId(HttpRequest upgradeRequest) {
        return String.format("ws_%d_%s", 
            System.currentTimeMillis(),
            Integer.toHexString(upgradeRequest.url().hashCode())
        );
    }
    
    // Public API methods
    public void addInterceptorRule(WebSocketMessageInterceptorRule rule) {
        interceptorRules.add(rule);
        logger.info("Added WebSocket interceptor rule: {}", rule.getClass().getSimpleName());
    }
    
    public void removeInterceptorRule(Class<? extends WebSocketMessageInterceptorRule> ruleClass) {
        interceptorRules.removeIf(rule -> rule.getClass().equals(ruleClass));
        logger.info("Removed WebSocket interceptor rule: {}", ruleClass.getSimpleName());
    }
    
    public void setInterceptionEnabled(boolean enabled) {
        this.interceptionEnabled = enabled;
        logger.info("WebSocket interception {}", enabled ? "enabled" : "disabled");
        
        if (api != null) {
            api.logging().logToOutput("[WEBSOCKET-CONFIG] Interception " + 
                (enabled ? "enabled" : "disabled"));
        }
    }
    
    public void setSecurityAnalysisEnabled(boolean enabled) {
        this.securityAnalysisEnabled = enabled;
        logger.info("WebSocket security analysis {}", enabled ? "enabled" : "disabled");
    }
    
    public void setMessageModificationEnabled(boolean enabled) {
        this.messageModificationEnabled = enabled;
        logger.info("WebSocket message modification {}", enabled ? "enabled" : "disabled");
    }
    
    public WebSocketInterceptionStats getStats() {
        var activeConnections = sessionManager.getActiveConnectionCount();
        var totalMessages = totalMessagesProcessed.get();
        var totalConnections = totalConnectionsCreated.get();
        
        var connectionStatsList = new ArrayList<>(connectionStats.values());
        
        return new WebSocketInterceptionStats(
            totalConnections, activeConnections, totalMessages,
            interceptorRules.size(), interceptionEnabled,
            connectionStatsList
        );
    }
    
    public void cleanup() {
        messageProcessingExecutor.shutdown();
        try {
            if (!messageProcessingExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                messageProcessingExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            messageProcessingExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        sessionManager.cleanup();
        connectionStats.clear();
        
        logger.info("WebSocket traffic interceptor cleanup completed");
    }
    
    /**
     * Statistics tracking for WebSocket connections
     */
    public static class WebSocketConnectionStats {
        private final String connectionId;
        private final String url;
        private final long createdTime;
        
        private long clientTextMessages = 0;
        private long serverTextMessages = 0;
        private long clientBinaryMessages = 0;
        private long serverBinaryMessages = 0;
        private long clientTextBytes = 0;
        private long serverTextBytes = 0;
        private long clientBinaryBytes = 0;
        private long serverBinaryBytes = 0;
        
        public WebSocketConnectionStats(String connectionId, String url) {
            this.connectionId = connectionId;
            this.url = url;
            this.createdTime = System.currentTimeMillis();
        }
        
        // Getters and increment methods
        public String getConnectionId() { return connectionId; }
        public String getUrl() { return url; }
        public long getCreatedTime() { return createdTime; }
        
        public void incrementClientTextMessages() { clientTextMessages++; }
        public void incrementServerTextMessages() { serverTextMessages++; }
        public void incrementClientBinaryMessages() { clientBinaryMessages++; }
        public void incrementServerBinaryMessages() { serverBinaryMessages++; }
        
        public void addClientTextBytes(long bytes) { clientTextBytes += bytes; }
        public void addServerTextBytes(long bytes) { serverTextBytes += bytes; }
        public void addClientBinaryBytes(long bytes) { clientBinaryBytes += bytes; }
        public void addServerBinaryBytes(long bytes) { serverBinaryBytes += bytes; }
        
        public long getTotalMessages() { 
            return clientTextMessages + serverTextMessages + clientBinaryMessages + serverBinaryMessages; 
        }
        
        public long getTotalBytes() { 
            return clientTextBytes + serverTextBytes + clientBinaryBytes + serverBinaryBytes; 
        }
    }
    
    /**
     * Overall WebSocket interception statistics
     */
    public static class WebSocketInterceptionStats {
        private final long totalConnections;
        private final int activeConnections;
        private final long totalMessages;
        private final int activeRules;
        private final boolean enabled;
        private final List<WebSocketConnectionStats> connectionStats;
        
        public WebSocketInterceptionStats(long totalConnections, int activeConnections, 
                long totalMessages, int activeRules, boolean enabled,
                List<WebSocketConnectionStats> connectionStats) {
            this.totalConnections = totalConnections;
            this.activeConnections = activeConnections;
            this.totalMessages = totalMessages;
            this.activeRules = activeRules;
            this.enabled = enabled;
            this.connectionStats = connectionStats;
        }
        
        // Getters
        public long getTotalConnections() { return totalConnections; }
        public int getActiveConnections() { return activeConnections; }
        public long getTotalMessages() { return totalMessages; }
        public int getActiveRules() { return activeRules; }
        public boolean isEnabled() { return enabled; }
        public List<WebSocketConnectionStats> getConnectionStats() { return connectionStats; }
    }
}
