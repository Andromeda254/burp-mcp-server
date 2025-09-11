package com.burp.mcp.proxy.websocket;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

/**
 * Analyzes WebSocket handshakes and messages for security issues
 */
public class WebSocketMessageAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketMessageAnalyzer.class);
    
    // Security patterns for WebSocket content analysis
    private final List<Pattern> injectionPatterns = List.of(
        Pattern.compile("(?i)(<script[^>]*>.*?</script>)", Pattern.DOTALL),
        Pattern.compile("(?i)(javascript:)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)('|(\\\\-\\\\-)|(;)|(\\\\||\\\\|))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(union(.*)select)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(eval\\s*\\(|exec\\s*\\(|system\\s*\\()", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()", Pattern.CASE_INSENSITIVE)
    );
    
    private final List<Pattern> sensitiveDataPatterns = List.of(
        Pattern.compile("\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b"), // Credit card
        Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"), // SSN
        Pattern.compile("(?i)password\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?"), // Password fields
        Pattern.compile("(?i)api[_-]?key\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?"), // API keys
        Pattern.compile("(?i)token\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?") // Tokens
    );
    
    public HandshakeAnalysis analyzeHandshake(HttpRequest upgradeRequest) {
        var analysis = new HandshakeAnalysis();
        
        try {
            var headers = upgradeRequest.headers();
            var url = upgradeRequest.url();
            
            // Check for security headers
            analyzeSecurityHeaders(headers, analysis);
            
            // Check for sensitive data in URL/headers
            analyzeSensitiveData(upgradeRequest, analysis);
            
            // Validate WebSocket specific headers
            validateWebSocketHeaders(headers, analysis);
            
            // Check for authentication mechanisms
            analyzeAuthentication(headers, analysis);
            
            logger.debug("WebSocket handshake analysis completed for {}", url);
            
        } catch (Exception e) {
            logger.error("Error analyzing WebSocket handshake: {}", e.getMessage(), e);
            analysis.addError("Handshake analysis failed: " + e.getMessage());
        }
        
        return analysis;
    }
    
    private void analyzeSecurityHeaders(List<burp.api.montoya.http.message.HttpHeader> headers, HandshakeAnalysis analysis) {
        var headerMap = new HashMap<String, String>();
        for (var header : headers) {
            headerMap.put(header.name().toLowerCase(), header.value());
        }
        
        // Check for missing security headers
        if (!headerMap.containsKey("origin")) {
            analysis.addSecurityIssue("Missing Origin header validation");
        }
        
        // Check for weak WebSocket configuration
        if (headerMap.containsKey("sec-websocket-protocol")) {
            var protocols = headerMap.get("sec-websocket-protocol");
            if (protocols.contains("*") || protocols.isEmpty()) {
                analysis.addSecurityIssue("Weak WebSocket protocol validation");
            }
        }
    }
    
    private void analyzeSensitiveData(HttpRequest request, HandshakeAnalysis analysis) {
        var url = request.url();
        var body = request.bodyToString();
        var allContent = url + " " + body;
        
        for (var pattern : sensitiveDataPatterns) {
            if (pattern.matcher(allContent).find()) {
                analysis.setSensitiveDataDetected(true);
                break;
            }
        }
    }
    
    private void validateWebSocketHeaders(List<burp.api.montoya.http.message.HttpHeader> headers, HandshakeAnalysis analysis) {
        var hasWebSocketKey = false;
        var hasUpgrade = false;
        var hasConnection = false;
        
        for (var header : headers) {
            var name = header.name().toLowerCase();
            var value = header.value().toLowerCase();
            
            if ("sec-websocket-key".equals(name)) {
                hasWebSocketKey = true;
                if (value.length() < 16) {
                    analysis.addSecurityIssue("Weak WebSocket key");
                }
            } else if ("upgrade".equals(name) && "websocket".equals(value)) {
                hasUpgrade = true;
            } else if ("connection".equals(name) && value.contains("upgrade")) {
                hasConnection = true;
            }
        }
        
        if (!hasWebSocketKey) {
            analysis.addSecurityIssue("Missing WebSocket key");
        }
        if (!hasUpgrade) {
            analysis.addSecurityIssue("Missing or invalid Upgrade header");
        }
        if (!hasConnection) {
            analysis.addSecurityIssue("Missing or invalid Connection header");
        }
    }
    
    private void analyzeAuthentication(List<burp.api.montoya.http.message.HttpHeader> headers, HandshakeAnalysis analysis) {
        var hasAuth = false;
        
        for (var header : headers) {
            var name = header.name().toLowerCase();
            if ("authorization".equals(name) || "cookie".equals(name) || 
                name.startsWith("x-auth") || name.startsWith("x-api")) {
                hasAuth = true;
                break;
            }
        }
        
        if (!hasAuth) {
            analysis.addSecurityIssue("No authentication mechanism detected");
        }
    }
    
    /**
     * Analysis result for WebSocket handshake
     */
    public static class HandshakeAnalysis {
        private final List<String> securityIssues = new ArrayList<>();
        private final List<String> errors = new ArrayList<>();
        private boolean sensitiveDataDetected = false;
        
        public void addSecurityIssue(String issue) {
            securityIssues.add(issue);
        }
        
        public void addError(String error) {
            errors.add(error);
        }
        
        public void setSensitiveDataDetected(boolean detected) {
            this.sensitiveDataDetected = detected;
        }
        
        public boolean hasSecurityIssues() {
            return !securityIssues.isEmpty();
        }
        
        public List<String> getSecurityIssues() {
            return new ArrayList<>(securityIssues);
        }
        
        public boolean hasErrors() {
            return !errors.isEmpty();
        }
        
        public List<String> getErrors() {
            return new ArrayList<>(errors);
        }
        
        public boolean containsSensitiveData() {
            return sensitiveDataDetected;
        }
    }
}
