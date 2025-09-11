package com.burp.mcp.proxy.websocket.rules;

import com.burp.mcp.proxy.websocket.WebSocketMessageInterceptorRule;
import com.burp.mcp.proxy.websocket.WebSocketMessageContext;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;
import java.util.List;

/**
 * Security scanning rule for WebSocket messages
 * Detects potential injection attacks and security vulnerabilities
 */
public class WebSocketSecurityScanningRule implements WebSocketMessageInterceptorRule {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketSecurityScanningRule.class);
    
    private final List<Pattern> securityPatterns = List.of(
        Pattern.compile("(?i)(<script[^>]*>.*?</script>)", Pattern.DOTALL),
        Pattern.compile("(?i)(javascript:)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)('|(\\\\-\\\\-)|(;)|(\\\\||\\\\|))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(union(.*)select)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(eval\\s*\\(|exec\\s*\\(|system\\s*\\()", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()", Pattern.CASE_INSENSITIVE)
    );
    
    @Override
    public boolean shouldApply(WebSocketMessageContext context) {
        // Apply to all messages for security scanning
        return true;
    }
    
    @Override
    public TextMessageRuleResult applyToTextMessage(TextMessage textMessage, WebSocketMessageContext context) {
        try {
            var payload = textMessage.payload();
            var threats = detectThreats(payload);
            
            if (!threats.isEmpty()) {
                logger.warn("Security threats detected in WebSocket text message #{}: {}", 
                    context.getMessageId(), threats);
                
                context.setAttribute("security_threats", threats);
                context.addModification("security_scan", 
                    String.format("Detected %d security threats", threats.size()));
                
                // For security rule, we log but don't block by default
                // Could be configured to block based on threat severity
                return TextMessageRuleResult.continueWith(textMessage);
            }
            
            return TextMessageRuleResult.continueWith(textMessage);
            
        } catch (Exception e) {
            logger.error("Error in WebSocket security scanning: {}", e.getMessage(), e);
            return TextMessageRuleResult.continueWith(textMessage);
        }
    }
    
    @Override
    public BinaryMessageRuleResult applyToBinaryMessage(BinaryMessage binaryMessage, WebSocketMessageContext context) {
        try {
            var payload = binaryMessage.payload();
            
            // For binary messages, do basic analysis
            if (payload.length() > 1024 * 1024) { // 1MB limit
                logger.warn("Large binary WebSocket message detected: {} bytes", payload.length());
                context.setAttribute("large_binary_message", true);
                context.addModification("security_scan", "Large binary message detected");
            }
            
            // Check for suspicious binary patterns (simple heuristics)
            if (containsSuspiciousBinaryContent(payload.getBytes())) {
                logger.warn("Suspicious binary content in WebSocket message #{}", context.getMessageId());
                context.setAttribute("suspicious_binary", true);
            }
            
            return BinaryMessageRuleResult.continueWith(binaryMessage);
            
        } catch (Exception e) {
            logger.error("Error in WebSocket binary security scanning: {}", e.getMessage(), e);
            return BinaryMessageRuleResult.continueWith(binaryMessage);
        }
    }
    
    private List<String> detectThreats(String payload) {
        var threats = new java.util.ArrayList<String>();
        
        for (var pattern : securityPatterns) {
            if (pattern.matcher(payload).find()) {
                threats.add("Injection pattern: " + pattern.pattern());
            }
        }
        
        return threats;
    }
    
    private boolean containsSuspiciousBinaryContent(byte[] payload) {
        // Simple heuristic: check for executable signatures
        if (payload.length >= 4) {
            // Check for PE header
            if (payload[0] == 0x4D && payload[1] == 0x5A) {
                return true;
            }
            // Check for ELF header
            if (payload[0] == 0x7F && payload[1] == 0x45 && 
                payload[2] == 0x4C && payload[3] == 0x46) {
                return true;
            }
        }
        
        return false;
    }
    
    @Override
    public String getDescription() {
        return "Scans WebSocket messages for security vulnerabilities and injection attempts";
    }
    
    @Override
    public int getPriority() {
        return 10; // High priority for security scanning
    }
}
