package com.burp.mcp.proxy.websocket;

import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.BinaryMessageAction;

/**
 * Interface for WebSocket message interceptor rules using Chain of Responsibility pattern
 * Each rule can inspect and modify WebSocket messages based on specific criteria
 */
public interface WebSocketMessageInterceptorRule {
    
    /**
     * Determines if this rule should be applied to the given message context
     * 
     * @param context The WebSocket message context
     * @return true if the rule should be applied, false otherwise
     */
    boolean shouldApply(WebSocketMessageContext context);
    
    /**
     * Apply this rule's modifications to a text message
     * 
     * @param textMessage The WebSocket text message to process
     * @param context The message context
     * @return Result of applying the rule
     */
    TextMessageRuleResult applyToTextMessage(TextMessage textMessage, WebSocketMessageContext context);
    
    /**
     * Apply this rule's modifications to a binary message
     * 
     * @param binaryMessage The WebSocket binary message to process
     * @param context The message context
     * @return Result of applying the rule
     */
    BinaryMessageRuleResult applyToBinaryMessage(BinaryMessage binaryMessage, WebSocketMessageContext context);
    
    /**
     * Get a human-readable description of what this rule does
     * 
     * @return Description of the rule's functionality
     */
    default String getDescription() {
        return getClass().getSimpleName();
    }
    
    /**
     * Get the priority of this rule (lower values execute first)
     * 
     * @return Priority value (0-100, default 50)
     */
    default int getPriority() {
        return 50;
    }
    
    /**
     * Whether this rule can be safely applied in production environments
     * 
     * @return true if safe for production, false for development/testing only
     */
    default boolean isProductionSafe() {
        return true;
    }
    
    /**
     * Result of applying a rule to a text message
     */
    public static class TextMessageRuleResult {
        private final boolean modified;
        private final boolean shouldBlock;
        private final TextMessage modifiedTextMessage;
        private final String reason;
        
        private TextMessageRuleResult(boolean modified, boolean shouldBlock, TextMessage modifiedTextMessage, String reason) {
            this.modified = modified;
            this.shouldBlock = shouldBlock;
            this.modifiedTextMessage = modifiedTextMessage;
            this.reason = reason;
        }
        
        public static TextMessageRuleResult continueWith(TextMessage message) {
            return new TextMessageRuleResult(false, false, message, null);
        }
        
        public static TextMessageRuleResult modifiedWith(TextMessage message, String reason) {
            return new TextMessageRuleResult(true, false, message, reason);
        }
        
        public static TextMessageRuleResult block(String reason) {
            return new TextMessageRuleResult(false, true, null, reason);
        }
        
        public boolean isModified() { return modified; }
        public boolean shouldBlock() { return shouldBlock; }
        public TextMessage getModifiedTextMessage() { return modifiedTextMessage; }
        public String getReason() { return reason; }
    }
    
    /**
     * Result of applying a rule to a binary message
     */
    public static class BinaryMessageRuleResult {
        private final boolean modified;
        private final boolean shouldBlock;
        private final BinaryMessage modifiedBinaryMessage;
        private final String reason;
        
        private BinaryMessageRuleResult(boolean modified, boolean shouldBlock, BinaryMessage modifiedBinaryMessage, String reason) {
            this.modified = modified;
            this.shouldBlock = shouldBlock;
            this.modifiedBinaryMessage = modifiedBinaryMessage;
            this.reason = reason;
        }
        
        public static BinaryMessageRuleResult continueWith(BinaryMessage message) {
            return new BinaryMessageRuleResult(false, false, message, null);
        }
        
        public static BinaryMessageRuleResult modifiedWith(BinaryMessage message, String reason) {
            return new BinaryMessageRuleResult(true, false, message, reason);
        }
        
        public static BinaryMessageRuleResult block(String reason) {
            return new BinaryMessageRuleResult(false, true, null, reason);
        }
        
        public boolean isModified() { return modified; }
        public boolean shouldBlock() { return shouldBlock; }
        public BinaryMessage getModifiedBinaryMessage() { return modifiedBinaryMessage; }
        public String getReason() { return reason; }
    }
}
