package com.burp.mcp.proxy.websocket;

import burp.api.montoya.websocket.Direction;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Context object for WebSocket message processing
 * Provides shared state and metadata across interceptor rules
 */
public class WebSocketMessageContext {
    
    public enum MessageType {
        TEXT,
        BINARY
    }
    
    private final String connectionId;
    private final long messageId;
    private final Direction direction;
    private final MessageType messageType;
    private final Instant timestamp;
    
    private String textPayload;
    private byte[] binaryPayload;
    
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();
    private final Set<String> appliedRules = ConcurrentHashMap.newKeySet();
    private final Map<String, String> modifications = new ConcurrentHashMap<>();
    
    public WebSocketMessageContext(String connectionId, long messageId, Direction direction, 
            MessageType messageType, Instant timestamp) {
        this.connectionId = connectionId;
        this.messageId = messageId;
        this.direction = direction;
        this.messageType = messageType;
        this.timestamp = timestamp;
    }
    
    // Getters
    public String getConnectionId() { return connectionId; }
    public long getMessageId() { return messageId; }
    public Direction getDirection() { return direction; }
    public MessageType getMessageType() { return messageType; }
    public Instant getTimestamp() { return timestamp; }
    
    public String getTextPayload() { return textPayload; }
    public void setTextPayload(String textPayload) { this.textPayload = textPayload; }
    
    public byte[] getBinaryPayload() { return binaryPayload; }
    public void setBinaryPayload(byte[] binaryPayload) { this.binaryPayload = binaryPayload; }
    
    // Attribute management
    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }
    
    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String key) {
        return (T) attributes.get(key);
    }
    
    public <T> T getAttribute(String key, T defaultValue) {
        T value = getAttribute(key);
        return value != null ? value : defaultValue;
    }
    
    public boolean hasAttribute(String key) {
        return attributes.containsKey(key);
    }
    
    // Rule tracking
    public void addAppliedRule(String ruleName) {
        appliedRules.add(ruleName);
    }
    
    public boolean hasRuleBeenApplied(String ruleName) {
        return appliedRules.contains(ruleName);
    }
    
    public Set<String> getAppliedRules() {
        return new HashSet<>(appliedRules);
    }
    
    // Modification tracking
    public void addModification(String type, String description) {
        modifications.put(type, description);
    }
    
    public Map<String, String> getModifications() {
        return new HashMap<>(modifications);
    }
    
    public int getModificationCount() {
        return modifications.size();
    }
    
    public boolean isFromClient() {
        return direction == Direction.CLIENT_TO_SERVER;
    }
    
    public boolean isFromServer() {
        return direction == Direction.SERVER_TO_CLIENT;
    }
    
    public boolean isTextMessage() {
        return messageType == MessageType.TEXT;
    }
    
    public boolean isBinaryMessage() {
        return messageType == MessageType.BINARY;
    }
    
    @Override
    public String toString() {
        return String.format("WebSocketMessageContext{connectionId='%s', messageId=%d, direction=%s, type=%s, appliedRules=%d}", 
            connectionId, messageId, direction, messageType, appliedRules.size());
    }
}
