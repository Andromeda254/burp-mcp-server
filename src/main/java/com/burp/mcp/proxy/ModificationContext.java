package com.burp.mcp.proxy;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Context object for traffic modification operations
 * Provides shared state and metadata across modification rules
 */
public class ModificationContext {
    
    public enum Type {
        REQUEST,
        RESPONSE
    }
    
    private final String sessionId;
    private final Type type;
    private final long timestamp;
    private final Map<String, Object> attributes;
    private final Set<String> appliedRules;
    private final Map<String, String> modifications;
    
    public ModificationContext(String sessionId, Type type) {
        this.sessionId = sessionId;
        this.type = type;
        this.timestamp = System.currentTimeMillis();
        this.attributes = new ConcurrentHashMap<>();
        this.appliedRules = ConcurrentHashMap.newKeySet();
        this.modifications = new ConcurrentHashMap<>();
    }
    
    // Getters
    public String getSessionId() { return sessionId; }
    public Type getType() { return type; }
    public long getTimestamp() { return timestamp; }
    
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
    
    @Override
    public String toString() {
        return String.format("ModificationContext{sessionId='%s', type=%s, appliedRules=%d, modifications=%d}", 
            sessionId, type, appliedRules.size(), modifications.size());
    }
}
