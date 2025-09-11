package com.burp.mcp.proxy;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Interface for request modification rules in Chain of Responsibility pattern
 * Each rule can inspect and modify HTTP requests based on specific criteria
 */
public interface RequestModificationRule {
    
    /**
     * Determines if this rule should be applied to the given request
     * 
     * @param request The HTTP request to evaluate
     * @param context The modification context for this session
     * @return true if the rule should be applied, false otherwise
     */
    boolean shouldApply(HttpRequest request, ModificationContext context);
    
    /**
     * Apply this rule's modifications to the request
     * 
     * @param request The HTTP request to modify
     * @param context The modification context for this session
     * @return The modified request, or null if no modification was made
     */
    HttpRequest apply(HttpRequest request, ModificationContext context);
    
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
}
