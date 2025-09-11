package com.burp.mcp.proxy;

import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Interface for response modification rules in Chain of Responsibility pattern
 * Each rule can inspect and modify HTTP responses based on specific criteria
 */
public interface ResponseModificationRule {
    
    /**
     * Determines if this rule should be applied to the given response
     * 
     * @param response The HTTP response to evaluate
     * @param context The modification context for this session
     * @return true if the rule should be applied, false otherwise
     */
    boolean shouldApply(HttpResponse response, ModificationContext context);
    
    /**
     * Apply this rule's modifications to the response
     * 
     * @param response The HTTP response to modify
     * @param context The modification context for this session
     * @return The modified response, or null if no modification was made
     */
    HttpResponse apply(HttpResponse response, ModificationContext context);
    
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
