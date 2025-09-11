package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.RequestModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Modifies authentication headers in outgoing requests
 * Can add, modify, or replace authentication tokens dynamically
 */
public class AuthenticationHeaderModifier implements RequestModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationHeaderModifier.class);
    
    // Common authentication header names
    private static final Set<String> AUTH_HEADERS = Set.of(
        "Authorization",
        "Authentication",
        "X-API-Key",
        "X-Auth-Token", 
        "X-Access-Token",
        "X-Session-ID",
        "Cookie"
    );
    
    private final Map<String, String> headerReplacements = new HashMap<>();
    private final Map<String, String> tokenMappings = new HashMap<>();
    private boolean enabled = false; // Disabled by default for security
    private boolean replaceExisting = true;
    
    @Override
    public boolean shouldApply(HttpRequest request, ModificationContext context) {
        if (!enabled || headerReplacements.isEmpty()) {
            return false;
        }
        
        // Apply if we have replacements configured and the request matches criteria
        return hasTargetHost(request.url()) && hasAuthenticationHeaders(request);
    }
    
    @Override
    public HttpRequest apply(HttpRequest request, ModificationContext context) {
        try {
            var headers = new ArrayList<>(request.headers());
            boolean modified = false;
            
            // Process header replacements
            for (var entry : headerReplacements.entrySet()) {
                var headerName = entry.getKey();
                var newValue = entry.getValue();
                
                // Replace or add header
                if (replaceExisting) {
                    headers.removeIf(header -> header.name().equalsIgnoreCase(headerName));
                }
                
                // Add new header if value is not empty
                if (newValue != null && !newValue.isEmpty()) {
                    headers.add(HttpHeader.httpHeader(headerName, newValue));
                    modified = true;
                    
                    logger.debug("Modified authentication header '{}' for request to {}", 
                        headerName, request.url());
                }
            }
            
            if (modified) {
                context.addModification("auth_headers", 
                    String.format("Modified %d authentication headers", headerReplacements.size()));
                
                return request.withUpdatedHeaders(headers);
            }
            
            return request;
            
        } catch (Exception e) {
            logger.error("Error modifying authentication headers: {}", e.getMessage(), e);
            return request;
        }
    }
    
    private boolean hasAuthenticationHeaders(HttpRequest request) {
        return request.headers().stream()
            .anyMatch(header -> AUTH_HEADERS.contains(header.name()));
    }
    
    private boolean hasTargetHost(String url) {
        // For now, apply to all hosts
        // Could be extended to target specific hosts
        return true;
    }
    
    @Override
    public String getDescription() {
        return "Modifies authentication headers for dynamic token replacement";
    }
    
    @Override
    public int getPriority() {
        return 30; // Medium priority - after header removal
    }
    
    @Override
    public boolean isProductionSafe() {
        return false; // Authentication modification should be carefully controlled
    }
    
    // Configuration methods
    public void addHeaderReplacement(String headerName, String newValue) {
        headerReplacements.put(headerName, newValue);
        logger.info("Added authentication header replacement: {} -> [REDACTED]", headerName);
    }
    
    public void removeHeaderReplacement(String headerName) {
        if (headerReplacements.remove(headerName) != null) {
            logger.info("Removed authentication header replacement: {}", headerName);
        }
    }
    
    public void addTokenMapping(String oldToken, String newToken) {
        tokenMappings.put(oldToken, newToken);
        logger.info("Added token mapping: [REDACTED] -> [REDACTED]");
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("Authentication header modifier {}", enabled ? "enabled" : "disabled");
    }
    
    public void setReplaceExisting(boolean replace) {
        this.replaceExisting = replace;
        logger.info("Replace existing auth headers: {}", replace);
    }
    
    public void clearReplacements() {
        headerReplacements.clear();
        tokenMappings.clear();
        logger.info("Cleared all authentication header replacements");
    }
    
    public Set<String> getConfiguredHeaders() {
        return new HashSet<>(headerReplacements.keySet());
    }
    
    public int getReplacementCount() {
        return headerReplacements.size();
    }
}
