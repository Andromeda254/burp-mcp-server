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
 * Removes potentially sensitive headers from outgoing requests
 * Helps prevent information disclosure and improves privacy
 */
public class SecurityHeaderRemovalRule implements RequestModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityHeaderRemovalRule.class);
    
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
        "X-Forwarded-For",
        "X-Real-IP", 
        "X-Original-IP",
        "Client-IP",
        "X-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Cluster-Client-IP",
        "X-Forwarded-Host",
        "X-Forwarded-Server",
        "Via",
        "X-Forwarded-Proto",
        "X-Scheme",
        "Front-End-Https",
        "X-Original-URL",
        "X-Rewrite-URL"
    );
    
    private final Set<String> customSensitiveHeaders = new HashSet<>();
    private boolean enabled = true;
    
    @Override
    public boolean shouldApply(HttpRequest request, ModificationContext context) {
        if (!enabled) {
            return false;
        }
        
        // Check if request has any sensitive headers
        return request.headers().stream()
            .anyMatch(header -> isSensitiveHeader(header.name()));
    }
    
    @Override
    public HttpRequest apply(HttpRequest request, ModificationContext context) {
        try {
            var originalHeaders = request.headers();
            var filteredHeaders = originalHeaders.stream()
                .filter(header -> !isSensitiveHeader(header.name()))
                .collect(Collectors.toList());
            
            if (filteredHeaders.size() != originalHeaders.size()) {
                var removedCount = originalHeaders.size() - filteredHeaders.size();
                context.addModification("header_removal", 
                    String.format("Removed %d sensitive headers", removedCount));
                
                logger.debug("Removed {} sensitive headers from request to {}", 
                    removedCount, request.url());
                
                return request.withUpdatedHeaders(filteredHeaders);
            }
            
            return request;
            
        } catch (Exception e) {
            logger.error("Error removing sensitive headers: {}", e.getMessage(), e);
            return request;
        }
    }
    
    private boolean isSensitiveHeader(String headerName) {
        return SENSITIVE_HEADERS.contains(headerName) || 
               customSensitiveHeaders.contains(headerName.toLowerCase());
    }
    
    @Override
    public String getDescription() {
        return "Removes sensitive headers that could leak internal network information";
    }
    
    @Override
    public int getPriority() {
        return 10; // High priority - remove headers early
    }
    
    @Override
    public boolean isProductionSafe() {
        return true;
    }
    
    // Configuration methods
    public void addSensitiveHeader(String headerName) {
        customSensitiveHeaders.add(headerName.toLowerCase());
        logger.info("Added custom sensitive header: {}", headerName);
    }
    
    public void removeSensitiveHeader(String headerName) {
        if (customSensitiveHeaders.remove(headerName.toLowerCase())) {
            logger.info("Removed custom sensitive header: {}", headerName);
        }
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("Security header removal rule {}", enabled ? "enabled" : "disabled");
    }
    
    public Set<String> getSensitiveHeaders() {
        var allHeaders = new HashSet<>(SENSITIVE_HEADERS);
        allHeaders.addAll(customSensitiveHeaders);
        return allHeaders;
    }
}
