package com.burp.mcp.proxy;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Security header injection utility for response modification
 * Implements security best practices by adding protective headers
 */
public class SecurityHeaderInjector {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityHeaderInjector.class);
    
    // Default security headers to inject
    private final Map<String, String> defaultSecurityHeaders = new LinkedHashMap<>();
    private final Set<String> sensitiveHeadersToRemove = new HashSet<>();
    
    public SecurityHeaderInjector() {
        initializeDefaultHeaders();
        initializeSensitiveHeaders();
    }
    
    private void initializeDefaultHeaders() {
        // Content Security Policy
        defaultSecurityHeaders.put("Content-Security-Policy", 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
        
        // HTTP Strict Transport Security
        defaultSecurityHeaders.put("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload");
        
        // X-Frame-Options
        defaultSecurityHeaders.put("X-Frame-Options", "SAMEORIGIN");
        
        // X-Content-Type-Options
        defaultSecurityHeaders.put("X-Content-Type-Options", "nosniff");
        
        // Referrer Policy
        defaultSecurityHeaders.put("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Permissions Policy
        defaultSecurityHeaders.put("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()");
        
        // X-XSS-Protection (legacy but still useful)
        defaultSecurityHeaders.put("X-XSS-Protection", "1; mode=block");
        
        logger.debug("Initialized {} default security headers", defaultSecurityHeaders.size());
    }
    
    private void initializeSensitiveHeaders() {
        sensitiveHeadersToRemove.add("Server");
        sensitiveHeadersToRemove.add("X-Powered-By");
        sensitiveHeadersToRemove.add("X-AspNet-Version");
        sensitiveHeadersToRemove.add("X-AspNetMvc-Version");
        sensitiveHeadersToRemove.add("X-Generator");
        
        logger.debug("Initialized {} sensitive headers for removal", sensitiveHeadersToRemove.size());
    }
    
    /**
     * Inject security headers into response
     * 
     * @param response Original HTTP response
     * @param options Injection options
     * @return Modified response with security headers
     */
    public HttpResponse injectSecurityHeaders(HttpResponse response, SecurityHeaderOptions options) {
        try {
            var existingHeaders = new ArrayList<>(response.headers());
            var modifiedHeaders = new ArrayList<HttpHeader>();
            
            // Remove sensitive headers if requested
            if (options.isRemoveSensitiveHeaders()) {
                existingHeaders = existingHeaders.stream()
                    .filter(header -> !sensitiveHeadersToRemove.contains(header.name()))
                    .collect(Collectors.toCollection(ArrayList::new));
                
                logger.debug("Removed {} sensitive headers", 
                    response.headers().size() - existingHeaders.size());
            }
            
            // Add existing headers (except those being overridden)
            var headersToInject = options.getCustomHeaders().isEmpty() ? 
                defaultSecurityHeaders : options.getCustomHeaders();
            
            for (var header : existingHeaders) {
                if (!headersToInject.containsKey(header.name()) || !options.isOverrideExisting()) {
                    modifiedHeaders.add(header);
                }
            }
            
            // Add security headers
            for (var entry : headersToInject.entrySet()) {
                var headerName = entry.getKey();
                var headerValue = entry.getValue();
                
                // Skip if header already exists and we're not overriding
                if (!options.isOverrideExisting() && hasHeader(existingHeaders, headerName)) {
                    continue;
                }
                
                modifiedHeaders.add(HttpHeader.httpHeader(headerName, headerValue));
                logger.debug("Added security header: {} = {}", headerName, headerValue);
            }
            
            // Create modified response
            return response.withUpdatedHeaders(modifiedHeaders);
            
        } catch (Exception e) {
            logger.error("Failed to inject security headers: {}", e.getMessage(), e);
            return response;
        }
    }
    
    /**
     * Inject default security headers
     */
    public HttpResponse injectDefaultSecurityHeaders(HttpResponse response) {
        return injectSecurityHeaders(response, new SecurityHeaderOptions());
    }
    
    /**
     * Check if response already has a specific header
     */
    private boolean hasHeader(List<HttpHeader> headers, String headerName) {
        return headers.stream()
            .anyMatch(header -> header.name().equalsIgnoreCase(headerName));
    }
    
    /**
     * Get current default security headers
     */
    public Map<String, String> getDefaultSecurityHeaders() {
        return new HashMap<>(defaultSecurityHeaders);
    }
    
    /**
     * Update default security headers
     */
    public void updateDefaultHeader(String name, String value) {
        defaultSecurityHeaders.put(name, value);
        logger.info("Updated default security header: {} = {}", name, value);
    }
    
    /**
     * Remove a default security header
     */
    public void removeDefaultHeader(String name) {
        if (defaultSecurityHeaders.remove(name) != null) {
            logger.info("Removed default security header: {}", name);
        }
    }
    
    /**
     * Configuration options for security header injection
     */
    public static class SecurityHeaderOptions {
        private boolean overrideExisting = true;
        private boolean removeSensitiveHeaders = true;
        private Map<String, String> customHeaders = new HashMap<>();
        
        public SecurityHeaderOptions() {}
        
        public SecurityHeaderOptions overrideExisting(boolean override) {
            this.overrideExisting = override;
            return this;
        }
        
        public SecurityHeaderOptions removeSensitiveHeaders(boolean remove) {
            this.removeSensitiveHeaders = remove;
            return this;
        }
        
        public SecurityHeaderOptions withCustomHeaders(Map<String, String> headers) {
            this.customHeaders = new HashMap<>(headers);
            return this;
        }
        
        public SecurityHeaderOptions addCustomHeader(String name, String value) {
            this.customHeaders.put(name, value);
            return this;
        }
        
        // Getters
        public boolean isOverrideExisting() { return overrideExisting; }
        public boolean isRemoveSensitiveHeaders() { return removeSensitiveHeaders; }
        public Map<String, String> getCustomHeaders() { return customHeaders; }
    }
}
