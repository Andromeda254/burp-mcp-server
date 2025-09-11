package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.RequestModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import com.burp.mcp.proxy.ContentFilterEngine;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.regex.Pattern;

/**
 * Sanitizes request payloads to prevent injection attacks
 * Uses content filtering engine for comprehensive payload analysis
 */
public class PayloadSanitizationRule implements RequestModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(PayloadSanitizationRule.class);
    
    private final ContentFilterEngine filterEngine;
    private boolean enabled = true;
    private boolean sanitizeBody = true;
    private boolean sanitizeParameters = true;
    private boolean strictMode = false;
    
    public PayloadSanitizationRule() {
        this.filterEngine = new ContentFilterEngine();
        initializeCustomFilters();
    }
    
    private void initializeCustomFilters() {
        // Add custom payload-specific patterns
        filterEngine.addRegexFilter("malicious_functions", 
            "(?i)(eval|exec|system|shell_exec|passthru|file_get_contents)\\s*\\(");
        
        filterEngine.addRegexFilter("path_traversal", 
            "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c)");
        
        filterEngine.addRegexFilter("command_injection", 
            "(?i)(;|\\||&|`|\\$\\(|\\${)");
        
        filterEngine.addRegexFilter("null_bytes", 
            "(%00|\\x00|\\u0000)");
    }
    
    @Override
    public boolean shouldApply(HttpRequest request, ModificationContext context) {
        if (!enabled) {
            return false;
        }
        
        // Apply to requests with bodies or parameters
        return hasRequestBody(request) || hasParameters(request);
    }
    
    @Override
    public HttpRequest apply(HttpRequest request, ModificationContext context) {
        try {
            boolean modified = false;
            HttpRequest modifiedRequest = request;
            
            // Sanitize request body
            if (sanitizeBody && hasRequestBody(request)) {
                var sanitizedBody = sanitizeBody(request);
                if (!sanitizedBody.equals(request.bodyToString())) {
                    modifiedRequest = modifiedRequest.withBody(sanitizedBody);
                    modified = true;
                    
                    logger.debug("Sanitized request body for {}", request.url());
                }
            }
            
            // Sanitize URL parameters
            if (sanitizeParameters && hasParameters(request)) {
                var sanitizedUrl = sanitizeUrl(request.url());
                if (!sanitizedUrl.equals(request.url())) {
                    modifiedRequest = modifiedRequest.withUpdatedHeaders(
                        modifiedRequest.headers()
                    ); // URL modification would require more complex approach
                    // For now, we log the sanitization
                    logger.debug("Would sanitize URL parameters for {}", request.url());
                }
            }
            
            if (modified) {
                context.addModification("payload_sanitization", "Sanitized malicious payload content");
            }
            
            return modifiedRequest;
            
        } catch (Exception e) {
            logger.error("Error sanitizing payload: {}", e.getMessage(), e);
            return request;
        }
    }
    
    private String sanitizeBody(HttpRequest request) {
        var body = request.bodyToString();
        if (body.isEmpty()) {
            return body;
        }
        
        var contentType = getContentType(request);
        var filterOptions = new ContentFilterEngine.FilterOptions()
            .sqlInjection(true)
            .xss(true)
            .sensitiveData(false) // Don't redact in request bodies
            .keywords(true)
            .replacements(true)
            .regexFilters(true);
        
        if (strictMode) {
            filterOptions = filterOptions.transformations(true);
        }
        
        return filterEngine.filterContent(body, contentType, filterOptions);
    }
    
    private String sanitizeUrl(String url) {
        try {
            // Extract and sanitize query parameters
            if (!url.contains("?")) {
                return url;
            }
            
            var parts = url.split("\\?", 2);
            var baseUrl = parts[0];
            var queryString = parts[1];
            
            var sanitizedQuery = sanitizeQueryString(queryString);
            
            return baseUrl + "?" + sanitizedQuery;
            
        } catch (Exception e) {
            logger.warn("Error sanitizing URL parameters: {}", e.getMessage());
            return url;
        }
    }
    
    private String sanitizeQueryString(String queryString) {
        if (queryString.isEmpty()) {
            return queryString;
        }
        
        var filterOptions = new ContentFilterEngine.FilterOptions()
            .sqlInjection(true)
            .xss(true)
            .regexFilters(true)
            .replacements(true);
        
        try {
            var decoded = URLDecoder.decode(queryString, StandardCharsets.UTF_8);
            var filtered = filterEngine.filterContent(decoded, "text/plain", filterOptions);
            return URLEncoder.encode(filtered, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.warn("Error processing query string: {}", e.getMessage());
            return queryString;
        }
    }
    
    private boolean hasRequestBody(HttpRequest request) {
        return !request.bodyToString().isEmpty();
    }
    
    private boolean hasParameters(HttpRequest request) {
        return request.url().contains("?");
    }
    
    private String getContentType(HttpRequest request) {
        return request.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
            .map(header -> header.value())
            .findFirst()
            .orElse("text/plain");
    }
    
    @Override
    public String getDescription() {
        return "Sanitizes request payloads to prevent injection attacks";
    }
    
    @Override
    public int getPriority() {
        return 40; // Medium-low priority - after auth but before body modifications
    }
    
    @Override
    public boolean isProductionSafe() {
        return true; // Payload sanitization is generally safe
    }
    
    // Configuration methods
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("Payload sanitization rule {}", enabled ? "enabled" : "disabled");
    }
    
    public void setSanitizeBody(boolean sanitize) {
        this.sanitizeBody = sanitize;
        logger.info("Body sanitization {}", sanitize ? "enabled" : "disabled");
    }
    
    public void setSanitizeParameters(boolean sanitize) {
        this.sanitizeParameters = sanitize;
        logger.info("Parameter sanitization {}", sanitize ? "enabled" : "disabled");
    }
    
    public void setStrictMode(boolean strict) {
        this.strictMode = strict;
        logger.info("Strict sanitization mode {}", strict ? "enabled" : "disabled");
    }
    
    public ContentFilterEngine getFilterEngine() {
        return filterEngine;
    }
}
