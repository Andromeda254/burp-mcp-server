package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.RequestModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;
import java.util.List;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;

/**
 * Prevents SQL injection attacks by detecting and blocking malicious patterns
 * Focuses specifically on SQL injection vectors in request parameters and body
 */
public class SQLInjectionPreventionRule implements RequestModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(SQLInjectionPreventionRule.class);
    
    // SQL injection patterns (compiled for performance)
    private static final List<Pattern> SQL_INJECTION_PATTERNS = List.of(
        Pattern.compile("(?i)('|(\\-\\-)|(;)|(\\||\\|)|(\\*|\\*))", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(exec(\\s|\\+)+(s|x)p\\w+)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(union(.*)select)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(select(.*)from)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(insert(.*)into)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(delete(.*)from)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(update(.*)set)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(drop(.*)table)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(create(.*)table)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(alter(.*)table)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(grant|revoke)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(information_schema)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(sleep\\s*\\(|benchmark\\s*\\(|waitfor)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(load_file\\s*\\(|into\\s+outfile)", Pattern.CASE_INSENSITIVE)
    );
    
    private boolean enabled = true;
    private boolean blockSuspiciousRequests = false; // Log only by default
    private boolean strictMode = false;
    private int suspiciousThreshold = 2; // Number of patterns to trigger action
    
    @Override
    public boolean shouldApply(HttpRequest request, ModificationContext context) {
        if (!enabled) {
            return false;
        }
        
        // Check if request contains potential SQL injection
        return containsSqlInjectionAttempt(request);
    }
    
    @Override
    public HttpRequest apply(HttpRequest request, ModificationContext context) {
        try {
            var detectedPatterns = detectSqlInjectionPatterns(request);
            
            if (!detectedPatterns.isEmpty()) {
                var patternCount = detectedPatterns.size();
                
                logger.warn("SQL injection attempt detected in request to {}: {} patterns matched", 
                    request.url(), patternCount);
                
                context.addModification("sql_injection_detection", 
                    String.format("Detected %d SQL injection patterns", patternCount));
                
                // Set alert in context for potential blocking
                context.setAttribute("sql_injection_detected", true);
                context.setAttribute("sql_injection_patterns", detectedPatterns);
                context.setAttribute("sql_injection_severity", getSeverity(patternCount));
                
                if (blockSuspiciousRequests && patternCount >= suspiciousThreshold) {
                    logger.error("BLOCKING SQL injection request to {}: {} patterns", 
                        request.url(), patternCount);
                    
                    // In a real implementation, this might throw an exception or return null
                    // to block the request. For now, we'll modify the request to neutralize it
                    return neutralizeSqlInjection(request);
                }
            }
            
            return request;
            
        } catch (Exception e) {
            logger.error("Error in SQL injection prevention: {}", e.getMessage(), e);
            return request;
        }
    }
    
    private boolean containsSqlInjectionAttempt(HttpRequest request) {
        try {
            // Check URL parameters
            if (containsSqlInUrl(request.url())) {
                return true;
            }
            
            // Check request body
            if (!request.bodyToString().isEmpty() && containsSqlInBody(request.bodyToString())) {
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.debug("Error checking SQL injection patterns: {}", e.getMessage());
            return false;
        }
    }
    
    private List<String> detectSqlInjectionPatterns(HttpRequest request) {
        var detectedPatterns = new ArrayList<String>();
        
        var fullContent = request.url() + " " + request.bodyToString();
        
        try {
            // URL decode the content for better pattern matching
            var decoded = URLDecoder.decode(fullContent, StandardCharsets.UTF_8);
            
            for (var pattern : SQL_INJECTION_PATTERNS) {
                var matcher = pattern.matcher(decoded);
                if (matcher.find()) {
                    detectedPatterns.add(pattern.pattern());
                    logger.debug("SQL injection pattern matched: {}", pattern.pattern());
                }
            }
            
        } catch (Exception e) {
            logger.debug("Error decoding content for SQL injection check: {}", e.getMessage());
        }
        
        return detectedPatterns;
    }
    
    private boolean containsSqlInUrl(String url) {
        if (!url.contains("?")) {
            return false;
        }
        
        try {
            var queryPart = url.substring(url.indexOf("?") + 1);
            var decoded = URLDecoder.decode(queryPart, StandardCharsets.UTF_8);
            
            return SQL_INJECTION_PATTERNS.stream()
                .anyMatch(pattern -> pattern.matcher(decoded).find());
                
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean containsSqlInBody(String body) {
        if (body.isEmpty()) {
            return false;
        }
        
        return SQL_INJECTION_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(body).find());
    }
    
    private HttpRequest neutralizeSqlInjection(HttpRequest request) {
        // Replace dangerous patterns with safe equivalents
        var body = request.bodyToString();
        
        if (!body.isEmpty()) {
            var sanitizedBody = body;
            for (var pattern : SQL_INJECTION_PATTERNS) {
                sanitizedBody = pattern.matcher(sanitizedBody).replaceAll("[SQL_BLOCKED]");
            }
            
            if (!sanitizedBody.equals(body)) {
                logger.info("Neutralized SQL injection in request body for {}", request.url());
                return request.withBody(sanitizedBody);
            }
        }
        
        return request;
    }
    
    private String getSeverity(int patternCount) {
        if (patternCount >= 5) {
            return "CRITICAL";
        } else if (patternCount >= 3) {
            return "HIGH";
        } else if (patternCount >= 2) {
            return "MEDIUM";
        } else {
            return "LOW";
        }
    }
    
    @Override
    public String getDescription() {
        return "Detects and prevents SQL injection attacks in request parameters and body";
    }
    
    @Override
    public int getPriority() {
        return 15; // High priority - security check
    }
    
    @Override
    public boolean isProductionSafe() {
        return true; // SQL injection prevention is always safe
    }
    
    // Configuration methods
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        logger.info("SQL injection prevention {}", enabled ? "enabled" : "disabled");
    }
    
    public void setBlockSuspiciousRequests(boolean block) {
        this.blockSuspiciousRequests = block;
        logger.info("Blocking suspicious SQL injection requests: {}", block);
    }
    
    public void setStrictMode(boolean strict) {
        this.strictMode = strict;
        logger.info("SQL injection strict mode {}", strict ? "enabled" : "disabled");
    }
    
    public void setSuspiciousThreshold(int threshold) {
        this.suspiciousThreshold = Math.max(1, threshold);
        logger.info("SQL injection suspicious threshold set to {}", this.suspiciousThreshold);
    }
    
    public int getPatternCount() {
        return SQL_INJECTION_PATTERNS.size();
    }
}
