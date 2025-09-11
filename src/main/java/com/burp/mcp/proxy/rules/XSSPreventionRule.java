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
 * Prevents XSS (Cross-Site Scripting) attacks by detecting malicious script patterns
 */
public class XSSPreventionRule implements RequestModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(XSSPreventionRule.class);
    
    private static final List<Pattern> XSS_PATTERNS = List.of(
        Pattern.compile("(?i)(<script[^>]*>.*?</script>)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("(?i)(javascript:)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(on\\w+\\s*=)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(<iframe[^>]*>)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(<object[^>]*>)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(<embed[^>]*>)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)(expression\\s*\\()", Pattern.CASE_INSENSITIVE)
    );
    
    private boolean enabled = true;
    private boolean blockSuspiciousRequests = false;
    
    @Override
    public boolean shouldApply(HttpRequest request, ModificationContext context) {
        if (!enabled) return false;
        
        String content = request.url() + " " + request.bodyToString();
        try {
            content = URLDecoder.decode(content, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Continue with original content
        }
        
        final String finalContent = content;
        return XSS_PATTERNS.stream().anyMatch(pattern -> pattern.matcher(finalContent).find());
    }
    
    @Override
    public HttpRequest apply(HttpRequest request, ModificationContext context) {
        try {
            var detectedPatterns = new ArrayList<String>();
            String content = request.url() + " " + request.bodyToString();
            
            try {
                content = URLDecoder.decode(content, StandardCharsets.UTF_8);
            } catch (Exception e) {
                // Continue with original content
            }
            
            for (var pattern : XSS_PATTERNS) {
                if (pattern.matcher(content).find()) {
                    detectedPatterns.add(pattern.pattern());
                }
            }
            
            if (!detectedPatterns.isEmpty()) {
                logger.warn("XSS attempt detected in request to {}: {} patterns", 
                    request.url(), detectedPatterns.size());
                
                context.addModification("xss_detection", 
                    String.format("Detected %d XSS patterns", detectedPatterns.size()));
                context.setAttribute("xss_detected", true);
                context.setAttribute("xss_patterns", detectedPatterns);
                
                if (blockSuspiciousRequests) {
                    return neutralizeXSS(request);
                }
            }
            
            return request;
            
        } catch (Exception e) {
            logger.error("Error in XSS prevention: {}", e.getMessage(), e);
            return request;
        }
    }
    
    private HttpRequest neutralizeXSS(HttpRequest request) {
        String body = request.bodyToString();
        if (!body.isEmpty()) {
            String sanitized = body;
            for (var pattern : XSS_PATTERNS) {
                sanitized = pattern.matcher(sanitized).replaceAll("[XSS_BLOCKED]");
            }
            if (!sanitized.equals(body)) {
                return request.withBody(sanitized);
            }
        }
        return request;
    }
    
    @Override
    public String getDescription() {
        return "Detects and prevents XSS attacks";
    }
    
    @Override
    public int getPriority() {
        return 16;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public void setBlockSuspiciousRequests(boolean block) {
        this.blockSuspiciousRequests = block;
    }
}
