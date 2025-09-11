package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.ResponseModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import com.burp.mcp.proxy.SecurityHeaderInjector;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Injects security headers into HTTP responses
 */
public class SecurityHeaderInjectionRule implements ResponseModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityHeaderInjectionRule.class);
    private final SecurityHeaderInjector injector;
    private boolean enabled = true;
    
    public SecurityHeaderInjectionRule() {
        this.injector = new SecurityHeaderInjector();
    }
    
    @Override
    public boolean shouldApply(HttpResponse response, ModificationContext context) {
        return enabled;
    }
    
    @Override
    public HttpResponse apply(HttpResponse response, ModificationContext context) {
        try {
            var modifiedResponse = injector.injectDefaultSecurityHeaders(response);
            
            if (!modifiedResponse.equals(response)) {
                context.addModification("security_headers", "Injected security headers");
                logger.debug("Injected security headers into response");
            }
            
            return modifiedResponse;
            
        } catch (Exception e) {
            logger.error("Error injecting security headers: {}", e.getMessage(), e);
            return response;
        }
    }
    
    @Override
    public String getDescription() {
        return "Injects security headers into responses";
    }
    
    @Override
    public int getPriority() {
        return 10;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public SecurityHeaderInjector getInjector() {
        return injector;
    }
}
