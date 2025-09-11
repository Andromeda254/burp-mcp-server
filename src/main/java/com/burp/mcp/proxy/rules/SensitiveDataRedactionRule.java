package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.ResponseModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import com.burp.mcp.proxy.ContentFilterEngine;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SensitiveDataRedactionRule implements ResponseModificationRule {
    
    private static final Logger logger = LoggerFactory.getLogger(SensitiveDataRedactionRule.class);
    private final ContentFilterEngine filterEngine;
    private boolean enabled = true;
    
    public SensitiveDataRedactionRule() {
        this.filterEngine = new ContentFilterEngine();
    }
    
    @Override
    public boolean shouldApply(HttpResponse response, ModificationContext context) {
        return enabled && !response.bodyToString().isEmpty();
    }
    
    @Override
    public HttpResponse apply(HttpResponse response, ModificationContext context) {
        try {
            var body = response.bodyToString();
            var contentType = getContentType(response);
            
            var filterOptions = new ContentFilterEngine.FilterOptions()
                .sensitiveData(true)
                .sqlInjection(false)
                .xss(false);
            
            var filteredBody = filterEngine.filterContent(body, contentType, filterOptions);
            
            if (!filteredBody.equals(body)) {
                context.addModification("sensitive_data_redaction", "Redacted sensitive data");
                return response.withBody(filteredBody);
            }
            
            return response;
            
        } catch (Exception e) {
            logger.error("Error redacting sensitive data: {}", e.getMessage(), e);
            return response;
        }
    }
    
    private String getContentType(HttpResponse response) {
        return response.headers().stream()
            .filter(header -> header.name().equalsIgnoreCase("Content-Type"))
            .map(header -> header.value())
            .findFirst()
            .orElse("text/plain");
    }
    
    @Override
    public String getDescription() {
        return "Redacts sensitive data from response bodies";
    }
    
    @Override
    public int getPriority() {
        return 20;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
