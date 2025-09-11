package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.ResponseModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

public class ContentTypeValidationRule implements ResponseModificationRule {
    
    private boolean enabled = true;
    
    @Override
    public boolean shouldApply(HttpResponse response, ModificationContext context) {
        return enabled;
    }
    
    @Override
    public HttpResponse apply(HttpResponse response, ModificationContext context) {
        // Validate and fix Content-Type headers
        var headers = response.headers();
        boolean hasContentType = headers.stream()
            .anyMatch(header -> header.name().equalsIgnoreCase("Content-Type"));
        
        if (!hasContentType && !response.bodyToString().isEmpty()) {
            var newHeaders = new java.util.ArrayList<>(headers);
            newHeaders.add(HttpHeader.httpHeader("Content-Type", "text/html; charset=UTF-8"));
            context.addModification("content_type", "Added missing Content-Type header");
            return response.withUpdatedHeaders(newHeaders);
        }
        
        return response;
    }
    
    @Override
    public String getDescription() {
        return "Validates and fixes Content-Type headers";
    }
    
    @Override
    public int getPriority() {
        return 30;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
