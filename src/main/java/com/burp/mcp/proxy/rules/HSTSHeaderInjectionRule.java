package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.ResponseModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

public class HSTSHeaderInjectionRule implements ResponseModificationRule {
    
    private boolean enabled = true;
    private String hstsValue = "max-age=31536000; includeSubDomains; preload";
    
    @Override
    public boolean shouldApply(HttpResponse response, ModificationContext context) {
        return enabled && !hasHSTSHeader(response) && isHttpsResponse(response);
    }
    
    @Override
    public HttpResponse apply(HttpResponse response, ModificationContext context) {
        var headers = new java.util.ArrayList<>(response.headers());
        headers.add(HttpHeader.httpHeader("Strict-Transport-Security", hstsValue));
        context.addModification("hsts_header", "Added HSTS header");
        return response.withUpdatedHeaders(headers);
    }
    
    private boolean hasHSTSHeader(HttpResponse response) {
        return response.headers().stream()
            .anyMatch(header -> header.name().equalsIgnoreCase("Strict-Transport-Security"));
    }
    
    private boolean isHttpsResponse(HttpResponse response) {
        // For now, assume HTTPS - in real implementation would check request context
        return true;
    }
    
    @Override
    public String getDescription() {
        return "Injects HTTP Strict Transport Security headers";
    }
    
    @Override
    public int getPriority() {
        return 12;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public void setHstsValue(String value) {
        this.hstsValue = value;
    }
}
