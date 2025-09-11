package com.burp.mcp.proxy.rules;

import com.burp.mcp.proxy.ResponseModificationRule;
import com.burp.mcp.proxy.ModificationContext;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;

public class CSPHeaderInjectionRule implements ResponseModificationRule {
    
    private boolean enabled = true;
    private String cspPolicy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    
    @Override
    public boolean shouldApply(HttpResponse response, ModificationContext context) {
        return enabled && !hasCSPHeader(response);
    }
    
    @Override
    public HttpResponse apply(HttpResponse response, ModificationContext context) {
        var headers = new java.util.ArrayList<>(response.headers());
        headers.add(HttpHeader.httpHeader("Content-Security-Policy", cspPolicy));
        context.addModification("csp_header", "Added CSP header");
        return response.withUpdatedHeaders(headers);
    }
    
    private boolean hasCSPHeader(HttpResponse response) {
        return response.headers().stream()
            .anyMatch(header -> header.name().equalsIgnoreCase("Content-Security-Policy"));
    }
    
    @Override
    public String getDescription() {
        return "Injects Content Security Policy headers";
    }
    
    @Override
    public int getPriority() {
        return 11;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public void setCspPolicy(String policy) {
        this.cspPolicy = policy;
    }
}
