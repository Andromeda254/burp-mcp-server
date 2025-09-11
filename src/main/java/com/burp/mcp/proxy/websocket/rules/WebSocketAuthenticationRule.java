package com.burp.mcp.proxy.websocket.rules;

import com.burp.mcp.proxy.websocket.WebSocketMessageInterceptorRule;
import com.burp.mcp.proxy.websocket.WebSocketMessageContext;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;

public class WebSocketAuthenticationRule implements WebSocketMessageInterceptorRule {
    
    @Override
    public boolean shouldApply(WebSocketMessageContext context) {
        return true;
    }
    
    @Override
    public TextMessageRuleResult applyToTextMessage(TextMessage textMessage, WebSocketMessageContext context) {
        // Stub implementation
        return TextMessageRuleResult.continueWith(textMessage);
    }
    
    @Override
    public BinaryMessageRuleResult applyToBinaryMessage(BinaryMessage binaryMessage, WebSocketMessageContext context) {
        // Stub implementation
        return BinaryMessageRuleResult.continueWith(binaryMessage);
    }
    
    @Override
    public String getDescription() {
        return "Validates WebSocket authentication";
    }
    
    @Override
    public int getPriority() {
        return 20;
    }
}
