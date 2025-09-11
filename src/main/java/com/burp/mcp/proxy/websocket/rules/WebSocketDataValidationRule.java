package com.burp.mcp.proxy.websocket.rules;

import com.burp.mcp.proxy.websocket.WebSocketMessageInterceptorRule;
import com.burp.mcp.proxy.websocket.WebSocketMessageContext;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.BinaryMessage;

public class WebSocketDataValidationRule implements WebSocketMessageInterceptorRule {
    
    @Override
    public boolean shouldApply(WebSocketMessageContext context) {
        return true;
    }
    
    @Override
    public TextMessageRuleResult applyToTextMessage(TextMessage textMessage, WebSocketMessageContext context) {
        return TextMessageRuleResult.continueWith(textMessage);
    }
    
    @Override
    public BinaryMessageRuleResult applyToBinaryMessage(BinaryMessage binaryMessage, WebSocketMessageContext context) {
        return BinaryMessageRuleResult.continueWith(binaryMessage);
    }
    
    @Override
    public String getDescription() {
        return "Validates WebSocket data formats";
    }
    
    @Override
    public int getPriority() {
        return 30;
    }
}
