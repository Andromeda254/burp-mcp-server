package com.burp.mcp.proxy.websocket;

import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Manages WebSocket sessions and connection tracking
 */
public class WebSocketSessionManager {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketSessionManager.class);
    
    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    private final Map<WebSocket, String> connectionIdMap = new ConcurrentHashMap<>();
    
    public WebSocketSession createSession(String connectionId, HttpRequest upgradeRequest, WebSocket webSocket) {
        var session = new WebSocketSession(connectionId, upgradeRequest.url(), webSocket);
        sessions.put(connectionId, session);
        connectionIdMap.put(webSocket, connectionId);
        
        logger.debug("Created WebSocket session: {}", connectionId);
        return session;
    }
    
    public String getConnectionId(WebSocket webSocket) {
        return connectionIdMap.getOrDefault(webSocket, "unknown");
    }
    
    public WebSocketSession getSession(String connectionId) {
        return sessions.get(connectionId);
    }
    
    public int getActiveConnectionCount() {
        return sessions.size();
    }
    
    public void removeSession(String connectionId) {
        var session = sessions.remove(connectionId);
        if (session != null) {
            connectionIdMap.remove(session.getWebSocket());
            logger.debug("Removed WebSocket session: {}", connectionId);
        }
    }
    
    public void cleanup() {
        sessions.clear();
        connectionIdMap.clear();
        logger.debug("WebSocket session manager cleanup completed");
    }
    
    /**
     * Represents a WebSocket session
     */
    public static class WebSocketSession {
        private final String connectionId;
        private final String url;
        private final WebSocket webSocket;
        private final long createdTime;
        
        public WebSocketSession(String connectionId, String url, WebSocket webSocket) {
            this.connectionId = connectionId;
            this.url = url;
            this.webSocket = webSocket;
            this.createdTime = System.currentTimeMillis();
        }
        
        public String getConnectionId() { return connectionId; }
        public String getUrl() { return url; }
        public WebSocket getWebSocket() { return webSocket; }
        public long getCreatedTime() { return createdTime; }
    }
}
