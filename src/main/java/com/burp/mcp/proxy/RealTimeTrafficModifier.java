package com.burp.mcp.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.burp.mcp.proxy.rules.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.net.URLEncoder;

/**
 * Real-time traffic modification system for live BurpSuite Professional integration
 * Implements Chain of Responsibility and Strategy patterns for extensible traffic modification
 * 
 * Features:
 * - Live HTTP request/response modification
 * - Header injection/modification/removal
 * - Body content filtering and transformation
 * - Rule-based modification engine
 * - Real-time security header injection
 * - Payload sanitization and encoding
 */
public class RealTimeTrafficModifier implements ProxyRequestHandler, ProxyResponseHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(RealTimeTrafficModifier.class);
    
    private final MontoyaApi api;
    private final List<RequestModificationRule> requestRules;
    private final List<ResponseModificationRule> responseRules;
    private final Map<String, TrafficSession> activeSessions;
    private final AtomicLong requestCounter;
    private final SecurityHeaderInjector securityHeaderInjector;
    private final ContentFilterEngine contentFilterEngine;
    
    // Configuration
    private boolean modificationEnabled = true;
    private boolean securityHeadersEnabled = true;
    private boolean contentFilteringEnabled = true;
    private Set<String> targetHosts = new HashSet<>();
    private Set<String> exemptPaths = new HashSet<>();
    
    public RealTimeTrafficModifier(MontoyaApi api) {
        this.api = api;
        this.requestRules = new ArrayList<>();
        this.responseRules = new ArrayList<>();
        this.activeSessions = new ConcurrentHashMap<>();
        this.requestCounter = new AtomicLong(0);
        this.securityHeaderInjector = new SecurityHeaderInjector();
        this.contentFilterEngine = new ContentFilterEngine();
        
        initializeDefaultRules();
        registerWithBurp();
        
        logger.info("Real-time traffic modifier initialized for live BurpSuite integration");
    }
    
    /**
     * Initialize default modification rules following security best practices
     */
    private void initializeDefaultRules() {
        // Request modification rules
        addRequestRule(new SecurityHeaderRemovalRule());
        addRequestRule(new AuthenticationHeaderModifier());
        addRequestRule(new PayloadSanitizationRule());
        addRequestRule(new SQLInjectionPreventionRule());
        addRequestRule(new XSSPreventionRule());
        
        // Response modification rules
        addResponseRule(new SecurityHeaderInjectionRule());
        addResponseRule(new SensitiveDataRedactionRule());
        addResponseRule(new ContentTypeValidationRule());
        addResponseRule(new CSPHeaderInjectionRule());
        addResponseRule(new HSTSHeaderInjectionRule());
        
        logger.info("Initialized {} request rules and {} response rules", 
            requestRules.size(), responseRules.size());
    }
    
    /**
     * Register this modifier with BurpSuite proxy
     */
    private void registerWithBurp() {
        if (api != null) {
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
            api.logging().logToOutput("[TRAFFIC-MODIFIER] Real-time traffic modification enabled");
            logger.info("Registered with BurpSuite proxy for live traffic modification");
        }
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (!modificationEnabled || isExemptRequest(interceptedRequest)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        
        try {
            var sessionId = createOrGetSession(interceptedRequest);
            logRequestReceived(interceptedRequest, sessionId);
            
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
            
        } catch (Exception e) {
            logger.error("Error in handleRequestReceived: {}", e.getMessage(), e);
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        if (!modificationEnabled || isExemptRequest(interceptedRequest)) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
        
        try {
            var requestId = requestCounter.incrementAndGet();
            var sessionId = createOrGetSession(interceptedRequest);
            
            logger.info("Modifying request #{} to: {}", requestId, interceptedRequest.url());
            
            // Apply request modification rules
            var modifiedRequest = applyRequestModifications(interceptedRequest, sessionId);
            
            // Log modification summary
            if (!modifiedRequest.equals(interceptedRequest)) {
                logRequestModification(interceptedRequest, modifiedRequest, requestId);
            }
            
            return ProxyRequestToBeSentAction.continueWith(modifiedRequest);
            
        } catch (Exception e) {
            logger.error("Error modifying request to {}: {}", 
                interceptedRequest.url(), e.getMessage(), e);
            
            if (api != null) {
                api.logging().logToError("[TRAFFIC-MODIFIER] Request modification failed: " + e.getMessage());
            }
            
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        if (!modificationEnabled || isExemptResponse(interceptedResponse)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        
        try {
            var sessionId = getSessionId(interceptedResponse.initiatingRequest());
            logResponseReceived(interceptedResponse, sessionId);
            
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            
        } catch (Exception e) {
            logger.error("Error in handleResponseReceived: {}", e.getMessage(), e);
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
    }
    
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        if (!modificationEnabled || isExemptResponse(interceptedResponse)) {
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
        
        try {
            var sessionId = getSessionId(interceptedResponse.initiatingRequest());
            
            logger.info("Modifying response from: {}", interceptedResponse.initiatingRequest().url());
            
            // Apply response modification rules
            var modifiedResponse = applyResponseModifications(interceptedResponse, sessionId);
            
            // Log modification summary
            if (!modifiedResponse.equals(interceptedResponse)) {
                logResponseModification(interceptedResponse, modifiedResponse);
            }
            
            return ProxyResponseToBeSentAction.continueWith(modifiedResponse);
            
        } catch (Exception e) {
            logger.error("Error modifying response from {}: {}", 
                interceptedResponse.initiatingRequest().url(), e.getMessage(), e);
            
            if (api != null) {
                api.logging().logToError("[TRAFFIC-MODIFIER] Response modification failed: " + e.getMessage());
            }
            
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
    }
    
    /**
     * Apply request modification rules using Chain of Responsibility pattern
     */
    private HttpRequest applyRequestModifications(InterceptedRequest request, String sessionId) {
        HttpRequest modifiedRequest = request;
        var context = new ModificationContext(sessionId, ModificationContext.Type.REQUEST);
        
        for (var rule : requestRules) {
            try {
                if (rule.shouldApply(modifiedRequest, context)) {
                    var result = rule.apply(modifiedRequest, context);
                    if (result != null) {
                        modifiedRequest = result;
                        context.addAppliedRule(rule.getClass().getSimpleName());
                        
                        logger.debug("Applied rule {} to request {}", 
                            rule.getClass().getSimpleName(), request.url());
                    }
                }
            } catch (Exception e) {
                logger.error("Error applying request rule {}: {}", 
                    rule.getClass().getSimpleName(), e.getMessage());
            }
        }
        
        return modifiedRequest;
    }
    
    /**
     * Apply response modification rules using Chain of Responsibility pattern
     */
    private HttpResponse applyResponseModifications(InterceptedResponse response, String sessionId) {
        HttpResponse modifiedResponse = response;
        var context = new ModificationContext(sessionId, ModificationContext.Type.RESPONSE);
        
        for (var rule : responseRules) {
            try {
                if (rule.shouldApply(modifiedResponse, context)) {
                    var result = rule.apply(modifiedResponse, context);
                    if (result != null) {
                        modifiedResponse = result;
                        context.addAppliedRule(rule.getClass().getSimpleName());
                        
                        logger.debug("Applied rule {} to response from {}", 
                            rule.getClass().getSimpleName(), 
                            response.initiatingRequest().url());
                    }
                }
            } catch (Exception e) {
                logger.error("Error applying response rule {}: {}", 
                    rule.getClass().getSimpleName(), e.getMessage());
            }
        }
        
        return modifiedResponse;
    }
    
    /**
     * Session management for tracking request/response pairs
     */
    private String createOrGetSession(InterceptedRequest request) {
        var sessionKey = generateSessionKey(request);
        return activeSessions.computeIfAbsent(sessionKey, k -> {
            var session = new TrafficSession(k, request.url(), System.currentTimeMillis());
            logger.debug("Created new traffic session: {}", k);
            return session;
        }).getSessionId();
    }
    
    private String getSessionId(HttpRequest request) {
        var sessionKey = generateSessionKey(request);
        var session = activeSessions.get(sessionKey);
        return session != null ? session.getSessionId() : "unknown";
    }
    
    private String generateSessionKey(HttpRequest request) {
        return String.format("%s_%d", request.url(), Thread.currentThread().getId());
    }
    
    /**
     * Exemption checks for requests that shouldn't be modified
     */
    private boolean isExemptRequest(InterceptedRequest request) {
        var url = request.url();
        
        // Check exempt paths
        for (var exemptPath : exemptPaths) {
            if (url.contains(exemptPath)) {
                return true;
            }
        }
        
        // Check if targeting specific hosts
        if (!targetHosts.isEmpty()) {
            var host = extractHost(url);
            return !targetHosts.contains(host);
        }
        
        // Don't modify BurpSuite internal requests
        return url.contains("burpsuite") || url.contains("portswigger");
    }
    
    private boolean isExemptResponse(InterceptedResponse response) {
        var url = response.initiatingRequest().url();
        
        // Check exempt paths
        for (var exemptPath : exemptPaths) {
            if (url.contains(exemptPath)) {
                return true;
            }
        }
        
        // Check if targeting specific hosts
        if (!targetHosts.isEmpty()) {
            var host = extractHost(url);
            return !targetHosts.contains(host);
        }
        
        // Don't modify BurpSuite internal requests
        return url.contains("burpsuite") || url.contains("portswigger");
    }
    
    private String extractHost(String url) {
        try {
            var uri = java.net.URI.create(url);
            return uri.getHost();
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * Logging methods for live BurpSuite integration
     */
    private void logRequestReceived(InterceptedRequest request, String sessionId) {
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[TRAFFIC-MODIFIER] Request received - Session: %s, URL: %s", 
                sessionId, request.url()
            ));
        }
    }
    
    private void logRequestModification(HttpRequest original, HttpRequest modified, long requestId) {
        if (api != null) {
            var originalHeaders = original.headers().size();
            var modifiedHeaders = modified.headers().size();
            var headerDiff = modifiedHeaders - originalHeaders;
            
            api.logging().logToOutput(String.format(
                "[TRAFFIC-MODIFIER] Request #%d modified - Headers: %+d, Body: %s", 
                requestId, headerDiff, 
                original.bodyToString().equals(modified.bodyToString()) ? "unchanged" : "modified"
            ));
        }
    }
    
    private void logResponseReceived(InterceptedResponse response, String sessionId) {
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[TRAFFIC-MODIFIER] Response received - Session: %s, Status: %d", 
                sessionId, response.statusCode()
            ));
        }
    }
    
    private void logResponseModification(HttpResponse original, HttpResponse modified) {
        if (api != null) {
            var originalHeaders = original.headers().size();
            var modifiedHeaders = modified.headers().size();
            var headerDiff = modifiedHeaders - originalHeaders;
            
            api.logging().logToOutput(String.format(
                "[TRAFFIC-MODIFIER] Response modified - Headers: %+d, Body: %s", 
                headerDiff,
                original.bodyToString().equals(modified.bodyToString()) ? "unchanged" : "modified"
            ));
        }
    }
    
    // Public API methods
    public void addRequestRule(RequestModificationRule rule) {
        requestRules.add(rule);
        logger.info("Added request modification rule: {}", rule.getClass().getSimpleName());
    }
    
    public void addResponseRule(ResponseModificationRule rule) {
        responseRules.add(rule);
        logger.info("Added response modification rule: {}", rule.getClass().getSimpleName());
    }
    
    public void setTargetHosts(Set<String> hosts) {
        this.targetHosts = new HashSet<>(hosts);
        logger.info("Set target hosts: {}", hosts);
    }
    
    public void addExemptPath(String path) {
        exemptPaths.add(path);
        logger.info("Added exempt path: {}", path);
    }
    
    public void setModificationEnabled(boolean enabled) {
        this.modificationEnabled = enabled;
        logger.info("Traffic modification {}", enabled ? "enabled" : "disabled");
        
        if (api != null) {
            api.logging().logToOutput("[TRAFFIC-MODIFIER] Traffic modification " + 
                (enabled ? "enabled" : "disabled"));
        }
    }
    
    public TrafficModificationStats getStats() {
        return new TrafficModificationStats(
            requestCounter.get(),
            activeSessions.size(),
            requestRules.size(),
            responseRules.size(),
            modificationEnabled
        );
    }
    
    public void cleanup() {
        activeSessions.clear();
        logger.info("Traffic modifier cleanup completed");
    }
    
    /**
     * Traffic session for tracking request/response pairs
     */
    private static class TrafficSession {
        private final String sessionId;
        private final String url;
        private final long createdTime;
        private int requestCount = 0;
        private int responseCount = 0;
        
        public TrafficSession(String sessionId, String url, long createdTime) {
            this.sessionId = sessionId;
            this.url = url;
            this.createdTime = createdTime;
        }
        
        public String getSessionId() { return sessionId; }
        public String getUrl() { return url; }
        public long getCreatedTime() { return createdTime; }
        public void incrementRequests() { requestCount++; }
        public void incrementResponses() { responseCount++; }
        public int getRequestCount() { return requestCount; }
        public int getResponseCount() { return responseCount; }
    }
    
    /**
     * Statistics for monitoring traffic modification activity
     */
    public static class TrafficModificationStats {
        private final long totalRequests;
        private final int activeSessions;
        private final int requestRules;
        private final int responseRules;
        private final boolean enabled;
        
        public TrafficModificationStats(long totalRequests, int activeSessions, 
                int requestRules, int responseRules, boolean enabled) {
            this.totalRequests = totalRequests;
            this.activeSessions = activeSessions;
            this.requestRules = requestRules;
            this.responseRules = responseRules;
            this.enabled = enabled;
        }
        
        // Getters
        public long getTotalRequests() { return totalRequests; }
        public int getActiveSessions() { return activeSessions; }
        public int getRequestRules() { return requestRules; }
        public int getResponseRules() { return responseRules; }
        public boolean isEnabled() { return enabled; }
    }
}
