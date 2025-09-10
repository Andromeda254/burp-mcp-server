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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Map;

/**
 * Advanced proxy interceptor for SSL/TLS traffic analysis using Montoya API 2023.12.1
 * Provides comprehensive traffic monitoring, security analysis, and real-time interception
 */
public class AdvancedProxyInterceptor implements ProxyRequestHandler, ProxyResponseHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(AdvancedProxyInterceptor.class);
    
    private final MontoyaApi api;
    private final TrafficAnalyzer trafficAnalyzer;
    private final Map<String, InterceptionSession> activeSessions;
    private final AtomicLong requestCounter;
    private boolean interceptEnabled = false;
    
    public AdvancedProxyInterceptor(MontoyaApi api) {
        this.api = api;
        this.trafficAnalyzer = new TrafficAnalyzer(api);
        this.activeSessions = new ConcurrentHashMap<>();
        this.requestCounter = new AtomicLong(0);
        
        // Register with Montoya API using correct proxy handlers
        if (api != null) {
            api.proxy().registerRequestHandler(this);
            api.proxy().registerResponseHandler(this);
            api.logging().logToOutput("[SSL-INTERCEPT] Advanced proxy interceptor initialized");
            logger.info("Advanced proxy interceptor registered with Montoya API");
        }
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // Log the received request and continue
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[SSL-INTERCEPT] Request received: %s", 
                interceptedRequest.url()
            ));
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        var requestId = requestCounter.incrementAndGet();
        
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[SSL-INTERCEPT] Processing request #%d to: %s", 
                requestId, interceptedRequest.url()
            ));
        }
        
        try {
            // Analyze request for security issues
            var analysis = trafficAnalyzer.analyzeRequest(interceptedRequest);
            
            // Log sensitive data detection
            if (analysis.containsSensitiveData()) {
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[SECURITY] Sensitive data detected in request to: %s", 
                        interceptedRequest.url()
                    ));
                }
                logSecurityEvent(interceptedRequest, analysis);
            }
            
            // Check for SSL/TLS specific analysis
            if (interceptedRequest.url().startsWith("https://")) {
                var sslAnalysis = analyzeSSLRequest(interceptedRequest);
                if (sslAnalysis.hasFindings()) {
                    if (api != null) {
                        api.logging().logToOutput(String.format(
                            "[SSL-ANALYSIS] SSL findings for %s: %s", 
                            interceptedRequest.url(), sslAnalysis.getSummary()
                        ));
                    }
                }
            }
            
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
            
        } catch (Exception e) {
            logger.error("Request processing failed for {}: {}", interceptedRequest.url(), e.getMessage(), e);
            if (api != null) {
                api.logging().logToError(String.format(
                    "[ERROR] Request processing failed for %s: %s", 
                    interceptedRequest.url(), e.getMessage()
                ));
            }
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
    }
    
    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // Log the response to be sent and continue
        if (api != null) {
            api.logging().logToOutput("[SSL-INTERCEPT] Response to be sent");
        }
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            if (api != null) {
                api.logging().logToOutput("[SSL-INTERCEPT] Processing response");
            }
            
            // Analyze response for security headers and vulnerabilities
            var analysis = trafficAnalyzer.analyzeResponse(interceptedResponse, interceptedResponse.initiatingRequest());
            
            // Extract and analyze sensitive data
            var extractedData = extractSensitiveInformation(interceptedResponse);
            if (!extractedData.isEmpty()) {
                if (api != null) {
                    api.logging().logToOutput("[DATA-EXTRACTION] Sensitive data found in response");
                }
                logger.info("Sensitive data detected in response");
            }
            
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            
        } catch (Exception e) {
            logger.error("Response processing failed: {}", e.getMessage(), e);
            if (api != null) {
                api.logging().logToError(String.format(
                    "[ERROR] Response processing failed: %s", e.getMessage()
                ));
            }
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
    }
    
    public void enableInterception(InterceptionConfig config) {
        this.interceptEnabled = true;
        
        if (api != null) {
            api.logging().logToOutput("[SSL-INTERCEPT] Traffic interception enabled");
        }
        logger.info("Advanced proxy interception enabled with config: {}", config);
    }
    
    public void disableInterception() {
        this.interceptEnabled = false;
        
        if (api != null) {
            api.logging().logToOutput("[SSL-INTERCEPT] Traffic interception disabled");
        }
        logger.info("Advanced proxy interception disabled");
    }
    
    private SSLAnalysis analyzeSSLRequest(HttpRequest request) {
        var analysis = new SSLAnalysis();
        
        try {
            var headers = request.headers();
            analysis.analyzeHeaders(headers);
            analysis.checkHSTSUsage(request.url());
            analysis.analyzeCertificateRequirements(request);
            
        } catch (Exception e) {
            logger.error("SSL request analysis failed: {}", e.getMessage());
            analysis.addError("SSL analysis failed: " + e.getMessage());
        }
        
        return analysis;
    }
    
    private void logSecurityEvent(HttpRequest request, SecurityAnalysis analysis) {
        var securityEvent = new SecurityEvent();
        securityEvent.setUrl(request.url());
        securityEvent.setTimestamp(System.currentTimeMillis());
        securityEvent.setAnalysis(analysis);
        
        logger.warn("Security event detected: {}", securityEvent);
        
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[SECURITY-EVENT] %s - Score: %d/100", 
                request.url(), analysis.getSecurityScore()
            ));
        }
    }
    
    private Map<String, Object> extractSensitiveInformation(HttpResponse response) {
        var sensitiveData = new ConcurrentHashMap<String, Object>();
        
        try {
            var body = response.bodyToString();
            
            if (body.contains("password") || body.contains("token") || body.contains("secret")) {
                sensitiveData.put("containsSensitiveTerms", true);
            }
            
            var headers = response.headers();
            for (var header : headers) {
                if (header.name().toLowerCase().contains("authorization") ||
                    header.name().toLowerCase().contains("cookie") ||
                    header.name().toLowerCase().contains("session")) {
                    sensitiveData.put("sensitiveHeaders", true);
                    break;
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to extract sensitive information: {}", e.getMessage());
        }
        
        return sensitiveData;
    }
    
    public InterceptionStatistics getStatistics() {
        var stats = new InterceptionStatistics();
        stats.setTotalRequests(requestCounter.get());
        stats.setActiveSessions(activeSessions.size());
        stats.setInterceptionEnabled(interceptEnabled);
        return stats;
    }
    
    // Supporting classes
    public static class InterceptionConfig {
        private boolean modifyRequests = false;
        private boolean modifyResponses = false;
        private java.util.Set<String> targetDomains = new java.util.HashSet<>();
        
        public boolean isModifyRequests() { return modifyRequests; }
        public void setModifyRequests(boolean modifyRequests) { this.modifyRequests = modifyRequests; }
        
        public boolean isModifyResponses() { return modifyResponses; }
        public void setModifyResponses(boolean modifyResponses) { this.modifyResponses = modifyResponses; }
        
        public java.util.Set<String> getTargetDomains() { return targetDomains; }
        public void setTargetDomains(java.util.Set<String> targetDomains) { this.targetDomains = targetDomains; }
    }
    
    public static class InterceptionSession {
        private final String sessionId;
        private final String targetUrl;
        private final long startTime;
        private long requestCount = 0;
        
        public InterceptionSession(String sessionId, String targetUrl) {
            this.sessionId = sessionId;
            this.targetUrl = targetUrl;
            this.startTime = System.currentTimeMillis();
        }
        
        public void incrementRequests() { requestCount++; }
        
        public String getSessionId() { return sessionId; }
        public String getTargetUrl() { return targetUrl; }
        public long getStartTime() { return startTime; }
        public long getRequestCount() { return requestCount; }
    }
    
    public static class InterceptionStatistics {
        private long totalRequests;
        private int activeSessions;
        private boolean interceptionEnabled;
        
        public long getTotalRequests() { return totalRequests; }
        public void setTotalRequests(long totalRequests) { this.totalRequests = totalRequests; }
        
        public int getActiveSessions() { return activeSessions; }
        public void setActiveSessions(int activeSessions) { this.activeSessions = activeSessions; }
        
        public boolean isInterceptionEnabled() { return interceptionEnabled; }
        public void setInterceptionEnabled(boolean interceptionEnabled) { this.interceptionEnabled = interceptionEnabled; }
    }
}
