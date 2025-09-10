package com.burp.mcp.protocol;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.burp.mcp.proxy.TrafficInterceptor;
import com.burp.mcp.proxy.SSLCertificateAnalyzer;
import com.burp.mcp.proxy.SafePatternMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Live traffic analyzer for real-time integration with BurpSuite Pro
 * Provides comprehensive SSL/TLS analysis and security pattern matching
 */
public class LiveTrafficAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(LiveTrafficAnalyzer.class);
    private static final Map<String, Object> analysisCache = new ConcurrentHashMap<>();
    private static final AtomicLong analysisCounter = new AtomicLong(0);
    
    private final MontoyaApi api;
    
    public LiveTrafficAnalyzer(MontoyaApi api) {
        this.api = api;
    }
    
    /**
     * Analyze live proxy history with comprehensive security analysis
     */
    public List<Map<String, Object>> analyzeLiveProxyHistory(int limit, String filter) {
        var history = new ArrayList<Map<String, Object>>();
        var analysisId = analysisCounter.incrementAndGet();
        
        api.logging().logToOutput("[BurpMCP] 🔬 Starting LIVE traffic analysis #" + analysisId + " (limit: " + limit + ")");
        
        try {
            // Get actual proxy history from BurpSuite Pro
            var proxyHistory = api.proxy().history();
            
            // Get traffic analysis summary for real-time data integration
            var trafficSummary = TrafficInterceptor.getTrafficSummary();
            
            // Add comprehensive metadata as first entry
            var metadata = createAnalysisMetadata(trafficSummary, analysisId);
            history.add(metadata);
            
            // Process actual proxy entries with enhanced live analysis
            var processedCount = 0;
            var sslAnalysisCount = 0;
            var securityFindingsCount = 0;
            
            for (var proxyEntry : proxyHistory) {
                if (processedCount >= limit) break;
                
                try {
                    var request = proxyEntry.finalRequest();
                    var response = proxyEntry.response();
                    
                    // Apply filter if specified
                    if (filter != null && !request.url().contains(filter)) {
                        continue;
                    }
                    
                    var entry = new HashMap<String, Object>();
                    populateBasicRequestInfo(entry, request, response);
                    
                    // LIVE SSL/TLS CERTIFICATE ANALYSIS for HTTPS requests
                    if (request.url().startsWith("https://")) {
                        var sslAnalysis = performLiveSSLAnalysis(request.url());
                        if (sslAnalysis != null) {
                            entry.put("live_ssl_analysis", sslAnalysis);
                            sslAnalysisCount++;
                            
                            if ("HIGH".equals(sslAnalysis.get("risk_level")) || "CRITICAL".equals(sslAnalysis.get("risk_level"))) {
                                entry.put("ssl_warning", true);
                                api.logging().logToOutput("[BurpMCP] ⚠️ SSL RISK: " + request.url() + " - " + sslAnalysis.get("risk_level"));
                            }
                        }
                    }
                    
                    // LIVE SECURITY PATTERN ANALYSIS
                    var patternAnalysis = performLivePatternAnalysis(request, response);
                    if (!patternAnalysis.isEmpty()) {
                        entry.putAll(patternAnalysis);
                        securityFindingsCount++;
                    }
                    
                    // LIVE TRAFFIC INTERCEPTION AND ANALYSIS
                    var trafficAnalysis = performLiveTrafficInterception(request, response);
                    if (trafficAnalysis != null) {
                        entry.put("live_traffic_analysis", trafficAnalysis);
                        
                        if (Boolean.TRUE.equals(trafficAnalysis.get("has_high_severity"))) {
                            entry.put("security_alert", true);
                            api.logging().logToOutput("[BurpMCP] 🚨 SECURITY ALERT: " + request.url());
                        }
                    }
                    
                    // ENHANCED SECURITY SCORING
                    var securityScore = calculateLiveSecurityScore(entry);
                    entry.put("live_security_score", securityScore);
                    
                    // Mark as interesting based on analysis results
                    markInterestingEntry(entry);
                    
                    history.add(entry);
                    processedCount++;
                    
                } catch (Exception e) {
                    api.logging().logToOutput("[BurpMCP] ⚠️ Error analyzing proxy entry: " + e.getMessage());
                    logger.warn("Error analyzing proxy entry: {}", e.getMessage());
                }
            }
            
            // Update metadata with final statistics
            updateAnalysisStatistics(metadata, processedCount, sslAnalysisCount, securityFindingsCount);
            
            api.logging().logToOutput("[BurpMCP] ✅ LIVE analysis #" + analysisId + " complete: " + 
                processedCount + " entries, " + sslAnalysisCount + " SSL analyses, " + 
                securityFindingsCount + " security findings");
            
        } catch (Exception e) {
            api.logging().logToError("[BurpMCP] ❌ LIVE analysis failed: " + e.getMessage());
            logger.error("Live traffic analysis failed: {}", e.getMessage(), e);
            throw new RuntimeException("Live traffic analysis failed", e);
        }
        
        return history;
    }
    
    private Map<String, Object> createAnalysisMetadata(TrafficInterceptor.TrafficAnalysisSummary trafficSummary, long analysisId) {
        var metadata = new HashMap<String, Object>();
        metadata.put("type", "LIVE_TRAFFIC_ANALYSIS_METADATA");
        metadata.put("analysis_id", analysisId);
        metadata.put("analysis_timestamp", System.currentTimeMillis());
        metadata.put("active_requests", trafficSummary.getActiveRequests());
        metadata.put("active_responses", trafficSummary.getActiveResponses());
        
        var securityStats = new HashMap<String, Object>();
        securityStats.put("total_threats", trafficSummary.getSecurityStatistics().getTotalThreatsDetected());
        securityStats.put("high_risk_requests", trafficSummary.getSecurityStatistics().getHighRiskRequests());
        securityStats.put("ssl_issues", trafficSummary.getSecurityStatistics().getSslIssues());
        metadata.put("security_statistics", securityStats);
        
        // Add pattern matcher status
        metadata.put("pattern_matcher_status", SafePatternMatcher.getPatternStatus());
        
        return metadata;
    }
    
    private void populateBasicRequestInfo(Map<String, Object> entry, 
            burp.api.montoya.http.message.requests.HttpRequest request,
            burp.api.montoya.http.message.responses.HttpResponse response) {
        
        entry.put("source", "BurpSuite Pro Proxy - LIVE");
        entry.put("url", request.url());
        entry.put("method", request.method());
        entry.put("status", response != null ? response.statusCode() : 0);
        entry.put("requestLength", request.toByteArray().getBytes().length);
        entry.put("responseLength", response != null ? response.toByteArray().getBytes().length : 0);
        entry.put("timestamp", System.currentTimeMillis());
        entry.put("mimeType", response != null ? response.mimeType().toString() : "unknown");
        
        // Add request headers
        var requestHeaders = new ArrayList<String>();
        request.headers().forEach(header -> requestHeaders.add(header.name() + ": " + header.value()));
        entry.put("requestHeaders", requestHeaders);
        
        // Add response headers if available
        if (response != null) {
            var responseHeaders = new ArrayList<String>();
            response.headers().forEach(header -> responseHeaders.add(header.name() + ": " + header.value()));
            entry.put("responseHeaders", responseHeaders);
        }
    }
    
    private Map<String, Object> performLiveSSLAnalysis(String url) {
        try {
            var urlObj = new URL(url);
            var hostname = urlObj.getHost();
            var port = urlObj.getPort() == -1 ? 443 : urlObj.getPort();
            
            // Check cache first
            var cacheKey = hostname + ":" + port;
            @SuppressWarnings("unchecked")
            var cachedAnalysis = (Map<String, Object>) analysisCache.get(cacheKey);
            if (cachedAnalysis != null) {
                var cacheAge = System.currentTimeMillis() - (Long) cachedAnalysis.get("cache_timestamp");
                if (cacheAge < 300000) { // 5 minutes cache
                    cachedAnalysis.put("from_cache", true);
                    return cachedAnalysis;
                }
            }
            
            api.logging().logToOutput("[BurpMCP] 🔒 Live SSL analysis for: " + hostname + ":" + port);
            
            // Perform live SSL certificate analysis
            var certFuture = SSLCertificateAnalyzer.analyzeCertificate(hostname, port);
            var certAnalysis = certFuture.get(10, TimeUnit.SECONDS); // 10 second timeout for live analysis
            
            var sslData = new HashMap<String, Object>();
            sslData.put("hostname", certAnalysis.getHostname());
            sslData.put("security_score", certAnalysis.getSecurityScore());
            sslData.put("risk_level", certAnalysis.getRiskLevel());
            sslData.put("chain_length", certAnalysis.getChainLength());
            sslData.put("analysis_timestamp", certAnalysis.getAnalysisTimestamp());
            sslData.put("cache_timestamp", System.currentTimeMillis());
            sslData.put("from_cache", false);
            
            if (certAnalysis.getLeafCertificate() != null) {
                var leafCert = certAnalysis.getLeafCertificate();
                var certDetails = new HashMap<String, Object>();
                certDetails.put("valid", !leafCert.isExpired());
                certDetails.put("days_until_expiry", leafCert.getDaysUntilExpiry());
                certDetails.put("signature_algorithm", leafCert.getSignatureAlgorithm());
                certDetails.put("key_algorithm", leafCert.getKeyAlgorithm());
                certDetails.put("key_size", leafCert.getKeySize());
                certDetails.put("weak_signature", leafCert.isWeakSignature());
                certDetails.put("weak_key", leafCert.isWeakKey());
                certDetails.put("subject", leafCert.getSubject());
                certDetails.put("issuer", leafCert.getIssuer());
                
                sslData.put("certificate_details", certDetails);
            }
            
            // Add chain validation info
            if (certAnalysis.getChainValidation() != null) {
                var chainInfo = new HashMap<String, Object>();
                chainInfo.put("valid", certAnalysis.getChainValidation().isValid());
                chainInfo.put("self_signed_root", certAnalysis.getChainValidation().isSelfSignedRoot());
                chainInfo.put("issues", certAnalysis.getChainValidation().getIssues());
                sslData.put("chain_validation", chainInfo);
            }
            
            sslData.put("recommendations", certAnalysis.getRecommendations());
            
            // Cache the result
            analysisCache.put(cacheKey, sslData);
            
            return sslData;
            
        } catch (Exception e) {
            api.logging().logToOutput("[BurpMCP] ⚠️ SSL analysis failed for " + url + ": " + e.getMessage());
            var errorData = new HashMap<String, Object>();
            errorData.put("error", e.getMessage());
            errorData.put("analysis_failed", true);
            return errorData;
        }
    }
    
    private Map<String, Object> performLivePatternAnalysis(
            burp.api.montoya.http.message.requests.HttpRequest request,
            burp.api.montoya.http.message.responses.HttpResponse response) {
        
        var analysis = new HashMap<String, Object>();
        
        try {
            // Analyze request URL for security patterns
            var urlPatterns = analyzeContentWithPatterns(request.url(), "url");
            if (!urlPatterns.isEmpty()) {
                analysis.put("url_security_patterns", urlPatterns);
            }
            
            // Analyze request body if present
            if (request.body().length() > 0) {
                var bodyString = request.bodyToString();
                var bodyPatterns = analyzeContentWithPatterns(bodyString, "request_body");
                if (!bodyPatterns.isEmpty()) {
                    analysis.put("request_body_patterns", bodyPatterns);
                }
            }
            
            // Analyze request headers for security issues
            var headerPatterns = new HashMap<String, Object>();
            request.headers().forEach(header -> {
                var headerAnalysis = analyzeContentWithPatterns(header.value(), "header:" + header.name());
                if (!headerAnalysis.isEmpty()) {
                    headerPatterns.put(header.name(), headerAnalysis);
                }
            });
            if (!headerPatterns.isEmpty()) {
                analysis.put("request_header_patterns", headerPatterns);
            }
            
            // Analyze response body for information disclosure if available
            if (response != null && response.body().length() > 0) {
                var responseBodyString = response.bodyToString();
                var responsePatterns = analyzeContentWithPatterns(responseBodyString, "response_body");
                if (!responsePatterns.isEmpty()) {
                    analysis.put("response_body_patterns", responsePatterns);
                }
                
                // Check for error disclosure patterns
                if (response.statusCode() >= 400) {
                    var errorPatterns = analyzeErrorDisclosure(responseBodyString, response.statusCode());
                    if (!errorPatterns.isEmpty()) {
                        analysis.put("error_disclosure_patterns", errorPatterns);
                    }
                }
            }
            
            // Analyze response headers for security issues
            if (response != null) {
                var responseHeaderAnalysis = analyzeSecurityHeaders(response);
                if (!responseHeaderAnalysis.isEmpty()) {
                    analysis.put("response_security_headers", responseHeaderAnalysis);
                }
            }
            
        } catch (Exception e) {
            api.logging().logToOutput("[BurpMCP] ⚠️ Pattern analysis failed for " + request.url() + ": " + e.getMessage());
            analysis.put("pattern_analysis_error", e.getMessage());
        }
        
        return analysis;
    }
    
    private Map<String, Object> analyzeContentWithPatterns(String content, String context) {
        var patternResults = new HashMap<String, Object>();
        
        if (content == null || content.isEmpty()) {
            return patternResults;
        }
        
        String[] patterns = {"SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "SENSITIVE_DATA"};
        
        for (String pattern : patterns) {
            try {
                var matchResult = SafePatternMatcher.advancedMatch(pattern, content, context);
                if (matchResult.isMatched()) {
                    var patternData = new HashMap<String, Object>();
                    patternData.put("matched", true);
                    patternData.put("confidence", matchResult.getConfidence());
                    patternData.put("severity", matchResult.getSeverity());
                    patternData.put("matched_content", matchResult.getMatchedSubstring());
                    patternData.put("pattern_name", matchResult.getPatternName());
                    patternData.put("context", context);
                    patternResults.put(pattern, patternData);
                    
                    api.logging().logToOutput("[BurpMCP] 🎯 LIVE PATTERN: " + pattern + 
                        " (" + matchResult.getSeverity() + ") in " + context);
                }
            } catch (Exception e) {
                api.logging().logToOutput("[BurpMCP] ⚠️ Pattern analysis failed for " + pattern + ": " + e.getMessage());
            }
        }
        
        return patternResults;
    }
    
    private Map<String, Object> analyzeErrorDisclosure(String responseBody, int statusCode) {
        var errorPatterns = new HashMap<String, Object>();
        String lowerBody = responseBody.toLowerCase();
        
        // Check for stack traces
        if (lowerBody.contains("stacktrace") || lowerBody.contains("exception") || 
            (lowerBody.contains("error:") && lowerBody.contains("line"))) {
            errorPatterns.put("stack_trace", Map.of(
                "detected", true,
                "severity", "MEDIUM",
                "description", "Potential stack trace disclosure detected"
            ));
        }
        
        // Check for SQL errors
        if (lowerBody.contains("sql") && (lowerBody.contains("error") || lowerBody.contains("syntax"))) {
            errorPatterns.put("sql_error", Map.of(
                "detected", true,
                "severity", "HIGH",
                "description", "SQL error information disclosure detected"
            ));
        }
        
        // Check for path disclosure
        if (lowerBody.contains("/var/www") || lowerBody.contains("/home/") || 
            lowerBody.contains("c:\\\\") || lowerBody.contains("/usr/")) {
            errorPatterns.put("path_disclosure", Map.of(
                "detected", true,
                "severity", "MEDIUM",
                "description", "File system path disclosure detected"
            ));
        }
        
        return errorPatterns;
    }
    
    private Map<String, Object> analyzeSecurityHeaders(burp.api.montoya.http.message.responses.HttpResponse response) {
        var headerAnalysis = new HashMap<String, Object>();
        var missingHeaders = new ArrayList<String>();
        var insecureHeaders = new HashMap<String, String>();
        
        // Check for required security headers
        var requiredHeaders = Map.of(
            "x-frame-options", "Clickjacking protection",
            "x-content-type-options", "MIME type sniffing protection",
            "x-xss-protection", "XSS filter protection",
            "strict-transport-security", "HTTPS enforcement",
            "content-security-policy", "Content injection protection"
        );
        
        for (var header : requiredHeaders.entrySet()) {
            var headerValue = response.headerValue(header.getKey());
            if (headerValue == null) {
                missingHeaders.add(header.getKey() + " (" + header.getValue() + ")");
            } else {
                // Check for insecure values
                switch (header.getKey()) {
                    case "x-frame-options":
                        if (!"DENY".equalsIgnoreCase(headerValue) && !"SAMEORIGIN".equalsIgnoreCase(headerValue)) {
                            insecureHeaders.put(header.getKey(), "Insecure value: " + headerValue);
                        }
                        break;
                    case "content-security-policy":
                        if (headerValue.contains("unsafe-inline") || headerValue.contains("unsafe-eval")) {
                            insecureHeaders.put(header.getKey(), "Contains unsafe directives");
                        }
                        break;
                    case "strict-transport-security":
                        if (!headerValue.contains("max-age") || headerValue.contains("max-age=0")) {
                            insecureHeaders.put(header.getKey(), "Weak HSTS configuration");
                        }
                        break;
                }
            }
        }
        
        if (!missingHeaders.isEmpty()) {
            headerAnalysis.put("missing_headers", missingHeaders);
        }
        
        if (!insecureHeaders.isEmpty()) {
            headerAnalysis.put("insecure_headers", insecureHeaders);
        }
        
        return headerAnalysis;
    }
    
    private Map<String, Object> performLiveTrafficInterception(
            burp.api.montoya.http.message.requests.HttpRequest request,
            burp.api.montoya.http.message.responses.HttpResponse response) {
        
        try {
            // Convert headers to Map for traffic interceptor
            var headerMap = new HashMap<String, String>();
            request.headers().forEach(header -> headerMap.put(header.name(), header.value()));
            
            // Intercept and analyze the request
            var interceptionFuture = TrafficInterceptor.interceptRequest(
                request.method(), request.url(), headerMap, request.toByteArray().getBytes());
            
            var interceptionResult = interceptionFuture.get(5, TimeUnit.SECONDS); // 5 second timeout
            
            var trafficAnalysis = new HashMap<String, Object>();
            trafficAnalysis.put("action", interceptionResult.getAction());
            trafficAnalysis.put("request_id", interceptionResult.getRequestId());
            
            if (interceptionResult.getSecurityFindings() != null && !interceptionResult.getSecurityFindings().isEmpty()) {
                var findings = new ArrayList<Map<String, Object>>();
                var highSeverityCount = 0;
                
                for (var finding : interceptionResult.getSecurityFindings()) {
                    var findingMap = new HashMap<String, Object>();
                    findingMap.put("type", finding.getType());
                    findingMap.put("severity", finding.getSeverity());
                    findingMap.put("confidence", finding.getConfidence());
                    findingMap.put("location", finding.getLocation());
                    findingMap.put("description", finding.getDescription());
                    findingMap.put("matched_content", finding.getMatchedContent() != null ? finding.getMatchedContent() : "");
                    findings.add(findingMap);
                    
                    if ("HIGH".equals(finding.getSeverity()) || "CRITICAL".equals(finding.getSeverity())) {
                        highSeverityCount++;
                    }
                }
                
                trafficAnalysis.put("security_findings", findings);
                trafficAnalysis.put("high_severity_count", highSeverityCount);
                trafficAnalysis.put("has_high_severity", highSeverityCount > 0);
            }
            
            if (interceptionResult.getModifications() != null && !interceptionResult.getModifications().isEmpty()) {
                trafficAnalysis.put("suggested_modifications", interceptionResult.getModifications());
            }
            
            // Add SSL certificate analysis if available
            if (interceptionResult.getCertificateAnalysis() != null) {
                var certData = new HashMap<String, Object>();
                certData.put("security_score", interceptionResult.getCertificateAnalysis().getSecurityScore());
                certData.put("risk_level", interceptionResult.getCertificateAnalysis().getRiskLevel());
                trafficAnalysis.put("interceptor_ssl_analysis", certData);
            }
            
            return trafficAnalysis;
            
        } catch (Exception e) {
            api.logging().logToOutput("[BurpMCP] ⚠️ Traffic interception failed for " + request.url() + ": " + e.getMessage());
            return Map.of("traffic_analysis_error", e.getMessage());
        }
    }
    
    private int calculateLiveSecurityScore(Map<String, Object> entry) {
        int score = 100; // Start with perfect score
        
        // SSL analysis impact
        if (entry.containsKey("live_ssl_analysis")) {
            @SuppressWarnings("unchecked")
            var sslAnalysis = (Map<String, Object>) entry.get("live_ssl_analysis");
            if (sslAnalysis.containsKey("security_score")) {
                var sslScore = (Integer) sslAnalysis.get("security_score");
                score = Math.min(score, sslScore);
            }
        }
        
        // Security pattern findings impact
        if (entry.containsKey("url_security_patterns") || 
            entry.containsKey("request_body_patterns") ||
            entry.containsKey("response_body_patterns")) {
            score -= 20; // Deduct for any pattern matches
        }
        
        // Traffic analysis findings impact
        if (entry.containsKey("live_traffic_analysis")) {
            @SuppressWarnings("unchecked")
            var trafficAnalysis = (Map<String, Object>) entry.get("live_traffic_analysis");
            if (Boolean.TRUE.equals(trafficAnalysis.get("has_high_severity"))) {
                score -= 30; // Major deduction for high severity findings
            }
        }
        
        // Security headers impact
        if (entry.containsKey("response_security_headers")) {
            @SuppressWarnings("unchecked")
            var headerAnalysis = (Map<String, Object>) entry.get("response_security_headers");
            if (headerAnalysis.containsKey("missing_headers")) {
                score -= 10;
            }
            if (headerAnalysis.containsKey("insecure_headers")) {
                score -= 15;
            }
        }
        
        return Math.max(0, score);
    }
    
    private void markInterestingEntry(Map<String, Object> entry) {
        var interestingFactors = new ArrayList<String>();
        
        if (entry.containsKey("live_ssl_analysis")) {
            interestingFactors.add("SSL/TLS Analysis");
        }
        
        if (entry.containsKey("url_security_patterns")) {
            interestingFactors.add("URL Patterns");
        }
        
        if (entry.containsKey("request_body_patterns")) {
            interestingFactors.add("Request Body Patterns");
        }
        
        if (entry.containsKey("response_body_patterns")) {
            interestingFactors.add("Response Body Patterns");
        }
        
        if (entry.containsKey("live_traffic_analysis")) {
            interestingFactors.add("Traffic Analysis");
        }
        
        if (Boolean.TRUE.equals(entry.get("ssl_warning"))) {
            interestingFactors.add("SSL Warning");
        }
        
        if (Boolean.TRUE.equals(entry.get("security_alert"))) {
            interestingFactors.add("Security Alert");
        }
        
        if (!interestingFactors.isEmpty()) {
            entry.put("interesting", true);
            entry.put("note", "Live analysis: " + String.join(", ", interestingFactors));
        }
        
        // Add security score classification
        if (entry.containsKey("live_security_score")) {
            var score = (Integer) entry.get("live_security_score");
            entry.put("security_classification", 
                score >= 80 ? "LOW_RISK" : 
                score >= 60 ? "MEDIUM_RISK" : 
                score >= 40 ? "HIGH_RISK" : "CRITICAL_RISK");
        }
    }
    
    private void updateAnalysisStatistics(Map<String, Object> metadata, int processedCount, 
                                        int sslAnalysisCount, int securityFindingsCount) {
        metadata.put("entries_processed", processedCount);
        metadata.put("ssl_analyses_performed", sslAnalysisCount);
        metadata.put("entries_with_security_findings", securityFindingsCount);
        metadata.put("analysis_completion_time", System.currentTimeMillis());
    }
    
    /**
     * Clear analysis cache (useful for testing or periodic cleanup)
     */
    public static void clearAnalysisCache() {
        analysisCache.clear();
    }
}
