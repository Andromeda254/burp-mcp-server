package com.burp.mcp.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.time.Instant;
import java.net.URL;
import java.util.regex.Pattern;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.DeflaterInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Enhanced traffic interception with real-time modification and security analysis
 * Integrates with SafePatternMatcher and SSLCertificateAnalyzer for comprehensive analysis
 */
public class TrafficInterceptor {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final AtomicLong requestIdGenerator = new AtomicLong(1);
    private static final Map<Long, InterceptedRequest> activeRequests = new ConcurrentHashMap<>();
    private static final Map<Long, InterceptedResponse> activeResponses = new ConcurrentHashMap<>();
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    
    // Configuration
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
        "authorization", "cookie", "x-auth-token", "x-api-key", 
        "bearer", "basic", "digest", "apikey", "access-token"
    );
    
    private static final Set<String> CONTENT_ENCODINGS = Set.of(
        "gzip", "deflate", "br", "compress"
    );
    
    private static final int MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB limit
    
    /**
     * Intercept HTTP request with comprehensive analysis
     */
    public static CompletableFuture<InterceptionResult> interceptRequest(
            String method, 
            String url, 
            Map<String, String> headers, 
            byte[] body) {
        
        return CompletableFuture.supplyAsync(() -> {
            long requestId = requestIdGenerator.getAndIncrement();
            
            try {
                var request = new InterceptedRequest();
                request.setRequestId(requestId);
                request.setMethod(method);
                request.setUrl(url);
                request.setHeaders(headers != null ? new HashMap<>(headers) : new HashMap<>());
                request.setOriginalBody(body);
                request.setTimestamp(Instant.now());
                
                // Parse URL for analysis
                URL parsedUrl = new URL(url);
                request.setHostname(parsedUrl.getHost());
                request.setPort(parsedUrl.getPort() == -1 ? parsedUrl.getDefaultPort() : parsedUrl.getPort());
                request.setPath(parsedUrl.getPath());
                request.setQuery(parsedUrl.getQuery());
                
                // SSL analysis for HTTPS
                if ("https".equals(parsedUrl.getProtocol())) {
                    analyzeCertificate(request);
                }
                
                // Security analysis
                analyzeRequestSecurity(request);
                
                // Store active request
                activeRequests.put(requestId, request);
                
                // Create result
                var result = new InterceptionResult();
                result.setRequestId(requestId);
                result.setAction(determineAction(request));
                result.setModifications(generateModifications(request));
                result.setSecurityFindings(request.getSecurityFindings());
                result.setCertificateAnalysis(request.getCertificateAnalysis());
                
                return result;
                
            } catch (Exception e) {
                return createErrorResult(requestId, "Request interception failed: " + e.getMessage());
            }
        });
    }
    
    /**
     * Intercept HTTP response with security analysis
     */
    public static CompletableFuture<InterceptionResult> interceptResponse(
            long requestId,
            int statusCode,
            Map<String, String> headers,
            byte[] body) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                var response = new InterceptedResponse();
                response.setRequestId(requestId);
                response.setStatusCode(statusCode);
                response.setHeaders(headers != null ? new HashMap<>(headers) : new HashMap<>());
                response.setOriginalBody(body);
                response.setTimestamp(Instant.now());
                
                // Get corresponding request
                InterceptedRequest request = activeRequests.get(requestId);
                if (request != null) {
                    response.setCorrelatedRequest(request);
                }
                
                // Decode response body if compressed
                decodeResponseBody(response);
                
                // Security analysis
                analyzeResponseSecurity(response);
                
                // Store active response
                activeResponses.put(requestId, response);
                
                // Create result
                var result = new InterceptionResult();
                result.setRequestId(requestId);
                result.setResponseId(requestId); // Using same ID for simplicity
                result.setAction(determineResponseAction(response));
                result.setModifications(generateResponseModifications(response));
                result.setSecurityFindings(response.getSecurityFindings());
                
                return result;
                
            } catch (Exception e) {
                return createErrorResult(requestId, "Response interception failed: " + e.getMessage());
            }
        });
    }
    
    /**
     * Apply modifications to intercepted request
     */
    public static ModificationResult applyRequestModifications(long requestId, RequestModification modifications) {
        lock.writeLock().lock();
        try {
            InterceptedRequest request = activeRequests.get(requestId);
            if (request == null) {
                return ModificationResult.error("Request not found: " + requestId);
            }
            
            var originalRequest = request.copy(); // Create backup
            
            // Apply modifications
            if (modifications.getHeaders() != null) {
                request.getHeaders().putAll(modifications.getHeaders());
            }
            
            if (modifications.getRemoveHeaders() != null) {
                modifications.getRemoveHeaders().forEach(request.getHeaders()::remove);
            }
            
            if (modifications.getNewBody() != null) {
                request.setModifiedBody(modifications.getNewBody());
            }
            
            if (modifications.getNewUrl() != null) {
                request.setUrl(modifications.getNewUrl());
            }
            
            // Re-analyze after modifications
            analyzeRequestSecurity(request);
            
            return ModificationResult.success(requestId, "Modifications applied successfully");
            
        } catch (Exception e) {
            return ModificationResult.error("Modification failed: " + e.getMessage());
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get traffic analysis summary
     */
    public static TrafficAnalysisSummary getTrafficSummary() {
        lock.readLock().lock();
        try {
            var summary = new TrafficAnalysisSummary();
            summary.setActiveRequests(activeRequests.size());
            summary.setActiveResponses(activeResponses.size());
            summary.setTimestamp(Instant.now());
            
            // Security statistics
            var securityStats = new SecurityStatistics();
            int totalThreats = 0;
            int highRiskRequests = 0;
            int sslIssues = 0;
            
            for (InterceptedRequest request : activeRequests.values()) {
                if (request.getSecurityFindings() != null) {
                    totalThreats += request.getSecurityFindings().size();
                    
                    boolean hasHighRisk = request.getSecurityFindings().stream()
                        .anyMatch(finding -> "HIGH".equals(finding.getSeverity()) || 
                                           "CRITICAL".equals(finding.getSeverity()));
                    if (hasHighRisk) {
                        highRiskRequests++;
                    }
                }
                
                if (request.getCertificateAnalysis() != null && 
                    "HIGH".equals(request.getCertificateAnalysis().getRiskLevel()) ||
                    "CRITICAL".equals(request.getCertificateAnalysis().getRiskLevel())) {
                    sslIssues++;
                }
            }
            
            securityStats.setTotalThreatsDetected(totalThreats);
            securityStats.setHighRiskRequests(highRiskRequests);
            securityStats.setSslIssues(sslIssues);
            summary.setSecurityStatistics(securityStats);
            
            return summary;
            
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clean up old requests and responses
     */
    public static void cleanup(int maxAge) {
        lock.writeLock().lock();
        try {
            Instant cutoff = Instant.now().minusSeconds(maxAge);
            
            activeRequests.entrySet().removeIf(entry -> 
                entry.getValue().getTimestamp().isBefore(cutoff));
                
            activeResponses.entrySet().removeIf(entry -> 
                entry.getValue().getTimestamp().isBefore(cutoff));
                
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    // Private analysis methods
    
    private static void analyzeCertificate(InterceptedRequest request) {
        try {
            var future = SSLCertificateAnalyzer.analyzeCertificate(request.getHostname(), request.getPort());
            var analysis = future.get(5, java.util.concurrent.TimeUnit.SECONDS);
            request.setCertificateAnalysis(analysis);
        } catch (Exception e) {
            // Certificate analysis failed, continue without it
            System.err.println("Certificate analysis failed for " + request.getHostname() + ": " + e.getMessage());
        }
    }
    
    private static void analyzeRequestSecurity(InterceptedRequest request) {
        var findings = new ArrayList<SecurityFinding>();
        
        // URL analysis
        String url = request.getUrl();
        analyzeWithPattern("SQL_INJECTION", url, "url", findings);
        analyzeWithPattern("XSS", url, "url", findings);
        analyzeWithPattern("PATH_TRAVERSAL", url, "url", findings);
        analyzeWithPattern("COMMAND_INJECTION", url, "url", findings);
        
        // Header analysis
        for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
            String headerName = header.getKey().toLowerCase();
            String headerValue = header.getValue();
            
            // Check for sensitive headers
            if (SENSITIVE_HEADERS.stream().anyMatch(headerName::contains)) {
                var finding = new SecurityFinding();
                finding.setType("SENSITIVE_DATA");
                finding.setDescription("Sensitive header detected: " + headerName);
                finding.setSeverity("MEDIUM");
                finding.setLocation("header:" + headerName);
                finding.setConfidence(0.9);
                findings.add(finding);
            }
            
            // Analyze header values
            analyzeWithPattern("XSS", headerValue, "header:" + headerName, findings);
            analyzeWithPattern("COMMAND_INJECTION", headerValue, "header:" + headerName, findings);
        }
        
        // Body analysis
        if (request.getModifiedBody() != null || request.getOriginalBody() != null) {
            byte[] body = request.getModifiedBody() != null ? 
                request.getModifiedBody() : request.getOriginalBody();
            
            if (body != null && body.length > 0 && body.length < MAX_BODY_SIZE) {
                String bodyString = new String(body, StandardCharsets.UTF_8);
                
                analyzeWithPattern("SQL_INJECTION", bodyString, "body", findings);
                analyzeWithPattern("XSS", bodyString, "body", findings);
                analyzeWithPattern("SENSITIVE_DATA", bodyString, "body", findings);
                analyzeWithPattern("COMMAND_INJECTION", bodyString, "body", findings);
            }
        }
        
        request.setSecurityFindings(findings);
    }
    
    private static void analyzeResponseSecurity(InterceptedResponse response) {
        var findings = new ArrayList<SecurityFinding>();
        
        // Header analysis
        for (Map.Entry<String, String> header : response.getHeaders().entrySet()) {
            String headerName = header.getKey().toLowerCase();
            String headerValue = header.getValue();
            
            // Check for security headers
            checkSecurityHeaders(headerName, headerValue, findings);
            
            // Analyze header values for XSS
            analyzeWithPattern("XSS", headerValue, "response-header:" + headerName, findings);
        }
        
        // Body analysis
        if (response.getDecodedBody() != null && response.getDecodedBody().length > 0 
            && response.getDecodedBody().length < MAX_BODY_SIZE) {
            
            String bodyString = new String(response.getDecodedBody(), StandardCharsets.UTF_8);
            
            analyzeWithPattern("XSS", bodyString, "response-body", findings);
            analyzeWithPattern("SENSITIVE_DATA", bodyString, "response-body", findings);
            
            // Check for error disclosures
            if (response.getStatusCode() >= 400) {
                checkErrorDisclosure(bodyString, findings);
            }
        }
        
        response.setSecurityFindings(findings);
    }
    
    private static void analyzeWithPattern(String patternName, String input, String context, List<SecurityFinding> findings) {
        var matchResult = SafePatternMatcher.advancedMatch(patternName, input, context);
        
        if (matchResult.isMatched()) {
            var finding = new SecurityFinding();
            finding.setType(patternName);
            finding.setDescription("Pattern detected: " + matchResult.getMatchedSubstring());
            finding.setSeverity(matchResult.getSeverity());
            finding.setLocation(context);
            finding.setConfidence(matchResult.getConfidence());
            finding.setMatchedContent(matchResult.getMatchedSubstring());
            findings.add(finding);
        }
    }
    
    private static void checkSecurityHeaders(String headerName, String headerValue, List<SecurityFinding> findings) {
        // Check for missing security headers or insecure values
        switch (headerName) {
            case "x-frame-options":
                if (!"DENY".equalsIgnoreCase(headerValue) && !"SAMEORIGIN".equalsIgnoreCase(headerValue)) {
                    addSecurityFinding(findings, "INSECURE_HEADER", 
                        "X-Frame-Options header has insecure value: " + headerValue, 
                        "MEDIUM", "response-header:x-frame-options");
                }
                break;
                
            case "content-security-policy":
                if (headerValue.contains("unsafe-inline") || headerValue.contains("unsafe-eval")) {
                    addSecurityFinding(findings, "INSECURE_CSP", 
                        "Content Security Policy contains unsafe directives", 
                        "MEDIUM", "response-header:content-security-policy");
                }
                break;
                
            case "strict-transport-security":
                if (!headerValue.contains("max-age") || headerValue.contains("max-age=0")) {
                    addSecurityFinding(findings, "WEAK_HSTS", 
                        "Weak HSTS configuration", 
                        "MEDIUM", "response-header:strict-transport-security");
                }
                break;
        }
    }
    
    private static void checkErrorDisclosure(String body, List<SecurityFinding> findings) {
        String lowerBody = body.toLowerCase();
        
        // Check for stack traces
        if (lowerBody.contains("stacktrace") || lowerBody.contains("exception") || 
            lowerBody.contains("error:") && lowerBody.contains("line")) {
            
            addSecurityFinding(findings, "ERROR_DISCLOSURE", 
                "Potential stack trace or error information disclosure", 
                "MEDIUM", "response-body");
        }
        
        // Check for SQL errors
        if (lowerBody.contains("sql") && (lowerBody.contains("error") || lowerBody.contains("syntax"))) {
            addSecurityFinding(findings, "SQL_ERROR_DISCLOSURE", 
                "SQL error information disclosure", 
                "HIGH", "response-body");
        }
    }
    
    private static void addSecurityFinding(List<SecurityFinding> findings, String type, 
                                         String description, String severity, String location) {
        var finding = new SecurityFinding();
        finding.setType(type);
        finding.setDescription(description);
        finding.setSeverity(severity);
        finding.setLocation(location);
        finding.setConfidence(0.8);
        findings.add(finding);
    }
    
    private static void decodeResponseBody(InterceptedResponse response) {
        byte[] originalBody = response.getOriginalBody();
        if (originalBody == null || originalBody.length == 0) {
            return;
        }
        
        String encoding = response.getHeaders().get("content-encoding");
        if (encoding == null) {
            response.setDecodedBody(originalBody);
            return;
        }
        
        try {
            byte[] decodedBody = null;
            encoding = encoding.toLowerCase();
            
            switch (encoding) {
                case "gzip":
                    decodedBody = decompressGzip(originalBody);
                    break;
                case "deflate":
                    decodedBody = decompressDeflate(originalBody);
                    break;
                default:
                    // Unsupported encoding, use original
                    decodedBody = originalBody;
                    break;
            }
            
            response.setDecodedBody(decodedBody);
            
        } catch (Exception e) {
            // Decompression failed, use original body
            response.setDecodedBody(originalBody);
        }
    }
    
    private static byte[] decompressGzip(byte[] compressed) throws IOException {
        try (var bais = new ByteArrayInputStream(compressed);
             var gzis = new GZIPInputStream(bais);
             var baos = new ByteArrayOutputStream()) {
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = gzis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }
    
    private static byte[] decompressDeflate(byte[] compressed) throws IOException {
        try (var bais = new ByteArrayInputStream(compressed);
             var dis = new DeflaterInputStream(bais);
             var baos = new ByteArrayOutputStream()) {
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = dis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }
    
    private static String determineAction(InterceptedRequest request) {
        if (request.getSecurityFindings() != null) {
            boolean hasCritical = request.getSecurityFindings().stream()
                .anyMatch(finding -> "CRITICAL".equals(finding.getSeverity()));
            if (hasCritical) {
                return "BLOCK";
            }
            
            boolean hasHigh = request.getSecurityFindings().stream()
                .anyMatch(finding -> "HIGH".equals(finding.getSeverity()));
            if (hasHigh) {
                return "WARN";
            }
        }
        
        return "ALLOW";
    }
    
    private static String determineResponseAction(InterceptedResponse response) {
        if (response.getSecurityFindings() != null) {
            boolean hasCritical = response.getSecurityFindings().stream()
                .anyMatch(finding -> "CRITICAL".equals(finding.getSeverity()) || "HIGH".equals(finding.getSeverity()));
            if (hasCritical) {
                return "MODIFY";
            }
        }
        
        return "ALLOW";
    }
    
    private static List<String> generateModifications(InterceptedRequest request) {
        var modifications = new ArrayList<String>();
        
        if (request.getSecurityFindings() != null) {
            for (SecurityFinding finding : request.getSecurityFindings()) {
                if ("HIGH".equals(finding.getSeverity()) || "CRITICAL".equals(finding.getSeverity())) {
                    modifications.add("Remove/sanitize " + finding.getType() + " in " + finding.getLocation());
                }
            }
        }
        
        return modifications;
    }
    
    private static List<String> generateResponseModifications(InterceptedResponse response) {
        var modifications = new ArrayList<String>();
        
        if (response.getSecurityFindings() != null) {
            for (SecurityFinding finding : response.getSecurityFindings()) {
                if ("HIGH".equals(finding.getSeverity()) || "CRITICAL".equals(finding.getSeverity())) {
                    modifications.add("Add security headers or sanitize " + finding.getType());
                }
            }
        }
        
        return modifications;
    }
    
    private static InterceptionResult createErrorResult(long requestId, String error) {
        var result = new InterceptionResult();
        result.setRequestId(requestId);
        result.setAction("ERROR");
        result.setError(error);
        return result;
    }
    
    // Data classes
    
    public static class InterceptedRequest {
        private long requestId;
        private String method;
        private String url;
        private String hostname;
        private int port;
        private String path;
        private String query;
        private Map<String, String> headers;
        private byte[] originalBody;
        private byte[] modifiedBody;
        private Instant timestamp;
        private List<SecurityFinding> securityFindings;
        private SSLCertificateAnalyzer.CertificateAnalysisResult certificateAnalysis;
        
        // Copy method for backup
        public InterceptedRequest copy() {
            var copy = new InterceptedRequest();
            copy.requestId = this.requestId;
            copy.method = this.method;
            copy.url = this.url;
            copy.hostname = this.hostname;
            copy.port = this.port;
            copy.path = this.path;
            copy.query = this.query;
            copy.headers = new HashMap<>(this.headers);
            copy.originalBody = this.originalBody != null ? this.originalBody.clone() : null;
            copy.modifiedBody = this.modifiedBody != null ? this.modifiedBody.clone() : null;
            copy.timestamp = this.timestamp;
            copy.securityFindings = this.securityFindings != null ? new ArrayList<>(this.securityFindings) : null;
            copy.certificateAnalysis = this.certificateAnalysis;
            return copy;
        }
        
        // Getters and setters
        public long getRequestId() { return requestId; }
        public void setRequestId(long requestId) { this.requestId = requestId; }
        
        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }
        
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        
        public String getHostname() { return hostname; }
        public void setHostname(String hostname) { this.hostname = hostname; }
        
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        
        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        
        public String getQuery() { return query; }
        public void setQuery(String query) { this.query = query; }
        
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
        
        public byte[] getOriginalBody() { return originalBody; }
        public void setOriginalBody(byte[] originalBody) { this.originalBody = originalBody; }
        
        public byte[] getModifiedBody() { return modifiedBody; }
        public void setModifiedBody(byte[] modifiedBody) { this.modifiedBody = modifiedBody; }
        
        public Instant getTimestamp() { return timestamp; }
        public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
        
        public List<SecurityFinding> getSecurityFindings() { return securityFindings; }
        public void setSecurityFindings(List<SecurityFinding> securityFindings) { this.securityFindings = securityFindings; }
        
        public SSLCertificateAnalyzer.CertificateAnalysisResult getCertificateAnalysis() { return certificateAnalysis; }
        public void setCertificateAnalysis(SSLCertificateAnalyzer.CertificateAnalysisResult certificateAnalysis) { this.certificateAnalysis = certificateAnalysis; }
    }
    
    public static class InterceptedResponse {
        private long requestId;
        private int statusCode;
        private Map<String, String> headers;
        private byte[] originalBody;
        private byte[] decodedBody;
        private Instant timestamp;
        private InterceptedRequest correlatedRequest;
        private List<SecurityFinding> securityFindings;
        
        // Getters and setters
        public long getRequestId() { return requestId; }
        public void setRequestId(long requestId) { this.requestId = requestId; }
        
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
        
        public byte[] getOriginalBody() { return originalBody; }
        public void setOriginalBody(byte[] originalBody) { this.originalBody = originalBody; }
        
        public byte[] getDecodedBody() { return decodedBody; }
        public void setDecodedBody(byte[] decodedBody) { this.decodedBody = decodedBody; }
        
        public Instant getTimestamp() { return timestamp; }
        public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
        
        public InterceptedRequest getCorrelatedRequest() { return correlatedRequest; }
        public void setCorrelatedRequest(InterceptedRequest correlatedRequest) { this.correlatedRequest = correlatedRequest; }
        
        public List<SecurityFinding> getSecurityFindings() { return securityFindings; }
        public void setSecurityFindings(List<SecurityFinding> securityFindings) { this.securityFindings = securityFindings; }
    }
    
    public static class SecurityFinding {
        private String type;
        private String description;
        private String severity;
        private String location;
        private double confidence;
        private String matchedContent;
        
        // Getters and setters
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        
        public String getLocation() { return location; }
        public void setLocation(String location) { this.location = location; }
        
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public String getMatchedContent() { return matchedContent; }
        public void setMatchedContent(String matchedContent) { this.matchedContent = matchedContent; }
    }
    
    public static class InterceptionResult {
        private long requestId;
        private Long responseId;
        private String action;
        private List<String> modifications;
        private List<SecurityFinding> securityFindings;
        private SSLCertificateAnalyzer.CertificateAnalysisResult certificateAnalysis;
        private String error;
        
        // Getters and setters
        public long getRequestId() { return requestId; }
        public void setRequestId(long requestId) { this.requestId = requestId; }
        
        public Long getResponseId() { return responseId; }
        public void setResponseId(Long responseId) { this.responseId = responseId; }
        
        public String getAction() { return action; }
        public void setAction(String action) { this.action = action; }
        
        public List<String> getModifications() { return modifications; }
        public void setModifications(List<String> modifications) { this.modifications = modifications; }
        
        public List<SecurityFinding> getSecurityFindings() { return securityFindings; }
        public void setSecurityFindings(List<SecurityFinding> securityFindings) { this.securityFindings = securityFindings; }
        
        public SSLCertificateAnalyzer.CertificateAnalysisResult getCertificateAnalysis() { return certificateAnalysis; }
        public void setCertificateAnalysis(SSLCertificateAnalyzer.CertificateAnalysisResult certificateAnalysis) { this.certificateAnalysis = certificateAnalysis; }
        
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }
    
    public static class RequestModification {
        private Map<String, String> headers;
        private List<String> removeHeaders;
        private byte[] newBody;
        private String newUrl;
        
        // Getters and setters
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
        
        public List<String> getRemoveHeaders() { return removeHeaders; }
        public void setRemoveHeaders(List<String> removeHeaders) { this.removeHeaders = removeHeaders; }
        
        public byte[] getNewBody() { return newBody; }
        public void setNewBody(byte[] newBody) { this.newBody = newBody; }
        
        public String getNewUrl() { return newUrl; }
        public void setNewUrl(String newUrl) { this.newUrl = newUrl; }
    }
    
    public static class ModificationResult {
        private boolean success;
        private long requestId;
        private String message;
        
        public static ModificationResult success(long requestId, String message) {
            var result = new ModificationResult();
            result.success = true;
            result.requestId = requestId;
            result.message = message;
            return result;
        }
        
        public static ModificationResult error(String message) {
            var result = new ModificationResult();
            result.success = false;
            result.message = message;
            return result;
        }
        
        // Getters
        public boolean isSuccess() { return success; }
        public long getRequestId() { return requestId; }
        public String getMessage() { return message; }
    }
    
    public static class TrafficAnalysisSummary {
        private int activeRequests;
        private int activeResponses;
        private Instant timestamp;
        private SecurityStatistics securityStatistics;
        
        // Getters and setters
        public int getActiveRequests() { return activeRequests; }
        public void setActiveRequests(int activeRequests) { this.activeRequests = activeRequests; }
        
        public int getActiveResponses() { return activeResponses; }
        public void setActiveResponses(int activeResponses) { this.activeResponses = activeResponses; }
        
        public Instant getTimestamp() { return timestamp; }
        public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
        
        public SecurityStatistics getSecurityStatistics() { return securityStatistics; }
        public void setSecurityStatistics(SecurityStatistics securityStatistics) { this.securityStatistics = securityStatistics; }
    }
    
    public static class SecurityStatistics {
        private int totalThreatsDetected;
        private int highRiskRequests;
        private int sslIssues;
        
        // Getters and setters
        public int getTotalThreatsDetected() { return totalThreatsDetected; }
        public void setTotalThreatsDetected(int totalThreatsDetected) { this.totalThreatsDetected = totalThreatsDetected; }
        
        public int getHighRiskRequests() { return highRiskRequests; }
        public void setHighRiskRequests(int highRiskRequests) { this.highRiskRequests = highRiskRequests; }
        
        public int getSslIssues() { return sslIssues; }
        public void setSslIssues(int sslIssues) { this.sslIssues = sslIssues; }
    }
}
