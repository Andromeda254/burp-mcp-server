package com.burp.mcp.proxy;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Simplified traffic analyzer for security analysis using Montoya API
 * Uses only string matching without regex for better stability
 */
public class TrafficAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(TrafficAnalyzer.class);
    
    private final MontoyaApi api;
    
    // Security keywords for detection
    private static final Set<String> SQL_KEYWORDS = Set.of(
        "union", "select", "insert", "update", "delete", "drop", "create", "alter", "exec", "script"
    );
    
    private static final Set<String> XSS_KEYWORDS = Set.of(
        "<script", "javascript:", "onload", "onerror"
    );
    
    private static final Set<String> PATH_TRAVERSAL_KEYWORDS = Set.of(
        "../", "..\\", "%2e%2e%2f"
    );
    
    private static final Set<String> SENSITIVE_KEYWORDS = Set.of(
        "password", "passwd", "pwd", "secret", "token", "key", "apikey", "auth"
    );
    
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
        "authorization", "cookie", "set-cookie", "x-auth-token", 
        "x-api-key", "x-session-token", "bearer"
    );
    
    private static final Set<String> SECURITY_HEADERS = Set.of(
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "referrer-policy",
        "permissions-policy", "cross-origin-embedder-policy"
    );
    
    public TrafficAnalyzer(MontoyaApi api) {
        this.api = api;
    }
    
    public SecurityAnalysis analyzeRequest(HttpRequest request) {
        var analysis = new SecurityAnalysis();
        
        try {
            var url = request.url();
            analysis.addCheck("URL Analysis", analyzeURL(url));
            
            var headers = request.headers();
            analysis.addCheck("Header Analysis", analyzeRequestHeaders(headers));
            
            if (request.body() != null) {
                var body = request.bodyToString();
                analysis.addCheck("Body Analysis", analyzeRequestBody(body));
            }
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[TRAFFIC-ANALYSIS] Request to %s - Security Score: %d/100",
                    url, analysis.getSecurityScore()
                ));
            }
            
            return analysis;
            
        } catch (Exception e) {
            logger.error("Request analysis failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Request analysis failed: " + e.getMessage());
            }
            return SecurityAnalysis.failed(e.getMessage());
        }
    }
    
    public SecurityAnalysis analyzeResponse(HttpResponse response, HttpRequest request) {
        var analysis = new SecurityAnalysis();
        
        try {
            var headers = response.headers();
            analysis.addCheck("Security Headers", analyzeSecurityHeaders(headers));
            
            var body = response.bodyToString();
            analysis.addCheck("Information Disclosure", checkInformationDisclosure(body));
            analysis.addCheck("Response Sensitive Data", analyzeSensitiveDataInResponse(body));
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[TRAFFIC-ANALYSIS] Response from %s - Security Score: %d/100",
                    request.url(), analysis.getSecurityScore()
                ));
            }
            
            return analysis;
            
        } catch (Exception e) {
            logger.error("Response analysis failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Response analysis failed: " + e.getMessage());
            }
            return SecurityAnalysis.failed(e.getMessage());
        }
    }
    
    private SecurityCheck analyzeURL(String url) {
        var check = new SecurityCheck("URL Analysis");
        
        try {
            var lowerUrl = url.toLowerCase();
            
            // Check for SQL injection keywords
            for (var keyword : SQL_KEYWORDS) {
                if (lowerUrl.contains(keyword)) {
                    check.addFinding("SQL injection keyword detected: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Check for XSS keywords
            for (var keyword : XSS_KEYWORDS) {
                if (lowerUrl.contains(keyword.toLowerCase())) {
                    check.addFinding("XSS keyword detected: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Check for path traversal keywords
            for (var keyword : PATH_TRAVERSAL_KEYWORDS) {
                if (url.contains(keyword)) {
                    check.addFinding("Path traversal pattern detected: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Check URL length
            if (url.length() > 2048) {
                check.addFinding("Unusually long URL detected", SecurityLevel.LOW);
            }
            
        } catch (Exception e) {
            check.addError("URL analysis failed: " + e.getMessage());
        }
        
        return check;
    }
    
    private SecurityCheck analyzeRequestHeaders(List<HttpHeader> headers) {
        var check = new SecurityCheck("Request Headers");
        
        try {
            for (var header : headers) {
                var name = header.name().toLowerCase();
                var value = header.value();
                
                // Check for sensitive headers
                if (SENSITIVE_HEADERS.contains(name)) {
                    check.addFinding("Sensitive header detected: " + name, SecurityLevel.INFO);
                }
                
                // Check for basic auth
                if (name.equals("authorization") && value.toLowerCase().startsWith("basic")) {
                    check.addFinding("Basic authentication detected", SecurityLevel.MEDIUM);
                }
            }
            
        } catch (Exception e) {
            check.addError("Header analysis failed: " + e.getMessage());
        }
        
        return check;
    }
    
    private SecurityCheck analyzeRequestBody(String body) {
        var check = new SecurityCheck("Request Body");
        
        try {
            var lowerBody = body.toLowerCase();
            
            // Check for SQL injection keywords
            for (var keyword : SQL_KEYWORDS) {
                if (lowerBody.contains(keyword)) {
                    check.addFinding("SQL injection keyword in body: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Check for XSS keywords
            for (var keyword : XSS_KEYWORDS) {
                if (lowerBody.contains(keyword.toLowerCase())) {
                    check.addFinding("XSS keyword in body: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Check for sensitive data
            for (var keyword : SENSITIVE_KEYWORDS) {
                if (lowerBody.contains(keyword)) {
                    check.addFinding("Sensitive keyword in body: " + keyword, SecurityLevel.MEDIUM);
                }
            }
            
        } catch (Exception e) {
            check.addError("Body analysis failed: " + e.getMessage());
        }
        
        return check;
    }
    
    private SecurityCheck analyzeSecurityHeaders(List<HttpHeader> headers) {
        var check = new SecurityCheck("Security Headers");
        
        try {
            Set<String> foundHeaders = new HashSet<>();
            
            for (var header : headers) {
                var name = header.name().toLowerCase();
                
                if (SECURITY_HEADERS.contains(name)) {
                    foundHeaders.add(name);
                    check.addFinding("Security header present: " + name, SecurityLevel.GOOD);
                }
            }
            
            // Check for missing security headers
            for (var requiredHeader : SECURITY_HEADERS) {
                if (!foundHeaders.contains(requiredHeader)) {
                    check.addFinding("Missing security header: " + requiredHeader, SecurityLevel.LOW);
                }
            }
            
        } catch (Exception e) {
            check.addError("Security header analysis failed: " + e.getMessage());
        }
        
        return check;
    }
    
    private SecurityCheck checkInformationDisclosure(String body) {
        var check = new SecurityCheck("Information Disclosure");
        
        try {
            var lowerBody = body.toLowerCase();
            
            // Check for stack traces
            if (lowerBody.contains("exception") || lowerBody.contains("stack trace") || 
                lowerBody.contains("error:")) {
                check.addFinding("Stack trace detected in response", SecurityLevel.MEDIUM);
            }
            
            // Check for database errors
            if (lowerBody.contains("sql") || lowerBody.contains("mysql") || 
                lowerBody.contains("postgresql") || lowerBody.contains("database")) {
                check.addFinding("Database error detected in response", SecurityLevel.MEDIUM);
            }
            
            // Check for server info
            if (lowerBody.contains("server") || lowerBody.contains("apache") ||
                lowerBody.contains("nginx") || lowerBody.contains("tomcat")) {
                check.addFinding("Server info detected in response", SecurityLevel.LOW);
            }
            
        } catch (Exception e) {
            check.addError("Information disclosure analysis failed: " + e.getMessage());
        }
        
        return check;
    }
    
    private SecurityCheck analyzeSensitiveDataInResponse(String body) {
        var check = new SecurityCheck("Response Sensitive Data");
        
        try {
            if (body == null || body.trim().isEmpty()) {
                return check;
            }
            
            var lowerBody = body.toLowerCase();
            
            // Check for sensitive keywords
            for (var keyword : SENSITIVE_KEYWORDS) {
                if (lowerBody.contains(keyword)) {
                    check.addFinding("Sensitive data keyword in response: " + keyword, SecurityLevel.HIGH);
                }
            }
            
            // Simple credit card detection
            long digitCount = body.chars().filter(Character::isDigit).count();
            if (digitCount >= 13 && (body.contains("4") || body.contains("5") || body.contains("3"))) {
                check.addFinding("Potential credit card pattern detected", SecurityLevel.MEDIUM);
            }
            
            // Email detection
            if (body.contains("@") && (body.contains(".com") || body.contains(".org") || body.contains(".net"))) {
                check.addFinding("Email addresses detected in response", SecurityLevel.INFO);
            }
            
        } catch (Exception e) {
            check.addError("Sensitive data analysis failed: " + e.getMessage());
        }
        
        return check;
    }
}
