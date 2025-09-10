package com.burp.mcp.proxy;

import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

/**
 * Safe pattern matching for security analysis with fallback mechanisms
 * Implements OWASP-recommended security patterns with robust error handling
 */
public class SafePatternMatcher {
    
    private static final Map<String, Pattern> COMPILED_PATTERNS = new ConcurrentHashMap<>();
    private static final Set<String> FAILED_PATTERNS = new HashSet<>();
    
    // Fallback string-based patterns for when regex fails
    private static final Map<String, Set<String>> FALLBACK_PATTERNS = Map.of(
        "SQL_INJECTION", Set.of("union", "select", "insert", "update", "delete", "drop", "create", "alter"),
        "XSS", Set.of("<script", "javascript:", "onload=", "onerror=", "onclick="),
        "PATH_TRAVERSAL", Set.of("../", "..\\", "%2e%2e%2f", "%2e%2e%5c"),
        "COMMAND_INJECTION", Set.of(";", "&", "|", "`", "$(", "${"),
        "SENSITIVE_DATA", Set.of("password", "passwd", "pwd", "secret", "token", "key", "apikey", "auth")
    );
    
    static {
        initializePatterns();
    }
    
    private static void initializePatterns() {
        try {
            // SQL Injection patterns (OWASP recommended)
            compilePattern("SQL_INJECTION", 
                "(?i)(union\\s+select|insert\\s+into|update\\s+set|delete\\s+from|drop\\s+table)");
            
            // XSS patterns - safer version without complex lookaheads
            compilePattern("XSS", 
                "(?i)(<script[^>]*>|javascript:|on\\w+\\s*=)");
                
            // Path traversal - simpler pattern
            compilePattern("PATH_TRAVERSAL", 
                "(\\.{2}[/\\\\]|%2e%2e%2f|%2e%2e%5c)");
            
            // Command injection - basic pattern
            compilePattern("COMMAND_INJECTION", 
                "[;&|`]\\s*(cat|ls|pwd|whoami|id|dir|type|echo)");
            
            // Sensitive data detection
            compilePattern("SENSITIVE_DATA", 
                "(?i)(password|passwd|pwd|secret|token|key|apikey|auth)");
                
        } catch (Exception e) {
            System.err.println("Pattern initialization failed: " + e.getMessage());
        }
    }
    
    private static void compilePattern(String name, String pattern) {
        try {
            COMPILED_PATTERNS.put(name, Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
        } catch (PatternSyntaxException e) {
            System.err.println("Failed to compile pattern " + name + ": " + e.getMessage());
            FAILED_PATTERNS.add(name);
        }
    }
    
    /**
     * Safely matches a pattern against input with fallback to string matching
     */
    public static boolean matches(String patternName, String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        
        // Try regex first if available
        Pattern pattern = COMPILED_PATTERNS.get(patternName);
        if (pattern != null) {
            try {
                return pattern.matcher(input).find();
            } catch (Exception e) {
                // Fall through to string matching
            }
        }
        
        // Fallback to string matching
        return matchesFallback(patternName, input);
    }
    
    private static boolean matchesFallback(String patternName, String input) {
        Set<String> fallbackSet = FALLBACK_PATTERNS.get(patternName);
        if (fallbackSet != null) {
            String lowerInput = input.toLowerCase();
            return fallbackSet.stream().anyMatch(lowerInput::contains);
        }
        return false;
    }
    
    /**
     * Advanced pattern matching with context awareness
     */
    public static MatchResult advancedMatch(String patternName, String input, String context) {
        var result = new MatchResult();
        result.setPatternName(patternName);
        result.setInput(input);
        result.setContext(context);
        
        boolean basicMatch = matches(patternName, input);
        result.setMatched(basicMatch);
        
        if (basicMatch) {
            // Add contextual analysis
            result.setConfidence(calculateConfidence(patternName, input, context));
            result.setSeverity(determineSeverity(patternName, context));
            result.setMatchedSubstring(extractMatchedSubstring(patternName, input));
        }
        
        return result;
    }
    
    private static double calculateConfidence(String patternName, String input, String context) {
        double confidence = 0.5; // Base confidence
        
        // Increase confidence based on pattern strength
        if (COMPILED_PATTERNS.containsKey(patternName) && !FAILED_PATTERNS.contains(patternName)) {
            confidence += 0.3; // Regex match is more reliable
        }
        
        // Context-based confidence adjustments
        if ("SQL_INJECTION".equals(patternName)) {
            if (context != null && (context.contains("parameter") || context.contains("form"))) {
                confidence += 0.2;
            }
        } else if ("XSS".equals(patternName)) {
            if (context != null && context.contains("html")) {
                confidence += 0.2;
            }
        }
        
        return Math.min(1.0, confidence);
    }
    
    private static String determineSeverity(String patternName, String context) {
        switch (patternName) {
            case "SQL_INJECTION":
            case "COMMAND_INJECTION":
                return "HIGH";
            case "XSS":
                return context != null && context.contains("authenticated") ? "HIGH" : "MEDIUM";
            case "PATH_TRAVERSAL":
                return "MEDIUM";
            case "SENSITIVE_DATA":
                return context != null && context.contains("transmission") ? "HIGH" : "LOW";
            default:
                return "LOW";
        }
    }
    
    private static String extractMatchedSubstring(String patternName, String input) {
        Pattern pattern = COMPILED_PATTERNS.get(patternName);
        if (pattern != null) {
            try {
                var matcher = pattern.matcher(input);
                if (matcher.find()) {
                    return matcher.group();
                }
            } catch (Exception e) {
                // Fall through to fallback
            }
        }
        
        // Fallback extraction
        Set<String> fallbackSet = FALLBACK_PATTERNS.get(patternName);
        if (fallbackSet != null) {
            String lowerInput = input.toLowerCase();
            for (String keyword : fallbackSet) {
                if (lowerInput.contains(keyword)) {
                    return keyword;
                }
            }
        }
        
        return "pattern_detected";
    }
    
    /**
     * Result of pattern matching with confidence and context
     */
    public static class MatchResult {
        private String patternName;
        private String input;
        private String context;
        private boolean matched;
        private double confidence;
        private String severity;
        private String matchedSubstring;
        
        // Getters and setters
        public String getPatternName() { return patternName; }
        public void setPatternName(String patternName) { this.patternName = patternName; }
        
        public String getInput() { return input; }
        public void setInput(String input) { this.input = input; }
        
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        
        public boolean isMatched() { return matched; }
        public void setMatched(boolean matched) { this.matched = matched; }
        
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        
        public String getSeverity() { return severity; }
        public void setSeverity(String severity) { this.severity = severity; }
        
        public String getMatchedSubstring() { return matchedSubstring; }
        public void setMatchedSubstring(String matchedSubstring) { this.matchedSubstring = matchedSubstring; }
    }
    
    /**
     * Get pattern compilation status for debugging
     */
    public static Map<String, String> getPatternStatus() {
        var status = new ConcurrentHashMap<String, String>();
        
        for (String pattern : FALLBACK_PATTERNS.keySet()) {
            if (COMPILED_PATTERNS.containsKey(pattern)) {
                status.put(pattern, "REGEX_COMPILED");
            } else if (FAILED_PATTERNS.contains(pattern)) {
                status.put(pattern, "REGEX_FAILED_FALLBACK_ACTIVE");
            } else {
                status.put(pattern, "FALLBACK_ONLY");
            }
        }
        
        return status;
    }
}
