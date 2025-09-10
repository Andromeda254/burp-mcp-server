package com.burp.mcp.browser;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.MontoyaApi;
import java.util.*;

/**
 * Authentication state detection and analysis
 */
public class AuthenticationAnalysis {
    
    private final MontoyaApi api;
    
    public AuthenticationAnalysis(MontoyaApi api) {
        this.api = api;
    }
    
    public AuthDetector createAuthDetector() {
        return new AuthDetector(api);
    }
    
    public PatternAnalyzer createPatternAnalyzer() {
        return new PatternAnalyzer(api);
    }
    
    public SequenceBuilder createSequenceBuilder() {
        return new SequenceBuilder(api);
    }
}

/**
 * Detects authentication state changes in HTTP responses
 */
class AuthDetector {
    private final MontoyaApi api;
    
    public AuthDetector(MontoyaApi api) {
        this.api = api;
    }
    
    public AuthenticationState analyzeAuthenticationState(HttpResponse response, HttpRequest request) {
        var state = new AuthenticationState();
        
        try {
            var body = response.bodyToString().toLowerCase();
            var statusCode = response.statusCode();
            
            // Detect login success
            if (body.contains("welcome") || body.contains("dashboard") || 
                body.contains("logout") || statusCode == 302) {
                state.setCurrentState("AUTHENTICATED");
                state.setStateChange(true);
            }
            // Detect login failure
            else if (body.contains("invalid") || body.contains("incorrect") ||
                     body.contains("failed") || statusCode == 401) {
                state.setCurrentState("FAILED");
                state.setStateChange(true);
            }
            // Detect MFA requirement
            else if (body.contains("verification") || body.contains("2fa") ||
                     body.contains("multi-factor")) {
                state.setCurrentState("MFA_REQUIRED");
                state.setStateChange(true);
            }
            else {
                state.setCurrentState("PENDING");
                state.setStateChange(false);
            }
            
        } catch (Exception e) {
            state.setCurrentState("ERROR");
            state.setStateChange(false);
        }
        
        return state;
    }
}

/**
 * AI-powered pattern analysis for login sequences
 */
class PatternAnalyzer {
    private final MontoyaApi api;
    
    public PatternAnalyzer(MontoyaApi api) {
        this.api = api;
    }
    
    public Map<String, Object> validateSequence(LoginSequence sequence) {
        var validation = new HashMap<String, Object>();
        
        try {
            // Basic validation metrics
            validation.put("step_count", sequence.getSteps().size());
            validation.put("has_password_step", hasPasswordStep(sequence));
            validation.put("has_csrf_protection", hasCsrfProtection(sequence));
            validation.put("uses_https", usesHttps(sequence));
            validation.put("confidence_score", calculateConfidenceScore(sequence));
            
        } catch (Exception e) {
            validation.put("error", e.getMessage());
            validation.put("confidence_score", 0.0);
        }
        
        return validation;
    }
    
    private boolean hasPasswordStep(LoginSequence sequence) {
        return sequence.getSteps().stream()
            .anyMatch(step -> step.getFormData().keySet().stream()
                .anyMatch(key -> key.toLowerCase().contains("password")));
    }
    
    private boolean hasCsrfProtection(LoginSequence sequence) {
        return sequence.getSteps().stream()
            .anyMatch(step -> step.getFormData().keySet().stream()
                .anyMatch(key -> key.toLowerCase().contains("csrf") || 
                               key.toLowerCase().contains("token")));
    }
    
    private boolean usesHttps(LoginSequence sequence) {
        return sequence.getSteps().stream()
            .allMatch(step -> step.getUrl().startsWith("https://"));
    }
    
    private double calculateConfidenceScore(LoginSequence sequence) {
        double score = 50.0; // Base score
        
        if (hasPasswordStep(sequence)) score += 20;
        if (hasCsrfProtection(sequence)) score += 15;
        if (usesHttps(sequence)) score += 10;
        if (sequence.getSteps().size() >= 2) score += 5;
        
        return Math.min(100.0, score);
    }
}

/**
 * Builds login sequences from captured traffic
 */
class SequenceBuilder {
    private final MontoyaApi api;
    private LoginSequence currentSequence;
    
    public SequenceBuilder(MontoyaApi api) {
        this.api = api;
    }
    
    public void startNewSequence(String targetUrl) {
        this.currentSequence = new LoginSequence(targetUrl);
    }
    
    public void addRequestStep(HttpRequest request) {
        if (currentSequence != null) {
            var step = new LoginStep(request.url(), request.method(), "REQUEST");
            
            // Extract form data if POST request
            if ("POST".equals(request.method())) {
                var body = request.bodyToString();
                if (body.contains("=")) {
                    // Simple form data parsing
                    String[] pairs = body.split("&");
                    for (String pair : pairs) {
                        String[] keyValue = pair.split("=", 2);
                        if (keyValue.length == 2) {
                            step.addFormData(keyValue[0], keyValue[1]);
                        }
                    }
                }
            }
            
            currentSequence.addStep(step);
        }
    }
    
    public void updateSequenceWithAuthResult(AuthenticationState authState) {
        if (currentSequence != null && authState.hasStateChange()) {
            currentSequence.addMetadata("auth_state", authState.getCurrentState());
            
            if ("AUTHENTICATED".equals(authState.getCurrentState())) {
                currentSequence.setComplete(true);
            }
        }
    }
    
    public LoginSequence getCurrentSequence() {
        return currentSequence;
    }
}

/**
 * Represents authentication state during login process
 */
class AuthenticationState {
    private String currentState = "PENDING";
    private String previousState = "UNKNOWN";
    private boolean stateChange = false;
    private long timestamp = System.currentTimeMillis();
    
    public String getCurrentState() { return currentState; }
    public void setCurrentState(String state) { 
        this.previousState = this.currentState;
        this.currentState = state; 
    }
    
    public String getPreviousState() { return previousState; }
    
    public boolean hasStateChange() { return stateChange; }
    public void setStateChange(boolean change) { this.stateChange = change; }
    
    public long getTimestamp() { return timestamp; }
}


/**
 * Session management for recording activities
 */
abstract class RecordingSession {
    protected final String targetUrl;
    protected final AILoginSequenceRecorder.LoginRecordingConfig config;
    protected final MontoyaApi api;
    protected final LoginSequence sequence;
    
    public RecordingSession(String targetUrl, AILoginSequenceRecorder.LoginRecordingConfig config, 
                           MontoyaApi api) {
        this.targetUrl = targetUrl;
        this.config = config;
        this.api = api;
        this.sequence = new LoginSequence(targetUrl);
    }
    
    public LoginSequence getRecordedSequence() {
        return sequence;
    }
    
    public abstract LoginSequence startRecording();
}

/**
 * Interactive recording session with user guidance
 */
class InteractiveRecordingSession extends RecordingSession {
    private boolean aiGuidanceEnabled = false;
    
    public InteractiveRecordingSession(String targetUrl, AILoginSequenceRecorder.LoginRecordingConfig config, 
                                      MontoyaApi api) {
        super(targetUrl, config, api);
    }
    
    public void enableAIGuidance() {
        this.aiGuidanceEnabled = true;
    }
    
    @Override
    public LoginSequence startRecording() {
        try {
            if (api != null) {
                api.logging().logToOutput("[INTERACTIVE-RECORDING] Starting interactive session");
            }
            
            // Simulate interactive recording
            Thread.sleep(1000);
            
            // Add mock login steps
            var step1 = new LoginStep(targetUrl + "/login", "GET", "NAVIGATE");
            sequence.addStep(step1);
            
            var step2 = new LoginStep(targetUrl + "/login", "POST", "SUBMIT_CREDENTIALS");
            step2.addFormData("username", "user@example.com");
            step2.addFormData("password", "********");
            sequence.addStep(step2);
            
            sequence.setComplete(true);
            sequence.setRecordingMethod("interactive");
            
            return sequence;
            
        } catch (Exception e) {
            sequence.setComplete(false);
            return sequence;
        }
    }
}

/**
 * Automatic recording session with traffic monitoring
 */
class AutomaticRecordingSession extends RecordingSession {
    
    public AutomaticRecordingSession(String targetUrl, AILoginSequenceRecorder.LoginRecordingConfig config, 
                                    MontoyaApi api, LoginSequence existingSequence) {
        super(targetUrl, config, api);
        if (existingSequence != null) {
            // Copy existing sequence data
            for (var step : existingSequence.getSteps()) {
                this.sequence.addStep(step);
            }
        }
    }
    
    @Override
    public LoginSequence startRecording() {
        try {
            if (api != null) {
                api.logging().logToOutput("[AUTO-RECORDING] Starting automatic session");
            }
            
            // Simulate automatic traffic monitoring
            // In real implementation, this would monitor actual traffic
            if (sequence.getSteps().isEmpty()) {
                // Add default steps if none captured
                var step = new LoginStep(targetUrl, "GET", "AUTO_DETECTED");
                sequence.addStep(step);
            }
            
            sequence.setRecordingMethod("automatic");
            return sequence;
            
        } catch (Exception e) {
            return sequence;
        }
    }
}
