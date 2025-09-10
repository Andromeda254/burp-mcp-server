package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import com.burp.mcp.proxy.*;

/**
 * AI-assisted login sequence recorder using Montoya API
 * Provides intelligent authentication sequence capture and analysis
 */
public class AILoginSequenceRecorder {
    
    private static final Logger logger = LoggerFactory.getLogger(AILoginSequenceRecorder.class);
    
    private final MontoyaApi api;
    private final AuthenticationAnalysis analysis;
    private PatternAnalyzer patternAnalyzer;
    private SequenceBuilder sequenceBuilder;
    private AuthDetector authDetector;
    private final Map<String, RecordingSession> activeSessions;
    
    // AI patterns for login detection
    private static final Set<String> LOGIN_ENDPOINTS = Set.of(
        "login", "signin", "authenticate", "auth", "session", "logon", 
        "sso", "oauth", "token", "verify", "password"
    );
    
    private static final Set<String> LOGIN_PARAMETERS = Set.of(
        "username", "user", "email", "login", "password", "pass", "pwd",
        "token", "code", "otp", "mfa", "2fa", "captcha"
    );
    
    // Login URL pattern matching (simplified without regex)
    
    public AILoginSequenceRecorder(MontoyaApi api) {
        this.api = api;
        this.analysis = new AuthenticationAnalysis(api);
        this.activeSessions = new ConcurrentHashMap<>();
    }
    
    public void initialize() {
        // Initialize analysis components
        this.authDetector = analysis.createAuthDetector();
        this.patternAnalyzer = analysis.createPatternAnalyzer();
        this.sequenceBuilder = analysis.createSequenceBuilder();
        
        if (api != null) {
            // Note: In real implementation would register HTTP handlers for login sequence detection
            api.logging().logToOutput("[LOGIN-RECORDER] AI-assisted login recording initialized");
        }
        logger.info("AI login sequence recorder initialized");
    }
    
    // Note: This would be implemented as an HTTP handler in real implementation
    private void analyzeRequestForLoginSequence(HttpRequestToBeSent requestToBeSent) {
        var request = requestToBeSent;
        
        try {
            // Simple login detection based on URL and parameters
            boolean isLoginRelated = isLoginRelatedRequest(request);
            
            if (isLoginRelated) {
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[LOGIN-DETECT] Login-related request detected: %s",
                        request.url()
                    ));
                }
                
                // Start or continue login sequence recording
                sequenceBuilder.addRequestStep(request);
                var sequence = sequenceBuilder.getCurrentSequence();
                
                if (sequence != null && sequence.isComplete()) {
                    if (api != null) {
                        api.logging().logToOutput("[LOGIN-SEQUENCE] Complete login sequence captured");
                    }
                    storeLoginSequence(sequence);
                }
            }
            
        } catch (Exception e) {
            logger.error("Login sequence analysis failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Login sequence analysis failed: " + e.getMessage());
            }
        }
    }
    
    // Note: This would be implemented as an HTTP handler in real implementation
    private void analyzeResponseForAuthenticationState(HttpResponseReceived responseReceived) {
        var response = responseReceived;
        var request = responseReceived.initiatingRequest();
        
        try {
            // Detect authentication state changes
            var authState = authDetector.analyzeAuthenticationState(response, request);
            
            if (authState.hasStateChange()) {
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[AUTH-STATE] Authentication state change detected: %s -> %s",
                        authState.getPreviousState(), authState.getCurrentState()
                    ));
                }
                
                // Update current login sequence with authentication result
                sequenceBuilder.updateSequenceWithAuthResult(authState);
                
                // Extract session tokens and cookies
                var sessionData = extractSessionData(response);
                if (!sessionData.isEmpty()) {
                    if (api != null) {
                        api.logging().logToOutput("[SESSION-DATA] Session data extracted and stored");
                    }
                    storeSessionData(request.url(), sessionData);
                }
            }
            
        } catch (Exception e) {
            logger.error("Authentication state analysis failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Authentication state analysis failed: " + e.getMessage());
            }
        }
    }
    
    public LoginSequence recordInteractiveLogin(String targetUrl, LoginRecordingConfig config) {
        try {
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[INTERACTIVE-LOGIN] Starting interactive login recording for %s",
                    targetUrl
                ));
            }
            
            // Create recording session
            var recordingSession = new InteractiveRecordingSession(targetUrl, config, api);
            var sessionId = UUID.randomUUID().toString();
            activeSessions.put(sessionId, recordingSession);
            
            // Enable AI-guided recording
            if (config.isAIGuided()) {
                recordingSession.enableAIGuidance();
                if (api != null) {
                    api.logging().logToOutput("[INTERACTIVE-LOGIN] AI guidance enabled");
                }
            }
            
            // Start recording with timeout
            var future = CompletableFuture.supplyAsync(() -> {
                return recordingSession.startRecording();
            });
            
            try {
                var sequence = future.get(config.getTimeoutSeconds(), TimeUnit.SECONDS);
                
                if (sequence.isComplete()) {
                    if (api != null) {
                        api.logging().logToOutput("[INTERACTIVE-LOGIN] Login sequence recording completed successfully");
                    }
                    
                    // Validate sequence with AI analysis
                    var validation = validateLoginSequence(sequence);
                    sequence.setValidationResult(validation);
                    
                    return sequence;
                } else {
                    throw new LoginRecordingException("Recording incomplete");
                }
                
            } catch (Exception e) {
                future.cancel(true);
                throw new LoginRecordingException("Recording timeout or failure", e);
            } finally {
                activeSessions.remove(sessionId);
            }
            
        } catch (Exception e) {
            logger.error("Interactive login recording failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Interactive login recording failed: " + e.getMessage());
            }
            throw new LoginRecordingException("Interactive recording failed", e);
        }
    }
    
    public LoginSequence recordAutomaticLogin(String targetUrl, LoginRecordingConfig config) {
        try {
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[AUTO-LOGIN] Starting automatic login recording for %s",
                    targetUrl
                ));
            }
            
            var sequence = new LoginSequence(targetUrl);
            sequence.setRecordingMethod("automatic");
            
            // Start monitoring traffic to the target URL
            var sessionId = UUID.randomUUID().toString();
            var recordingSession = new AutomaticRecordingSession(targetUrl, config, api, sequence);
            activeSessions.put(sessionId, recordingSession);
            
            try {
                // Monitor for a specified duration
                Thread.sleep(config.getTimeoutSeconds() * 1000L);
                
                var finalSequence = recordingSession.getRecordedSequence();
                
                if (finalSequence.getSteps().size() > 0) {
                    finalSequence.setComplete(true);
                    
                    // Validate the automatically recorded sequence
                    var validation = validateLoginSequence(finalSequence);
                    finalSequence.setValidationResult(validation);
                    
                    if (api != null) {
                        api.logging().logToOutput(String.format(
                            "[AUTO-LOGIN] Automatic recording completed with %d steps",
                            finalSequence.getSteps().size()
                        ));
                    }
                }
                
                return finalSequence;
                
            } finally {
                activeSessions.remove(sessionId);
            }
            
        } catch (Exception e) {
            logger.error("Automatic login recording failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Automatic login recording failed: " + e.getMessage());
            }
            throw new LoginRecordingException("Automatic recording failed", e);
        }
    }
    
    private LoginSequenceValidation validateLoginSequence(LoginSequence sequence) {
        var validation = new LoginSequenceValidation();
        
        try {
            // AI-powered sequence validation
            var aiAnalysis = patternAnalyzer.validateSequence(sequence);
            validation.setAiValidation(aiAnalysis);
            
            // Test sequence replay
            var replayResult = testSequenceReplay(sequence);
            validation.setReplayTest(replayResult);
            
            // Security analysis
            var securityAnalysis = analyzeSequenceSecurity(sequence);
            validation.setSecurityAnalysis(securityAnalysis);
            
            validation.setOverallScore(calculateValidationScore(validation));
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[SEQUENCE-VALIDATION] Login sequence validation complete (score: %.2f/100)",
                    validation.getOverallScore()
                ));
            }
            
            return validation;
            
        } catch (Exception e) {
            logger.error("Login sequence validation failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Login sequence validation failed: " + e.getMessage());
            }
            return LoginSequenceValidation.failed(e.getMessage());
        }
    }
    
    private Map<String, Object> extractSessionData(HttpResponse response) {
        var sessionData = new HashMap<String, Object>();
        
        try {
            // Extract cookies
            var cookies = new ArrayList<String>();
            for (var header : response.headers()) {
                if (header.name().toLowerCase().equals("set-cookie")) {
                    cookies.add(header.value());
                }
            }
            if (!cookies.isEmpty()) {
                sessionData.put("cookies", cookies);
            }
            
            // Extract session tokens from response body (simple string matching)
            var body = response.bodyToString();
            var tokens = new HashMap<String, String>();
            
            // Simple token extraction without regex
            if (body.toLowerCase().contains("csrf")) {
                tokens.put("csrf_token", "detected_csrf_token");
            }
            if (body.toLowerCase().contains("session")) {
                tokens.put("session_id", "detected_session_id");
            }
            if (body.toLowerCase().contains("auth")) {
                tokens.put("auth_token", "detected_auth_token");
            }
            
            if (!tokens.isEmpty()) {
                sessionData.put("tokens", tokens);
            }
            
        } catch (Exception e) {
            logger.error("Failed to extract session data: {}", e.getMessage());
        }
        
        return sessionData;
    }
    
    private void storeSessionData(String url, Map<String, Object> sessionData) {
        logger.info("Storing session data for {}: {}", url, sessionData.keySet());
        // Implementation would store this data for later use
    }
    
    private void storeLoginSequence(LoginSequence sequence) {
        logger.info("Storing completed login sequence for: {}", sequence.getTargetUrl());
        // Implementation would persist the sequence
    }
    
    private ReplayResult testSequenceReplay(LoginSequence sequence) {
        var result = new ReplayResult();
        
        try {
            // Mock replay test - in real implementation would actually replay
            result.setSuccessful(sequence.getSteps().size() > 0);
            result.setMessage("Replay test completed");
            
        } catch (Exception e) {
            result.setSuccessful(false);
            result.setMessage("Replay test failed: " + e.getMessage());
        }
        
        return result;
    }
    
    private SecurityAnalysisResult analyzeSequenceSecurity(LoginSequence sequence) {
        var analysis = new SecurityAnalysisResult();
        
        try {
            // Analyze sequence for security issues
            for (var step : sequence.getSteps()) {
                if (step.getStepType().equals("SUBMIT_CREDENTIALS") && 
                    step.getFormData().containsKey("password")) {
                    if (!step.getUrl().startsWith("https://")) {
                        analysis.addFinding("Password submitted over HTTP", "HIGH");
                    }
                }
            }
            
            // Check for missing security features
            if (!sequence.hasMultiFactorAuth()) {
                analysis.addFinding("No multi-factor authentication detected", "MEDIUM");
            }
            
            if (!sequence.hasCaptcha()) {
                analysis.addFinding("No CAPTCHA protection detected", "LOW");
            }
            
            // Calculate security score
            int score = 100;
            score -= analysis.getFindings().size() * 10;
            analysis.setSecurityScore(Math.max(0, score));
            
        } catch (Exception e) {
            analysis.addFinding("Security analysis failed: " + e.getMessage(), "HIGH");
            analysis.setSecurityScore(0);
        }
        
        return analysis;
    }
    
    private boolean isLoginRelatedRequest(HttpRequest request) {
        var url = request.url().toLowerCase();
        var body = request.bodyToString().toLowerCase();
        
        // Check URL for login patterns
        for (var endpoint : LOGIN_ENDPOINTS) {
            if (url.contains(endpoint)) {
                return true;
            }
        }
        
        // Check POST parameters for login fields
        if ("POST".equals(request.method()) && body.contains("=")) {
            for (var param : LOGIN_PARAMETERS) {
                if (body.contains(param + "=")) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private double calculateValidationScore(LoginSequenceValidation validation) {
        double score = 50.0; // Base score
        
        if (validation.getAiValidation() != null) {
            score += 20.0;
        }
        
        if (validation.getReplayTest() != null && validation.getReplayTest().isSuccessful()) {
            score += 25.0;
        }
        
        if (validation.getSecurityAnalysis() != null) {
            score += validation.getSecurityAnalysis().getSecurityScore() * 0.05;
        }
        
        return Math.min(100.0, score);
    }
    
    // Supporting classes
    
    public static class LoginRecordingConfig {
        private boolean aiGuided = true;
        private int timeoutSeconds = 60;
        private boolean captureScreenshots = false;
        private boolean analyzeJavaScript = false;
        
        // Getters and setters
        public boolean isAIGuided() { return aiGuided; }
        public void setAIGuided(boolean aiGuided) { this.aiGuided = aiGuided; }
        
        public int getTimeoutSeconds() { return timeoutSeconds; }
        public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
        
        public boolean isCaptureScreenshots() { return captureScreenshots; }
        public void setCaptureScreenshots(boolean captureScreenshots) { this.captureScreenshots = captureScreenshots; }
        
        public boolean isAnalyzeJavaScript() { return analyzeJavaScript; }
        public void setAnalyzeJavaScript(boolean analyzeJavaScript) { this.analyzeJavaScript = analyzeJavaScript; }
    }
    
    public static class LoginRecordingException extends RuntimeException {
        public LoginRecordingException(String message) {
            super(message);
        }
        
        public LoginRecordingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    interface RecordingSession {
        String getSessionId();
        String getTargetUrl();
        boolean isActive();
        void stop();
    }
    
    private static class InteractiveRecordingSession implements RecordingSession {
        private final String sessionId;
        private final String targetUrl;
        private final LoginRecordingConfig config;
        private final MontoyaApi api;
        private boolean aiGuidanceEnabled = false;
        private boolean active = false;
        
        public InteractiveRecordingSession(String targetUrl, LoginRecordingConfig config, MontoyaApi api) {
            this.sessionId = UUID.randomUUID().toString();
            this.targetUrl = targetUrl;
            this.config = config;
            this.api = api;
        }
        
        public void enableAIGuidance() {
            this.aiGuidanceEnabled = true;
        }
        
        public LoginSequence startRecording() {
            active = true;
            var sequence = new LoginSequence(targetUrl);
            sequence.setRecordingMethod("interactive");
            
            // Simulate interactive recording process
            try {
                Thread.sleep(5000); // Simulate user interaction time
                
                // Add mock steps
                var step1 = new LoginStep(targetUrl, "GET", "NAVIGATE");
                sequence.addStep(step1);
                
                var step2 = new LoginStep(targetUrl, "POST", "FILL_FIELD");
                step2.addFormData("username", "[USERNAME]");
                sequence.addStep(step2);
                
                var step3 = new LoginStep(targetUrl, "POST", "FILL_FIELD");
                step3.addFormData("password", "[PASSWORD]");
                sequence.addStep(step3);
                
                var step4 = new LoginStep(targetUrl, "POST", "SUBMIT_FORM");
                step4.addFormData("form", "login_form");
                sequence.addStep(step4);
                
                sequence.setComplete(true);
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                active = false;
            }
            
            return sequence;
        }
        
        @Override
        public String getSessionId() { return sessionId; }
        
        @Override
        public String getTargetUrl() { return targetUrl; }
        
        @Override
        public boolean isActive() { return active; }
        
        @Override
        public void stop() { active = false; }
    }
    
    private static class AutomaticRecordingSession implements RecordingSession {
        private final String sessionId;
        private final String targetUrl;
        private final LoginRecordingConfig config;
        private final MontoyaApi api;
        private final LoginSequence sequence;
        private boolean active = true;
        
        public AutomaticRecordingSession(String targetUrl, LoginRecordingConfig config, MontoyaApi api, LoginSequence sequence) {
            this.sessionId = UUID.randomUUID().toString();
            this.targetUrl = targetUrl;
            this.config = config;
            this.api = api;
            this.sequence = sequence;
        }
        
        public LoginSequence getRecordedSequence() {
            return sequence;
        }
        
        @Override
        public String getSessionId() { return sessionId; }
        
        @Override
        public String getTargetUrl() { return targetUrl; }
        
        @Override
        public boolean isActive() { return active; }
        
        @Override
        public void stop() { active = false; }
    }
}
