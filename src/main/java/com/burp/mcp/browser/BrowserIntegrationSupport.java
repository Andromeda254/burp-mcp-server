package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.burp.mcp.proxy.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Supporting classes for browser integration functionality
 */

/**
 * AI-powered login pattern analyzer
 */
class LoginPatternAnalyzer {
    private final MontoyaApi api;
    
    // Login detection patterns
    private static final Set<String> LOGIN_KEYWORDS = Set.of(
        "login", "signin", "authenticate", "auth", "session", "sso", "oauth", "logon"
    );
    
    private static final Set<String> FORM_FIELD_PATTERNS = Set.of(
        "username", "user", "email", "login", "password", "pass", "pwd", "token"
    );
    
    private static final Pattern LOGIN_URL_PATTERN = Pattern.compile(
        "(?i)/(login|signin|auth|session|sso|oauth|authenticate)", Pattern.CASE_INSENSITIVE
    );
    
    public LoginPatternAnalyzer(MontoyaApi api) {
        this.api = api;
    }
    
    public LoginAnalysisResult analyzeRequest(HttpRequest request) {
        var result = new LoginAnalysisResult();
        var confidence = 0.0;
        var reasons = new ArrayList<String>();
        
        try {
            var url = request.url().toLowerCase();
            var method = request.method();
            var body = request.body() != null ? request.bodyToString() : "";
            
            // Check URL patterns
            if (LOGIN_URL_PATTERN.matcher(url).find()) {
                confidence += 0.4;
                reasons.add("Login URL pattern detected");
            }
            
            // Check for login keywords in URL
            for (var keyword : LOGIN_KEYWORDS) {
                if (url.contains(keyword)) {
                    confidence += 0.2;
                    reasons.add("Login keyword in URL: " + keyword);
                    break;
                }
            }
            
            // Check POST requests with form data
            if ("POST".equalsIgnoreCase(method) && !body.isEmpty()) {
                confidence += 0.2;
                reasons.add("POST request with body data");
                
                // Check for login form fields
                for (var field : FORM_FIELD_PATTERNS) {
                    if (body.toLowerCase().contains(field)) {
                        confidence += 0.1;
                        reasons.add("Login form field detected: " + field);
                    }
                }
            }
            
            // Check headers for authentication
            for (var header : request.headers()) {
                var name = header.name().toLowerCase();
                if (name.contains("auth") || name.contains("token")) {
                    confidence += 0.1;
                    reasons.add("Authentication header detected: " + name);
                }
            }
            
            result.setLoginRelated(confidence > 0.3);
            result.setConfidence(Math.min(confidence, 1.0));
            result.setReasons(reasons);
            
        } catch (Exception e) {
            result.setError("Analysis failed: " + e.getMessage());
        }
        
        return result;
    }
    
    public AIValidationResult validateSequence(LoginSequence sequence) {
        var result = new AIValidationResult();
        
        try {
            var confidence = 0.0;
            var issues = new ArrayList<String>();
            
            // Check sequence completeness
            if (sequence.getSteps().size() < 2) {
                issues.add("Sequence too short");
                confidence -= 0.2;
            }
            
            // Check for essential steps
            boolean hasFormSubmission = false;
            boolean hasCredentialInput = false;
            
            for (var step : sequence.getSteps()) {
                if ("submit_form".equals(step.getAction())) {
                    hasFormSubmission = true;
                    confidence += 0.3;
                }
                if ("fill_field".equals(step.getAction()) && 
                    (step.getData().containsKey("password") || step.getData().containsKey("username"))) {
                    hasCredentialInput = true;
                    confidence += 0.3;
                }
            }
            
            if (!hasFormSubmission) {
                issues.add("No form submission detected");
            }
            
            if (!hasCredentialInput) {
                issues.add("No credential input detected");
            }
            
            result.setConfidence(Math.max(0.0, Math.min(100.0, confidence * 100)));
            result.setResult(confidence > 0.5 ? "VALID" : "INVALID");
            result.setIssues(issues);
            
        } catch (Exception e) {
            result.setResult("ERROR");
            result.setIssues(List.of("Validation failed: " + e.getMessage()));
        }
        
        return result;
    }
}

/**
 * Sequence builder for constructing login sequences
 */
class SequenceBuilder {
    private final MontoyaApi api;
    private final Map<String, LoginSequence> activeSequences = new ConcurrentHashMap<>();
    
    public SequenceBuilder(MontoyaApi api) {
        this.api = api;
    }
    
    public LoginSequence processLoginRequest(HttpRequest request, LoginAnalysisResult analysis) {
        var sequenceId = extractSequenceId(request);
        var sequence = activeSequences.computeIfAbsent(sequenceId, 
            id -> new LoginSequence(request.url()));
        
        // Add step to sequence
        var step = createLoginStep(request, analysis);
        sequence.addStep(step);
        
        // Check if sequence is complete
        if (isSequenceComplete(sequence)) {
            sequence.setComplete(true);
            activeSequences.remove(sequenceId);
        }
        
        return sequence;
    }
    
    public void updateSequenceWithAuthResult(AuthenticationState authState) {
        // Update sequences with authentication results
        for (var sequence : activeSequences.values()) {
            if (!sequence.isComplete()) {
                sequence.setAuthenticationResult(authState.getCurrentState());
            }
        }
    }
    
    private String extractSequenceId(HttpRequest request) {
        // Generate sequence ID based on domain
        try {
            var url = new java.net.URL(request.url());
            return url.getHost();
        } catch (Exception e) {
            return "unknown";
        }
    }
    
    private LoginStep createLoginStep(HttpRequest request, LoginAnalysisResult analysis) {
        var action = determineAction(request, analysis);
        var data = extractStepData(request);
        return new LoginStep(action, request.url(), data);
    }
    
    private String determineAction(HttpRequest request, LoginAnalysisResult analysis) {
        if ("GET".equalsIgnoreCase(request.method())) {
            return "navigate";
        } else if ("POST".equalsIgnoreCase(request.method()) && request.body() != null) {
            return "submit_form";
        } else {
            return "request";
        }
    }
    
    private Map<String, Object> extractStepData(HttpRequest request) {
        var data = new HashMap<String, Object>();
        
        if (request.body() != null) {
            var body = request.bodyToString();
            // Parse form data or JSON data
            if (body.contains("=") && body.contains("&")) {
                // Form data
                var pairs = body.split("&");
                for (var pair : pairs) {
                    var keyValue = pair.split("=", 2);
                    if (keyValue.length == 2) {
                        data.put(keyValue[0], keyValue[1]);
                    }
                }
            }
        }
        
        return data;
    }
    
    private boolean isSequenceComplete(LoginSequence sequence) {
        // Simple heuristic: sequence is complete if it has navigation + form submission
        var actions = sequence.getSteps().stream()
            .map(LoginStep::getAction)
            .collect(java.util.stream.Collectors.toSet());
        
        return actions.contains("navigate") && actions.contains("submit_form");
    }
}

/**
 * Authentication state detector
 */
class AuthenticationDetector {
    private final MontoyaApi api;
    private final Map<String, String> lastStates = new ConcurrentHashMap<>();
    
    public AuthenticationDetector(MontoyaApi api) {
        this.api = api;
    }
    
    public AuthenticationState analyzeAuthenticationState(HttpResponse response, HttpRequest request) {
        var state = new AuthenticationState();
        var currentState = determineAuthState(response, request);
        var url = request.url();
        
        var previousState = lastStates.get(url);
        lastStates.put(url, currentState);
        
        state.setPreviousState(previousState != null ? previousState : "UNKNOWN");
        state.setCurrentState(currentState);
        state.setStateChange(!currentState.equals(previousState));
        
        return state;
    }
    
    private String determineAuthState(HttpResponse response, HttpRequest request) {
        var statusCode = response.statusCode();
        var body = response.bodyToString().toLowerCase();
        var url = request.url().toLowerCase();
        
        // Check for authentication success indicators
        if (statusCode == 200 && 
            (body.contains("dashboard") || body.contains("welcome") || body.contains("profile"))) {
            return "AUTHENTICATED";
        }
        
        // Check for authentication failure indicators
        if (statusCode == 401 || statusCode == 403 ||
            body.contains("invalid") || body.contains("failed") || body.contains("error")) {
            return "AUTHENTICATION_FAILED";
        }
        
        // Check for logout
        if (url.contains("logout") || body.contains("logged out")) {
            return "LOGGED_OUT";
        }
        
        // Check for login page
        if (url.contains("login") || body.contains("username") || body.contains("password")) {
            return "LOGIN_PAGE";
        }
        
        return "UNAUTHENTICATED";
    }
}

/**
 * Data classes for browser integration
 */

class LoginAnalysisResult {
    private boolean loginRelated = false;
    private double confidence = 0.0;
    private List<String> reasons = new ArrayList<>();
    private String error;
    
    // Getters and setters
    public boolean isLoginRelated() { return loginRelated; }
    public void setLoginRelated(boolean loginRelated) { this.loginRelated = loginRelated; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public List<String> getReasons() { return new ArrayList<>(reasons); }
    public void setReasons(List<String> reasons) { this.reasons = new ArrayList<>(reasons); }
    
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
}

class LoginSequence {
    private final String targetUrl;
    private final List<LoginStep> steps = new ArrayList<>();
    private final List<String> successIndicators = new ArrayList<>();
    private final Map<String, String> sessionTokens = new HashMap<>();
    private String recordingMethod = "unknown";
    private String authenticationType = "form_based";
    private boolean complete = false;
    private boolean hasMultiFactorAuth = false;
    private boolean hasCaptcha = false;
    private String authenticationResult = "PENDING";
    private LoginSequenceValidation validationResult;
    
    public LoginSequence(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    public void addStep(LoginStep step) {
        steps.add(step);
    }
    
    public double getValidationScore() {
        return validationResult != null ? validationResult.getOverallScore() : 0.0;
    }
    
    public boolean hasValidation() {
        return validationResult != null;
    }
    
    public String getStatus() {
        if (complete) {
            return validationResult != null ? "VALIDATED" : "COMPLETED";
        }
        return "IN_PROGRESS";
    }
    
    // Getters and setters
    public String getTargetUrl() { return targetUrl; }
    public List<LoginStep> getSteps() { return new ArrayList<>(steps); }
    public String getRecordingMethod() { return recordingMethod; }
    public void setRecordingMethod(String recordingMethod) { this.recordingMethod = recordingMethod; }
    
    public String getAuthenticationType() { return authenticationType; }
    public void setAuthenticationType(String authenticationType) { this.authenticationType = authenticationType; }
    
    public boolean isComplete() { return complete; }
    public void setComplete(boolean complete) { this.complete = complete; }
    
    public boolean hasMultiFactorAuth() { return hasMultiFactorAuth; }
    public void setHasMultiFactorAuth(boolean hasMultiFactorAuth) { this.hasMultiFactorAuth = hasMultiFactorAuth; }
    
    public boolean hasCaptcha() { return hasCaptcha; }
    public void setHasCaptcha(boolean hasCaptcha) { this.hasCaptcha = hasCaptcha; }
    
    public String getAuthenticationResult() { return authenticationResult; }
    public void setAuthenticationResult(String authenticationResult) { this.authenticationResult = authenticationResult; }
    
    public LoginSequenceValidation getValidationResult() { return validationResult; }
    public void setValidationResult(LoginSequenceValidation validationResult) { this.validationResult = validationResult; }
    
    public List<String> getSuccessIndicators() { return new ArrayList<>(successIndicators); }
    public Map<String, String> getSessionTokens() { return new HashMap<>(sessionTokens); }
}

class LoginStep {
    private final String action;
    private final String url;
    private final Map<String, Object> data;
    private final long timestamp = System.currentTimeMillis();
    
    public LoginStep(String action, String url, Map<String, Object> data) {
        this.action = action;
        this.url = url;
        this.data = new HashMap<>(data);
    }
    
    public String getTarget() {
        if ("fill_field".equals(action)) {
            return "Field: " + data.get("field");
        } else if ("submit_form".equals(action)) {
            return "Form: " + data.get("form");
        } else {
            return url;
        }
    }
    
    // Getters
    public String getAction() { return action; }
    public String getUrl() { return url; }
    public Map<String, Object> getData() { return new HashMap<>(data); }
    public long getTimestamp() { return timestamp; }
}

class LoginSequenceValidation {
    private AIValidationResult aiValidation;
    private ReplayResult replayTest;
    private SecurityAnalysis securityAnalysis;
    private double overallScore = 0.0;
    private boolean failed = false;
    private String failureReason;
    
    public static LoginSequenceValidation failed(String reason) {
        var validation = new LoginSequenceValidation();
        validation.failed = true;
        validation.failureReason = reason;
        return validation;
    }
    
    // Getters and setters
    public AIValidationResult getAiValidation() { return aiValidation; }
    public void setAiValidation(AIValidationResult aiValidation) { this.aiValidation = aiValidation; }
    
    public ReplayResult getReplayTest() { return replayTest; }
    public void setReplayTest(ReplayResult replayTest) { this.replayTest = replayTest; }
    
    public SecurityAnalysis getSecurityAnalysis() { return securityAnalysis; }
    public void setSecurityAnalysis(SecurityAnalysis securityAnalysis) { this.securityAnalysis = securityAnalysis; }
    
    public double getOverallScore() { return overallScore; }
    public void setOverallScore(double overallScore) { this.overallScore = overallScore; }
    
    public boolean isFailed() { return failed; }
    public String getFailureReason() { return failureReason; }
}

class AIValidationResult {
    private double confidence = 0.0;
    private String result = "UNKNOWN";
    private List<String> issues = new ArrayList<>();
    
    // Getters and setters
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }
    
    public List<String> getIssues() { return new ArrayList<>(issues); }
    public void setIssues(List<String> issues) { this.issues = new ArrayList<>(issues); }
}

class ReplayResult {
    private boolean successful = false;
    private String message = "";
    
    // Getters and setters
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}

class AuthenticationState {
    private String previousState = "UNKNOWN";
    private String currentState = "UNKNOWN";
    private boolean stateChange = false;
    
    public boolean hasStateChange() { return stateChange; }
    
    // Getters and setters
    public String getPreviousState() { return previousState; }
    public void setPreviousState(String previousState) { this.previousState = previousState; }
    
    public String getCurrentState() { return currentState; }
    public void setCurrentState(String currentState) { this.currentState = currentState; }
    
    public boolean isStateChange() { return stateChange; }
    public void setStateChange(boolean stateChange) { this.stateChange = stateChange; }
}
