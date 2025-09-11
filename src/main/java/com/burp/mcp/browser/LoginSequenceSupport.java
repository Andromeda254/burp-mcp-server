package com.burp.mcp.browser;

import org.openqa.selenium.WebElement;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Supporting classes for enhanced login sequence recording with visual verification
 */
public class LoginSequenceSupport {
    
    // This class serves as a container for related classes
    private LoginSequenceSupport() {
        // Utility class - no instantiation
    }
    
    /**
     * Represents login form detection results
     */
    public static class LoginFormDetection {
    private WebElement form;
    private String formSelector;
    private WebElement usernameField;
    private String usernameSelector;
    private WebElement passwordField;
    private String passwordSelector;
    private WebElement submitButton;
    private String submitSelector;
    private double confidenceScore;
    private Map<String, Object> metadata;
    
    public LoginFormDetection() {
        this.metadata = new HashMap<>();
    }
    
    // Getters and setters
    public WebElement getForm() { return form; }
    public void setForm(WebElement form) { this.form = form; }
    
    public String getFormSelector() { return formSelector; }
    public void setFormSelector(String formSelector) { this.formSelector = formSelector; }
    
    public WebElement getUsernameField() { return usernameField; }
    public void setUsernameField(WebElement usernameField) { this.usernameField = usernameField; }
    
    public String getUsernameSelector() { return usernameSelector; }
    public void setUsernameSelector(String usernameSelector) { this.usernameSelector = usernameSelector; }
    
    public WebElement getPasswordField() { return passwordField; }
    public void setPasswordField(WebElement passwordField) { this.passwordField = passwordField; }
    
    public String getPasswordSelector() { return passwordSelector; }
    public void setPasswordSelector(String passwordSelector) { this.passwordSelector = passwordSelector; }
    
    public WebElement getSubmitButton() { return submitButton; }
    public void setSubmitButton(WebElement submitButton) { this.submitButton = submitButton; }
    
    public String getSubmitSelector() { return submitSelector; }
    public void setSubmitSelector(String submitSelector) { this.submitSelector = submitSelector; }
    
    public double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(double confidenceScore) { this.confidenceScore = confidenceScore; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

    /**
     * Represents login sequence replay results with visual verification
     */
    public static class LoginSequenceReplay {
    private final LoginSequence originalSequence;
    private final String replaySessionId;
    private final long startTime;
    private long completedAt;
    private boolean overallSuccess = true;
    private String failureReason;
    private List<LoginStepReplayResult> stepResults;
    private AuthenticationState finalAuthState;
    private Map<String, Object> visualComparison;
    private Map<String, Object> metadata;
    
    public LoginSequenceReplay(LoginSequence originalSequence, String replaySessionId) {
        this.originalSequence = originalSequence;
        this.replaySessionId = replaySessionId;
        this.startTime = System.currentTimeMillis();
        this.stepResults = new ArrayList<>();
        this.metadata = new HashMap<>();
    }
    
    public void addStepResult(LoginStepReplayResult result) {
        stepResults.add(result);
    }
    
    // Getters and setters
    public LoginSequence getOriginalSequence() { return originalSequence; }
    public String getReplaySessionId() { return replaySessionId; }
    public long getStartTime() { return startTime; }
    
    public long getCompletedAt() { return completedAt; }
    public void setCompletedAt(long completedAt) { this.completedAt = completedAt; }
    
    public boolean isOverallSuccess() { return overallSuccess; }
    public void setOverallSuccess(boolean overallSuccess) { this.overallSuccess = overallSuccess; }
    
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    
    public List<LoginStepReplayResult> getStepResults() { return new ArrayList<>(stepResults); }
    
    public AuthenticationState getFinalAuthState() { return finalAuthState; }
    public void setFinalAuthState(AuthenticationState finalAuthState) { this.finalAuthState = finalAuthState; }
    
    public Map<String, Object> getVisualComparison() { return visualComparison; }
    public void setVisualComparison(Map<String, Object> visualComparison) { this.visualComparison = visualComparison; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public long getDuration() {
        return completedAt > 0 ? completedAt - startTime : System.currentTimeMillis() - startTime;
    }
}

    /**
     * Represents individual step replay result
     */
    public static class LoginStepReplayResult {
    private final LoginStep originalStep;
    private boolean successful;
    private String message;
    private long timestamp;
    private Map<String, Object> metadata;
    
    public LoginStepReplayResult(LoginStep originalStep) {
        this.originalStep = originalStep;
        this.timestamp = System.currentTimeMillis();
        this.metadata = new HashMap<>();
    }
    
    // Getters and setters
    public LoginStep getOriginalStep() { return originalStep; }
    
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

    /**
     * Enhanced authentication state with additional context
     */
    public static class AuthenticationState {
    private String currentState = "PENDING";
    private String previousState = "UNKNOWN";
    private boolean stateChange = false;
    private long timestamp = System.currentTimeMillis();
    private String currentUrl;
    private String pageTitle;
    private Map<String, Object> indicators;
    
    public AuthenticationState() {
        this.indicators = new HashMap<>();
    }
    
    // Getters and setters
    public String getCurrentState() { return currentState; }
    public void setCurrentState(String state) { 
        this.previousState = this.currentState;
        this.currentState = state; 
    }
    
    public String getPreviousState() { return previousState; }
    
    public boolean hasStateChange() { return stateChange; }
    public void setStateChange(boolean change) { this.stateChange = change; }
    
    public long getTimestamp() { return timestamp; }
    
    public String getCurrentUrl() { return currentUrl; }
    public void setCurrentUrl(String currentUrl) { this.currentUrl = currentUrl; }
    
    public String getPageTitle() { return pageTitle; }
    public void setPageTitle(String pageTitle) { this.pageTitle = pageTitle; }
    
    public Map<String, Object> getIndicators() { return indicators; }
    public void setIndicators(Map<String, Object> indicators) { this.indicators = indicators; }
}

    /**
     * Enhanced login sequence validation with visual verification
     */
    public static class LoginSequenceValidation {
    private Map<String, Object> aiValidation;
    private Map<String, Object> visualValidation;
    private SecurityAnalysisResult securityAnalysis;
    private double overallScore;
    private boolean passed;
    private String failureReason;
    private long validationTimestamp;
    private ReplayResult replayTest;
    
    public LoginSequenceValidation() {
        this.validationTimestamp = System.currentTimeMillis();
    }
    
    public static LoginSequenceValidation failed(String reason) {
        var validation = new LoginSequenceValidation();
        validation.setPassed(false);
        validation.setFailureReason(reason);
        validation.setOverallScore(0.0);
        return validation;
    }
    
    // Getters and setters
    public Map<String, Object> getAiValidation() { return aiValidation; }
    public void setAiValidation(Map<String, Object> aiValidation) { this.aiValidation = aiValidation; }
    
    public Map<String, Object> getVisualValidation() { return visualValidation; }
    public void setVisualValidation(Map<String, Object> visualValidation) { this.visualValidation = visualValidation; }
    
    public SecurityAnalysisResult getSecurityAnalysis() { return securityAnalysis; }
    public void setSecurityAnalysis(SecurityAnalysisResult securityAnalysis) { this.securityAnalysis = securityAnalysis; }
    
    public double getOverallScore() { return overallScore; }
    public void setOverallScore(double overallScore) { 
        this.overallScore = overallScore;
        this.passed = overallScore >= 70.0; // 70% threshold for passing
    }
    
    public boolean isPassed() { return passed; }
    public void setPassed(boolean passed) { this.passed = passed; }
    
    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    
    public long getValidationTimestamp() { return validationTimestamp; }
    
    public ReplayResult getReplayTest() { return replayTest; }
    public void setReplayTest(ReplayResult replayTest) { this.replayTest = replayTest; }
}

    /**
     * Enhanced security analysis result
     */
    public static class SecurityAnalysisResult {
    private List<SecurityFinding> findings;
    private int securityScore;
    private Map<String, Object> metrics;
    private long analysisTimestamp;
    
    public SecurityAnalysisResult() {
        this.findings = new ArrayList<>();
        this.metrics = new HashMap<>();
        this.analysisTimestamp = System.currentTimeMillis();
    }
    
    public void addFinding(String description, String severity) {
        findings.add(new SecurityFinding(description, severity));
    }
    
    // Getters and setters
    public List<SecurityFinding> getFindings() { return new ArrayList<>(findings); }
    public void setFindings(List<SecurityFinding> findings) { this.findings = findings; }
    
    public int getSecurityScore() { return securityScore; }
    public void setSecurityScore(int securityScore) { this.securityScore = securityScore; }
    
    public Map<String, Object> getMetrics() { return metrics; }
    public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
    
    public long getAnalysisTimestamp() { return analysisTimestamp; }
    
    public static class SecurityFinding {
        private final String description;
        private final String severity;
        private final long timestamp;
        
        public SecurityFinding(String description, String severity) {
            this.description = description;
            this.severity = severity;
            this.timestamp = System.currentTimeMillis();
        }
        
        public String getDescription() { return description; }
        public String getSeverity() { return severity; }
        public long getTimestamp() { return timestamp; }
    }
}

    /**
     * Replay test result
     */
    public static class ReplayResult {
    private boolean successful;
    private String message;
    private long timestamp;
    private Map<String, Object> details;
    
    public ReplayResult() {
        this.timestamp = System.currentTimeMillis();
        this.details = new HashMap<>();
    }
    
    // Getters and setters
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public long getTimestamp() { return timestamp; }
    
    public Map<String, Object> getDetails() { return details; }
    public void setDetails(Map<String, Object> details) { this.details = details; }
}

    /**
     * Recording session interface
     */
    public interface RecordingSession {
        String getSessionId();
        String getTargetUrl();
        boolean isActive();
        void stop();
    }
    
    /**
     * Login sequence class
     */
    public static class LoginSequence {
        private String targetUrl;
        private List<LoginStep> steps;
        private Map<String, Object> metadata;
        private boolean complete;
        private long timestamp;
        
        public LoginSequence(String targetUrl) {
            this.targetUrl = targetUrl;
            this.steps = new ArrayList<>();
            this.metadata = new HashMap<>();
            this.timestamp = System.currentTimeMillis();
        }
        
        public void addStep(LoginStep step) {
            steps.add(step);
        }
        
        // Getters and setters
        public String getTargetUrl() { return targetUrl; }
        public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }
        
        public List<LoginStep> getSteps() { return new ArrayList<>(steps); }
        public void setSteps(List<LoginStep> steps) { this.steps = steps; }
        
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
        
        public boolean isComplete() { return complete; }
        public void setComplete(boolean complete) { this.complete = complete; }
        
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        
        public void addMetadata(String key, Object value) {
            metadata.put(key, value);
        }
        
        public void setRecordingMethod(String recordingMethod) {
            addMetadata("recordingMethod", recordingMethod);
        }
        
        public void setValidationResult(LoginSequenceValidation validation) {
            addMetadata("validationResult", validation);
        }
        
        public boolean hasMultiFactorAuth() {
            return (Boolean) metadata.getOrDefault("hasMultiFactorAuth", false);
        }
        
        public boolean hasCaptcha() {
            return (Boolean) metadata.getOrDefault("hasCaptcha", false);
        }
    }
    
    /**
     * Login step class
     */
    public static class LoginStep {
        private String url;
        private String httpMethod;
        private String stepType;
        private Map<String, String> formData;
        private long timestamp;
        
        public LoginStep(String url, String httpMethod, String stepType) {
            this.url = url;
            this.httpMethod = httpMethod;
            this.stepType = stepType;
            this.formData = new HashMap<>();
            this.timestamp = System.currentTimeMillis();
        }
        
        public void addFormData(String key, String value) {
            formData.put(key, value);
        }
        
        public void addFormData(String key, Object value) {
            formData.put(key, String.valueOf(value));
        }
        
        // Getters and setters
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        
        public String getHttpMethod() { return httpMethod; }
        public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }
        
        public String getStepType() { return stepType; }
        public void setStepType(String stepType) { this.stepType = stepType; }
        
        public Map<String, String> getFormData() { return new HashMap<>(formData); }
        public void setFormData(Map<String, String> formData) { this.formData = formData; }
        
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        
        private boolean successful = false;
        
        public boolean isSuccessful() { return successful; }
        public void setSuccessful(boolean successful) { this.successful = successful; }
    }
    
    /**
     * Step replay result alias for compatibility
     */
    public static class StepReplayResult extends LoginStepReplayResult {
        public StepReplayResult(LoginStep originalStep) {
            super(originalStep);
        }
    }
}
