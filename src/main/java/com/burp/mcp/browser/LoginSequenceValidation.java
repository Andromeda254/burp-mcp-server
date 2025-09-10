package com.burp.mcp.browser;

import java.util.*;

/**
 * Validation results for login sequences
 */
public class LoginSequenceValidation {
    
    private double overallScore = 0.0;
    private boolean successful = false;
    private String message;
    private Map<String, Object> aiValidation;
    private ReplayResult replayTest;
    private SecurityAnalysisResult securityAnalysis;
    private final List<String> warnings = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    
    public static LoginSequenceValidation failed(String reason) {
        var validation = new LoginSequenceValidation();
        validation.successful = false;
        validation.message = reason;
        validation.overallScore = 0.0;
        return validation;
    }
    
    // Getters and Setters
    public double getOverallScore() { return overallScore; }
    public void setOverallScore(double score) { this.overallScore = score; }
    
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public Map<String, Object> getAiValidation() { return aiValidation; }
    public void setAiValidation(Map<String, Object> aiValidation) { this.aiValidation = aiValidation; }
    
    public ReplayResult getReplayTest() { return replayTest; }
    public void setReplayTest(ReplayResult replayTest) { this.replayTest = replayTest; }
    
    public SecurityAnalysisResult getSecurityAnalysis() { return securityAnalysis; }
    public void setSecurityAnalysis(SecurityAnalysisResult securityAnalysis) { this.securityAnalysis = securityAnalysis; }
    
    public List<String> getWarnings() { return new ArrayList<>(warnings); }
    public void addWarning(String warning) { warnings.add(warning); }
    
    public List<String> getErrors() { return new ArrayList<>(errors); }
    public void addError(String error) { errors.add(error); }
}

/**
 * Results from replaying a login sequence
 */
class ReplayResult {
    private boolean successful = false;
    private String message;
    private long replayTime;
    private Map<String, Object> metrics;
    
    public boolean isSuccessful() { return successful; }
    public void setSuccessful(boolean successful) { this.successful = successful; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public long getReplayTime() { return replayTime; }
    public void setReplayTime(long replayTime) { this.replayTime = replayTime; }
    
    public Map<String, Object> getMetrics() { return metrics; }
    public void setMetrics(Map<String, Object> metrics) { this.metrics = metrics; }
}

/**
 * Security analysis results for login sequences
 */
class SecurityAnalysisResult {
    private int securityScore = 50;
    private final List<String> findings = new ArrayList<>();
    private final Map<String, String> recommendations = new HashMap<>();
    
    public int getSecurityScore() { return securityScore; }
    public void setSecurityScore(int score) { this.securityScore = score; }
    
    public List<String> getFindings() { return new ArrayList<>(findings); }
    public void addFinding(String finding, String level) { 
        findings.add(String.format("[%s] %s", level, finding));
    }
    
    public Map<String, String> getRecommendations() { return new HashMap<>(recommendations); }
    public void addRecommendation(String category, String recommendation) {
        recommendations.put(category, recommendation);
    }
}
