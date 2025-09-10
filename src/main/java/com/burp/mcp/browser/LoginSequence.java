package com.burp.mcp.browser;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a complete login sequence with steps and validation
 */
public class LoginSequence {
    
    private final String targetUrl;
    private final String sequenceId;
    private final List<LoginStep> steps;
    private final Map<String, Object> metadata;
    private boolean complete = false;
    private String recordingMethod;
    private LoginSequenceValidation validationResult;
    private long startTime;
    private long endTime;
    
    public LoginSequence(String targetUrl) {
        this.targetUrl = targetUrl;
        this.sequenceId = UUID.randomUUID().toString();
        this.steps = new ArrayList<>();
        this.metadata = new ConcurrentHashMap<>();
        this.startTime = System.currentTimeMillis();
    }
    
    public void addStep(LoginStep step) {
        steps.add(step);
    }
    
    public void setComplete(boolean complete) {
        this.complete = complete;
        if (complete) {
            this.endTime = System.currentTimeMillis();
        }
    }
    
    public boolean isComplete() {
        return complete;
    }
    
    public void setRecordingMethod(String method) {
        this.recordingMethod = method;
    }
    
    public String getRecordingMethod() {
        return recordingMethod;
    }
    
    public void setValidationResult(LoginSequenceValidation validation) {
        this.validationResult = validation;
    }
    
    public LoginSequenceValidation getValidationResult() {
        return validationResult;
    }
    
    public String getTargetUrl() {
        return targetUrl;
    }
    
    public String getSequenceId() {
        return sequenceId;
    }
    
    public List<LoginStep> getSteps() {
        return new ArrayList<>(steps);
    }
    
    public Map<String, Object> getMetadata() {
        return new HashMap<>(metadata);
    }
    
    public void addMetadata(String key, Object value) {
        metadata.put(key, value);
    }
    
    public long getDuration() {
        return endTime > 0 ? endTime - startTime : System.currentTimeMillis() - startTime;
    }
    
    public boolean hasMultiFactorAuth() {
        return steps.stream().anyMatch(step -> 
            step.getStepType().equals("MFA") || 
            step.getUrl().contains("mfa") || 
            step.getUrl().contains("2fa"));
    }
    
    public boolean hasCaptcha() {
        return steps.stream().anyMatch(step ->
            step.getFormData().values().stream()
                .anyMatch(value -> value.toString().toLowerCase().contains("captcha")));
    }
    
    @Override
    public String toString() {
        return String.format("LoginSequence{url='%s', steps=%d, complete=%s}", 
            targetUrl, steps.size(), complete);
    }
}
