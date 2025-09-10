package com.burp.mcp.browser;

import java.util.*;

/**
 * Represents a single step in a login sequence
 */
public class LoginStep {
    
    private final String stepId;
    private final String url;
    private final String httpMethod;
    private final String stepType;
    private final Map<String, Object> formData;
    private final Map<String, String> headers;
    private final long timestamp;
    private String response;
    private int statusCode;
    private boolean successful = false;
    
    public LoginStep(String url, String httpMethod, String stepType) {
        this.stepId = UUID.randomUUID().toString();
        this.url = url;
        this.httpMethod = httpMethod;
        this.stepType = stepType;
        this.formData = new HashMap<>();
        this.headers = new HashMap<>();
        this.timestamp = System.currentTimeMillis();
    }
    
    public void addFormData(String key, Object value) {
        formData.put(key, value);
    }
    
    public void addHeader(String name, String value) {
        headers.put(name, value);
    }
    
    public void setResponse(String response, int statusCode) {
        this.response = response;
        this.statusCode = statusCode;
    }
    
    public void setSuccessful(boolean successful) {
        this.successful = successful;
    }
    
    // Getters
    public String getStepId() { return stepId; }
    public String getUrl() { return url; }
    public String getHttpMethod() { return httpMethod; }
    public String getStepType() { return stepType; }
    public Map<String, Object> getFormData() { return new HashMap<>(formData); }
    public Map<String, String> getHeaders() { return new HashMap<>(headers); }
    public long getTimestamp() { return timestamp; }
    public String getResponse() { return response; }
    public int getStatusCode() { return statusCode; }
    public boolean isSuccessful() { return successful; }
    
    @Override
    public String toString() {
        return String.format("LoginStep{type='%s', url='%s', method='%s', successful=%s}", 
            stepType, url, httpMethod, successful);
    }
}
