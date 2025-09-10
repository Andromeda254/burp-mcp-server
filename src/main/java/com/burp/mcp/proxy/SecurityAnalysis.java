package com.burp.mcp.proxy;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Comprehensive security analysis results container
 * Provides structured storage and reporting of security findings
 */
public class SecurityAnalysis {
    
    private final Map<String, SecurityCheck> checks = new ConcurrentHashMap<>();
    private final List<String> errors = new ArrayList<>();
    private final long analysisTime = System.currentTimeMillis();
    private boolean failed = false;
    private String failureReason;
    
    public SecurityAnalysis() {}
    
    public static SecurityAnalysis failed(String reason) {
        var analysis = new SecurityAnalysis();
        analysis.failed = true;
        analysis.failureReason = reason;
        return analysis;
    }
    
    public void addCheck(String name, SecurityCheck check) {
        checks.put(name, check);
    }
    
    public SecurityCheck getCheck(String name) {
        return checks.get(name);
    }
    
    public Map<String, SecurityCheck> getChecks() {
        return new HashMap<>(checks);
    }
    
    public boolean containsSensitiveData() {
        return checks.values().stream()
            .anyMatch(check -> check.getFindings().stream()
                .anyMatch(finding -> finding.getMessage().toLowerCase().contains("sensitive") ||
                                   finding.getMessage().toLowerCase().contains("password") ||
                                   finding.getMessage().toLowerCase().contains("token")));
    }
    
    public boolean hasSecurityIssues() {
        return checks.values().stream()
            .anyMatch(check -> check.hasHighSeverityFindings());
    }
    
    public int getSecurityScore() {
        if (failed) {
            return 0;
        }
        
        if (checks.isEmpty()) {
            return 100;
        }
        
        int totalScore = 0;
        int checkCount = 0;
        
        for (var check : checks.values()) {
            totalScore += check.getScore();
            checkCount++;
        }
        
        return checkCount > 0 ? totalScore / checkCount : 100;
    }
    
    public List<SecurityFinding> getAllFindings() {
        var allFindings = new ArrayList<SecurityFinding>();
        
        for (var check : checks.values()) {
            allFindings.addAll(check.getFindings());
        }
        
        return allFindings;
    }
    
    public List<SecurityFinding> getHighSeverityFindings() {
        return getAllFindings().stream()
            .filter(finding -> finding.getLevel() == SecurityLevel.HIGH)
            .toList();
    }
    
    public String getSummary() {
        if (failed) {
            return "Analysis failed: " + failureReason;
        }
        
        var summary = new StringBuilder();
        summary.append("Security Analysis Summary:\n");
        summary.append("- Checks performed: ").append(checks.size()).append("\n");
        summary.append("- Security Score: ").append(getSecurityScore()).append("/100\n");
        summary.append("- Total findings: ").append(getAllFindings().size()).append("\n");
        summary.append("- High severity: ").append(getHighSeverityFindings().size()).append("\n");
        
        if (!errors.isEmpty()) {
            summary.append("- Errors: ").append(errors.size()).append("\n");
        }
        
        return summary.toString();
    }
    
    public String getDetailedReport() {
        var report = new StringBuilder();
        report.append(getSummary()).append("\n");
        
        if (failed) {
            return report.toString();
        }
        
        // Group findings by severity
        var findingsBySeverity = new EnumMap<SecurityLevel, List<SecurityFinding>>(SecurityLevel.class);
        for (var level : SecurityLevel.values()) {
            findingsBySeverity.put(level, new ArrayList<>());
        }
        
        for (var finding : getAllFindings()) {
            findingsBySeverity.get(finding.getLevel()).add(finding);
        }
        
        // Report by severity
        for (var level : Arrays.asList(SecurityLevel.HIGH, SecurityLevel.MEDIUM, SecurityLevel.LOW, SecurityLevel.INFO, SecurityLevel.GOOD)) {
            var findings = findingsBySeverity.get(level);
            if (!findings.isEmpty()) {
                report.append("\n").append(level).append(" FINDINGS (").append(findings.size()).append("):\n");
                for (var finding : findings) {
                    report.append("- ").append(finding.getMessage()).append("\n");
                }
            }
        }
        
        if (!errors.isEmpty()) {
            report.append("\nERRORS:\n");
            for (var error : errors) {
                report.append("- ").append(error).append("\n");
            }
        }
        
        return report.toString();
    }
    
    // Getters
    public boolean isFailed() { return failed; }
    public String getFailureReason() { return failureReason; }
    public long getAnalysisTime() { return analysisTime; }
    public List<String> getErrors() { return new ArrayList<>(errors); }
    
    public void addError(String error) {
        errors.add(error);
    }
    
    public int getScore() {
        return getSecurityScore();
    }
    
    public void addFinding(String message, String level) {
        SecurityLevel severityLevel;
        try {
            severityLevel = SecurityLevel.valueOf(level.toUpperCase());
        } catch (IllegalArgumentException e) {
            severityLevel = SecurityLevel.INFO;
        }
        
        var check = checks.computeIfAbsent("general", SecurityCheck::new);
        check.addFinding(message, severityLevel);
    }
}

/**
 * Individual security check with findings and score
 */
class SecurityCheck {
    private final String name;
    private final List<SecurityFinding> findings = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    
    public SecurityCheck(String name) {
        this.name = name;
    }
    
    public void addFinding(String message, SecurityLevel level) {
        findings.add(new SecurityFinding(message, level));
    }
    
    public void addError(String error) {
        errors.add(error);
    }
    
    public boolean hasHighSeverityFindings() {
        return findings.stream().anyMatch(f -> f.getLevel() == SecurityLevel.HIGH);
    }
    
    public int getScore() {
        if (!errors.isEmpty()) {
            return 0; // Failed checks get 0 score
        }
        
        if (findings.isEmpty()) {
            return 100; // No findings is good
        }
        
        // Calculate score based on findings severity
        int deductions = 0;
        for (var finding : findings) {
            switch (finding.getLevel()) {
                case HIGH -> deductions += 20;
                case MEDIUM -> deductions += 10;
                case LOW -> deductions += 5;
                case INFO -> deductions += 1;
                case GOOD -> deductions -= 5; // Positive findings improve score
            }
        }
        
        return Math.max(0, Math.min(100, 100 - deductions));
    }
    
    // Getters
    public String getName() { return name; }
    public List<SecurityFinding> getFindings() { return new ArrayList<>(findings); }
    public List<String> getErrors() { return new ArrayList<>(errors); }
}

/**
 * Individual security finding with severity level
 */
class SecurityFinding {
    private final String message;
    private final SecurityLevel level;
    private final long timestamp;
    
    public SecurityFinding(String message, SecurityLevel level) {
        this.message = message;
        this.level = level;
        this.timestamp = System.currentTimeMillis();
    }
    
    // Getters
    public String getMessage() { return message; }
    public SecurityLevel getLevel() { return level; }
    public long getTimestamp() { return timestamp; }
    
    @Override
    public String toString() {
        return String.format("[%s] %s", level, message);
    }
}

/**
 * Security severity levels
 */
enum SecurityLevel {
    HIGH,     // Critical security issues
    MEDIUM,   // Important security concerns
    LOW,      // Minor security issues
    INFO,     // Informational findings
    GOOD      // Positive security findings
}

/**
 * SSL-specific analysis results
 */
class SSLAnalysis {
    private final List<String> findings = new ArrayList<>();
    private final List<String> errors = new ArrayList<>();
    private final Map<String, Object> properties = new HashMap<>();
    
    public void analyzeHeaders(List<burp.api.montoya.http.message.HttpHeader> headers) {
        // Analyze SSL/TLS related headers
        for (var header : headers) {
            var name = header.name().toLowerCase();
            
            if (name.equals("strict-transport-security")) {
                findings.add("HSTS header present");
            } else if (name.equals("upgrade-insecure-requests")) {
                findings.add("Upgrade insecure requests header present");
            }
        }
    }
    
    public void checkHSTSUsage(String url) {
        if (url.startsWith("https://")) {
            properties.put("usesHTTPS", true);
        }
    }
    
    public void analyzeCertificateRequirements(burp.api.montoya.http.message.requests.HttpRequest request) {
        // Placeholder for certificate requirement analysis
        properties.put("requiresCertificate", request.url().startsWith("https://"));
    }
    
    public void addError(String error) {
        errors.add(error);
    }
    
    public boolean hasFindings() {
        return !findings.isEmpty() || !errors.isEmpty();
    }
    
    public String getSummary() {
        var summary = new StringBuilder();
        
        if (!findings.isEmpty()) {
            summary.append("Findings: ").append(String.join(", ", findings));
        }
        
        if (!errors.isEmpty()) {
            if (summary.length() > 0) summary.append("; ");
            summary.append("Errors: ").append(String.join(", ", errors));
        }
        
        return summary.length() > 0 ? summary.toString() : "No findings";
    }
    
    // Getters
    public List<String> getFindings() { return new ArrayList<>(findings); }
    public List<String> getErrors() { return new ArrayList<>(errors); }
    public Map<String, Object> getProperties() { return new HashMap<>(properties); }
}

/**
 * TLS configuration analysis results
 */
class TLSAnalysis {
    private String host;
    private int port;
    private String protocolVersion;
    private List<String> cipherSuites = new ArrayList<>();
    private List<String> certificateChain = new ArrayList<>();
    private List<String> vulnerabilities = new ArrayList<>();
    private List<String> errors = new ArrayList<>();
    private boolean apiIntegration = false;
    
    public boolean hasFindings() {
        return !vulnerabilities.isEmpty() || !errors.isEmpty();
    }
    
    public String getSummary() {
        var summary = new StringBuilder();
        
        if (protocolVersion != null) {
            summary.append("TLS ").append(protocolVersion);
        }
        
        if (!cipherSuites.isEmpty()) {
            if (summary.length() > 0) summary.append(", ");
            summary.append(cipherSuites.size()).append(" cipher suites");
        }
        
        if (!vulnerabilities.isEmpty()) {
            if (summary.length() > 0) summary.append(", ");
            summary.append(vulnerabilities.size()).append(" vulnerabilities");
        }
        
        return summary.length() > 0 ? summary.toString() : "Basic TLS analysis";
    }
    
    public void addError(String error) {
        errors.add(error);
    }
    
    // Getters and Setters
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    
    public String getProtocolVersion() { return protocolVersion; }
    public void setProtocolVersion(String protocolVersion) { this.protocolVersion = protocolVersion; }
    
    public List<String> getCipherSuites() { return new ArrayList<>(cipherSuites); }
    public void setCipherSuites(List<String> cipherSuites) { this.cipherSuites = new ArrayList<>(cipherSuites); }
    
    public List<String> getCertificateChain() { return new ArrayList<>(certificateChain); }
    public void setCertificateChain(List<String> certificateChain) { this.certificateChain = new ArrayList<>(certificateChain); }
    
    public List<String> getVulnerabilities() { return new ArrayList<>(vulnerabilities); }
    public void setVulnerabilities(List<String> vulnerabilities) { this.vulnerabilities = new ArrayList<>(vulnerabilities); }
    
    public boolean isApiIntegration() { return apiIntegration; }
    public void setApiIntegration(boolean apiIntegration) { this.apiIntegration = apiIntegration; }
    
    public List<String> getErrors() { return new ArrayList<>(errors); }
    
    public static TLSAnalysis failed(String error) {
        var analysis = new TLSAnalysis();
        analysis.addError(error);
        return analysis;
    }
}

/**
 * Security event for logging and reporting
 */
class SecurityEvent {
    private String url;
    private long timestamp;
    private SecurityAnalysis analysis;
    
    // Getters and Setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    
    public SecurityAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(SecurityAnalysis analysis) { this.analysis = analysis; }
    
    @Override
    public String toString() {
        return String.format("SecurityEvent{url='%s', timestamp=%d, score=%d}", 
            url, timestamp, analysis != null ? analysis.getSecurityScore() : 0);
    }
}
