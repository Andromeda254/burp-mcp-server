package com.burp.mcp.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.charset.StandardCharsets;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Content filtering engine for HTTP request/response body modification
 * Supports various filtering strategies including regex, keyword, and transformation rules
 */
public class ContentFilterEngine {
    
    private static final Logger logger = LoggerFactory.getLogger(ContentFilterEngine.class);
    
    // Filter patterns and rules
    private final Map<String, Pattern> regexFilters = new ConcurrentHashMap<>();
    private final Map<String, String> replacementRules = new ConcurrentHashMap<>();
    private final Set<String> keywordFilters = ConcurrentHashMap.newKeySet();
    private final List<ContentTransformationRule> transformationRules = new ArrayList<>();
    
    // Security patterns
    private final List<Pattern> sqlInjectionPatterns = new ArrayList<>();
    private final List<Pattern> xssPatterns = new ArrayList<>();
    private final List<Pattern> sensitiveDataPatterns = new ArrayList<>();
    
    public ContentFilterEngine() {
        initializeSecurityPatterns();
        initializeDefaultFilters();
    }
    
    private void initializeSecurityPatterns() {
        // SQL Injection patterns
        sqlInjectionPatterns.add(Pattern.compile("(?i)('|(\\-\\-)|(;)|(\\||\\|)|(\\*|\\*))", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(exec(\\s|\\+)+(s|x)p\\w+)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(union(.*)select)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(select(.*)from(.*)where)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(insert(.*)into(.*)values)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(delete(.*)from(.*)where)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(update(.*)set(.*)where)", Pattern.CASE_INSENSITIVE));
        sqlInjectionPatterns.add(Pattern.compile("(?i)(drop(.*)table)", Pattern.CASE_INSENSITIVE));
        
        // XSS patterns
        xssPatterns.add(Pattern.compile("(?i)(<script[^>]*>.*?</script>)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
        xssPatterns.add(Pattern.compile("(?i)(javascript:)", Pattern.CASE_INSENSITIVE));
        xssPatterns.add(Pattern.compile("(?i)(on\\w+\\s*=)", Pattern.CASE_INSENSITIVE));
        xssPatterns.add(Pattern.compile("(?i)(<iframe[^>]*>.*?</iframe>)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
        xssPatterns.add(Pattern.compile("(?i)(<object[^>]*>.*?</object>)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL));
        xssPatterns.add(Pattern.compile("(?i)(<embed[^>]*>)", Pattern.CASE_INSENSITIVE));
        xssPatterns.add(Pattern.compile("(?i)(<link[^>]*>)", Pattern.CASE_INSENSITIVE));
        xssPatterns.add(Pattern.compile("(?i)(expression\\s*\\()", Pattern.CASE_INSENSITIVE));
        
        // Sensitive data patterns
        sensitiveDataPatterns.add(Pattern.compile("\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b")); // Credit card
        sensitiveDataPatterns.add(Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b")); // SSN
        sensitiveDataPatterns.add(Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b")); // Email
        sensitiveDataPatterns.add(Pattern.compile("(?i)password\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?")); // Password fields
        sensitiveDataPatterns.add(Pattern.compile("(?i)api[_-]?key\\s*[:=]\\s*[\"']?([^\"'\\s]+)[\"']?")); // API keys
        
        logger.info("Initialized {} SQL injection, {} XSS, and {} sensitive data patterns", 
            sqlInjectionPatterns.size(), xssPatterns.size(), sensitiveDataPatterns.size());
    }
    
    private void initializeDefaultFilters() {
        // Add default keyword filters
        keywordFilters.add("eval(");
        keywordFilters.add("document.write");
        keywordFilters.add("innerHTML");
        keywordFilters.add("document.cookie");
        
        // Add default replacement rules
        replacementRules.put("<script", "&lt;script");
        replacementRules.put("</script>", "&lt;/script&gt;");
        replacementRules.put("javascript:", "");
        replacementRules.put("vbscript:", "");
        
        logger.info("Initialized {} keyword filters and {} replacement rules", 
            keywordFilters.size(), replacementRules.size());
    }
    
    /**
     * Filter content based on configured rules
     * 
     * @param content Original content
     * @param contentType Content type (e.g., "application/json", "text/html")
     * @param options Filter options
     * @return Filtered content
     */
    public String filterContent(String content, String contentType, FilterOptions options) {
        if (content == null || content.isEmpty()) {
            return content;
        }
        
        try {
            String filteredContent = content;
            
            // Apply SQL injection filtering
            if (options.isFilterSqlInjection()) {
                filteredContent = filterSqlInjection(filteredContent);
            }
            
            // Apply XSS filtering
            if (options.isFilterXss()) {
                filteredContent = filterXss(filteredContent);
            }
            
            // Apply sensitive data redaction
            if (options.isRedactSensitiveData()) {
                filteredContent = redactSensitiveData(filteredContent);
            }
            
            // Apply keyword filtering
            if (options.isFilterKeywords()) {
                filteredContent = filterKeywords(filteredContent);
            }
            
            // Apply replacement rules
            if (options.isApplyReplacements()) {
                filteredContent = applyReplacements(filteredContent);
            }
            
            // Apply regex filters
            if (options.isApplyRegexFilters()) {
                filteredContent = applyRegexFilters(filteredContent);
            }
            
            // Apply transformation rules
            if (options.isApplyTransformations()) {
                filteredContent = applyTransformations(filteredContent, contentType);
            }
            
            // Log filtering if content was modified
            if (!filteredContent.equals(content)) {
                var originalLength = content.length();
                var filteredLength = filteredContent.length();
                logger.debug("Content filtered: {} chars -> {} chars ({}%)", 
                    originalLength, filteredLength, 
                    Math.round(((double)filteredLength / originalLength) * 100));
            }
            
            return filteredContent;
            
        } catch (Exception e) {
            logger.error("Error filtering content: {}", e.getMessage(), e);
            return content; // Return original on error
        }
    }
    
    /**
     * Filter SQL injection attempts
     */
    private String filterSqlInjection(String content) {
        String filtered = content;
        
        for (var pattern : sqlInjectionPatterns) {
            var matcher = pattern.matcher(filtered);
            if (matcher.find()) {
                filtered = matcher.replaceAll("[SQL_INJECTION_FILTERED]");
                logger.debug("Filtered SQL injection pattern: {}", pattern.pattern());
            }
        }
        
        return filtered;
    }
    
    /**
     * Filter XSS attempts
     */
    private String filterXss(String content) {
        String filtered = content;
        
        for (var pattern : xssPatterns) {
            var matcher = pattern.matcher(filtered);
            if (matcher.find()) {
                filtered = matcher.replaceAll("[XSS_FILTERED]");
                logger.debug("Filtered XSS pattern: {}", pattern.pattern());
            }
        }
        
        return filtered;
    }
    
    /**
     * Redact sensitive data
     */
    private String redactSensitiveData(String content) {
        String filtered = content;
        
        for (var pattern : sensitiveDataPatterns) {
            var matcher = pattern.matcher(filtered);
            if (matcher.find()) {
                filtered = matcher.replaceAll("[REDACTED]");
                logger.debug("Redacted sensitive data pattern: {}", pattern.pattern());
            }
        }
        
        return filtered;
    }
    
    /**
     * Filter based on keywords
     */
    private String filterKeywords(String content) {
        String filtered = content;
        
        for (var keyword : keywordFilters) {
            if (filtered.contains(keyword)) {
                filtered = filtered.replace(keyword, "[KEYWORD_FILTERED]");
                logger.debug("Filtered keyword: {}", keyword);
            }
        }
        
        return filtered;
    }
    
    /**
     * Apply replacement rules
     */
    private String applyReplacements(String content) {
        String filtered = content;
        
        for (var entry : replacementRules.entrySet()) {
            var search = entry.getKey();
            var replacement = entry.getValue();
            
            if (filtered.contains(search)) {
                filtered = filtered.replace(search, replacement);
                logger.debug("Applied replacement: {} -> {}", search, replacement);
            }
        }
        
        return filtered;
    }
    
    /**
     * Apply regex filters
     */
    private String applyRegexFilters(String content) {
        String filtered = content;
        
        for (var entry : regexFilters.entrySet()) {
            var name = entry.getKey();
            var pattern = entry.getValue();
            
            var matcher = pattern.matcher(filtered);
            if (matcher.find()) {
                filtered = matcher.replaceAll("[REGEX_FILTERED]");
                logger.debug("Applied regex filter: {}", name);
            }
        }
        
        return filtered;
    }
    
    /**
     * Apply content transformations
     */
    private String applyTransformations(String content, String contentType) {
        String transformed = content;
        
        for (var rule : transformationRules) {
            if (rule.appliesTo(contentType)) {
                transformed = rule.transform(transformed);
                logger.debug("Applied transformation rule: {}", rule.getName());
            }
        }
        
        return transformed;
    }
    
    // Configuration methods
    public void addRegexFilter(String name, String pattern) {
        regexFilters.put(name, Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
        logger.info("Added regex filter: {} -> {}", name, pattern);
    }
    
    public void addReplacementRule(String search, String replacement) {
        replacementRules.put(search, replacement);
        logger.info("Added replacement rule: {} -> {}", search, replacement);
    }
    
    public void addKeywordFilter(String keyword) {
        keywordFilters.add(keyword);
        logger.info("Added keyword filter: {}", keyword);
    }
    
    public void addTransformationRule(ContentTransformationRule rule) {
        transformationRules.add(rule);
        logger.info("Added transformation rule: {}", rule.getName());
    }
    
    /**
     * Filter configuration options
     */
    public static class FilterOptions {
        private boolean filterSqlInjection = true;
        private boolean filterXss = true;
        private boolean redactSensitiveData = true;
        private boolean filterKeywords = true;
        private boolean applyReplacements = true;
        private boolean applyRegexFilters = true;
        private boolean applyTransformations = true;
        
        public FilterOptions() {}
        
        // Builder methods
        public FilterOptions sqlInjection(boolean filter) {
            this.filterSqlInjection = filter;
            return this;
        }
        
        public FilterOptions xss(boolean filter) {
            this.filterXss = filter;
            return this;
        }
        
        public FilterOptions sensitiveData(boolean redact) {
            this.redactSensitiveData = redact;
            return this;
        }
        
        public FilterOptions keywords(boolean filter) {
            this.filterKeywords = filter;
            return this;
        }
        
        public FilterOptions replacements(boolean apply) {
            this.applyReplacements = apply;
            return this;
        }
        
        public FilterOptions regexFilters(boolean apply) {
            this.applyRegexFilters = apply;
            return this;
        }
        
        public FilterOptions transformations(boolean apply) {
            this.applyTransformations = apply;
            return this;
        }
        
        // Getters
        public boolean isFilterSqlInjection() { return filterSqlInjection; }
        public boolean isFilterXss() { return filterXss; }
        public boolean isRedactSensitiveData() { return redactSensitiveData; }
        public boolean isFilterKeywords() { return filterKeywords; }
        public boolean isApplyReplacements() { return applyReplacements; }
        public boolean isApplyRegexFilters() { return applyRegexFilters; }
        public boolean isApplyTransformations() { return applyTransformations; }
    }
    
    /**
     * Interface for content transformation rules
     */
    public interface ContentTransformationRule {
        String getName();
        boolean appliesTo(String contentType);
        String transform(String content);
    }
}
