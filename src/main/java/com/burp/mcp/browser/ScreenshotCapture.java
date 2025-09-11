package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Screenshot capture and management for browser automation
 * 
 * Handles screenshot processing, storage, and analysis for browser sessions.
 */
public class ScreenshotCapture {
    
    private static final Logger logger = LoggerFactory.getLogger(ScreenshotCapture.class);
    
    private final MontoyaApi api;
    private final Map<String, ScreenshotData> screenshots = new ConcurrentHashMap<>();
    
    public ScreenshotCapture(MontoyaApi api) {
        this.api = api;
        logger.info("ScreenshotCapture initialized");
    }
    
    /**
     * Process screenshot from browser extension
     */
    public void processScreenshot(String sessionId, String screenshotId, String screenshotData, String context) {
        try {
            // Validate base64 data
            if (!screenshotData.startsWith("data:image/")) {
                throw new IllegalArgumentException("Invalid screenshot data format");
            }
            
            // Extract base64 content
            String base64Data = screenshotData.substring(screenshotData.indexOf(",") + 1);
            byte[] imageData = Base64.getDecoder().decode(base64Data);
            
            // Create screenshot metadata
            ScreenshotData screenshot = new ScreenshotData();
            screenshot.setScreenshotId(screenshotId);
            screenshot.setSessionId(sessionId);
            screenshot.setContext(context);
            screenshot.setTimestamp(System.currentTimeMillis());
            screenshot.setDataSize(imageData.length);
            screenshot.setFormat(extractImageFormat(screenshotData));
            
            // Store screenshot reference (not the full data to save memory)
            screenshots.put(screenshotId, screenshot);
            
            logger.info("Screenshot processed - ID: {}, Session: {}, Size: {} bytes, Context: {}", 
                screenshotId, sessionId, imageData.length, context);
                
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[SCREENSHOT] Captured: %s (Session: %s, Context: %s, Size: %d bytes)",
                    screenshotId, sessionId, context, imageData.length
                ));
            }
            
        } catch (Exception e) {
            logger.error("Failed to process screenshot {} for session {}: {}", 
                screenshotId, sessionId, e.getMessage(), e);
        }
    }
    
    /**
     * Get screenshot metadata
     */
    public ScreenshotData getScreenshot(String screenshotId) {
        return screenshots.get(screenshotId);
    }
    
    /**
     * Get all screenshots for a session
     */
    public Map<String, ScreenshotData> getScreenshotsForSession(String sessionId) {
        Map<String, ScreenshotData> sessionScreenshots = new HashMap<>();
        
        screenshots.entrySet().stream()
            .filter(entry -> sessionId.equals(entry.getValue().getSessionId()))
            .forEach(entry -> sessionScreenshots.put(entry.getKey(), entry.getValue()));
            
        return sessionScreenshots;
    }
    
    /**
     * Clean up old screenshots
     */
    public void cleanup(long maxAge) {
        long cutoffTime = System.currentTimeMillis() - maxAge;
        
        screenshots.entrySet().removeIf(entry -> {
            ScreenshotData screenshot = entry.getValue();
            if (screenshot.getTimestamp() < cutoffTime) {
                logger.debug("Cleaned up old screenshot: {}", entry.getKey());
                return true;
            }
            return false;
        });
    }
    
    /**
     * Get screenshot statistics
     */
    public ScreenshotStatistics getStatistics() {
        ScreenshotStatistics stats = new ScreenshotStatistics();
        stats.setTotalScreenshots(screenshots.size());
        
        // Calculate total size and categorize by context
        long totalSize = 0;
        Map<String, Integer> contextCounts = new HashMap<>();
        
        for (ScreenshotData screenshot : screenshots.values()) {
            totalSize += screenshot.getDataSize();
            
            String context = screenshot.getContext();
            contextCounts.put(context, contextCounts.getOrDefault(context, 0) + 1);
        }
        
        stats.setTotalDataSize(totalSize);
        stats.setContextCounts(contextCounts);
        
        return stats;
    }
    
    /**
     * Extract image format from data URL
     */
    private String extractImageFormat(String dataUrl) {
        try {
            // Extract format from "data:image/png;base64," format
            int startIndex = dataUrl.indexOf("image/") + 6;
            int endIndex = dataUrl.indexOf(";", startIndex);
            
            if (startIndex > 5 && endIndex > startIndex) {
                return dataUrl.substring(startIndex, endIndex).toLowerCase();
            }
            
            return "png"; // Default format
            
        } catch (Exception e) {
            logger.warn("Could not extract image format from data URL, using default: {}", e.getMessage());
            return "png";
        }
    }
    
    /**
     * Screenshot data container
     */
    public static class ScreenshotData {
        private String screenshotId;
        private String sessionId;
        private String context;
        private long timestamp;
        private long dataSize;
        private String format;
        
        // Getters and setters
        public String getScreenshotId() { return screenshotId; }
        public void setScreenshotId(String screenshotId) { this.screenshotId = screenshotId; }
        
        public String getSessionId() { return sessionId; }
        public void setSessionId(String sessionId) { this.sessionId = sessionId; }
        
        public String getContext() { return context; }
        public void setContext(String context) { this.context = context; }
        
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        
        public long getDataSize() { return dataSize; }
        public void setDataSize(long dataSize) { this.dataSize = dataSize; }
        
        public String getFormat() { return format; }
        public void setFormat(String format) { this.format = format; }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("screenshotId", screenshotId);
            map.put("sessionId", sessionId);
            map.put("context", context);
            map.put("timestamp", timestamp);
            map.put("dataSize", dataSize);
            map.put("format", format);
            return map;
        }
    }
    
    /**
     * Screenshot statistics
     */
    public static class ScreenshotStatistics {
        private int totalScreenshots;
        private long totalDataSize;
        private Map<String, Integer> contextCounts;
        
        public int getTotalScreenshots() { return totalScreenshots; }
        public void setTotalScreenshots(int totalScreenshots) { this.totalScreenshots = totalScreenshots; }
        
        public long getTotalDataSize() { return totalDataSize; }
        public void setTotalDataSize(long totalDataSize) { this.totalDataSize = totalDataSize; }
        
        public Map<String, Integer> getContextCounts() { return contextCounts != null ? contextCounts : new HashMap<>(); }
        public void setContextCounts(Map<String, Integer> contextCounts) { this.contextCounts = contextCounts; }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("totalScreenshots", totalScreenshots);
            map.put("totalDataSize", totalDataSize);
            map.put("contextCounts", getContextCounts());
            return map;
        }
    }
}