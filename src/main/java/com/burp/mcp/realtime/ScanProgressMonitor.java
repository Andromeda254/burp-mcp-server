package com.burp.mcp.realtime;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.HashMap;
import java.util.function.Consumer;

/**
 * Real-time scan progress monitoring system
 * Provides WebSocket/EventStream capabilities for live scan updates
 * 
 * Features:
 * - Live progress tracking with percentage completion
 * - Real-time vulnerability notifications as they are discovered
 * - Scan status updates (queued, running, completed, failed)
 * - Performance metrics and timing information
 * - Multi-client subscription support
 * - Event history for late subscribers
 */
public class ScanProgressMonitor {
    
    private static final Logger logger = LoggerFactory.getLogger(ScanProgressMonitor.class);
    private final ObjectMapper objectMapper;
    
    // Concurrent data structures for thread-safe operations
    private final ConcurrentHashMap<String, ScanProgressInfo> activeScanProgresses;
    private final ConcurrentHashMap<String, List<ScanProgressEvent>> scanEventHistory;
    private final CopyOnWriteArrayList<ProgressSubscriber> subscribers;
    
    // Scheduled executor for periodic progress updates
    private final ScheduledExecutorService progressScheduler;
    
    public ScanProgressMonitor() {
        this.objectMapper = new ObjectMapper();
        this.activeScanProgresses = new ConcurrentHashMap<>();
        this.scanEventHistory = new ConcurrentHashMap<>();
        this.subscribers = new CopyOnWriteArrayList<>();
        this.progressScheduler = Executors.newScheduledThreadPool(2);
        
        // Start the periodic progress update task
        startProgressUpdateTask();
        
        logger.info("✅ ScanProgressMonitor initialized with real-time capabilities");
    }
    
    /**
     * Start monitoring a new scan task
     */
    public void startScanMonitoring(String taskId, String url, String scanType) {
        var progressInfo = new ScanProgressInfo(
            taskId, url, scanType, 
            Instant.now(), "QUEUED", 0.0, 0, 0
        );
        
        activeScanProgresses.put(taskId, progressInfo);
        scanEventHistory.put(taskId, new CopyOnWriteArrayList<>());
        
        // Send initial event
        sendProgressEvent(new ScanProgressEvent(
            taskId, "SCAN_STARTED", 0.0, 
            Map.of("message", "Scan queued and ready to begin", "url", url, "scanType", scanType),
            Instant.now()
        ));
        
        logger.info("📊 Started monitoring scan: {} - {} ({})", taskId, url, scanType);
    }
    
    /**
     * Update scan progress with current status
     */
    public void updateScanProgress(String taskId, String status, double progressPercent, 
                                 int vulnerabilitiesFound, int requestsSent) {
        var progressInfo = activeScanProgresses.get(taskId);
        if (progressInfo == null) {
            logger.warn("⚠️ Attempted to update progress for unknown task: {}", taskId);
            return;
        }
        
        // Update progress information
        var updatedProgress = progressInfo.withProgress(status, progressPercent, 
                                                     vulnerabilitiesFound, requestsSent);
        activeScanProgresses.put(taskId, updatedProgress);
        
        // Send progress update event
        var eventData = new HashMap<String, Object>();
        eventData.put("status", status);
        eventData.put("progressPercent", progressPercent);
        eventData.put("vulnerabilitiesFound", vulnerabilitiesFound);
        eventData.put("requestsSent", requestsSent);
        eventData.put("elapsedTime", getElapsedTime(progressInfo.startTime()));
        eventData.put("estimatedRemaining", estimateRemainingTime(progressPercent));
        
        sendProgressEvent(new ScanProgressEvent(
            taskId, "PROGRESS_UPDATE", progressPercent, eventData, Instant.now()
        ));
        
        logger.debug("📈 Progress update - {}: {}% ({} vulns, {} requests)", 
                    taskId, String.format("%.1f", progressPercent), vulnerabilitiesFound, requestsSent);
    }
    
    /**
     * Report a newly discovered vulnerability in real-time
     */
    public void reportVulnerabilityFound(String taskId, Map<String, Object> vulnerability) {
        var progressInfo = activeScanProgresses.get(taskId);
        if (progressInfo == null) {
            logger.warn("⚠️ Attempted to report vulnerability for unknown task: {}", taskId);
            return;
        }
        
        // Create vulnerability notification data
        var eventData = Map.of(
            "vulnerability", vulnerability,
            "severity", vulnerability.getOrDefault("severity", "Unknown"),
            "name", vulnerability.getOrDefault("name", "Security Issue"),
            "url", vulnerability.getOrDefault("url", progressInfo.url()),
            "totalVulnerabilities", progressInfo.vulnerabilitiesFound() + 1
        );
        
        sendProgressEvent(new ScanProgressEvent(
            taskId, "VULNERABILITY_FOUND", progressInfo.progressPercent(), 
            eventData, Instant.now()
        ));
        
        var severity = vulnerability.getOrDefault("severity", "Unknown");
        var name = vulnerability.getOrDefault("name", "Security Issue");
        
        logger.info("🚨 Vulnerability discovered in {}: {} [{}]", taskId, name, severity);
    }
    
    /**
     * Complete scan monitoring with final results
     */
    public void completeScanMonitoring(String taskId, String finalStatus, 
                                     int totalVulnerabilities, Map<String, Object> scanSummary) {
        var progressInfo = activeScanProgresses.get(taskId);
        if (progressInfo == null) {
            logger.warn("⚠️ Attempted to complete unknown task: {}", taskId);
            return;
        }
        
        // Update final progress
        var completedProgress = progressInfo.withProgress(finalStatus, 100.0, 
                                                        totalVulnerabilities, progressInfo.requestsSent());
        activeScanProgresses.put(taskId, completedProgress);
        
        // Prepare completion event data
        var eventData = Map.of(
            "finalStatus", finalStatus,
            "totalVulnerabilities", totalVulnerabilities,
            "totalRequests", progressInfo.requestsSent(),
            "duration", getElapsedTime(progressInfo.startTime()),
            "scanSummary", scanSummary,
            "completed", true
        );
        
        sendProgressEvent(new ScanProgressEvent(
            taskId, "SCAN_COMPLETED", 100.0, eventData, Instant.now()
        ));
        
        logger.info("✅ Scan monitoring completed for {}: {} ({} vulnerabilities found)", 
                   taskId, finalStatus, totalVulnerabilities);
        
        // Schedule cleanup of completed scan data (after 1 hour)
        progressScheduler.schedule(() -> cleanupCompletedScan(taskId), 1, TimeUnit.HOURS);
    }
    
    /**
     * Subscribe to real-time progress updates
     */
    public String subscribeToProgress(Consumer<ScanProgressEvent> eventConsumer) {
        var subscriberId = UUID.randomUUID().toString();
        var subscriber = new ProgressSubscriber(subscriberId, eventConsumer);
        
        subscribers.add(subscriber);
        
        // Send current state of all active scans to new subscriber
        sendCurrentStateToSubscriber(subscriber);
        
        logger.info("🔔 New progress subscriber registered: {}", subscriberId);
        return subscriberId;
    }
    
    /**
     * Unsubscribe from progress updates
     */
    public void unsubscribeFromProgress(String subscriberId) {
        subscribers.removeIf(subscriber -> subscriber.id().equals(subscriberId));
        logger.info("🔕 Progress subscriber unregistered: {}", subscriberId);
    }
    
    /**
     * Get current progress for a specific scan
     */
    public ScanProgressInfo getCurrentProgress(String taskId) {
        return activeScanProgresses.get(taskId);
    }
    
    /**
     * Get event history for a specific scan
     */
    public List<ScanProgressEvent> getEventHistory(String taskId) {
        return scanEventHistory.getOrDefault(taskId, List.of());
    }
    
    /**
     * Get all active scan progresses
     */
    public Map<String, ScanProgressInfo> getAllActiveProgresses() {
        return Map.copyOf(activeScanProgresses);
    }
    
    // ===== PRIVATE HELPER METHODS =====
    
    private void sendProgressEvent(ScanProgressEvent event) {
        // Store event in history
        scanEventHistory.computeIfAbsent(event.taskId(), k -> new CopyOnWriteArrayList<>()).add(event);
        
        // Notify all subscribers
        for (var subscriber : subscribers) {
            try {
                subscriber.eventConsumer().accept(event);
            } catch (Exception e) {
                logger.warn("⚠️ Failed to notify progress subscriber {}: {}", subscriber.id(), e.getMessage());
            }
        }
    }
    
    private void sendCurrentStateToSubscriber(ProgressSubscriber subscriber) {
        // Send current state of all active scans
        for (var entry : activeScanProgresses.entrySet()) {
            var taskId = entry.getKey();
            var progress = entry.getValue();
            
            var stateEvent = new ScanProgressEvent(
                taskId, "CURRENT_STATE", progress.progressPercent(),
                Map.of(
                    "status", progress.status(),
                    "progressPercent", progress.progressPercent(),
                    "vulnerabilitiesFound", progress.vulnerabilitiesFound(),
                    "requestsSent", progress.requestsSent(),
                    "url", progress.url(),
                    "scanType", progress.scanType(),
                    "elapsedTime", getElapsedTime(progress.startTime())
                ),
                Instant.now()
            );
            
            try {
                subscriber.eventConsumer().accept(stateEvent);
            } catch (Exception e) {
                logger.warn("⚠️ Failed to send current state to subscriber {}: {}", subscriber.id(), e.getMessage());
            }
        }
    }
    
    private void startProgressUpdateTask() {
        progressScheduler.scheduleAtFixedRate(() -> {
            try {
                // Send periodic heartbeat updates for long-running scans
                for (var entry : activeScanProgresses.entrySet()) {
                    var taskId = entry.getKey();
                    var progress = entry.getValue();
                    
                    if ("RUNNING".equals(progress.status())) {
                        var elapsedMinutes = getElapsedTime(progress.startTime()) / 60;
                        
                        // Send heartbeat every 30 seconds for active scans
                        if (elapsedMinutes > 0 && elapsedMinutes % 0.5 == 0) {
                            sendProgressEvent(new ScanProgressEvent(
                                taskId, "HEARTBEAT", progress.progressPercent(),
                                Map.of("elapsedTime", getElapsedTime(progress.startTime()),
                                      "status", progress.status()),
                                Instant.now()
                            ));
                        }
                    }
                }
            } catch (Exception e) {
                logger.warn("⚠️ Error in progress update task: {}", e.getMessage());
            }
        }, 30, 30, TimeUnit.SECONDS);
    }
    
    private void cleanupCompletedScan(String taskId) {
        activeScanProgresses.remove(taskId);
        // Keep event history but limit size
        var events = scanEventHistory.get(taskId);
        if (events != null && events.size() > 1000) {
            // Keep only the last 1000 events
            var recentEvents = events.subList(events.size() - 1000, events.size());
            scanEventHistory.put(taskId, new CopyOnWriteArrayList<>(recentEvents));
        }
        
        logger.debug("🧹 Cleaned up completed scan data for {}", taskId);
    }
    
    private long getElapsedTime(Instant startTime) {
        return Instant.now().getEpochSecond() - startTime.getEpochSecond();
    }
    
    private String estimateRemainingTime(double progressPercent) {
        if (progressPercent <= 0) return "Calculating...";
        if (progressPercent >= 100) return "Completed";
        
        // Simple estimation based on current progress
        var remainingPercent = 100 - progressPercent;
        var estimatedMinutes = (int) (remainingPercent / 2); // Rough estimate: ~2% per minute
        
        if (estimatedMinutes < 1) return "< 1 minute";
        if (estimatedMinutes < 60) return estimatedMinutes + " minutes";
        
        var hours = estimatedMinutes / 60;
        var minutes = estimatedMinutes % 60;
        return String.format("%d:%02d hours", hours, minutes);
    }
    
    /**
     * Shutdown the progress monitor and cleanup resources
     */
    public void shutdown() {
        progressScheduler.shutdown();
        try {
            if (!progressScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                progressScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            progressScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        subscribers.clear();
        activeScanProgresses.clear();
        scanEventHistory.clear();
        
        logger.info("🔄 ScanProgressMonitor shutdown completed");
    }
    
    // ===== RECORD CLASSES =====
    
    /**
     * Immutable scan progress information
     */
    public record ScanProgressInfo(
        String taskId,
        String url,
        String scanType,
        Instant startTime,
        String status,
        double progressPercent,
        int vulnerabilitiesFound,
        int requestsSent
    ) {
        public ScanProgressInfo withProgress(String newStatus, double newProgressPercent, 
                                           int newVulnerabilities, int newRequests) {
            return new ScanProgressInfo(taskId, url, scanType, startTime, 
                                      newStatus, newProgressPercent, newVulnerabilities, newRequests);
        }
        
        public String toJsonString() {
            var formatter = DateTimeFormatter.ISO_INSTANT;
            return String.format("""
                {
                  "taskId": "%s",
                  "url": "%s",
                  "scanType": "%s",
                  "startTime": "%s",
                  "status": "%s",
                  "progressPercent": %.1f,
                  "vulnerabilitiesFound": %d,
                  "requestsSent": %d
                }""", 
                taskId, url, scanType, startTime.atOffset(ZoneOffset.UTC).format(formatter),
                status, progressPercent, vulnerabilitiesFound, requestsSent);
        }
    }
    
    /**
     * Progress event for real-time updates
     */
    public record ScanProgressEvent(
        String taskId,
        String eventType,
        double progressPercent,
        Map<String, Object> data,
        Instant timestamp
    ) {
        public String toJsonString() {
            try {
                var mapper = new ObjectMapper();
                var formatter = DateTimeFormatter.ISO_INSTANT;
                
                var eventMap = Map.of(
                    "taskId", taskId,
                    "eventType", eventType,
                    "progressPercent", progressPercent,
                    "data", data,
                    "timestamp", timestamp.atOffset(ZoneOffset.UTC).format(formatter)
                );
                
                return mapper.writeValueAsString(eventMap);
            } catch (Exception e) {
                return String.format("{\"error\":\"Failed to serialize event: %s\"}", e.getMessage());
            }
        }
    }
    
    /**
     * Progress subscriber information
     */
    public record ProgressSubscriber(
        String id,
        Consumer<ScanProgressEvent> eventConsumer
    ) {}
}
