package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Browser Manager for Burp MCP Integration
 * 
 * Coordinates browser sessions, automation tasks, and integration between
 * Chrome extension, BurpSuite, and AI-assisted authentication analysis.
 */
public class BrowserManager {
    
    private static final Logger logger = LoggerFactory.getLogger(BrowserManager.class);
    
    private final MontoyaApi api;
    private final AILoginSequenceRecorder loginRecorder;
    private final AuthenticationAnalysis authAnalysis;
    private final ScreenshotCapture screenshotCapture;
    private final ObjectMapper objectMapper;
    private final ScheduledExecutorService scheduler;
    
    // Session management
    private final Map<String, BrowserSession> activeSessions = new ConcurrentHashMap<>();
    private final Map<String, ChromeExtensionServer.ExtensionSession> extensionSessions = new ConcurrentHashMap<>();
    
    // Task management
    private final Map<String, AutomationTask> activeTasks = new ConcurrentHashMap<>();
    private final Map<String, LoginSequence> activeLoginSequences = new ConcurrentHashMap<>();
    
    public BrowserManager(MontoyaApi api) {
        this.api = api;
        this.loginRecorder = new AILoginSequenceRecorder(api);
        this.authAnalysis = new AuthenticationAnalysis(api);
        this.screenshotCapture = new ScreenshotCapture(api);
        this.objectMapper = new ObjectMapper();
        this.scheduler = Executors.newScheduledThreadPool(2);
        
        // Start session cleanup task
        scheduler.scheduleAtFixedRate(this::cleanupInactiveSessions, 5, 5, TimeUnit.MINUTES);
        
        logger.info("BrowserManager initialized");
        
        if (api != null) {
            api.logging().logToOutput("[BROWSER-MGR] Browser manager initialized");
        }
    }
    
    // ===== SESSION MANAGEMENT =====
    
    /**
     * Create a new browser session
     */
    public BrowserSession createSession(String sessionId, String targetUrl, BrowserSessionConfig config) {
        BrowserSession session = new BrowserSession(sessionId, targetUrl, config);
        activeSessions.put(sessionId, session);
        
        // Initialize login recording if enabled
        if (config.isAiAssisted()) {
            LoginSequence loginSequence = new LoginSequence(targetUrl);
            loginSequence.setRecordingMethod("ai_assisted");
            activeLoginSequences.put(sessionId, loginSequence);
        }
        
        logger.info("Created browser session: {} for URL: {}", sessionId, targetUrl);
        
        if (api != null) {
            api.logging().logToOutput(String.format(
                "[BROWSER-MGR] Session created: %s -> %s", sessionId, targetUrl
            ));
        }
        
        return session;
    }
    
    /**
     * Register Chrome extension session
     */
    public void registerExtensionSession(String sessionId, ChromeExtensionServer.ExtensionSession extensionSession) {
        extensionSessions.put(sessionId, extensionSession);
        
        // Update existing browser session if it exists
        BrowserSession browserSession = activeSessions.get(sessionId);
        if (browserSession != null) {
            browserSession.setChromeExtensionConnected(true);
            browserSession.setExtensionVersion(extensionSession.getExtensionVersion());
        }
        
        logger.info("Registered Chrome extension session: {}", sessionId);
    }
    
    /**
     * Get browser session
     */
    public BrowserSession getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    /**
     * Get all active sessions
     */
    public Map<String, BrowserSession> getAllSessions() {
        return new HashMap<>(activeSessions);
    }
    
    // ===== BROWSER EVENT HANDLERS =====
    
    /**
     * Handle page loaded event from Chrome extension
     */
    public void handlePageLoaded(String sessionId, String url, String title) {
        BrowserSession session = activeSessions.get(sessionId);
        if (session != null) {
            session.setCurrentUrl(url);
            session.setPageTitle(title);
            session.updateLastActivity();
            
            // Check if this looks like a login page
            if (isLoginPage(url, title)) {
                session.setOnLoginPage(true);
                
                // Start login sequence recording if AI-assisted
                if (session.getConfig().isAiAssisted()) {
                    startLoginRecording(sessionId, url);
                }
            }
        }
        
        logger.debug("Page loaded - Session: {}, URL: {}, Title: {}", sessionId, url, title);
    }
    
    /**
     * Handle form detection from Chrome extension
     */
    public void handleFormDetected(String sessionId, JsonNode formData) {
        BrowserSession session = activeSessions.get(sessionId);
        if (session == null) return;
        
        try {
            // Analyze form for login patterns
            boolean isLoginForm = analyzeFormForLogin(formData);
            
            if (isLoginForm) {
                session.setLoginFormDetected(true);
                
                // Record form detection in login sequence
                LoginSequence loginSequence = activeLoginSequences.get(sessionId);
                if (loginSequence != null) {
                    Map<String, Object> stepData = new HashMap<>();
                    stepData.put("formId", formData.has("id") ? formData.get("id").asText() : "unknown");
                    stepData.put("action", formData.has("action") ? formData.get("action").asText() : "");
                    stepData.put("method", formData.has("method") ? formData.get("method").asText() : "POST");
                    
                    LoginStep step = new LoginStep("form_detected", session.getCurrentUrl(), stepData);
                    loginSequence.addStep(step);
                }
                
                logger.info("Login form detected - Session: {}", sessionId);
                
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[BROWSER-MGR] Login form detected in session: %s", sessionId
                    ));
                }
            }
            
        } catch (Exception e) {
            logger.error("Error handling form detection for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
    
    /**
     * Handle login attempt from Chrome extension
     */
    public boolean handleLoginAttempt(String sessionId, JsonNode loginData) {
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                logger.warn("Login attempt for unknown session: {}", sessionId);
                return false;
            }
            
            // Extract login attempt data
            String username = loginData.has("username") ? loginData.get("username").asText() : "";
            String url = loginData.has("url") ? loginData.get("url").asText() : session.getCurrentUrl();
            
            // Record login attempt in sequence
            LoginSequence loginSequence = activeLoginSequences.get(sessionId);
            if (loginSequence != null) {
                Map<String, Object> stepData = new HashMap<>();
                stepData.put("username", username);
                stepData.put("hasPassword", loginData.has("password"));
                stepData.put("timestamp", System.currentTimeMillis());
                
                LoginStep step = new LoginStep("login_attempt", url, stepData);
                loginSequence.addStep(step);
            }
            
            // Update session state
            session.setLastLoginAttempt(System.currentTimeMillis());
            session.updateLastActivity();
            
            logger.info("Login attempt recorded - Session: {}, Username: {}", sessionId, 
                username.isEmpty() ? "[empty]" : username);
            
            return true;
            
        } catch (Exception e) {
            logger.error("Error handling login attempt for session {}: {}", sessionId, e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Handle authentication state change
     */
    public void handleAuthStateChange(String sessionId, String previousState, String newState) {
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) return;
            
            // Update session authentication state
            session.setAuthenticationState(newState);
            session.updateLastActivity();
            
            // Process authentication analysis
            AuthenticationState authState = new AuthenticationState();
            authState.setPreviousState(previousState);
            authState.setCurrentState(newState);
            authState.setStateChange(true);
            
            // Update login sequence if active
            LoginSequence loginSequence = activeLoginSequences.get(sessionId);
            if (loginSequence != null) {
                loginSequence.setAuthenticationResult(newState);
                
                // Check if login sequence is complete
                if ("AUTHENTICATED".equals(newState) || "AUTHENTICATION_FAILED".equals(newState)) {
                    completeLoginSequence(sessionId, newState);
                }
            }
            
            logger.info("Auth state change - Session: {}, {} -> {}", sessionId, previousState, newState);
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[BROWSER-MGR] Auth state change: %s -> %s (Session: %s)", 
                    previousState, newState, sessionId
                ));
            }
            
        } catch (Exception e) {
            logger.error("Error handling auth state change for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
    
    /**
     * Handle screenshot from Chrome extension
     */
    public String handleScreenshot(String sessionId, String screenshotData, String context) {
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                logger.warn("Screenshot for unknown session: {}", sessionId);
                return null;
            }
            
            // Process screenshot
            String screenshotId = UUID.randomUUID().toString();
            screenshotCapture.processScreenshot(sessionId, screenshotId, screenshotData, context);
            
            // Update session
            session.addScreenshot(screenshotId, context);
            session.updateLastActivity();
            
            logger.debug("Screenshot processed - Session: {}, Context: {}, ID: {}", 
                sessionId, context, screenshotId);
            
            return screenshotId;
            
        } catch (Exception e) {
            logger.error("Error handling screenshot for session {}: {}", sessionId, e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Handle DOM analysis from Chrome extension
     */
    public void handleDOMAnalysis(String sessionId, JsonNode domData) {
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) return;
            
            // Process DOM analysis for authentication patterns
            boolean hasLoginElements = analyzeForLoginElements(domData);
            boolean hasAuthenticatedElements = analyzeForAuthenticatedElements(domData);
            
            session.setHasLoginElements(hasLoginElements);
            session.setHasAuthenticatedElements(hasAuthenticatedElements);
            session.updateLastActivity();
            
            logger.debug("DOM analysis processed - Session: {}, LoginElements: {}, AuthElements: {}", 
                sessionId, hasLoginElements, hasAuthenticatedElements);
            
        } catch (Exception e) {
            logger.error("Error handling DOM analysis for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
    
    // ===== AUTOMATION METHODS =====
    
    /**
     * Automate form filling
     */
    public Map<String, Object> automateFormFill(String sessionId, JsonNode request) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("action", "fill_form");
        
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                result.put("success", false);
                result.put("error", "Session not found");
                return result;
            }
            
            // Create automation task
            String taskId = UUID.randomUUID().toString();
            AutomationTask task = new AutomationTask(taskId, "fill_form", request);
            activeTasks.put(taskId, task);
            
            // Process form fill request
            JsonNode formData = request.get("formData");
            result.put("taskId", taskId);
            result.put("message", "Form fill automation queued");
            
            logger.info("Form fill automation requested - Session: {}, Task: {}", sessionId, taskId);
            
        } catch (Exception e) {
            logger.error("Form fill automation failed for session {}: {}", sessionId, e.getMessage(), e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Automate element clicking
     */
    public Map<String, Object> automateClick(String sessionId, JsonNode request) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("action", "click_element");
        
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                result.put("success", false);
                result.put("error", "Session not found");
                return result;
            }
            
            String taskId = UUID.randomUUID().toString();
            AutomationTask task = new AutomationTask(taskId, "click_element", request);
            activeTasks.put(taskId, task);
            
            String selector = request.get("selector").asText();
            result.put("taskId", taskId);
            result.put("message", "Click automation queued for: " + selector);
            
            logger.info("Click automation requested - Session: {}, Selector: {}", sessionId, selector);
            
        } catch (Exception e) {
            logger.error("Click automation failed for session {}: {}", sessionId, e.getMessage(), e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Automate navigation
     */
    public Map<String, Object> automateNavigation(String sessionId, JsonNode request) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("action", "navigate");
        
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                result.put("success", false);
                result.put("error", "Session not found");
                return result;
            }
            
            String targetUrl = request.get("url").asText();
            String taskId = UUID.randomUUID().toString();
            
            AutomationTask task = new AutomationTask(taskId, "navigate", request);
            activeTasks.put(taskId, task);
            
            result.put("taskId", taskId);
            result.put("message", "Navigation queued to: " + targetUrl);
            
            logger.info("Navigation automation requested - Session: {}, URL: {}", sessionId, targetUrl);
            
        } catch (Exception e) {
            logger.error("Navigation automation failed for session {}: {}", sessionId, e.getMessage(), e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Automate waiting for elements
     */
    public Map<String, Object> automateWait(String sessionId, JsonNode request) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("action", "wait_for_element");
        
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) {
                result.put("success", false);
                result.put("error", "Session not found");
                return result;
            }
            
            String selector = request.get("selector").asText();
            int timeout = request.has("timeout") ? request.get("timeout").asInt() : 5000;
            
            String taskId = UUID.randomUUID().toString();
            AutomationTask task = new AutomationTask(taskId, "wait_for_element", request);
            activeTasks.put(taskId, task);
            
            result.put("taskId", taskId);
            result.put("message", "Wait automation queued for: " + selector + " (timeout: " + timeout + "ms)");
            
            logger.info("Wait automation requested - Session: {}, Selector: {}, Timeout: {}ms", 
                sessionId, selector, timeout);
            
        } catch (Exception e) {
            logger.error("Wait automation failed for session {}: {}", sessionId, e.getMessage(), e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    // ===== LOGIN SEQUENCE MANAGEMENT =====
    
    /**
     * Start login recording for a session
     */
    private void startLoginRecording(String sessionId, String url) {
        try {
            BrowserSession session = activeSessions.get(sessionId);
            if (session == null) return;
            
            LoginSequence existingSequence = activeLoginSequences.get(sessionId);
            if (existingSequence == null) {
                LoginSequence loginSequence = new LoginSequence(url);
                loginSequence.setRecordingMethod("ai_assisted");
                activeLoginSequences.put(sessionId, loginSequence);
                
                logger.info("Started login recording - Session: {}, URL: {}", sessionId, url);
            }
            
        } catch (Exception e) {
            logger.error("Failed to start login recording for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
    
    /**
     * Complete login sequence recording
     */
    private void completeLoginSequence(String sessionId, String authResult) {
        try {
            LoginSequence loginSequence = activeLoginSequences.get(sessionId);
            if (loginSequence == null) return;
            
            loginSequence.setComplete(true);
            loginSequence.setAuthenticationResult(authResult);
            
            // Run AI validation
            CompletableFuture.supplyAsync(() -> {
                try {
                    return loginRecorder.validateLoginSequence(loginSequence);
                } catch (Exception e) {
                    logger.error("Login sequence validation failed: {}", e.getMessage(), e);
                    return LoginSequenceValidation.failed("Validation error: " + e.getMessage());
                }
            }).thenAccept(validation -> {
                loginSequence.setValidationResult(validation);
                
                logger.info("Login sequence completed - Session: {}, Result: {}, Score: {}", 
                    sessionId, authResult, validation.getOverallScore());
                
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[BROWSER-MGR] Login sequence completed: %s (Score: %.1f%%)", 
                        sessionId, validation.getOverallScore()
                    ));
                }
            });
            
            // Remove from active sequences
            activeLoginSequences.remove(sessionId);
            
        } catch (Exception e) {
            logger.error("Failed to complete login sequence for session {}: {}", sessionId, e.getMessage(), e);
        }
    }
    
    /**
     * Get login sequence for session
     */
    public LoginSequence getLoginSequence(String sessionId) {
        return activeLoginSequences.get(sessionId);
    }
    
    // ===== UTILITY METHODS =====
    
    /**
     * Check if URL/title indicates a login page
     */
    private boolean isLoginPage(String url, String title) {
        String urlLower = url.toLowerCase();
        String titleLower = title != null ? title.toLowerCase() : "";
        
        return urlLower.contains("login") || 
               urlLower.contains("signin") || 
               urlLower.contains("auth") ||
               titleLower.contains("login") ||
               titleLower.contains("sign in");
    }
    
    /**
     * Analyze form data for login patterns
     */
    private boolean analyzeFormForLogin(JsonNode formData) {
        try {
            // Check form action
            if (formData.has("action")) {
                String action = formData.get("action").asText().toLowerCase();
                if (action.contains("login") || action.contains("signin") || action.contains("auth")) {
                    return true;
                }
            }
            
            // Check form fields
            if (formData.has("fields")) {
                JsonNode fields = formData.get("fields");
                boolean hasPasswordField = false;
                boolean hasUsernameField = false;
                
                if (fields.isArray()) {
                    for (JsonNode field : fields) {
                        String fieldType = field.has("type") ? field.get("type").asText().toLowerCase() : "";
                        String fieldName = field.has("name") ? field.get("name").asText().toLowerCase() : "";
                        
                        if ("password".equals(fieldType)) {
                            hasPasswordField = true;
                        }
                        
                        if (fieldName.contains("user") || fieldName.contains("email") || 
                            fieldName.contains("login") || "text".equals(fieldType)) {
                            hasUsernameField = true;
                        }
                    }
                }
                
                return hasPasswordField && hasUsernameField;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Error analyzing form for login patterns: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Analyze DOM for login elements
     */
    private boolean analyzeForLoginElements(JsonNode domData) {
        try {
            if (domData.has("hasPasswordFields") && domData.get("hasPasswordFields").asBoolean()) {
                return true;
            }
            
            if (domData.has("loginKeywords")) {
                JsonNode keywords = domData.get("loginKeywords");
                return keywords.isArray() && keywords.size() > 0;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Error analyzing DOM for login elements: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Analyze DOM for authenticated user elements
     */
    private boolean analyzeForAuthenticatedElements(JsonNode domData) {
        try {
            if (domData.has("hasUserProfile") && domData.get("hasUserProfile").asBoolean()) {
                return true;
            }
            
            if (domData.has("hasLogoutButton") && domData.get("hasLogoutButton").asBoolean()) {
                return true;
            }
            
            if (domData.has("authenticatedKeywords")) {
                JsonNode keywords = domData.get("authenticatedKeywords");
                return keywords.isArray() && keywords.size() > 0;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Error analyzing DOM for authenticated elements: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Cleanup inactive sessions
     */
    private void cleanupInactiveSessions() {
        try {
            long cutoffTime = System.currentTimeMillis() - TimeUnit.HOURS.toMillis(2); // 2 hours
            
            Iterator<Map.Entry<String, BrowserSession>> sessionIter = activeSessions.entrySet().iterator();
            while (sessionIter.hasNext()) {
                Map.Entry<String, BrowserSession> entry = sessionIter.next();
                BrowserSession session = entry.getValue();
                
                if (session.getLastActivity() < cutoffTime) {
                    String sessionId = entry.getKey();
                    sessionIter.remove();
                    
                    // Cleanup related data
                    extensionSessions.remove(sessionId);
                    activeLoginSequences.remove(sessionId);
                    
                    logger.info("Cleaned up inactive session: {}", sessionId);
                }
            }
            
            // Cleanup completed tasks
            Iterator<Map.Entry<String, AutomationTask>> taskIter = activeTasks.entrySet().iterator();
            while (taskIter.hasNext()) {
                Map.Entry<String, AutomationTask> entry = taskIter.next();
                AutomationTask task = entry.getValue();
                
                if (task.isCompleted() && task.getCompletedAt() < cutoffTime) {
                    taskIter.remove();
                }
            }
            
        } catch (Exception e) {
            logger.error("Error during session cleanup: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Shutdown the browser manager
     */
    public void shutdown() {
        try {
            scheduler.shutdown();
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
            
            activeSessions.clear();
            extensionSessions.clear();
            activeLoginSequences.clear();
            activeTasks.clear();
            
            logger.info("BrowserManager shutdown completed");
            
        } catch (Exception e) {
            logger.error("Error during BrowserManager shutdown: {}", e.getMessage(), e);
        }
    }
    
    // ===== DATA CLASSES =====
    
    /**
     * Browser session configuration
     */
    public static class BrowserSessionConfig {
        private boolean aiAssisted = true;
        private boolean proxyEnabled = true;
        private boolean sessionTracking = true;
        private boolean screenshotCapture = false;
        private int maxLoginAttempts = 5;
        private long sessionTimeout = TimeUnit.HOURS.toMillis(2);
        
        // Getters and setters
        public boolean isAiAssisted() { return aiAssisted; }
        public void setAiAssisted(boolean aiAssisted) { this.aiAssisted = aiAssisted; }
        
        public boolean isProxyEnabled() { return proxyEnabled; }
        public void setProxyEnabled(boolean proxyEnabled) { this.proxyEnabled = proxyEnabled; }
        
        public boolean isSessionTracking() { return sessionTracking; }
        public void setSessionTracking(boolean sessionTracking) { this.sessionTracking = sessionTracking; }
        
        public boolean isScreenshotCapture() { return screenshotCapture; }
        public void setScreenshotCapture(boolean screenshotCapture) { this.screenshotCapture = screenshotCapture; }
        
        public int getMaxLoginAttempts() { return maxLoginAttempts; }
        public void setMaxLoginAttempts(int maxLoginAttempts) { this.maxLoginAttempts = maxLoginAttempts; }
        
        public long getSessionTimeout() { return sessionTimeout; }
        public void setSessionTimeout(long sessionTimeout) { this.sessionTimeout = sessionTimeout; }
    }
    
    /**
     * Browser session data
     */
    public static class BrowserSession {
        private final String sessionId;
        private final String initialUrl;
        private final BrowserSessionConfig config;
        private final long createdAt;
        
        private String currentUrl;
        private String pageTitle;
        private String authenticationState = "UNKNOWN";
        private boolean chromeExtensionConnected = false;
        private String extensionVersion;
        private long lastActivity;
        private long lastLoginAttempt = 0;
        private boolean onLoginPage = false;
        private boolean loginFormDetected = false;
        private boolean hasLoginElements = false;
        private boolean hasAuthenticatedElements = false;
        private int loginAttempts = 0;
        
        private final List<String> screenshots = new ArrayList<>();
        private final Map<String, Object> metadata = new HashMap<>();
        
        public BrowserSession(String sessionId, String initialUrl, BrowserSessionConfig config) {
            this.sessionId = sessionId;
            this.initialUrl = initialUrl;
            this.config = config;
            this.createdAt = System.currentTimeMillis();
            this.currentUrl = initialUrl;
            this.lastActivity = createdAt;
        }
        
        public void updateLastActivity() {
            this.lastActivity = System.currentTimeMillis();
        }
        
        public void addScreenshot(String screenshotId, String context) {
            screenshots.add(screenshotId + ":" + context);
        }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("sessionId", sessionId);
            map.put("initialUrl", initialUrl);
            map.put("currentUrl", currentUrl);
            map.put("pageTitle", pageTitle);
            map.put("authenticationState", authenticationState);
            map.put("chromeExtensionConnected", chromeExtensionConnected);
            map.put("extensionVersion", extensionVersion);
            map.put("createdAt", createdAt);
            map.put("lastActivity", lastActivity);
            map.put("onLoginPage", onLoginPage);
            map.put("loginFormDetected", loginFormDetected);
            map.put("hasLoginElements", hasLoginElements);
            map.put("hasAuthenticatedElements", hasAuthenticatedElements);
            map.put("loginAttempts", loginAttempts);
            map.put("config", config);
            map.put("screenshots", screenshots);
            map.put("metadata", metadata);
            return map;
        }
        
        // Getters and setters
        public String getSessionId() { return sessionId; }
        public String getInitialUrl() { return initialUrl; }
        public String getCurrentUrl() { return currentUrl; }
        public void setCurrentUrl(String currentUrl) { this.currentUrl = currentUrl; }
        
        public String getPageTitle() { return pageTitle; }
        public void setPageTitle(String pageTitle) { this.pageTitle = pageTitle; }
        
        public String getAuthenticationState() { return authenticationState; }
        public void setAuthenticationState(String authenticationState) { this.authenticationState = authenticationState; }
        
        public boolean isChromeExtensionConnected() { return chromeExtensionConnected; }
        public void setChromeExtensionConnected(boolean connected) { this.chromeExtensionConnected = connected; }
        
        public String getExtensionVersion() { return extensionVersion; }
        public void setExtensionVersion(String extensionVersion) { this.extensionVersion = extensionVersion; }
        
        public BrowserSessionConfig getConfig() { return config; }
        public long getCreatedAt() { return createdAt; }
        public long getLastActivity() { return lastActivity; }
        public long getLastLoginAttempt() { return lastLoginAttempt; }
        public void setLastLoginAttempt(long lastLoginAttempt) { this.lastLoginAttempt = lastLoginAttempt; }
        
        public boolean isOnLoginPage() { return onLoginPage; }
        public void setOnLoginPage(boolean onLoginPage) { this.onLoginPage = onLoginPage; }
        
        public boolean isLoginFormDetected() { return loginFormDetected; }
        public void setLoginFormDetected(boolean loginFormDetected) { this.loginFormDetected = loginFormDetected; }
        
        public boolean hasLoginElements() { return hasLoginElements; }
        public void setHasLoginElements(boolean hasLoginElements) { this.hasLoginElements = hasLoginElements; }
        
        public boolean hasAuthenticatedElements() { return hasAuthenticatedElements; }
        public void setHasAuthenticatedElements(boolean hasAuthenticatedElements) { this.hasAuthenticatedElements = hasAuthenticatedElements; }
        
        public int getLoginAttempts() { return loginAttempts; }
        public void incrementLoginAttempts() { this.loginAttempts++; }
        
        public List<String> getScreenshots() { return new ArrayList<>(screenshots); }
        public Map<String, Object> getMetadata() { return new HashMap<>(metadata); }
        public void putMetadata(String key, Object value) { this.metadata.put(key, value); }
    }
    
    /**
     * Automation task data
     */
    public static class AutomationTask {
        private final String taskId;
        private final String action;
        private final JsonNode request;
        private final long createdAt;
        
        private String status = "QUEUED";
        private String result;
        private String error;
        private long completedAt = 0;
        
        public AutomationTask(String taskId, String action, JsonNode request) {
            this.taskId = taskId;
            this.action = action;
            this.request = request;
            this.createdAt = System.currentTimeMillis();
        }
        
        public void complete(String result) {
            this.status = "COMPLETED";
            this.result = result;
            this.completedAt = System.currentTimeMillis();
        }
        
        public void fail(String error) {
            this.status = "FAILED";
            this.error = error;
            this.completedAt = System.currentTimeMillis();
        }
        
        public boolean isCompleted() {
            return "COMPLETED".equals(status) || "FAILED".equals(status);
        }
        
        // Getters
        public String getTaskId() { return taskId; }
        public String getAction() { return action; }
        public JsonNode getRequest() { return request; }
        public long getCreatedAt() { return createdAt; }
        public String getStatus() { return status; }
        public String getResult() { return result; }
        public String getError() { return error; }
        public long getCompletedAt() { return completedAt; }
    }
}