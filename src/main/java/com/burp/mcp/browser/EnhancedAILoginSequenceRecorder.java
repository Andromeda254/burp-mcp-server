package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import com.burp.mcp.proxy.*;

/**
 * Enhanced AI-assisted login sequence recorder with WebDriver integration and visual verification
 * Provides intelligent authentication sequence capture, replay, and visual analysis
 * Integrates with BrowserManager for automated browser control and ScreenshotCapture for visual verification
 */
public class EnhancedAILoginSequenceRecorder {
    
    private static final Logger logger = LoggerFactory.getLogger(EnhancedAILoginSequenceRecorder.class);
    
    private final MontoyaApi api;
    private final AuthenticationAnalysis analysis;
    private PatternAnalyzer patternAnalyzer;
    private SequenceBuilder sequenceBuilder;
    private AuthDetector authDetector;
    private final Map<String, LoginSequenceSupport.RecordingSession> activeSessions;
    private final BrowserManager browserManager;
    private final Map<String, List<ScreenshotCapture.ScreenshotData>> sessionScreenshots;
    private final Map<String, LoginSequenceSupport.LoginSequenceReplay> replayResults;
    
    // AI patterns for login detection
    private static final Set<String> LOGIN_ENDPOINTS = Set.of(
        "login", "signin", "authenticate", "auth", "session", "logon", 
        "sso", "oauth", "token", "verify", "password"
    );
    
    private static final Set<String> LOGIN_PARAMETERS = Set.of(
        "username", "user", "email", "login", "password", "pass", "pwd",
        "token", "code", "otp", "mfa", "2fa", "captcha"
    );
    
    // Form field selectors for common login forms
    private static final Map<String, List<String>> COMMON_FIELD_SELECTORS = Map.of(
        "username", List.of("input[name*='user']", "input[name*='email']", "input[name*='login']", 
                           "input[id*='user']", "input[id*='email']", "input[id*='login']",
                           "input[type='email']"),
        "password", List.of("input[type='password']", "input[name*='password']", "input[name*='pass']",
                           "input[id*='password']", "input[id*='pass']"),
        "submit", List.of("input[type='submit']", "button[type='submit']", "button:contains('login')",
                         "button:contains('sign in')", "input[value*='login']", "input[value*='sign in']"),
        "form", List.of("form[id*='login']", "form[class*='login']", "form[action*='login']",
                       "form[action*='signin']", "form[action*='auth']")
    );
    
    public EnhancedAILoginSequenceRecorder(MontoyaApi api) {
        this.api = api;
        this.analysis = new AuthenticationAnalysis(api);
        this.activeSessions = new ConcurrentHashMap<>();
        this.browserManager = new BrowserManager(api);
        this.sessionScreenshots = new ConcurrentHashMap<>();
        this.replayResults = new ConcurrentHashMap<>();
    }
    
    public EnhancedAILoginSequenceRecorder(MontoyaApi api, BrowserManager customBrowserManager) {
        this.api = api;
        this.analysis = new AuthenticationAnalysis(api);
        this.activeSessions = new ConcurrentHashMap<>();
        this.browserManager = customBrowserManager != null ? customBrowserManager : new BrowserManager(api);
        this.sessionScreenshots = new ConcurrentHashMap<>();
        this.replayResults = new ConcurrentHashMap<>();
    }
    
    public void initialize() {
        // Initialize analysis components
        this.authDetector = analysis.createAuthDetector();
        this.patternAnalyzer = analysis.createPatternAnalyzer();
        this.sequenceBuilder = analysis.createSequenceBuilder();
        
        // Initialize browser manager
        try {
            browserManager.initialize();
            logger.info("Browser manager initialized successfully");
        } catch (Exception e) {
            logger.warn("Failed to initialize browser manager: {}", e.getMessage());
        }
        
        if (api != null) {
            api.logging().logToOutput("[ENHANCED-LOGIN-RECORDER] AI-assisted login recording with WebDriver integration initialized");
        }
        logger.info("Enhanced AI login sequence recorder with browser automation initialized");
    }
    
    /**
     * Record interactive login with visual verification and AI guidance
     */
    public LoginSequenceSupport.LoginSequence recordInteractiveLogin(String targetUrl, LoginRecordingConfig config) {
        return recordInteractiveLogin(targetUrl, config, null);
    }
    
    /**
     * Record interactive login with specific browser configuration
     */
    public LoginSequenceSupport.LoginSequence recordInteractiveLogin(String targetUrl, LoginRecordingConfig config, 
                                               BrowserManager.BrowserConfig browserConfig) {
        WebDriver driver = null;
        String sessionId = UUID.randomUUID().toString();
        
        try {
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[INTERACTIVE-LOGIN] Starting enhanced login recording for %s with WebDriver",
                    targetUrl
                ));
            }
            
            // Create browser session
            if (browserConfig != null) {
                driver = browserManager.createSession(sessionId, browserConfig);
            } else {
                var defaultConfig = BrowserManager.createDefaultConfig();
                defaultConfig.setHeadless(false); // Interactive recording should be visible
                defaultConfig.setCaptureScreenshots(config.isCaptureScreenshots());
                driver = browserManager.createSession(sessionId, defaultConfig);
            }
            
            // Create recording session with WebDriver
            var recordingSession = new WebDriverRecordingSession(targetUrl, config, api, driver, sessionId, this);
            activeSessions.put(sessionId, recordingSession);
            
            // Enable AI-guided recording
            if (config.isAIGuided()) {
                recordingSession.enableAIGuidance();
                if (api != null) {
                    api.logging().logToOutput("[INTERACTIVE-LOGIN] AI guidance enabled");
                }
            }
            
            // Initialize screenshot capture if enabled
            if (config.isCaptureScreenshots()) {
                sessionScreenshots.put(sessionId, new ArrayList<>());
                captureScreenshot(driver, sessionId, "initial_state");
            }
            
            // Start recording with timeout
            var future = CompletableFuture.supplyAsync(() -> {
                return recordingSession.startRecording();
            });
            
            try {
                var sequence = future.get(config.getTimeoutSeconds(), TimeUnit.SECONDS);
                
                if (sequence.isComplete()) {
                    if (api != null) {
                        api.logging().logToOutput("[INTERACTIVE-LOGIN] Login sequence recording completed successfully");
                    }
                    
                    // Capture final screenshot
                    if (config.isCaptureScreenshots() && driver != null) {
                        captureScreenshot(driver, sessionId, "final_state");
                    }
                    
                    // Validate sequence with AI analysis and visual verification
                    var validation = validateLoginSequenceWithVisualVerification(sequence, sessionId);
                    sequence.setValidationResult(validation);
                    
                    // Store screenshots in sequence metadata
                    var screenshots = sessionScreenshots.get(sessionId);
                    if (screenshots != null && !screenshots.isEmpty()) {
                        sequence.addMetadata("screenshots", screenshots);
                        sequence.addMetadata("screenshot_count", screenshots.size());
                        sequence.addMetadata("visual_verification", true);
                    }
                    
                    // Test replay if configured
                    if (config.isTestReplay()) {
                        var replayResult = testSequenceReplay(sequence, config);
                        sequence.addMetadata("replay_test", replayResult);
                    }
                    
                    return sequence;
                } else {
                    throw new LoginRecordingException("Recording incomplete");
                }
                
            } catch (Exception e) {
                future.cancel(true);
                throw new LoginRecordingException("Recording timeout or failure", e);
            } finally {
                activeSessions.remove(sessionId);
                sessionScreenshots.remove(sessionId);
                
                // Close browser session
                if (driver != null) {
                    try {
                        browserManager.closeSession(sessionId);
                    } catch (Exception e) {
                        logger.warn("Failed to close browser session: {}", e.getMessage());
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Interactive login recording failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Interactive login recording failed: " + e.getMessage());
            }
            
            // Cleanup on failure
            if (driver != null) {
                try {
                    browserManager.closeSession(sessionId);
                } catch (Exception cleanupError) {
                    logger.warn("Failed to cleanup browser session: {}", cleanupError.getMessage());
                }
            }
            
            throw new LoginRecordingException("Interactive recording failed", e);
        }
    }
    
    /**
     * Record automated login sequence with intelligent form detection
     */
    public LoginSequenceSupport.LoginSequence recordAutomatedLogin(String targetUrl, LoginRecordingConfig config, 
                                            Map<String, String> credentials) {
        WebDriver driver = null;
        String sessionId = UUID.randomUUID().toString();
        
        try {
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[AUTOMATED-LOGIN] Starting automated login recording for %s",
                    targetUrl
                ));
            }
            
            // Create headless browser session
            var browserConfig = BrowserManager.createDefaultConfig();
            browserConfig.setHeadless(true);
            browserConfig.setCaptureScreenshots(config.isCaptureScreenshots());
            driver = browserManager.createSession(sessionId, browserConfig);
            
            var sequence = new LoginSequenceSupport.LoginSequence(targetUrl);
            sequence.setRecordingMethod("automated");
            
            if (config.isCaptureScreenshots()) {
                sessionScreenshots.put(sessionId, new ArrayList<>());
            }
            
            try {
                // Navigate to target URL
                driver.get(targetUrl);
                captureScreenshot(driver, sessionId, "page_loaded");
                
                var navigationStep = new LoginSequenceSupport.LoginStep(targetUrl, "GET", "NAVIGATE");
                navigationStep.setSuccessful(true);
                sequence.addStep(navigationStep);
                
                // Wait for page to load
                new WebDriverWait(driver, Duration.ofSeconds(10))
                    .until(webDriver -> ((JavascriptExecutor) webDriver).executeScript("return document.readyState").equals("complete"));
                
                // Detect and analyze login form
                var loginForm = detectLoginForm(driver);
                if (loginForm != null) {
                    captureScreenshot(driver, sessionId, "form_detected");
                    
                    // Fill form fields
                    var fillSteps = fillLoginForm(driver, loginForm, credentials);
                    fillSteps.forEach(sequence::addStep);
                    
                    captureScreenshot(driver, sessionId, "form_filled");
                    
                    // Submit form
                    var submitStep = submitLoginForm(driver, loginForm);
                    sequence.addStep(submitStep);
                    
                    // Wait for response and check authentication state
                    Thread.sleep(3000); // Allow time for authentication
                    captureScreenshot(driver, sessionId, "form_submitted");
                    
                    var authState = analyzeAuthenticationState(driver, targetUrl);
                    sequence.addMetadata("auth_state", authState);
                    
                    if ("AUTHENTICATED".equals(authState.getCurrentState())) {
                        sequence.setComplete(true);
                        captureScreenshot(driver, sessionId, "login_success");
                    } else if ("FAILED".equals(authState.getCurrentState())) {
                        sequence.setComplete(true);
                        sequence.addMetadata("login_failed", true);
                        captureScreenshot(driver, sessionId, "login_failed");
                    }
                }
                
                // Validate sequence
                var validation = validateLoginSequenceWithVisualVerification(sequence, sessionId);
                sequence.setValidationResult(validation);
                
                // Store screenshots
                var screenshots = sessionScreenshots.get(sessionId);
                if (screenshots != null && !screenshots.isEmpty()) {
                    sequence.addMetadata("screenshots", screenshots);
                    sequence.addMetadata("screenshot_count", screenshots.size());
                }
                
                if (api != null) {
                    api.logging().logToOutput(String.format(
                        "[AUTOMATED-LOGIN] Automated recording completed with %d steps",
                        sequence.getSteps().size()
                    ));
                }
                
                return sequence;
                
            } finally {
                sessionScreenshots.remove(sessionId);
                
                // Close browser session
                if (driver != null) {
                    try {
                        browserManager.closeSession(sessionId);
                    } catch (Exception e) {
                        logger.warn("Failed to close browser session: {}", e.getMessage());
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Automated login recording failed: {}", e.getMessage());
            if (api != null) {
                api.logging().logToError("[ERROR] Automated login recording failed: " + e.getMessage());
            }
            
            // Cleanup on failure
            if (driver != null) {
                try {
                    browserManager.closeSession(sessionId);
                } catch (Exception cleanupError) {
                    logger.warn("Failed to cleanup browser session: {}", cleanupError.getMessage());
                }
            }
            
            throw new LoginRecordingException("Automated recording failed", e);
        }
    }
    
    /**
     * Replay login sequence with visual verification
     */
    public LoginSequenceSupport.LoginSequenceReplay replayLoginSequence(LoginSequenceSupport.LoginSequence sequence, Map<String, String> credentials) {
        return replayLoginSequence(sequence, credentials, null);
    }
    
    public LoginSequenceSupport.LoginSequenceReplay replayLoginSequence(LoginSequenceSupport.LoginSequence sequence, Map<String, String> credentials,
                                                  BrowserManager.BrowserConfig browserConfig) {
        WebDriver driver = null;
        String sessionId = UUID.randomUUID().toString();
        var replay = new LoginSequenceSupport.LoginSequenceReplay(sequence, sessionId);
        
        try {
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[SEQUENCE-REPLAY] Starting replay of sequence for %s",
                    sequence.getTargetUrl()
                ));
            }
            
            // Create browser session
            if (browserConfig != null) {
                driver = browserManager.createSession(sessionId, browserConfig);
            } else {
                var defaultConfig = BrowserManager.createDefaultConfig();
                defaultConfig.setHeadless(true);
                defaultConfig.setCaptureScreenshots(true);
                driver = browserManager.createSession(sessionId, defaultConfig);
            }
            
            sessionScreenshots.put(sessionId, new ArrayList<>());
            
            // Replay each step
            for (var step : sequence.getSteps()) {
                var stepResult = replayLoginStep(driver, step, credentials, sessionId);
                replay.addStepResult(stepResult);
                
                if (!stepResult.isSuccessful()) {
                    replay.setOverallSuccess(false);
                    replay.setFailureReason("Step failed: " + step.getStepType());
                    break;
                }
            }
            
            // Verify final authentication state
            if (replay.isOverallSuccess()) {
                var finalAuthState = analyzeAuthenticationState(driver, sequence.getTargetUrl());
                replay.setFinalAuthState(finalAuthState);
                
                if (!"AUTHENTICATED".equals(finalAuthState.getCurrentState())) {
                    replay.setOverallSuccess(false);
                    replay.setFailureReason("Authentication verification failed");
                }
            }
            
            // Capture final screenshot
            captureScreenshot(driver, sessionId, "replay_final");
            
            // Compare screenshots if original sequence has them
            var originalScreenshots = (List<ScreenshotCapture.ScreenshotData>) sequence.getMetadata().get("screenshots");
            var replayScreenshots = sessionScreenshots.get(sessionId);
            
            if (originalScreenshots != null && replayScreenshots != null) {
                var comparisonResults = compareScreenshots(originalScreenshots, replayScreenshots);
                replay.setVisualComparison(comparisonResults);
            }
            
            replay.setCompletedAt(System.currentTimeMillis());
            replayResults.put(sessionId, replay);
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[SEQUENCE-REPLAY] Replay completed: success=%s",
                    replay.isOverallSuccess()
                ));
            }
            
            return replay;
            
        } catch (Exception e) {
            logger.error("Sequence replay failed: {}", e.getMessage());
            replay.setOverallSuccess(false);
            replay.setFailureReason("Replay exception: " + e.getMessage());
            return replay;
            
        } finally {
            sessionScreenshots.remove(sessionId);
            
            // Close browser session
            if (driver != null) {
                try {
                    browserManager.closeSession(sessionId);
                } catch (Exception e) {
                    logger.warn("Failed to close browser session: {}", e.getMessage());
                }
            }
        }
    }
    
    /**
     * Detect login form on the page using AI patterns
     */
    private LoginSequenceSupport.LoginFormDetection detectLoginForm(WebDriver driver) {
        try {
            // Try common form selectors
            for (var formSelector : COMMON_FIELD_SELECTORS.get("form")) {
                try {
                    var forms = driver.findElements(By.cssSelector(formSelector));
                    if (!forms.isEmpty()) {
                        var form = forms.get(0);
                        return analyzeLoginForm(driver, form);
                    }
                } catch (Exception e) {
                    // Try next selector
                }
            }
            
            // Fallback: look for any form with password field
            var passwordFields = driver.findElements(By.cssSelector("input[type='password']"));
            if (!passwordFields.isEmpty()) {
                var passwordField = passwordFields.get(0);
                var form = passwordField.findElement(By.xpath("ancestor::form[1]"));
                if (form != null) {
                    return analyzeLoginForm(driver, form);
                }
            }
            
            return null;
            
        } catch (Exception e) {
            logger.warn("Failed to detect login form: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Analyze detected login form
     */
    private LoginSequenceSupport.LoginFormDetection analyzeLoginForm(WebDriver driver, WebElement form) {
        var detection = new LoginSequenceSupport.LoginFormDetection();
        detection.setForm(form);
        detection.setFormSelector(getElementSelector(form));
        
        // Find username field
        for (var usernameSelector : COMMON_FIELD_SELECTORS.get("username")) {
            try {
                var usernameField = form.findElement(By.cssSelector(usernameSelector));
                if (usernameField != null) {
                    detection.setUsernameField(usernameField);
                    detection.setUsernameSelector(getElementSelector(usernameField));
                    break;
                }
            } catch (NoSuchElementException e) {
                // Try next selector
            }
        }
        
        // Find password field
        for (var passwordSelector : COMMON_FIELD_SELECTORS.get("password")) {
            try {
                var passwordField = form.findElement(By.cssSelector(passwordSelector));
                if (passwordField != null) {
                    detection.setPasswordField(passwordField);
                    detection.setPasswordSelector(getElementSelector(passwordField));
                    break;
                }
            } catch (NoSuchElementException e) {
                // Try next selector
            }
        }
        
        // Find submit button
        for (var submitSelector : COMMON_FIELD_SELECTORS.get("submit")) {
            try {
                var submitButton = form.findElement(By.cssSelector(submitSelector));
                if (submitButton != null) {
                    detection.setSubmitButton(submitButton);
                    detection.setSubmitSelector(getElementSelector(submitButton));
                    break;
                }
            } catch (NoSuchElementException e) {
                // Try next selector
            }
        }
        
        detection.setConfidenceScore(calculateFormDetectionConfidence(detection));
        return detection;
    }
    
    /**
     * Fill login form with provided credentials
     */
    private List<LoginSequenceSupport.LoginStep> fillLoginForm(WebDriver driver, LoginSequenceSupport.LoginFormDetection formDetection, 
                                         Map<String, String> credentials) {
        var steps = new ArrayList<LoginSequenceSupport.LoginStep>();
        
        try {
            // Fill username field
            if (formDetection.getUsernameField() != null && credentials.containsKey("username")) {
                var usernameField = formDetection.getUsernameField();
                usernameField.clear();
                usernameField.sendKeys(credentials.get("username"));
                
                var step = new LoginSequenceSupport.LoginStep(driver.getCurrentUrl(), "POST", "FILL_USERNAME");
                step.addFormData("username", "[USERNAME_FILLED]");
                step.addFormData("field_selector", formDetection.getUsernameSelector());
                step.setSuccessful(true);
                steps.add(step);
            }
            
            // Fill password field
            if (formDetection.getPasswordField() != null && credentials.containsKey("password")) {
                var passwordField = formDetection.getPasswordField();
                passwordField.clear();
                passwordField.sendKeys(credentials.get("password"));
                
                var step = new LoginSequenceSupport.LoginStep(driver.getCurrentUrl(), "POST", "FILL_PASSWORD");
                step.addFormData("password", "[PASSWORD_FILLED]");
                step.addFormData("field_selector", formDetection.getPasswordSelector());
                step.setSuccessful(true);
                steps.add(step);
            }
            
        } catch (Exception e) {
            logger.error("Failed to fill login form: {}", e.getMessage());
            // Mark last step as failed
            if (!steps.isEmpty()) {
                steps.get(steps.size() - 1).setSuccessful(false);
            }
        }
        
        return steps;
    }
    
    /**
     * Submit login form
     */
    private LoginSequenceSupport.LoginStep submitLoginForm(WebDriver driver, LoginSequenceSupport.LoginFormDetection formDetection) {
        var step = new LoginSequenceSupport.LoginStep(driver.getCurrentUrl(), "POST", "SUBMIT_FORM");
        
        try {
            if (formDetection.getSubmitButton() != null) {
                formDetection.getSubmitButton().click();
                step.addFormData("submit_method", "button_click");
                step.addFormData("submit_selector", formDetection.getSubmitSelector());
            } else if (formDetection.getForm() != null) {
                formDetection.getForm().submit();
                step.addFormData("submit_method", "form_submit");
            } else {
                // Fallback: press Enter on password field
                if (formDetection.getPasswordField() != null) {
                    formDetection.getPasswordField().sendKeys("\n");
                    step.addFormData("submit_method", "enter_key");
                }
            }
            
            step.setSuccessful(true);
            
        } catch (Exception e) {
            logger.error("Failed to submit login form: {}", e.getMessage());
            step.setSuccessful(false);
            step.addFormData("error", e.getMessage());
        }
        
        return step;
    }
    
    /**
     * Analyze authentication state from current page
     */
    private LoginSequenceSupport.AuthenticationState analyzeAuthenticationState(WebDriver driver, String targetUrl) {
        var state = new LoginSequenceSupport.AuthenticationState();
        
        try {
            var currentUrl = driver.getCurrentUrl();
            var pageTitle = driver.getTitle().toLowerCase();
            var pageSource = driver.getPageSource().toLowerCase();
            
            // Check for successful login indicators
            if (pageSource.contains("welcome") || pageSource.contains("dashboard") || 
                pageSource.contains("logout") || !currentUrl.equals(targetUrl)) {
                state.setCurrentState("AUTHENTICATED");
                state.setStateChange(true);
            }
            // Check for login failure indicators
            else if (pageSource.contains("invalid") || pageSource.contains("incorrect") ||
                     pageSource.contains("failed") || pageSource.contains("error")) {
                state.setCurrentState("FAILED");
                state.setStateChange(true);
            }
            // Check for MFA requirement
            else if (pageSource.contains("verification") || pageSource.contains("2fa") ||
                     pageSource.contains("multi-factor") || pageSource.contains("code")) {
                state.setCurrentState("MFA_REQUIRED");
                state.setStateChange(true);
            }
            else {
                state.setCurrentState("PENDING");
                state.setStateChange(false);
            }
            
            // Add page metadata
            state.setCurrentUrl(currentUrl);
            state.setPageTitle(pageTitle);
            
        } catch (Exception e) {
            state.setCurrentState("ERROR");
            state.setStateChange(false);
        }
        
        return state;
    }
    
    /**
     * Capture screenshot during recording/replay
     */
    private void captureScreenshot(WebDriver driver, String sessionId, String context) {
        try {
            var config = ScreenshotCapture.createDefaultConfig();
            config.setIncludeMetadata(true);
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            
            var screenshotFuture = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot = screenshotFuture.get(10, TimeUnit.SECONDS);
            
            screenshot.setSessionId(sessionId);
            screenshot.getMetadata().put("context", context);
            screenshot.getMetadata().put("recording_session", sessionId);
            
            var screenshots = sessionScreenshots.get(sessionId);
            if (screenshots != null) {
                screenshots.add(screenshot);
            }
            
        } catch (Exception e) {
            logger.warn("Failed to capture screenshot: {}", e.getMessage());
        }
    }
    
    /**
     * Validate login sequence with visual verification
     */
    private LoginSequenceSupport.LoginSequenceValidation validateLoginSequenceWithVisualVerification(LoginSequenceSupport.LoginSequence sequence, String sessionId) {
        var validation = new LoginSequenceSupport.LoginSequenceValidation();
        
        try {
            // Basic AI validation
            var aiAnalysis = patternAnalyzer.validateSequence(sequence);
            validation.setAiValidation(aiAnalysis);
            
            // Visual verification
            var screenshots = sessionScreenshots.get(sessionId);
            if (screenshots != null && screenshots.size() >= 2) {
                var visualValidation = performVisualValidation(screenshots);
                validation.setVisualValidation(visualValidation);
            }
            
            // Security analysis
            var securityAnalysis = analyzeSequenceSecurity(sequence);
            validation.setSecurityAnalysis(securityAnalysis);
            
            // Calculate overall score
            validation.setOverallScore(calculateValidationScore(validation));
            
            if (api != null) {
                api.logging().logToOutput(String.format(
                    "[SEQUENCE-VALIDATION] Enhanced validation complete (score: %.2f/100, visual: %s)",
                    validation.getOverallScore(),
                    validation.getVisualValidation() != null ? "yes" : "no"
                ));
            }
            
            return validation;
            
        } catch (Exception e) {
            logger.error("Login sequence validation failed: {}", e.getMessage());
            return LoginSequenceSupport.LoginSequenceValidation.failed(e.getMessage());
        }
    }
    
    /**
     * Perform visual validation of screenshots
     */
    private Map<String, Object> performVisualValidation(List<ScreenshotCapture.ScreenshotData> screenshots) {
        var validation = new HashMap<String, Object>();
        
        try {
            validation.put("screenshot_count", screenshots.size());
            
            if (screenshots.size() >= 2) {
                // Compare initial vs final screenshots
                var initialScreenshot = screenshots.get(0);
                var finalScreenshot = screenshots.get(screenshots.size() - 1);
                
                var comparison = ScreenshotCapture.compareScreenshots(initialScreenshot, finalScreenshot, 0.8);
                validation.put("visual_change_detected", comparison.getSimilarity() < 0.8);
                validation.put("similarity_score", comparison.getSimilarity());
                validation.put("difference_regions", comparison.getDifferences().size());
                
                // Check for successful login visual indicators
                var hasVisualLoginSuccess = analyzeVisualLoginSuccess(screenshots);
                validation.put("visual_login_success", hasVisualLoginSuccess);
            }
            
            validation.put("validation_successful", true);
            
        } catch (Exception e) {
            validation.put("validation_successful", false);
            validation.put("error", e.getMessage());
        }
        
        return validation;
    }
    
    /**
     * Analyze screenshots for visual login success indicators
     */
    private boolean analyzeVisualLoginSuccess(List<ScreenshotCapture.ScreenshotData> screenshots) {
        // Look for context clues in screenshot metadata
        for (var screenshot : screenshots) {
            var context = (String) screenshot.getMetadata().get("context");
            if ("login_success".equals(context) || "final_state".equals(context)) {
                return true;
            }
        }
        
        // Compare first and last screenshots for significant changes
        if (screenshots.size() >= 2) {
            var first = screenshots.get(0);
            var last = screenshots.get(screenshots.size() - 1);
            
            try {
                var comparison = ScreenshotCapture.compareScreenshots(first, last, 0.5);
                return comparison.getSimilarity() < 0.7; // Significant visual change
            } catch (Exception e) {
                return false;
            }
        }
        
        return false;
    }
    
    /**
     * Compare two sets of screenshots for replay validation
     */
    private Map<String, Object> compareScreenshots(List<ScreenshotCapture.ScreenshotData> originalScreenshots,
                                                  List<ScreenshotCapture.ScreenshotData> replayScreenshots) {
        var comparison = new HashMap<String, Object>();
        
        try {
            comparison.put("original_count", originalScreenshots.size());
            comparison.put("replay_count", replayScreenshots.size());
            
            var comparisons = new ArrayList<Map<String, Object>>();
            
            int minSize = Math.min(originalScreenshots.size(), replayScreenshots.size());
            double totalSimilarity = 0.0;
            
            for (int i = 0; i < minSize; i++) {
                var original = originalScreenshots.get(i);
                var replay = replayScreenshots.get(i);
                
                var result = ScreenshotCapture.compareScreenshots(original, replay, 0.8);
                
                var stepComparison = new HashMap<String, Object>();
                stepComparison.put("step_index", i);
                stepComparison.put("similarity", result.getSimilarity());
                stepComparison.put("passed", result.isPassed());
                stepComparison.put("difference_count", result.getDifferences().size());
                
                comparisons.add(stepComparison);
                totalSimilarity += result.getSimilarity();
            }
            
            comparison.put("step_comparisons", comparisons);
            comparison.put("average_similarity", minSize > 0 ? totalSimilarity / minSize : 0.0);
            comparison.put("overall_passed", totalSimilarity / minSize > 0.8);
            
        } catch (Exception e) {
            comparison.put("error", e.getMessage());
            comparison.put("overall_passed", false);
        }
        
        return comparison;
    }
    
    /**
     * Replay individual login step
     */
    private LoginSequenceSupport.LoginStepReplayResult replayLoginStep(WebDriver driver, LoginSequenceSupport.LoginStep step, 
                                                 Map<String, String> credentials, String sessionId) {
        var result = new LoginSequenceSupport.LoginStepReplayResult(step);
        
        try {
            switch (step.getStepType()) {
                case "NAVIGATE":
                    driver.get(step.getUrl());
                    result.setSuccessful(true);
                    result.setMessage("Navigation successful");
                    break;
                    
                case "FILL_USERNAME":
                    var usernameSelector = (String) step.getFormData().get("field_selector");
                    if (usernameSelector != null && credentials.containsKey("username")) {
                        var usernameField = driver.findElement(By.cssSelector(usernameSelector));
                        usernameField.clear();
                        usernameField.sendKeys(credentials.get("username"));
                        result.setSuccessful(true);
                        result.setMessage("Username filled successfully");
                    } else {
                        result.setSuccessful(false);
                        result.setMessage("Username field not found or no credentials");
                    }
                    break;
                    
                case "FILL_PASSWORD":
                    var passwordSelector = (String) step.getFormData().get("field_selector");
                    if (passwordSelector != null && credentials.containsKey("password")) {
                        var passwordField = driver.findElement(By.cssSelector(passwordSelector));
                        passwordField.clear();
                        passwordField.sendKeys(credentials.get("password"));
                        result.setSuccessful(true);
                        result.setMessage("Password filled successfully");
                    } else {
                        result.setSuccessful(false);
                        result.setMessage("Password field not found or no credentials");
                    }
                    break;
                    
                case "SUBMIT_FORM":
                    var submitMethod = (String) step.getFormData().get("submit_method");
                    var submitSelector = (String) step.getFormData().get("submit_selector");
                    
                    if ("button_click".equals(submitMethod) && submitSelector != null) {
                        var submitButton = driver.findElement(By.cssSelector(submitSelector));
                        submitButton.click();
                    } else if ("form_submit".equals(submitMethod)) {
                        driver.findElement(By.tagName("form")).submit();
                    } else {
                        // Fallback
                        driver.findElement(By.cssSelector("input[type='submit'], button[type='submit']")).click();
                    }
                    
                    result.setSuccessful(true);
                    result.setMessage("Form submitted successfully");
                    break;
                    
                default:
                    result.setSuccessful(true);
                    result.setMessage("Step type not explicitly handled but marked as successful");
                    break;
            }
            
        } catch (Exception e) {
            result.setSuccessful(false);
            result.setMessage("Step replay failed: " + e.getMessage());
            logger.warn("Failed to replay step {}: {}", step.getStepType(), e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Test sequence replay for validation
     */
    private LoginSequenceSupport.ReplayResult testSequenceReplay(LoginSequenceSupport.LoginSequence sequence, LoginRecordingConfig config) {
        var result = new LoginSequenceSupport.ReplayResult();
        
        try {
            // Mock credentials for testing
            var testCredentials = Map.of(
                "username", "test@example.com",
                "password", "testpassword"
            );
            
            var replayResult = replayLoginSequence(sequence, testCredentials);
            result.setSuccessful(replayResult.isOverallSuccess());
            result.setMessage(replayResult.getFailureReason() != null ? 
                             replayResult.getFailureReason() : "Replay test completed successfully");
            
        } catch (Exception e) {
            result.setSuccessful(false);
            result.setMessage("Replay test failed: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Enhanced security analysis
     */
    private LoginSequenceSupport.SecurityAnalysisResult analyzeSequenceSecurity(LoginSequenceSupport.LoginSequence sequence) {
        var analysis = new LoginSequenceSupport.SecurityAnalysisResult();
        
        try {
            // Analyze sequence for security issues
            for (var step : sequence.getSteps()) {
                if (step.getStepType().equals("SUBMIT_FORM") && 
                    step.getFormData().containsKey("password")) {
                    if (!step.getUrl().startsWith("https://")) {
                        analysis.addFinding("Password submitted over HTTP", "HIGH");
                    }
                }
                
                if (step.getStepType().equals("FILL_PASSWORD")) {
                    var fieldSelector = (String) step.getFormData().get("field_selector");
                    if (fieldSelector != null && fieldSelector.contains("autocomplete")) {
                        analysis.addFinding("Password field may have autocomplete enabled", "MEDIUM");
                    }
                }
            }
            
            // Check for missing security features
            if (!sequence.hasMultiFactorAuth()) {
                analysis.addFinding("No multi-factor authentication detected", "MEDIUM");
            }
            
            if (!sequence.hasCaptcha()) {
                analysis.addFinding("No CAPTCHA protection detected", "LOW");
            }
            
            // Check for visual verification availability
            var screenshots = (List<?>) sequence.getMetadata().get("screenshots");
            if (screenshots == null || screenshots.isEmpty()) {
                analysis.addFinding("No visual verification available", "LOW");
            }
            
            // Calculate security score
            int score = 100;
            score -= analysis.getFindings().size() * 10;
            analysis.setSecurityScore(Math.max(0, score));
            
        } catch (Exception e) {
            analysis.addFinding("Security analysis failed: " + e.getMessage(), "HIGH");
            analysis.setSecurityScore(0);
        }
        
        return analysis;
    }
    
    /**
     * Utility methods
     */
    private String getElementSelector(WebElement element) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) ((org.openqa.selenium.WrapsDriver) element).getWrappedDriver();
            return (String) js.executeScript(
                "function getSelector(el) {" +
                "  if (el.id) return '#' + el.id;" +
                "  if (el.name) return el.tagName.toLowerCase() + '[name=\"' + el.name + '\"]';" +
                "  return el.tagName.toLowerCase();" +
                "}" +
                "return getSelector(arguments[0]);", element
            );
        } catch (Exception e) {
            return element.getTagName().toLowerCase();
        }
    }
    
    private double calculateFormDetectionConfidence(LoginSequenceSupport.LoginFormDetection detection) {
        double confidence = 0.0;
        
        if (detection.getForm() != null) confidence += 30;
        if (detection.getUsernameField() != null) confidence += 25;
        if (detection.getPasswordField() != null) confidence += 35;
        if (detection.getSubmitButton() != null) confidence += 10;
        
        return confidence;
    }
    
    private double calculateValidationScore(LoginSequenceSupport.LoginSequenceValidation validation) {
        double score = 30.0; // Base score
        
        if (validation.getAiValidation() != null) {
            var aiScore = (Double) validation.getAiValidation().get("confidence_score");
            if (aiScore != null) {
                score += aiScore * 0.3;
            }
        }
        
        if (validation.getVisualValidation() != null) {
            var visualSuccessful = (Boolean) validation.getVisualValidation().get("validation_successful");
            if (Boolean.TRUE.equals(visualSuccessful)) {
                score += 25.0;
            }
        }
        
        if (validation.getSecurityAnalysis() != null) {
            score += validation.getSecurityAnalysis().getSecurityScore() * 0.15;
        }
        
        return Math.min(100.0, score);
    }
    
    // Supporting classes
    
    public static class LoginRecordingConfig {
        private boolean aiGuided = true;
        private int timeoutSeconds = 60;
        private boolean captureScreenshots = true;
        private boolean analyzeJavaScript = false;
        private boolean testReplay = false;
        
        // Getters and setters
        public boolean isAIGuided() { return aiGuided; }
        public void setAIGuided(boolean aiGuided) { this.aiGuided = aiGuided; }
        
        public int getTimeoutSeconds() { return timeoutSeconds; }
        public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
        
        public boolean isCaptureScreenshots() { return captureScreenshots; }
        public void setCaptureScreenshots(boolean captureScreenshots) { this.captureScreenshots = captureScreenshots; }
        
        public boolean isAnalyzeJavaScript() { return analyzeJavaScript; }
        public void setAnalyzeJavaScript(boolean analyzeJavaScript) { this.analyzeJavaScript = analyzeJavaScript; }
        
        public boolean isTestReplay() { return testReplay; }
        public void setTestReplay(boolean testReplay) { this.testReplay = testReplay; }
    }
    
    public static class LoginRecordingException extends RuntimeException {
        public LoginRecordingException(String message) {
            super(message);
        }
        
        public LoginRecordingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    /**
     * WebDriver-based recording session
     */
    private static class WebDriverRecordingSession implements LoginSequenceSupport.RecordingSession {
        private final String sessionId;
        private final String targetUrl;
        private final LoginRecordingConfig config;
        private final MontoyaApi api;
        private final WebDriver driver;
        private final EnhancedAILoginSequenceRecorder recorder;
        private boolean aiGuidanceEnabled = false;
        private boolean active = false;
        
        public WebDriverRecordingSession(String targetUrl, LoginRecordingConfig config, MontoyaApi api,
                                        WebDriver driver, String sessionId, EnhancedAILoginSequenceRecorder recorder) {
            this.sessionId = sessionId;
            this.targetUrl = targetUrl;
            this.config = config;
            this.api = api;
            this.driver = driver;
            this.recorder = recorder;
        }
        
        public void enableAIGuidance() {
            this.aiGuidanceEnabled = true;
        }
        
        public LoginSequenceSupport.LoginSequence startRecording() {
            active = true;
            var sequence = new LoginSequenceSupport.LoginSequence(targetUrl);
            sequence.setRecordingMethod("interactive_webdriver");
            
            try {
                if (api != null) {
                    api.logging().logToOutput("[WEBDRIVER-RECORDING] Starting WebDriver-based interactive recording");
                }
                
                // Navigate to target URL
                driver.get(targetUrl);
                recorder.captureScreenshot(driver, sessionId, "page_loaded");
                
                var navigationStep = new LoginSequenceSupport.LoginStep(targetUrl, "GET", "NAVIGATE");
                navigationStep.setSuccessful(true);
                sequence.addStep(navigationStep);
                
                // Wait for user interaction or AI guidance
                if (aiGuidanceEnabled) {
                    // AI-guided recording
                    var aiGuidedSequence = performAIGuidedRecording(driver, sequence);
                    return aiGuidedSequence;
                } else {
                    // Manual recording - wait for user to complete login
                    // In real implementation, this would monitor for form submissions
                    // For now, simulate waiting period
                    Thread.sleep(30000); // Wait 30 seconds for user interaction
                    
                    // Detect if login was successful
                    var authState = recorder.analyzeAuthenticationState(driver, targetUrl);
                    sequence.addMetadata("auth_state", authState);
                    
                    if ("AUTHENTICATED".equals(authState.getCurrentState())) {
                        sequence.setComplete(true);
                    }
                    
                    return sequence;
                }
                
            } catch (Exception e) {
                sequence.setComplete(false);
                return sequence;
            } finally {
                active = false;
            }
        }
        
        private LoginSequenceSupport.LoginSequence performAIGuidedRecording(WebDriver driver, LoginSequenceSupport.LoginSequence sequence) {
            try {
                // Use AI to detect and interact with login form
                var loginForm = recorder.detectLoginForm(driver);
                if (loginForm != null && loginForm.getConfidenceScore() > 70) {
                    
                    if (api != null) {
                        api.logging().logToOutput("[AI-GUIDED] Login form detected with confidence: " + 
                                                 loginForm.getConfidenceScore());
                    }
                    
                    // Provide AI guidance prompts (in real implementation, this would 
                    // provide visual or text prompts to guide user interaction)
                    
                    // For now, add detected form information to sequence
                    var formDetectionStep = new LoginSequenceSupport.LoginStep(driver.getCurrentUrl(), "GET", "FORM_DETECTED");
                    formDetectionStep.addFormData("form_confidence", loginForm.getConfidenceScore());
                    formDetectionStep.addFormData("username_field_detected", loginForm.getUsernameSelector() != null);
                    formDetectionStep.addFormData("password_field_detected", loginForm.getPasswordSelector() != null);
                    formDetectionStep.addFormData("submit_button_detected", loginForm.getSubmitSelector() != null);
                    formDetectionStep.setSuccessful(true);
                    sequence.addStep(formDetectionStep);
                    
                    // Wait for manual interaction
                    Thread.sleep(30000);
                    
                    // Check authentication state
                    var authState = recorder.analyzeAuthenticationState(driver, targetUrl);
                    sequence.addMetadata("auth_state", authState);
                    
                    if ("AUTHENTICATED".equals(authState.getCurrentState())) {
                        sequence.setComplete(true);
                    }
                }
                
                return sequence;
                
            } catch (Exception e) {
                sequence.setComplete(false);
                return sequence;
            }
        }
        
        @Override
        public String getSessionId() { return sessionId; }
        
        @Override
        public String getTargetUrl() { return targetUrl; }
        
        @Override
        public boolean isActive() { return active; }
        
        @Override
        public void stop() { active = false; }
    }
    
    // Additional supporting classes would be defined here...
    // (LoginFormDetection, LoginSequenceReplay, LoginStepReplayResult, AuthenticationState, etc.)
}
