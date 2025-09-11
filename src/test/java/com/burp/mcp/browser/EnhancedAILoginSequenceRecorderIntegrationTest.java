package com.burp.mcp.browser;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Integration tests for EnhancedAILoginSequenceRecorder
 * Tests comprehensive login recording, replay, and visual verification functionality
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EnhancedAILoginSequenceRecorderIntegrationTest {
    
    private static final Logger logger = LoggerFactory.getLogger(EnhancedAILoginSequenceRecorderIntegrationTest.class);
    
    @Mock
    private MontoyaApi mockApi;
    
    @Mock
    private burp.api.montoya.logging.Logging mockLogging;
    
    private EnhancedAILoginSequenceRecorder recorder;
    private BrowserManager browserManager;
    private static boolean systemSupportsChrome;
    
    // Test data
    private static final String TEST_LOGIN_URL = "https://the-internet.herokuapp.com/login";
    private static final String VALID_USERNAME = "tomsmith";
    private static final String VALID_PASSWORD = "SuperSecretPassword!";
    private static final String INVALID_USERNAME = "invaliduser";
    private static final String INVALID_PASSWORD = "invalidpass";
    
    @BeforeAll
    static void checkSystemCapabilities() {
        systemSupportsChrome = checkChromeAvailability();
        logger.info("System supports Chrome: {}", systemSupportsChrome);
    }
    
    @BeforeEach
    void setUp() {
        assumeTrue(systemSupportsChrome, "Chrome driver required for login sequence tests");
        
        // Mock BurpSuite API
        when(mockApi.logging()).thenReturn(mockLogging);
        doNothing().when(mockLogging).logToOutput(anyString());
        doNothing().when(mockLogging).logToError(anyString());
        
        // Initialize components
        browserManager = new BrowserManager();
        try {
            browserManager.initialize();
        } catch (Exception e) {
            logger.error("Failed to initialize BrowserManager", e);
            fail("BrowserManager initialization failed");
        }
        
        recorder = new EnhancedAILoginSequenceRecorder(mockApi, browserManager);
        try {
            recorder.initialize();
            logger.info("EnhancedAILoginSequenceRecorder initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize recorder", e);
            fail("Recorder initialization failed");
        }
    }
    
    @AfterEach
    void tearDown() {
        if (browserManager != null) {
            try {
                browserManager.closeAllSessions();
            } catch (Exception e) {
                logger.warn("Error during cleanup", e);
            }
        }
        
        // Clear screenshot cache
        ScreenshotCapture.clearCache();
    }
    
    @Test
    @Order(1)
    @DisplayName("Test recorder initialization and configuration")
    void testRecorderInitialization() {
        assertNotNull(recorder, "Recorder should be initialized");
        
        // Test configuration objects
        var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
        assertNotNull(config, "Config should be created");
        assertTrue(config.isAIGuided(), "AI guidance should be enabled by default");
        assertTrue(config.isCaptureScreenshots(), "Screenshot capture should be enabled by default");
        assertEquals(60, config.getTimeoutSeconds(), "Default timeout should be 60 seconds");
        
        logger.info("Recorder initialization test successful");
    }
    
    @Test
    @Order(2)
    @DisplayName("Test automated login recording with valid credentials")
    void testAutomatedLoginRecordingWithValidCredentials() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(true);
            config.setTimeoutSeconds(30);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            // Record login sequence
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            
            // Verify sequence was recorded
            assertNotNull(sequence, "Login sequence should not be null");
            assertTrue(sequence.isComplete(), "Login sequence should be complete");
            assertEquals("automated", sequence.getRecordingMethod(), "Recording method should be automated");
            assertEquals(TEST_LOGIN_URL, sequence.getTargetUrl(), "Target URL should match");
            
            // Verify steps were recorded
            assertFalse(sequence.getSteps().isEmpty(), "Should have recorded steps");
            assertTrue(sequence.getSteps().size() >= 3, "Should have at least 3 steps (navigate, fill, submit)");
            
            // Check for navigation step
            var hasNavigateStep = sequence.getSteps().stream()
                .anyMatch(step -> "NAVIGATE".equals(step.getStepType()));
            assertTrue(hasNavigateStep, "Should have navigation step");
            
            // Check for form filling steps
            var hasUsernameStep = sequence.getSteps().stream()
                .anyMatch(step -> "FILL_USERNAME".equals(step.getStepType()));
            var hasPasswordStep = sequence.getSteps().stream()
                .anyMatch(step -> "FILL_PASSWORD".equals(step.getStepType()));
            assertTrue(hasUsernameStep, "Should have username filling step");
            assertTrue(hasPasswordStep, "Should have password filling step");
            
            // Check for form submission step
            var hasSubmitStep = sequence.getSteps().stream()
                .anyMatch(step -> "SUBMIT_FORM".equals(step.getStepType()));
            assertTrue(hasSubmitStep, "Should have form submission step");
            
            // Verify authentication state
            var authState = (AuthenticationState) sequence.getMetadata().get("auth_state");
            assertNotNull(authState, "Authentication state should be recorded");
            assertEquals("AUTHENTICATED", authState.getCurrentState(), "Should show authenticated state");
            
            // Verify screenshots were captured if enabled
            if (config.isCaptureScreenshots()) {
                var screenshots = (java.util.List<?>) sequence.getMetadata().get("screenshots");
                assertNotNull(screenshots, "Screenshots should be captured");
                assertFalse(screenshots.isEmpty(), "Should have at least one screenshot");
            }
            
            // Verify validation result
            var validation = sequence.getValidationResult();
            assertNotNull(validation, "Validation result should not be null");
            assertTrue(validation.getOverallScore() > 0, "Validation score should be positive");
            
            logger.info("Automated login recording test successful - Steps: {}, Score: {}", 
                       sequence.getSteps().size(), validation.getOverallScore());
            
        } catch (Exception e) {
            logger.error("Automated login recording test failed", e);
            fail("Automated login recording failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test automated login recording with invalid credentials")
    void testAutomatedLoginRecordingWithInvalidCredentials() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(true);
            config.setTimeoutSeconds(20);
            
            var credentials = Map.of(
                "username", INVALID_USERNAME,
                "password", INVALID_PASSWORD
            );
            
            // Record login sequence with invalid credentials
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            
            // Verify sequence was recorded even with invalid credentials
            assertNotNull(sequence, "Login sequence should not be null");
            assertTrue(sequence.isComplete(), "Login sequence should be complete");
            
            // Verify authentication state shows failure
            var authState = (AuthenticationState) sequence.getMetadata().get("auth_state");
            assertNotNull(authState, "Authentication state should be recorded");
            assertEquals("FAILED", authState.getCurrentState(), "Should show failed authentication state");
            
            // Check if login failure was detected in metadata
            var loginFailed = (Boolean) sequence.getMetadata().get("login_failed");
            assertEquals(Boolean.TRUE, loginFailed, "Should detect login failure");
            
            logger.info("Invalid credentials test successful - Auth state: {}", 
                       authState.getCurrentState());
            
        } catch (Exception e) {
            logger.error("Invalid credentials test failed", e);
            fail("Invalid credentials test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test login sequence replay functionality")
    void testLoginSequenceReplay() {
        try {
            // First, record a login sequence
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(true);
            config.setTimeoutSeconds(30);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            var originalSequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            assertNotNull(originalSequence, "Original sequence should be recorded");
            assertTrue(originalSequence.isComplete(), "Original sequence should be complete");
            
            // Now replay the sequence
            var replayResult = recorder.replayLoginSequence(originalSequence, credentials);
            
            // Verify replay result
            assertNotNull(replayResult, "Replay result should not be null");
            assertEquals(originalSequence.getSequenceId(), 
                        replayResult.getOriginalSequence().getSequenceId(), "Should reference original sequence");
            
            // Check step results
            var stepResults = replayResult.getStepResults();
            assertNotNull(stepResults, "Step results should not be null");
            assertFalse(stepResults.isEmpty(), "Should have step results");
            
            // Verify most steps succeeded (allowing for some tolerance in dynamic environments)
            long successfulSteps = stepResults.stream()
                .mapToLong(result -> result.isSuccessful() ? 1 : 0)
                .sum();
            
            double successRate = (double) successfulSteps / stepResults.size();
            assertTrue(successRate >= 0.7, "At least 70% of steps should succeed"); // Allowing for some failure tolerance
            
            // Check final authentication state
            var finalAuthState = replayResult.getFinalAuthState();
            assertNotNull(finalAuthState, "Final auth state should be recorded");
            
            // Check visual comparison if available
            var visualComparison = replayResult.getVisualComparison();
            if (visualComparison != null) {
                assertNotNull(visualComparison, "Visual comparison should be available");
                assertTrue(visualComparison.containsKey("overall_passed"), "Should have overall pass result");
            }
            
            logger.info("Login sequence replay test successful - Success rate: {:.1f}%, Overall: {}", 
                       successRate * 100, replayResult.isOverallSuccess());
            
        } catch (Exception e) {
            logger.error("Login sequence replay test failed", e);
            fail("Login sequence replay failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test visual verification during recording")
    void testVisualVerificationDuringRecording() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(true);
            config.setTimeoutSeconds(30);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            // Record login sequence with visual verification
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            
            // Verify visual verification was performed
            var validation = sequence.getValidationResult();
            assertNotNull(validation, "Validation should not be null");
            
            var visualValidation = validation.getVisualValidation();
            if (visualValidation != null) {
                assertTrue(visualValidation.containsKey("screenshot_count"), "Should track screenshot count");
                assertTrue(visualValidation.containsKey("validation_successful"), "Should have validation status");
                
                var screenshotCount = (Integer) visualValidation.get("screenshot_count");
                assertTrue(screenshotCount > 0, "Should have captured screenshots");
                
                logger.info("Visual verification test successful - Screenshots: {}", screenshotCount);
            } else {
                logger.info("Visual verification not available (expected in some test environments)");
            }
            
            // Verify screenshots are stored in sequence metadata
            var screenshots = (java.util.List<?>) sequence.getMetadata().get("screenshots");
            if (screenshots != null) {
                assertFalse(screenshots.isEmpty(), "Should have screenshots in metadata");
                assertTrue((Boolean) sequence.getMetadata().get("visual_verification"), "Should be marked as visually verified");
            }
            
        } catch (Exception e) {
            logger.error("Visual verification test failed", e);
            fail("Visual verification test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Test login form detection capabilities")
    void testLoginFormDetection() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(false); // Disable screenshots for faster test
            config.setTimeoutSeconds(20);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            // Record login sequence (this will internally test form detection)
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            
            assertNotNull(sequence, "Sequence should be recorded");
            assertTrue(sequence.isComplete(), "Sequence should be complete");
            
            // Verify that form detection worked by checking if form interaction steps exist
            var hasFormSteps = sequence.getSteps().stream()
                .anyMatch(step -> step.getStepType().startsWith("FILL_") || 
                                 step.getStepType().equals("SUBMIT_FORM"));
            
            assertTrue(hasFormSteps, "Should have detected and interacted with login form");
            
            // Check for successful field selector capture
            var usernameStep = sequence.getSteps().stream()
                .filter(step -> "FILL_USERNAME".equals(step.getStepType()))
                .findFirst();
            
            if (usernameStep.isPresent()) {
                var formData = usernameStep.get().getFormData();
                assertTrue(formData.containsKey("field_selector"), "Should capture field selector");
                assertNotNull(formData.get("field_selector"), "Field selector should not be null");
            }
            
            logger.info("Login form detection test successful");
            
        } catch (Exception e) {
            logger.error("Login form detection test failed", e);
            fail("Login form detection test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test security analysis during recording")
    void testSecurityAnalysisDuringRecording() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(false);
            config.setTimeoutSeconds(20);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            // Record login sequence
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            
            // Verify security analysis was performed
            var validation = sequence.getValidationResult();
            assertNotNull(validation, "Validation should not be null");
            
            var securityAnalysis = validation.getSecurityAnalysis();
            assertNotNull(securityAnalysis, "Security analysis should not be null");
            
            // Check security findings
            var findings = securityAnalysis.getFindings();
            assertNotNull(findings, "Security findings should not be null");
            
            // Verify security score
            int securityScore = securityAnalysis.getSecurityScore();
            assertTrue(securityScore >= 0, "Security score should be non-negative");
            assertTrue(securityScore <= 100, "Security score should not exceed 100");
            
            // Check for HTTPS usage (test site should use HTTPS)
            boolean hasHttpsRelatedFinding = findings.stream()
                .anyMatch(finding -> finding.getDescription().toLowerCase().contains("http"));
            
            if (TEST_LOGIN_URL.startsWith("https://")) {
                logger.info("Test site uses HTTPS - Security score: {}", securityScore);
            }
            
            logger.info("Security analysis test successful - Findings: {}, Score: {}", 
                       findings.size(), securityScore);
            
        } catch (Exception e) {
            logger.error("Security analysis test failed", e);
            fail("Security analysis test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test error handling and edge cases")
    void testErrorHandlingAndEdgeCases() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setTimeoutSeconds(10); // Short timeout for faster test
            
            // Test with invalid URL
            assertThrows(Exception.class, () -> {
                recorder.recordAutomatedLogin("invalid-url", config, Map.of());
            }, "Should throw exception for invalid URL");
            
            // Test with empty credentials
            var emptyCredentials = Map.<String, String>of();
            
            try {
                var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, emptyCredentials);
                assertNotNull(sequence, "Should handle empty credentials gracefully");
                // Login should fail but sequence should still be recorded
                assertFalse(sequence.getSteps().isEmpty(), "Should still record navigation steps");
            } catch (Exception e) {
                // This is acceptable - empty credentials might cause various failures
                logger.info("Empty credentials test resulted in expected exception: {}", e.getMessage());
            }
            
            // Test null config
            assertThrows(Exception.class, () -> {
                recorder.recordAutomatedLogin(TEST_LOGIN_URL, null, Map.of());
            }, "Should throw exception for null config");
            
            logger.info("Error handling test successful");
            
        } catch (Exception e) {
            logger.error("Error handling test failed", e);
            fail("Error handling test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(9)
    @DisplayName("Test performance and resource management")
    void testPerformanceAndResourceManagement() {
        try {
            var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
            config.setCaptureScreenshots(false); // Disable for performance test
            config.setTimeoutSeconds(30);
            
            var credentials = Map.of(
                "username", VALID_USERNAME,
                "password", VALID_PASSWORD
            );
            
            // Measure recording performance
            long startTime = System.currentTimeMillis();
            var sequence = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
            long endTime = System.currentTimeMillis();
            long recordingDuration = endTime - startTime;
            
            assertNotNull(sequence, "Sequence should be recorded");
            assertTrue(recordingDuration < 60000, "Recording should complete within 60 seconds");
            
            // Test multiple sequential recordings (resource reuse)
            startTime = System.currentTimeMillis();
            for (int i = 0; i < 2; i++) {
                var sequenceMultiple = recorder.recordAutomatedLogin(TEST_LOGIN_URL, config, credentials);
                assertNotNull(sequenceMultiple, "Multiple recordings should succeed");
            }
            endTime = System.currentTimeMillis();
            long multipleRecordingDuration = endTime - startTime;
            
            // Verify resource cleanup (browser sessions should be properly closed)
            var browserSessions = browserManager.getSessions();
            assertEquals(0, browserSessions.size(), "All browser sessions should be cleaned up");
            
            logger.info("Performance test successful - Single: {}ms, Multiple: {}ms", 
                       recordingDuration, multipleRecordingDuration);
            
        } catch (Exception e) {
            logger.error("Performance test failed", e);
            fail("Performance test failed: " + e.getMessage());
        }
    }
    
    /**
     * Utility method to check Chrome availability
     */
    private static boolean checkChromeAvailability() {
        try {
            var options = new org.openqa.selenium.chrome.ChromeOptions();
            options.addArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage");
            var driver = new org.openqa.selenium.chrome.ChromeDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.warn("Chrome driver not available for login sequence tests: {}", e.getMessage());
            return false;
        }
    }
}
