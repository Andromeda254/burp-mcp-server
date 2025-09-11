package com.burp.mcp.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import com.burp.mcp.browser.BrowserManager;
import com.burp.mcp.browser.ScreenshotCapture;
import com.burp.mcp.browser.EnhancedAILoginSequenceRecorder;
import com.burp.mcp.browser.LoginSequenceSupport.LoginSequence;
import com.burp.mcp.browser.LoginSequenceSupport.AuthenticationState;
import com.burp.mcp.browser.LoginSequenceSupport.LoginStep;
import com.burp.mcp.browser.LoginSequenceSupport.StepReplayResult;
import com.burp.mcp.browser.BrowserManager.BrowserSession;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Comprehensive integration tests for browser automation components.
 * Tests end-to-end workflows including WebDriver, screenshot capture, 
 * login recording, and Chrome Extension integration.
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class BrowserAutomationIntegrationTest {
    
    private static MontoyaApi api;
    private static Logging logging;
    
    private BrowserManager browserManager;
    private ScreenshotCapture screenshotCapture;
    private EnhancedAILoginSequenceRecorder loginRecorder;
    
    private static ExecutorService executorService;
    private static Path tempDir;
    
    // Test configuration
    private static final String TEST_TARGET_URL = "https://example.com";
    private static final String TEST_LOGIN_URL = "https://httpbin.org/forms/post";
    private static final int INTEGRATION_TEST_TIMEOUT = 30;
    
    @BeforeAll
    static void setUpClass() throws Exception {
        // Setup test environment
        executorService = Executors.newFixedThreadPool(4);
        tempDir = Files.createTempDirectory("browser-automation-test");
        
        // Mock Burp API
        api = mock(MontoyaApi.class);
        logging = mock(Logging.class);
        when(api.logging()).thenReturn(logging);
        
        // Check system capabilities
        assumeTrue(isSystemCapable(), "System not capable of browser automation tests");
        
        System.out.println("Browser automation integration test environment ready");
    }
    
    @AfterAll
    static void tearDownClass() throws Exception {
        if (executorService != null) {
            executorService.shutdown();
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        }
        
        // Cleanup test directory
        if (tempDir != null && Files.exists(tempDir)) {
            Files.walk(tempDir)
                .sorted((a, b) -> b.compareTo(a)) // Delete files before directories
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception e) {
                        System.err.println("Failed to cleanup: " + path);
                    }
                });
        }
    }
    
    @BeforeEach
    void setUp() {
        browserManager = new BrowserManager(api);
        screenshotCapture = new ScreenshotCapture(api);
        loginRecorder = new EnhancedAILoginSequenceRecorder(api);
        
        // Reset mocks
        reset(logging);
    }
    
    @AfterEach
    void tearDown() {
        // Cleanup browser sessions
        if (browserManager != null) {
            browserManager.cleanupAllSessions();
        }
        
        // Cleanup screenshots
        if (screenshotCapture != null) {
            screenshotCapture.cleanup();
        }
        
        // Cleanup login recorder
        if (loginRecorder != null) {
            loginRecorder.cleanup();
        }
    }
    
    @Test
    @Order(1)
    @DisplayName("Test complete browser session lifecycle")
    void testCompleteBrowserSessionLifecycle() throws Exception {
        // Create browser session
        String sessionId = browserManager.createBrowserSession(
            "chrome", 
            Map.of("headless", true, "target", TEST_TARGET_URL)
        );
        
        assertNotNull(sessionId, "Session ID should not be null");
        
        // Get session details
        BrowserSession session = browserManager.getSession(sessionId);
        assertNotNull(session, "Session should exist");
        assertEquals("chrome", session.getBrowserType());
        assertEquals(TEST_TARGET_URL, session.getTargetUrl());
        assertTrue(session.isActive());
        
        // Navigate to target URL
        boolean navigationSuccess = browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
        assertTrue(navigationSuccess, "Navigation should succeed");
        
        // Get current URL
        String currentUrl = browserManager.getCurrentUrl(sessionId);
        assertEquals(TEST_TARGET_URL, currentUrl);
        
        // Take screenshot
        String screenshotPath = screenshotCapture.captureScreenshot(
            sessionId,
            "lifecycle-test",
            tempDir.toString()
        );
        
        assertNotNull(screenshotPath, "Screenshot path should not be null");
        assertTrue(Files.exists(Paths.get(screenshotPath)), "Screenshot file should exist");
        
        // Close session
        boolean closed = browserManager.closeBrowserSession(sessionId);
        assertTrue(closed, "Session should close successfully");
        
        // Verify session is cleaned up
        BrowserSession closedSession = browserManager.getSession(sessionId);
        assertNull(closedSession, "Session should be cleaned up");
    }
    
    @Test
    @Order(2)
    @DisplayName("Test browser automation with multiple sessions")
    void testMultipleBrowserSessions() throws Exception {
        List<String> sessionIds = new ArrayList<>();
        
        try {
            // Create multiple sessions concurrently
            CompletableFuture<String>[] sessionCreation = new CompletableFuture[3];
            
            for (int i = 0; i < 3; i++) {
                final int sessionIndex = i;
                sessionCreation[i] = CompletableFuture.supplyAsync(() -> {
                    try {
                        return browserManager.createBrowserSession(
                            "chrome",
                            Map.of(
                                "headless", true,
                                "target", TEST_TARGET_URL + "?session=" + sessionIndex
                            )
                        );
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, executorService);
            }
            
            // Wait for all sessions to be created
            CompletableFuture.allOf(sessionCreation).join();
            
            for (CompletableFuture<String> future : sessionCreation) {
                String sessionId = future.get();
                assertNotNull(sessionId);
                sessionIds.add(sessionId);
            }
            
            assertEquals(3, sessionIds.size(), "Should have created 3 sessions");
            assertEquals(3, browserManager.getActiveSessionCount(), "Should have 3 active sessions");
            
            // Test concurrent operations
            CountDownLatch operationsLatch = new CountDownLatch(sessionIds.size());
            List<String> screenshotPaths = Collections.synchronizedList(new ArrayList<>());
            
            for (int i = 0; i < sessionIds.size(); i++) {
                final String sessionId = sessionIds.get(i);
                final int index = i;
                
                executorService.submit(() -> {
                    try {
                        // Navigate
                        browserManager.navigateToUrl(sessionId, TEST_TARGET_URL + "?test=" + index);
                        
                        // Screenshot
                        String path = screenshotCapture.captureScreenshot(
                            sessionId,
                            "concurrent-test-" + index,
                            tempDir.toString()
                        );
                        screenshotPaths.add(path);
                        
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        operationsLatch.countDown();
                    }
                });
            }
            
            assertTrue(operationsLatch.await(30, TimeUnit.SECONDS), "Concurrent operations should complete");
            assertEquals(3, screenshotPaths.size(), "Should have 3 screenshots");
            
            // Verify all screenshots exist
            for (String path : screenshotPaths) {
                assertTrue(Files.exists(Paths.get(path)), "Screenshot should exist: " + path);
            }
            
        } finally {
            // Cleanup sessions
            sessionIds.forEach(id -> {
                try {
                    browserManager.closeBrowserSession(id);
                } catch (Exception e) {
                    System.err.println("Failed to close session: " + id);
                }
            });
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test screenshot capture with image comparison")
    void testScreenshotCaptureWithComparison() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_TARGET_URL)
        );
        
        try {
            // Navigate to target
            browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
            
            // Take first screenshot
            String screenshot1 = screenshotCapture.captureScreenshot(
                sessionId,
                "comparison-baseline",
                tempDir.toString()
            );
            assertNotNull(screenshot1);
            assertTrue(Files.exists(Paths.get(screenshot1)));
            
            // Navigate to different page
            browserManager.navigateToUrl(sessionId, TEST_TARGET_URL + "/json");
            
            // Take second screenshot
            String screenshot2 = screenshotCapture.captureScreenshot(
                sessionId,
                "comparison-changed",
                tempDir.toString()
            );
            assertNotNull(screenshot2);
            assertTrue(Files.exists(Paths.get(screenshot2)));
            
            // Compare screenshots
            double similarity = screenshotCapture.compareImages(screenshot1, screenshot2);
            assertTrue(similarity >= 0.0 && similarity <= 1.0, "Similarity should be between 0 and 1");
            assertTrue(similarity < 0.9, "Screenshots should be different"); // Different pages should be less similar
            
            // Take screenshot of same page again
            browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
            String screenshot3 = screenshotCapture.captureScreenshot(
                sessionId,
                "comparison-same",
                tempDir.toString()
            );
            
            // Compare with original
            double sameSimilarity = screenshotCapture.compareImages(screenshot1, screenshot3);
            assertTrue(sameSimilarity > 0.8, "Same page screenshots should be very similar");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test login sequence recording and replay")
    void testLoginSequenceRecordingAndReplay() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_LOGIN_URL)
        );
        
        try {
            // Start recording session
            String recordingId = loginRecorder.startRecordingSession(sessionId, TEST_LOGIN_URL);
            assertNotNull(recordingId, "Recording ID should not be null");
            
            // Simulate automated login recording
            Map<String, String> credentials = Map.of(
                "username", "testuser",
                "password", "testpass"
            );
            
            LoginSequence sequence = loginRecorder.performAutomatedLogin(
                sessionId,
                TEST_LOGIN_URL,
                credentials
            );
            
            assertNotNull(sequence, "Login sequence should be recorded");
            assertTrue(sequence.isComplete(), "Sequence should be marked complete");
            assertFalse(sequence.getSteps().isEmpty(), "Sequence should have steps");
            
            // Verify sequence structure
            List<LoginStep> steps = sequence.getSteps();
            assertTrue(steps.size() >= 1, "Should have at least one step");
            
            LoginStep firstStep = steps.get(0);
            assertEquals(TEST_LOGIN_URL, firstStep.getUrl());
            assertNotNull(firstStep.getStepType());
            
            // Test sequence replay
            StepReplayResult replayResult = loginRecorder.replayLoginSequence(sessionId, sequence);
            assertNotNull(replayResult, "Replay result should not be null");
            assertTrue(replayResult.isSuccess(), "Replay should succeed");
            
            // Verify authentication state
            AuthenticationState authState = loginRecorder.detectAuthenticationState(sessionId);
            assertNotNull(authState, "Authentication state should be detected");
            
            // Stop recording session
            boolean stopped = loginRecorder.stopRecordingSession(recordingId);
            assertTrue(stopped, "Recording session should stop successfully");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test login sequence visual verification")
    void testLoginSequenceVisualVerification() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_LOGIN_URL)
        );
        
        try {
            // Record login with visual verification
            String recordingId = loginRecorder.startRecordingSession(sessionId, TEST_LOGIN_URL);
            
            // Take initial screenshot
            String beforeLogin = screenshotCapture.captureScreenshot(
                sessionId,
                "before-login",
                tempDir.toString()
            );
            assertNotNull(beforeLogin);
            
            // Perform login
            Map<String, String> credentials = Map.of(
                "username", "testuser",
                "password", "testpass"
            );
            
            LoginSequence sequence = loginRecorder.performAutomatedLogin(
                sessionId,
                TEST_LOGIN_URL,
                credentials
            );
            
            // Take after login screenshot
            String afterLogin = screenshotCapture.captureScreenshot(
                sessionId,
                "after-login",
                tempDir.toString()
            );
            assertNotNull(afterLogin);
            
            // Visual verification should detect changes
            double visualDifference = screenshotCapture.compareImages(beforeLogin, afterLogin);
            assertTrue(visualDifference < 1.0, "Login should cause visual changes");
            
            // Test replay with visual verification
            boolean replayWithVerification = loginRecorder.replayWithVisualVerification(
                sessionId,
                sequence,
                beforeLogin
            );
            assertTrue(replayWithVerification, "Replay with visual verification should succeed");
            
            loginRecorder.stopRecordingSession(recordingId);
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @ParameterizedTest
    @ValueSource(strings = {"chrome", "firefox"})
    @Order(6)
    @DisplayName("Test cross-browser compatibility")
    void testCrossBrowserCompatibility(String browserType) throws Exception {
        assumeTrue(isBrowserAvailable(browserType), "Browser not available: " + browserType);
        
        String sessionId = browserManager.createBrowserSession(
            browserType,
            Map.of("headless", true, "target", TEST_TARGET_URL)
        );
        
        try {
            // Basic navigation test
            boolean navigated = browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
            assertTrue(navigated, "Navigation should work with " + browserType);
            
            // Screenshot test
            String screenshot = screenshotCapture.captureScreenshot(
                sessionId,
                "cross-browser-" + browserType,
                tempDir.toString()
            );
            assertNotNull(screenshot, "Screenshot should work with " + browserType);
            assertTrue(Files.exists(Paths.get(screenshot)), "Screenshot file should exist");
            
            // Session management test
            BrowserSession session = browserManager.getSession(sessionId);
            assertNotNull(session);
            assertEquals(browserType, session.getBrowserType());
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test Chrome Extension communication")
    void testChromeExtensionCommunication() throws Exception {
        // This test assumes Chrome Extension is installed and configured
        assumeTrue(isChromeExtensionAvailable(), "Chrome Extension not available");
        
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false, // Need non-headless for extension
                "target", TEST_TARGET_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Test extension communication
            Map<String, Object> extensionResult = browserManager.executeExtensionCommand(
                sessionId,
                "getPageInfo",
                Map.of("includeMetrics", true)
            );
            
            assertNotNull(extensionResult, "Extension should respond");
            assertTrue(extensionResult.containsKey("url"), "Should include URL info");
            
            // Test form detection via extension
            browserManager.navigateToUrl(sessionId, TEST_LOGIN_URL);
            
            Map<String, Object> formInfo = browserManager.executeExtensionCommand(
                sessionId,
                "detectForms",
                Map.of()
            );
            
            assertNotNull(formInfo, "Extension should detect forms");
            assertTrue(formInfo.containsKey("forms"), "Should include form information");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test error handling and recovery")
    void testErrorHandlingAndRecovery() throws Exception {
        // Test invalid session operations
        assertThrows(IllegalArgumentException.class, () -> {
            browserManager.navigateToUrl("invalid-session-id", TEST_TARGET_URL);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            screenshotCapture.captureScreenshot("invalid-session-id", "test", tempDir.toString());
        });
        
        // Test recovery from browser crash
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_TARGET_URL)
        );
        
        try {
            // Force session corruption
            browserManager.simulateSessionFailure(sessionId);
            
            // Attempt recovery
            boolean recovered = browserManager.recoverSession(sessionId);
            assertTrue(recovered, "Session should be recoverable");
            
            // Verify functionality after recovery
            boolean navigated = browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
            assertTrue(navigated, "Navigation should work after recovery");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(9)
    @DisplayName("Test performance and resource management")
    void testPerformanceAndResourceManagement() throws Exception {
        long startTime = System.currentTimeMillis();
        List<String> sessionIds = new ArrayList<>();
        
        try {
            // Create multiple sessions to test resource usage
            for (int i = 0; i < 3; i++) {
                String sessionId = browserManager.createBrowserSession(
                    "chrome",
                    Map.of("headless", true, "target", TEST_TARGET_URL + "?perf=" + i)
                );
                sessionIds.add(sessionId);
            }
            
            long sessionCreationTime = System.currentTimeMillis() - startTime;
            assertTrue(sessionCreationTime < 30000, "Session creation should be under 30s");
            
            // Test memory usage
            long initialMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            
            // Perform operations on all sessions
            for (int i = 0; i < sessionIds.size(); i++) {
                String sessionId = sessionIds.get(i);
                browserManager.navigateToUrl(sessionId, TEST_TARGET_URL + "/json");
                screenshotCapture.captureScreenshot(sessionId, "perf-test-" + i, tempDir.toString());
            }
            
            long afterOperationsMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
            long memoryIncrease = afterOperationsMemory - initialMemory;
            
            // Memory increase should be reasonable (less than 500MB)
            assertTrue(memoryIncrease < 500_000_000, "Memory usage should be reasonable");
            
            // Test cleanup efficiency
            long cleanupStart = System.currentTimeMillis();
            sessionIds.forEach(id -> {
                try {
                    browserManager.closeBrowserSession(id);
                } catch (Exception e) {
                    // Ignore cleanup errors for this test
                }
            });
            
            long cleanupTime = System.currentTimeMillis() - cleanupStart;
            assertTrue(cleanupTime < 10000, "Cleanup should be fast");
            
            // Verify all sessions cleaned up
            assertEquals(0, browserManager.getActiveSessionCount(), "All sessions should be cleaned up");
            
        } finally {
            // Ensure cleanup
            sessionIds.forEach(id -> {
                try {
                    browserManager.closeBrowserSession(id);
                } catch (Exception e) {
                    // Ignore cleanup errors
                }
            });
        }
    }
    
    @Test
    @Order(10)
    @DisplayName("Test integration with BurpSuite proxy")
    void testBurpSuiteProxyIntegration() throws Exception {
        // Configure browser with Burp proxy settings
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", true,
                "target", TEST_TARGET_URL,
                "proxy", Map.of(
                    "host", "127.0.0.1",
                    "port", 8080,
                    "protocol", "http"
                ),
                "ignoreSslErrors", true
            )
        );
        
        try {
            // Navigate through proxy
            boolean navigated = browserManager.navigateToUrl(sessionId, TEST_TARGET_URL);
            assertTrue(navigated, "Navigation through proxy should work");
            
            // Verify traffic is intercepted (mock verification)
            Map<String, Object> trafficStats = browserManager.getTrafficStatistics(sessionId);
            assertNotNull(trafficStats, "Traffic statistics should be available");
            assertTrue(trafficStats.containsKey("requestCount"), "Should track request count");
            
            // Test certificate handling with proxy
            String httpsUrl = "https://httpbin.org/get";
            boolean httpsNavigated = browserManager.navigateToUrl(sessionId, httpsUrl);
            assertTrue(httpsNavigated, "HTTPS navigation through proxy should work");
            
            // Take screenshot to verify page loaded correctly
            String screenshot = screenshotCapture.captureScreenshot(
                sessionId,
                "proxy-test",
                tempDir.toString()
            );
            assertNotNull(screenshot, "Screenshot through proxy should work");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    // Utility methods for test setup and assumptions
    
    private static boolean isSystemCapable() {
        try {
            // Check if we have necessary system capabilities
            String os = System.getProperty("os.name").toLowerCase();
            boolean hasDisplay = !Boolean.parseBoolean(System.getProperty("java.awt.headless", "false"));
            
            // For CI/CD environments, we should have headless capability
            return true; // Assume capability for now
            
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isBrowserAvailable(String browserType) {
        try {
            // Mock check - in real implementation, this would check for browser executables
            return Arrays.asList("chrome", "firefox").contains(browserType.toLowerCase());
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isChromeExtensionAvailable() {
        try {
            // Mock check - in real implementation, this would verify extension installation
            return false; // Disabled by default as extension may not be installed
        } catch (Exception e) {
            return false;
        }
    }
}
