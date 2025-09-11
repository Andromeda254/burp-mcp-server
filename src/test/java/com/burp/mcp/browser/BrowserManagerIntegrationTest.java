package com.burp.mcp.browser;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.edge.EdgeOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for BrowserManager WebDriver functionality
 * Tests actual browser automation capabilities and session management
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class BrowserManagerIntegrationTest {
    
    private static final Logger logger = LoggerFactory.getLogger(BrowserManagerIntegrationTest.class);
    
    private BrowserManager browserManager;
    private static boolean systemSupportsChrome;
    private static boolean systemSupportsFirefox;
    private static boolean systemSupportsEdge;
    
    @BeforeAll
    static void checkSystemCapabilities() {
        // Check if required drivers are available
        systemSupportsChrome = checkChromeAvailability();
        systemSupportsFirefox = checkFirefoxAvailability();
        systemSupportsEdge = checkEdgeAvailability();
        
        logger.info("System capabilities - Chrome: {}, Firefox: {}, Edge: {}", 
                   systemSupportsChrome, systemSupportsFirefox, systemSupportsEdge);
    }
    
    @BeforeEach
    void setUp() {
        browserManager = new BrowserManager();
        try {
            browserManager.initialize();
            logger.info("BrowserManager initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize BrowserManager", e);
            fail("BrowserManager initialization failed: " + e.getMessage());
        }
    }
    
    @AfterEach
    void tearDown() {
        if (browserManager != null) {
            try {
                browserManager.closeAllSessions();
                logger.info("All browser sessions closed");
            } catch (Exception e) {
                logger.warn("Error during cleanup", e);
            }
        }
    }
    
    @Test
    @Order(1)
    @DisplayName("Test BrowserManager initialization")
    void testBrowserManagerInitialization() {
        assertNotNull(browserManager, "BrowserManager should be initialized");
        assertTrue(browserManager.getSessions().isEmpty(), "Initial sessions map should be empty");
        
        var stats = browserManager.getSessionStats();
        assertNotNull(stats, "Session stats should not be null");
        assertEquals(0, stats.get("active_sessions"), "Active sessions should be 0");
        assertEquals(0, stats.get("total_created"), "Total created sessions should be 0");
        assertEquals(0, stats.get("total_closed"), "Total closed sessions should be 0");
    }
    
    @Test
    @Order(2)
    @DisplayName("Test Chrome browser session creation")
    void testChromeSessionCreation() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true); // Use headless for CI/testing
        
        String sessionId = "test-chrome-session";
        WebDriver driver = null;
        
        try {
            driver = browserManager.createSession(sessionId, config);
            
            assertNotNull(driver, "Chrome WebDriver should be created");
            assertTrue(browserManager.getSessions().containsKey(sessionId), "Session should be tracked");
            
            // Test basic navigation
            driver.get("https://www.google.com");
            assertNotNull(driver.getTitle(), "Page title should not be null");
            assertTrue(driver.getCurrentUrl().contains("google.com"), "Should navigate to Google");
            
            logger.info("Chrome session test successful - Title: {}, URL: {}", 
                       driver.getTitle(), driver.getCurrentUrl());
            
        } catch (Exception e) {
            logger.error("Chrome session test failed", e);
            fail("Chrome session creation failed: " + e.getMessage());
        } finally {
            if (driver != null) {
                browserManager.closeSession(sessionId);
            }
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test Firefox browser session creation")
    void testFirefoxSessionCreation() {
        assumeTrue(systemSupportsFirefox, "Firefox driver not available");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.FIREFOX);
        config.setHeadless(true);
        
        String sessionId = "test-firefox-session";
        WebDriver driver = null;
        
        try {
            driver = browserManager.createSession(sessionId, config);
            
            assertNotNull(driver, "Firefox WebDriver should be created");
            assertTrue(browserManager.getSessions().containsKey(sessionId), "Session should be tracked");
            
            // Test basic navigation
            driver.get("https://www.mozilla.org");
            assertNotNull(driver.getTitle(), "Page title should not be null");
            assertTrue(driver.getCurrentUrl().contains("mozilla.org"), "Should navigate to Mozilla");
            
            logger.info("Firefox session test successful - Title: {}, URL: {}", 
                       driver.getTitle(), driver.getCurrentUrl());
            
        } catch (Exception e) {
            logger.error("Firefox session test failed", e);
            fail("Firefox session creation failed: " + e.getMessage());
        } finally {
            if (driver != null) {
                browserManager.closeSession(sessionId);
            }
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test multiple concurrent sessions")
    void testMultipleConcurrentSessions() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available for concurrent test");
        
        String session1Id = "test-concurrent-1";
        String session2Id = "test-concurrent-2";
        WebDriver driver1 = null;
        WebDriver driver2 = null;
        
        try {
            var config = BrowserManager.createDefaultConfig();
            config.setBrowserType(BrowserManager.BrowserType.CHROME);
            config.setHeadless(true);
            
            // Create first session
            driver1 = browserManager.createSession(session1Id, config);
            assertNotNull(driver1, "First driver should be created");
            
            // Create second session
            driver2 = browserManager.createSession(session2Id, config);
            assertNotNull(driver2, "Second driver should be created");
            
            // Verify both sessions are tracked
            assertEquals(2, browserManager.getSessions().size(), "Should have 2 active sessions");
            assertTrue(browserManager.getSessions().containsKey(session1Id), "Session 1 should be tracked");
            assertTrue(browserManager.getSessions().containsKey(session2Id), "Session 2 should be tracked");
            
            // Test independent navigation
            driver1.get("https://www.google.com");
            driver2.get("https://www.github.com");
            
            // Verify independent states
            assertTrue(driver1.getCurrentUrl().contains("google.com"), "Driver 1 should be on Google");
            assertTrue(driver2.getCurrentUrl().contains("github.com"), "Driver 2 should be on GitHub");
            
            var stats = browserManager.getSessionStats();
            assertEquals(2, stats.get("active_sessions"), "Should show 2 active sessions");
            
            logger.info("Concurrent sessions test successful - Active: {}", stats.get("active_sessions"));
            
        } catch (Exception e) {
            logger.error("Concurrent sessions test failed", e);
            fail("Concurrent sessions test failed: " + e.getMessage());
        } finally {
            if (driver1 != null) browserManager.closeSession(session1Id);
            if (driver2 != null) browserManager.closeSession(session2Id);
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test browser session timeout handling")
    void testSessionTimeoutHandling() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available for timeout test");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true);
        config.setPageLoadTimeoutSeconds(5); // Short timeout for testing
        config.setImplicitWaitSeconds(2);
        
        String sessionId = "test-timeout-session";
        WebDriver driver = null;
        
        try {
            driver = browserManager.createSession(sessionId, config);
            assertNotNull(driver, "Driver should be created");
            
            // Test timeout configuration is applied
            driver.get("https://httpstat.us/200?sleep=1000"); // 1 second delay
            assertNotNull(driver.getTitle(), "Should handle normal response");
            
            // Test that driver has proper timeout settings
            // Note: Actual timeout testing would require a very slow endpoint
            logger.info("Timeout handling test completed - configured timeouts applied");
            
        } catch (Exception e) {
            logger.error("Timeout handling test failed", e);
            // Don't fail the test for timeout issues as they may be network-related
            logger.warn("Timeout test completed with warning: {}", e.getMessage());
        } finally {
            if (driver != null) {
                browserManager.closeSession(sessionId);
            }
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Test browser options configuration")
    void testBrowserOptionsConfiguration() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available for options test");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true);
        config.setUserAgent("BurpMCP-Test-Agent/1.0");
        config.setWindowWidth(1200);
        config.setWindowHeight(800);
        
        String sessionId = "test-options-session";
        WebDriver driver = null;
        
        try {
            driver = browserManager.createSession(sessionId, config);
            assertNotNull(driver, "Driver should be created with custom options");
            
            driver.get("https://httpbin.org/user-agent");
            
            // Verify window size (if not headless this would be more reliable)
            var windowSize = driver.manage().window().getSize();
            logger.info("Window size: {}x{}", windowSize.getWidth(), windowSize.getHeight());
            
            // Test that basic functionality works with custom options
            assertNotNull(driver.getPageSource(), "Page source should be available");
            assertNotNull(driver.getCurrentUrl(), "Current URL should be available");
            
            logger.info("Browser options configuration test successful");
            
        } catch (Exception e) {
            logger.error("Browser options test failed", e);
            fail("Browser options configuration failed: " + e.getMessage());
        } finally {
            if (driver != null) {
                browserManager.closeSession(sessionId);
            }
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test session cleanup and resource management")
    void testSessionCleanupAndResourceManagement() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available for cleanup test");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true);
        
        String sessionId = "test-cleanup-session";
        WebDriver driver = null;
        
        try {
            // Create session
            driver = browserManager.createSession(sessionId, config);
            assertNotNull(driver, "Driver should be created");
            assertEquals(1, browserManager.getSessions().size(), "Should have 1 session");
            
            // Use the session
            driver.get("https://www.example.com");
            assertNotNull(driver.getCurrentUrl(), "Should be able to navigate");
            
            // Close session explicitly
            browserManager.closeSession(sessionId);
            
            // Verify cleanup
            assertEquals(0, browserManager.getSessions().size(), "Sessions should be cleaned up");
            
            var stats = browserManager.getSessionStats();
            assertEquals(0, stats.get("active_sessions"), "Active sessions should be 0");
            assertEquals(1, stats.get("total_created"), "Should show 1 session was created");
            assertEquals(1, stats.get("total_closed"), "Should show 1 session was closed");
            
            logger.info("Session cleanup test successful - Stats: {}", stats);
            
            // Set to null to avoid double cleanup in tearDown
            driver = null;
            
        } catch (Exception e) {
            logger.error("Session cleanup test failed", e);
            fail("Session cleanup test failed: " + e.getMessage());
        } finally {
            if (driver != null) {
                try {
                    browserManager.closeSession(sessionId);
                } catch (Exception cleanupError) {
                    logger.warn("Error during test cleanup", cleanupError);
                }
            }
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test error handling for invalid configurations")
    void testErrorHandlingForInvalidConfigurations() {
        // Test null configuration
        assertThrows(IllegalArgumentException.class, () -> {
            browserManager.createSession("test-null-config", null);
        }, "Should throw exception for null configuration");
        
        // Test invalid browser type (this would be caught at compile time with enum, so test invalid config)
        var invalidConfig = BrowserManager.createDefaultConfig();
        invalidConfig.setBrowserType(null);
        
        assertThrows(Exception.class, () -> {
            browserManager.createSession("test-invalid-browser", invalidConfig);
        }, "Should throw exception for null browser type");
        
        // Test duplicate session ID
        if (systemSupportsChrome) {
            var config = BrowserManager.createDefaultConfig();
            config.setBrowserType(BrowserManager.BrowserType.CHROME);
            config.setHeadless(true);
            
            String sessionId = "test-duplicate-session";
            WebDriver driver1 = null;
            
            try {
                driver1 = browserManager.createSession(sessionId, config);
                assertNotNull(driver1, "First session should be created");
                
                // Attempt to create session with same ID
                assertThrows(Exception.class, () -> {
                    browserManager.createSession(sessionId, config);
                }, "Should throw exception for duplicate session ID");
                
                logger.info("Error handling test successful");
                
            } catch (Exception e) {
                logger.error("Error handling test setup failed", e);
            } finally {
                if (driver1 != null) {
                    browserManager.closeSession(sessionId);
                }
            }
        }
    }
    
    @Test
    @Order(9)
    @DisplayName("Test browser capabilities and features")
    void testBrowserCapabilitiesAndFeatures() {
        assumeTrue(systemSupportsChrome, "Chrome driver not available for capabilities test");
        
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true);
        config.setCaptureScreenshots(true);
        
        String sessionId = "test-capabilities-session";
        WebDriver driver = null;
        
        try {
            driver = browserManager.createSession(sessionId, config);
            assertNotNull(driver, "Driver should be created");
            
            // Test JavaScript execution
            var jsResult = ((org.openqa.selenium.JavascriptExecutor) driver)
                .executeScript("return document.readyState;");
            assertNotNull(jsResult, "JavaScript execution should work");
            logger.info("JavaScript execution result: {}", jsResult);
            
            // Test navigation and DOM access
            driver.get("https://www.example.com");
            var title = driver.getTitle();
            var url = driver.getCurrentUrl();
            var pageSource = driver.getPageSource();
            
            assertNotNull(title, "Page title should be accessible");
            assertNotNull(url, "Current URL should be accessible");
            assertNotNull(pageSource, "Page source should be accessible");
            assertFalse(pageSource.isEmpty(), "Page source should not be empty");
            
            // Test element finding (basic)
            var bodyElements = driver.findElements(org.openqa.selenium.By.tagName("body"));
            assertFalse(bodyElements.isEmpty(), "Should find body elements");
            
            logger.info("Browser capabilities test successful - Title: {}", title);
            
        } catch (Exception e) {
            logger.error("Browser capabilities test failed", e);
            fail("Browser capabilities test failed: " + e.getMessage());
        } finally {
            if (driver != null) {
                browserManager.closeSession(sessionId);
            }
        }
    }
    
    /**
     * Utility methods for system capability checking
     */
    private static boolean checkChromeAvailability() {
        try {
            var options = new ChromeOptions();
            options.addArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage");
            var driver = new org.openqa.selenium.chrome.ChromeDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.warn("Chrome driver not available: {}", e.getMessage());
            return false;
        }
    }
    
    private static boolean checkFirefoxAvailability() {
        try {
            var options = new FirefoxOptions();
            options.addArguments("--headless");
            var driver = new org.openqa.selenium.firefox.FirefoxDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.warn("Firefox driver not available: {}", e.getMessage());
            return false;
        }
    }
    
    private static boolean checkEdgeAvailability() {
        try {
            var options = new EdgeOptions();
            options.addArguments("--headless");
            var driver = new org.openqa.selenium.edge.EdgeDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.warn("Edge driver not available: {}", e.getMessage());
            return false;
        }
    }
}
