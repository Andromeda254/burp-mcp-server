package com.burp.mcp.browser;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Comprehensive test suite for browser automation functionality
 * Orchestrates execution of all browser automation integration tests
 */
@Suite
@SuiteDisplayName("Browser Automation Integration Test Suite")
@SelectClasses({
    BrowserManagerIntegrationTest.class,
    ScreenshotCaptureIntegrationTest.class,
    EnhancedAILoginSequenceRecorderIntegrationTest.class
})
public class BrowserAutomationTestSuite {
    
    private static final Logger logger = LoggerFactory.getLogger(BrowserAutomationTestSuite.class);
    
    @BeforeAll
    static void setUpSuite() {
        logger.info("=".repeat(80));
        logger.info("STARTING BROWSER AUTOMATION INTEGRATION TEST SUITE");
        logger.info("=".repeat(80));
        
        // Log system information
        logger.info("Java Version: {}", System.getProperty("java.version"));
        logger.info("Operating System: {} {}", System.getProperty("os.name"), System.getProperty("os.version"));
        logger.info("Architecture: {}", System.getProperty("os.arch"));
        logger.info("Working Directory: {}", System.getProperty("user.dir"));
        
        // Log browser driver availability
        checkBrowserDriverAvailability();
        
        // Set up system properties for testing
        setupSystemProperties();
    }
    
    @AfterAll
    static void tearDownSuite() {
        logger.info("=".repeat(80));
        logger.info("BROWSER AUTOMATION INTEGRATION TEST SUITE COMPLETED");
        logger.info("=".repeat(80));
        
        // Clean up any remaining resources
        cleanup();
    }
    
    /**
     * Check availability of browser drivers for testing
     */
    private static void checkBrowserDriverAvailability() {
        logger.info("Checking browser driver availability...");
        
        boolean chromeAvailable = checkChromeDriver();
        boolean firefoxAvailable = checkFirefoxDriver();
        boolean edgeAvailable = checkEdgeDriver();
        
        logger.info("Chrome WebDriver: {}", chromeAvailable ? "AVAILABLE" : "NOT AVAILABLE");
        logger.info("Firefox WebDriver: {}", firefoxAvailable ? "AVAILABLE" : "NOT AVAILABLE");
        logger.info("Edge WebDriver: {}", edgeAvailable ? "AVAILABLE" : "NOT AVAILABLE");
        
        if (!chromeAvailable && !firefoxAvailable && !edgeAvailable) {
            logger.warn("NO BROWSER DRIVERS AVAILABLE - Tests will be skipped");
            logger.warn("Install ChromeDriver, GeckoDriver (Firefox), or EdgeDriver to run tests");
        }
    }
    
    /**
     * Set up system properties for optimal test execution
     */
    private static void setupSystemProperties() {
        // Set headless mode for CI environments
        if (isRunningInCI()) {
            System.setProperty("browser.headless", "true");
            logger.info("CI environment detected - enabling headless mode");
        }
        
        // Set reasonable timeouts
        System.setProperty("selenium.webdriver.timeout", "30");
        System.setProperty("selenium.pageload.timeout", "30");
        System.setProperty("selenium.script.timeout", "30");
        
        // Configure screenshot directory
        System.setProperty("screenshot.output.dir", System.getProperty("java.io.tmpdir") + "/browser-automation-tests");
        
        // Enable debug logging if requested
        if (Boolean.getBoolean("test.debug")) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "DEBUG");
            logger.info("Debug logging enabled");
        }
        
        logger.info("System properties configured for testing");
    }
    
    /**
     * Check if running in CI environment
     */
    private static boolean isRunningInCI() {
        return System.getenv("CI") != null || 
               System.getenv("CONTINUOUS_INTEGRATION") != null ||
               System.getenv("GITHUB_ACTIONS") != null ||
               System.getenv("JENKINS_URL") != null ||
               System.getenv("TRAVIS") != null;
    }
    
    /**
     * Check Chrome WebDriver availability
     */
    private static boolean checkChromeDriver() {
        try {
            var options = new org.openqa.selenium.chrome.ChromeOptions();
            options.addArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu");
            var driver = new org.openqa.selenium.chrome.ChromeDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.debug("Chrome driver check failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Check Firefox WebDriver availability
     */
    private static boolean checkFirefoxDriver() {
        try {
            var options = new org.openqa.selenium.firefox.FirefoxOptions();
            options.addArguments("--headless");
            var driver = new org.openqa.selenium.firefox.FirefoxDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.debug("Firefox driver check failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Check Edge WebDriver availability
     */
    private static boolean checkEdgeDriver() {
        try {
            var options = new org.openqa.selenium.edge.EdgeOptions();
            options.addArguments("--headless");
            var driver = new org.openqa.selenium.edge.EdgeDriver(options);
            driver.quit();
            return true;
        } catch (Exception e) {
            logger.debug("Edge driver check failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Clean up resources after test suite
     */
    private static void cleanup() {
        try {
            // Clear any remaining screenshot cache
            ScreenshotCapture.clearCache();
            
            // Clean up temporary files
            var screenshotDir = System.getProperty("screenshot.output.dir");
            if (screenshotDir != null) {
                var dir = new java.io.File(screenshotDir);
                if (dir.exists() && dir.isDirectory()) {
                    var files = dir.listFiles();
                    if (files != null) {
                        for (var file : files) {
                            if (file.getName().startsWith("test-") || file.getName().contains("screenshot-")) {
                                if (file.delete()) {
                                    logger.debug("Cleaned up test file: {}", file.getName());
                                }
                            }
                        }
                    }
                }
            }
            
            logger.info("Test suite cleanup completed");
            
        } catch (Exception e) {
            logger.warn("Error during test suite cleanup: {}", e.getMessage());
        }
    }
}

/**
 * Base test class with common utilities for browser automation tests
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class BaseBrowserAutomationTest {
    
    protected static final Logger logger = LoggerFactory.getLogger(BaseBrowserAutomationTest.class);
    
    // Common test URLs
    protected static final String EXAMPLE_URL = "https://www.example.com";
    protected static final String HTTPBIN_URL = "https://httpbin.org";
    protected static final String THE_INTERNET_URL = "https://the-internet.herokuapp.com";
    
    // Test timeouts
    protected static final int DEFAULT_TIMEOUT_SECONDS = 30;
    protected static final int SHORT_TIMEOUT_SECONDS = 10;
    protected static final int LONG_TIMEOUT_SECONDS = 60;
    
    /**
     * Get browser configuration for testing
     */
    protected BrowserManager.BrowserConfig getTestBrowserConfig() {
        var config = BrowserManager.createDefaultConfig();
        config.setBrowserType(BrowserManager.BrowserType.CHROME);
        config.setHeadless(true);
        config.setWindowWidth(1200);
        config.setWindowHeight(800);
        config.setPageLoadTimeoutSeconds(DEFAULT_TIMEOUT_SECONDS);
        config.setImplicitWaitSeconds(5);
        config.setCaptureScreenshots(true);
        
        // Add CI-specific options
        if (isRunningInCI()) {
            config.setUserAgent("BurpMCP-TestAgent/1.0 (CI)");
        }
        
        return config;
    }
    
    /**
     * Get screenshot configuration for testing
     */
    protected ScreenshotCapture.ScreenshotConfig getTestScreenshotConfig() {
        var config = ScreenshotCapture.createDefaultConfig();
        config.setSaveToFile(false);
        config.setIncludeInCache(true);
        config.setIncludeMetadata(true);
        config.setImageFormat("PNG");
        return config;
    }
    
    /**
     * Get login recording configuration for testing
     */
    protected EnhancedAILoginSequenceRecorder.LoginRecordingConfig getTestLoginRecordingConfig() {
        var config = new EnhancedAILoginSequenceRecorder.LoginRecordingConfig();
        config.setCaptureScreenshots(true);
        config.setAIGuided(true);
        config.setTimeoutSeconds(DEFAULT_TIMEOUT_SECONDS);
        config.setTestReplay(false); // Disable for most tests to save time
        return config;
    }
    
    /**
     * Wait for a condition with timeout
     */
    protected void waitFor(java.util.function.BooleanSupplier condition, int timeoutSeconds, String description) {
        long startTime = System.currentTimeMillis();
        long timeoutMs = timeoutSeconds * 1000L;
        
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() - startTime > timeoutMs) {
                fail("Timeout waiting for: " + description);
            }
            
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("Interrupted while waiting for: " + description);
            }
        }
    }
    
    /**
     * Check if running in CI environment
     */
    protected boolean isRunningInCI() {
        return System.getenv("CI") != null || 
               System.getenv("CONTINUOUS_INTEGRATION") != null ||
               System.getenv("GITHUB_ACTIONS") != null;
    }
    
    /**
     * Assert with retry for flaky operations
     */
    protected void assertWithRetry(java.util.function.BooleanSupplier assertion, String message, int maxRetries) {
        Exception lastException = null;
        
        for (int i = 0; i <= maxRetries; i++) {
            try {
                assertTrue(assertion.getAsBoolean(), message);
                return; // Success
            } catch (Exception e) {
                lastException = e;
                if (i < maxRetries) {
                    logger.debug("Assertion failed, retrying... ({}/{}): {}", i + 1, maxRetries, e.getMessage());
                    try {
                        Thread.sleep(1000); // Wait before retry
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        
        if (lastException instanceof RuntimeException) {
            throw (RuntimeException) lastException;
        } else {
            fail(message + " (after " + maxRetries + " retries)");
        }
    }
}
