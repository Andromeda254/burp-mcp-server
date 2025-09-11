package com.burp.mcp.browser;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for ScreenshotCapture with real WebDriver instances
 * Tests screenshot capture, comparison, and visual verification capabilities
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ScreenshotCaptureIntegrationTest {
    
    private static final Logger logger = LoggerFactory.getLogger(ScreenshotCaptureIntegrationTest.class);
    
    private BrowserManager browserManager;
    private WebDriver driver;
    private String testSessionId;
    private static boolean systemSupportsChrome;
    
    @TempDir
    Path tempDir;
    
    @BeforeAll
    static void checkSystemCapabilities() {
        systemSupportsChrome = checkChromeAvailability();
        logger.info("System supports Chrome: {}", systemSupportsChrome);
    }
    
    @BeforeEach
    void setUp() {
        assumeTrue(systemSupportsChrome, "Chrome driver required for screenshot tests");
        
        browserManager = new BrowserManager();
        testSessionId = "screenshot-test-session-" + System.currentTimeMillis();
        
        try {
            browserManager.initialize();
            
            var config = BrowserManager.createDefaultConfig();
            config.setBrowserType(BrowserManager.BrowserType.CHROME);
            config.setHeadless(true);
            config.setWindowWidth(1200);
            config.setWindowHeight(800);
            config.setCaptureScreenshots(true);
            
            driver = browserManager.createSession(testSessionId, config);
            logger.info("Test setup completed with session: {}", testSessionId);
            
        } catch (Exception e) {
            logger.error("Test setup failed", e);
            fail("Test setup failed: " + e.getMessage());
        }
    }
    
    @AfterEach
    void tearDown() {
        if (browserManager != null && testSessionId != null) {
            try {
                browserManager.closeSession(testSessionId);
                logger.info("Test session closed: {}", testSessionId);
            } catch (Exception e) {
                logger.warn("Error closing test session", e);
            }
        }
        
        // Clear screenshot cache
        ScreenshotCapture.clearCache();
    }
    
    @Test
    @Order(1)
    @DisplayName("Test basic screenshot capture")
    void testBasicScreenshotCapture() {
        try {
            // Navigate to test page
            driver.get("https://www.example.com");
            Thread.sleep(2000); // Wait for page load
            
            var config = ScreenshotCapture.createDefaultConfig();
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            config.setIncludeMetadata(true);
            
            // Capture screenshot
            var future = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot = future.get(10, TimeUnit.SECONDS);
            
            // Verify screenshot data
            assertNotNull(screenshot, "Screenshot should not be null");
            assertNotNull(screenshot.getImageData(), "Image data should not be null");
            assertTrue(screenshot.getImageData().length > 0, "Image data should not be empty");
            assertTrue(screenshot.getWidth() > 0, "Width should be positive");
            assertTrue(screenshot.getHeight() > 0, "Height should be positive");
            assertEquals("PNG", screenshot.getImageFormat(), "Default format should be PNG");
            
            // Verify metadata
            var metadata = screenshot.getMetadata();
            assertNotNull(metadata, "Metadata should not be null");
            assertTrue(metadata.containsKey("user_agent"), "Should contain user agent");
            assertTrue(metadata.containsKey("viewport_width"), "Should contain viewport width");
            assertTrue(metadata.containsKey("viewport_height"), "Should contain viewport height");
            assertTrue(metadata.containsKey("domain"), "Should contain domain");
            
            logger.info("Basic screenshot capture test successful - Size: {}x{}, Data: {}KB", 
                       screenshot.getWidth(), screenshot.getHeight(), screenshot.getImageData().length / 1024);
            
        } catch (Exception e) {
            logger.error("Basic screenshot capture test failed", e);
            fail("Screenshot capture failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(2)
    @DisplayName("Test full page screenshot capture")
    void testFullPageScreenshotCapture() {
        try {
            // Navigate to a longer page
            driver.get("https://en.wikipedia.org/wiki/Selenium_(software)");
            Thread.sleep(3000); // Wait for page load
            
            var config = ScreenshotCapture.createFullPageConfig();
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            
            // Capture full page screenshot
            var future = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot = future.get(30, TimeUnit.SECONDS); // Longer timeout for full page
            
            // Verify full page screenshot
            assertNotNull(screenshot, "Full page screenshot should not be null");
            assertTrue(screenshot.getImageData().length > 0, "Image data should not be empty");
            assertTrue(screenshot.getHeight() > 800, "Full page should be taller than viewport");
            
            // Verify it's marked as full page in metadata
            var metadata = screenshot.getMetadata();
            assertEquals(true, metadata.get("config_full_page"), "Should be marked as full page");
            
            logger.info("Full page screenshot test successful - Size: {}x{}, Data: {}KB", 
                       screenshot.getWidth(), screenshot.getHeight(), screenshot.getImageData().length / 1024);
            
        } catch (Exception e) {
            logger.error("Full page screenshot test failed", e);
            fail("Full page screenshot failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test screenshot with file saving")
    void testScreenshotWithFileSaving() {
        try {
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            var config = ScreenshotCapture.createDefaultConfig();
            config.setSaveToFile(true);
            config.setOutputDirectory(tempDir.toString());
            config.setIncludeInCache(true);
            
            // Capture screenshot with file saving
            var future = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot = future.get(10, TimeUnit.SECONDS);
            
            // Verify file was saved
            assertNotNull(screenshot.getFilePath(), "File path should not be null");
            var file = new java.io.File(screenshot.getFilePath());
            assertTrue(file.exists(), "Screenshot file should exist");
            assertTrue(file.length() > 0, "Screenshot file should not be empty");
            
            // Verify file content matches image data
            var fileBytes = java.nio.file.Files.readAllBytes(file.toPath());
            assertArrayEquals(screenshot.getImageData(), fileBytes, "File content should match image data");
            
            logger.info("Screenshot file saving test successful - File: {}, Size: {}KB", 
                       screenshot.getFilePath(), file.length() / 1024);
            
        } catch (Exception e) {
            logger.error("Screenshot file saving test failed", e);
            fail("Screenshot file saving failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test screenshot element highlighting")
    void testScreenshotElementHighlighting() {
        try {
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            var config = ScreenshotCapture.createElementConfig("h1");
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            
            // Capture screenshot with element highlighting
            var future = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot = future.get(10, TimeUnit.SECONDS);
            
            // Verify screenshot was captured
            assertNotNull(screenshot, "Screenshot with highlighting should not be null");
            assertTrue(screenshot.getImageData().length > 0, "Image data should not be empty");
            
            // Verify highlighting configuration in metadata
            var metadata = screenshot.getMetadata();
            var elementsHighlighted = (java.util.List<?>) metadata.get("elements_highlighted");
            assertNotNull(elementsHighlighted, "Should contain highlighted elements");
            assertFalse(elementsHighlighted.isEmpty(), "Should have highlighted elements");
            assertTrue(elementsHighlighted.contains("h1"), "Should contain h1 element");
            
            logger.info("Screenshot element highlighting test successful");
            
        } catch (Exception e) {
            logger.error("Screenshot element highlighting test failed", e);
            fail("Screenshot element highlighting failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test screenshot comparison functionality")
    void testScreenshotComparison() {
        try {
            // Capture first screenshot
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            var config = ScreenshotCapture.createDefaultConfig();
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            
            var future1 = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot1 = future1.get(10, TimeUnit.SECONDS);
            
            // Capture second screenshot of same page (should be identical)
            var future2 = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot2 = future2.get(10, TimeUnit.SECONDS);
            
            // Compare identical screenshots
            var comparison = ScreenshotCapture.compareScreenshots(screenshot1, screenshot2, 0.95);
            
            assertNotNull(comparison, "Comparison result should not be null");
            assertTrue(comparison.getSimilarity() > 0.95, "Identical screenshots should have high similarity");
            assertTrue(comparison.isPassed(), "Comparison should pass for identical screenshots");
            assertEquals(0.95, comparison.getThreshold(), 0.001, "Threshold should match");
            
            // Verify metrics
            var metrics = comparison.getMetrics();
            assertNotNull(metrics, "Metrics should not be null");
            assertTrue(metrics.containsKey("total_pixels"), "Should contain total pixels");
            assertTrue(metrics.containsKey("different_pixels"), "Should contain different pixels");
            assertTrue(metrics.containsKey("similarity_percentage"), "Should contain similarity percentage");
            
            logger.info("Screenshot comparison test successful - Similarity: {}, Passed: {}", 
                       comparison.getSimilarity(), comparison.isPassed());
            
            // Test comparison with different page
            driver.get("https://www.github.com");
            Thread.sleep(3000);
            
            var future3 = ScreenshotCapture.captureScreenshot(driver, config);
            var screenshot3 = future3.get(10, TimeUnit.SECONDS);
            
            var comparisonDifferent = ScreenshotCapture.compareScreenshots(screenshot1, screenshot3, 0.95);
            assertTrue(comparisonDifferent.getSimilarity() < 0.95, "Different pages should have low similarity");
            assertFalse(comparisonDifferent.isPassed(), "Comparison should fail for different pages");
            
            logger.info("Different page comparison - Similarity: {}, Passed: {}", 
                       comparisonDifferent.getSimilarity(), comparisonDifferent.isPassed());
            
        } catch (Exception e) {
            logger.error("Screenshot comparison test failed", e);
            fail("Screenshot comparison failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Test screenshot cache functionality")
    void testScreenshotCache() {
        try {
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            var config = ScreenshotCapture.createDefaultConfig();
            config.setSaveToFile(false);
            config.setIncludeInCache(true);
            
            // Capture multiple screenshots
            var screenshot1 = ScreenshotCapture.captureScreenshot(driver, config).get(10, TimeUnit.SECONDS);
            var screenshot2 = ScreenshotCapture.captureScreenshot(driver, config).get(10, TimeUnit.SECONDS);
            var screenshot3 = ScreenshotCapture.captureScreenshot(driver, config).get(10, TimeUnit.SECONDS);
            
            // Test cache retrieval
            var cachedScreenshot1 = ScreenshotCapture.getScreenshotFromCache(screenshot1.getId());
            assertNotNull(cachedScreenshot1, "Should retrieve screenshot from cache");
            assertEquals(screenshot1.getId(), cachedScreenshot1.getId(), "IDs should match");
            
            // Test cache listing
            var allCached = ScreenshotCapture.getAllCachedScreenshots();
            assertTrue(allCached.size() >= 3, "Should have at least 3 cached screenshots");
            assertTrue(allCached.containsKey(screenshot1.getId()), "Should contain screenshot 1");
            assertTrue(allCached.containsKey(screenshot2.getId()), "Should contain screenshot 2");
            assertTrue(allCached.containsKey(screenshot3.getId()), "Should contain screenshot 3");
            
            logger.info("Screenshot cache test successful - Cached: {}", allCached.size());
            
            // Test cache clearing
            ScreenshotCapture.clearCache();
            var clearedCache = ScreenshotCapture.getAllCachedScreenshots();
            assertTrue(clearedCache.isEmpty(), "Cache should be empty after clearing");
            
            logger.info("Screenshot cache clearing test successful");
            
        } catch (Exception e) {
            logger.error("Screenshot cache test failed", e);
            fail("Screenshot cache test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test screenshot image quality and format")
    void testScreenshotImageQualityAndFormat() {
        try {
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            // Test PNG format
            var pngConfig = ScreenshotCapture.createDefaultConfig();
            pngConfig.setImageFormat("PNG");
            pngConfig.setSaveToFile(false);
            pngConfig.setIncludeInCache(false);
            
            var pngScreenshot = ScreenshotCapture.captureScreenshot(driver, pngConfig).get(10, TimeUnit.SECONDS);
            assertEquals("PNG", pngScreenshot.getImageFormat(), "Format should be PNG");
            
            // Verify image can be decoded
            var pngImage = ImageIO.read(new ByteArrayInputStream(pngScreenshot.getImageData()));
            assertNotNull(pngImage, "PNG image should be decodable");
            assertEquals(pngScreenshot.getWidth(), pngImage.getWidth(), "Width should match");
            assertEquals(pngScreenshot.getHeight(), pngImage.getHeight(), "Height should match");
            
            // Test image size constraints
            var constrainedConfig = ScreenshotCapture.createDefaultConfig();
            constrainedConfig.setSaveToFile(false);
            constrainedConfig.setIncludeInCache(false);
            constrainedConfig.setMaxWidth(800);
            constrainedConfig.setMaxHeight(600);
            
            var constrainedScreenshot = ScreenshotCapture.captureScreenshot(driver, constrainedConfig).get(10, TimeUnit.SECONDS);
            assertTrue(constrainedScreenshot.getWidth() <= 800, "Width should be constrained");
            assertTrue(constrainedScreenshot.getHeight() <= 600, "Height should be constrained");
            
            logger.info("Image quality test successful - PNG: {}x{}, Constrained: {}x{}", 
                       pngScreenshot.getWidth(), pngScreenshot.getHeight(),
                       constrainedScreenshot.getWidth(), constrainedScreenshot.getHeight());
            
        } catch (Exception e) {
            logger.error("Screenshot image quality test failed", e);
            fail("Screenshot image quality test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test screenshot error handling")
    void testScreenshotErrorHandling() {
        try {
            // Test with null driver
            var config = ScreenshotCapture.createDefaultConfig();
            
            assertThrows(Exception.class, () -> {
                ScreenshotCapture.captureScreenshot(null, config).get(10, TimeUnit.SECONDS);
            }, "Should throw exception for null driver");
            
            // Test with null config
            assertThrows(Exception.class, () -> {
                ScreenshotCapture.captureScreenshot(driver, null).get(10, TimeUnit.SECONDS);
            }, "Should throw exception for null config");
            
            // Test invalid output directory
            var invalidConfig = ScreenshotCapture.createDefaultConfig();
            invalidConfig.setSaveToFile(true);
            invalidConfig.setOutputDirectory("/invalid/path/that/does/not/exist");
            
            // This should handle the error gracefully or throw appropriate exception
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            assertThrows(Exception.class, () -> {
                ScreenshotCapture.captureScreenshot(driver, invalidConfig).get(10, TimeUnit.SECONDS);
            }, "Should handle invalid output directory");
            
            logger.info("Screenshot error handling test successful");
            
        } catch (Exception e) {
            logger.error("Screenshot error handling test failed", e);
            fail("Screenshot error handling test failed: " + e.getMessage());
        }
    }
    
    @Test
    @Order(9)
    @DisplayName("Test screenshot performance and timeout")
    void testScreenshotPerformanceAndTimeout() {
        try {
            driver.get("https://www.example.com");
            Thread.sleep(2000);
            
            var config = ScreenshotCapture.createDefaultConfig();
            config.setSaveToFile(false);
            config.setIncludeInCache(false);
            
            // Measure screenshot capture time
            long startTime = System.currentTimeMillis();
            var screenshot = ScreenshotCapture.captureScreenshot(driver, config).get(10, TimeUnit.SECONDS);
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            assertNotNull(screenshot, "Screenshot should be captured");
            assertTrue(duration < 10000, "Screenshot should be captured in under 10 seconds");
            
            logger.info("Screenshot performance test successful - Duration: {}ms, Size: {}KB", 
                       duration, screenshot.getImageData().length / 1024);
            
            // Test concurrent screenshots
            var futures = new java.util.ArrayList<java.util.concurrent.CompletableFuture<ScreenshotCapture.ScreenshotData>>();
            
            startTime = System.currentTimeMillis();
            for (int i = 0; i < 3; i++) {
                futures.add(ScreenshotCapture.captureScreenshot(driver, config));
            }
            
            // Wait for all to complete
            for (var future : futures) {
                var result = future.get(15, TimeUnit.SECONDS);
                assertNotNull(result, "Concurrent screenshot should be captured");
            }
            
            endTime = System.currentTimeMillis();
            long concurrentDuration = endTime - startTime;
            
            logger.info("Concurrent screenshot test successful - Total duration: {}ms for 3 screenshots", 
                       concurrentDuration);
            
        } catch (Exception e) {
            logger.error("Screenshot performance test failed", e);
            fail("Screenshot performance test failed: " + e.getMessage());
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
            logger.warn("Chrome driver not available for screenshot tests: {}", e.getMessage());
            return false;
        }
    }
}
