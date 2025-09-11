package com.burp.mcp.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import com.burp.mcp.browser.BrowserManager;
import com.burp.mcp.browser.BrowserManager.BrowserType;
import com.burp.mcp.browser.BrowserManager.BrowserSession;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/**
 * WebDriver-specific integration tests focusing on Selenium WebDriver patterns,
 * browser driver management, and WebDriver automation workflows.
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class WebDriverIntegrationTest {
    
    private static MontoyaApi api;
    private static Logging logging;
    
    private BrowserManager browserManager;
    private static ExecutorService executorService;
    
    // Test configuration
    private static final String TEST_BASE_URL = "https://example.com";
    private static final String TEST_FORM_URL = "https://httpbin.org/forms/post";
    private static final String TEST_JSON_URL = "https://httpbin.org/json";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    
    @BeforeAll
    static void setUpClass() {
        executorService = Executors.newCachedThreadPool();
        
        // Mock Burp API
        api = mock(MontoyaApi.class);
        logging = mock(Logging.class);
        when(api.logging()).thenReturn(logging);
        
        System.out.println("WebDriver integration test environment ready");
    }
    
    @AfterAll
    static void tearDownClass() throws InterruptedException {
        if (executorService != null) {
            executorService.shutdown();
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        }
    }
    
    @BeforeEach
    void setUp() {
        browserManager = new BrowserManager(api);
        reset(logging);
    }
    
    @AfterEach
    void tearDown() {
        if (browserManager != null) {
            browserManager.cleanupAllSessions();
        }
    }
    
    @Test
    @Order(1)
    @DisplayName("Test WebDriver initialization patterns")
    void testWebDriverInitializationPatterns() throws Exception {
        // Test standard initialization
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", true,
                "target", TEST_BASE_URL,
                "timeout", 10,
                "windowSize", "1920x1080"
            )
        );
        
        assertNotNull(sessionId, "Session should be created");
        
        BrowserSession session = browserManager.getSession(sessionId);
        assertNotNull(session, "Session should be retrievable");
        assertTrue(session.isActive(), "Session should be active");
        
        // Test WebDriver capabilities
        Map<String, Object> capabilities = browserManager.getWebDriverCapabilities(sessionId);
        assertNotNull(capabilities, "Capabilities should be available");
        assertTrue(capabilities.containsKey("browserName"), "Should have browser name");
        assertTrue(capabilities.containsKey("version"), "Should have browser version");
        
        // Test driver health check
        boolean healthy = browserManager.isWebDriverHealthy(sessionId);
        assertTrue(healthy, "WebDriver should be healthy");
        
        browserManager.closeBrowserSession(sessionId);
    }
    
    @ParameterizedTest
    @EnumSource(BrowserType.class)
    @Order(2)
    @DisplayName("Test WebDriver setup for different browsers")
    void testWebDriverSetupForBrowsers(BrowserType browserType) throws Exception {
        assumeTrue(isBrowserSupported(browserType), "Browser not supported: " + browserType);
        
        String sessionId = browserManager.createBrowserSession(
            browserType.name().toLowerCase(),
            Map.of(
                "headless", true,
                "target", TEST_BASE_URL,
                "browserSpecificOptions", getBrowserSpecificOptions(browserType)
            )
        );
        
        try {
            // Verify browser-specific setup
            BrowserSession session = browserManager.getSession(sessionId);
            assertEquals(browserType.name().toLowerCase(), session.getBrowserType());
            
            // Test browser-specific capabilities
            Map<String, Object> capabilities = browserManager.getWebDriverCapabilities(sessionId);
            assertBrowserSpecificCapabilities(browserType, capabilities);
            
            // Test basic navigation
            boolean navigated = browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            assertTrue(navigated, "Should navigate successfully with " + browserType);
            
            // Verify current URL
            String currentUrl = browserManager.getCurrentUrl(sessionId);
            assertEquals(TEST_BASE_URL, currentUrl);
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test WebDriver element interaction patterns")
    void testWebDriverElementInteractions() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_FORM_URL)
        );
        
        try {
            // Navigate to form page
            browserManager.navigateToUrl(sessionId, TEST_FORM_URL);
            
            // Test element finding patterns
            Map<String, Object> findResult = browserManager.findElement(
                sessionId,
                "css",
                "input[name='custname']"
            );
            assertNotNull(findResult, "Should find form element");
            assertTrue((Boolean) findResult.get("found"), "Element should be found");
            
            // Test element interaction
            boolean filled = browserManager.fillElement(
                sessionId,
                "css",
                "input[name='custname']",
                "Test User"
            );
            assertTrue(filled, "Should fill element successfully");
            
            // Test element attribute retrieval
            String value = browserManager.getElementAttribute(
                sessionId,
                "css",
                "input[name='custname']",
                "value"
            );
            assertEquals("Test User", value);
            
            // Test element visibility
            boolean visible = browserManager.isElementVisible(
                sessionId,
                "css",
                "input[name='custname']"
            );
            assertTrue(visible, "Element should be visible");
            
            // Test multiple element finding
            List<Map<String, Object>> inputs = browserManager.findElements(
                sessionId,
                "css",
                "input"
            );
            assertFalse(inputs.isEmpty(), "Should find multiple input elements");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test WebDriver JavaScript execution patterns")
    void testWebDriverJavaScriptExecution() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test synchronous JavaScript execution
            Object result = browserManager.executeScript(
                sessionId,
                "return document.title;",
                List.of()
            );
            assertNotNull(result, "Script should return result");
            assertTrue(result instanceof String, "Result should be string");
            
            // Test JavaScript execution with arguments
            Object mathResult = browserManager.executeScript(
                sessionId,
                "return arguments[0] + arguments[1];",
                List.of(10, 20)
            );
            assertEquals(30L, mathResult); // WebDriver returns Long for numbers
            
            // Test DOM manipulation
            boolean domModified = browserManager.executeScript(
                sessionId,
                "document.body.setAttribute('data-test', 'modified'); return true;",
                List.of()
            ) != null;
            assertTrue(domModified, "Should execute DOM manipulation script");
            
            // Verify DOM modification
            String attribute = (String) browserManager.executeScript(
                sessionId,
                "return document.body.getAttribute('data-test');",
                List.of()
            );
            assertEquals("modified", attribute);
            
            // Test asynchronous JavaScript execution
            Object asyncResult = browserManager.executeAsyncScript(
                sessionId,
                "var callback = arguments[arguments.length - 1]; setTimeout(function() { callback('async-complete'); }, 100);",
                List.of(),
                Duration.ofSeconds(5)
            );
            assertEquals("async-complete", asyncResult);
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test WebDriver wait and timeout patterns")
    void testWebDriverWaitPatterns() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test explicit wait for element
            boolean elementAppeared = browserManager.waitForElement(
                sessionId,
                "css",
                "body",
                DEFAULT_TIMEOUT
            );
            assertTrue(elementAppeared, "Body element should appear");
            
            // Test wait for element visibility
            boolean visible = browserManager.waitForElementVisible(
                sessionId,
                "css",
                "body",
                DEFAULT_TIMEOUT
            );
            assertTrue(visible, "Body element should be visible");
            
            // Test wait for page load
            boolean loaded = browserManager.waitForPageLoad(
                sessionId,
                DEFAULT_TIMEOUT
            );
            assertTrue(loaded, "Page should load completely");
            
            // Test wait for JavaScript condition
            boolean conditionMet = browserManager.waitForCondition(
                sessionId,
                "return document.readyState === 'complete';",
                DEFAULT_TIMEOUT
            );
            assertTrue(conditionMet, "JavaScript condition should be met");
            
            // Test custom wait with polling
            boolean customWaitResult = browserManager.waitForCustomCondition(
                sessionId,
                () -> {
                    try {
                        String title = browserManager.getTitle(sessionId);
                        return title != null && !title.isEmpty();
                    } catch (Exception e) {
                        return false;
                    }
                },
                DEFAULT_TIMEOUT,
                Duration.ofMillis(500)
            );
            assertTrue(customWaitResult, "Custom condition should be met");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Test WebDriver frame and window handling")
    void testWebDriverFrameAndWindowHandling() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test window handle management
            String mainWindow = browserManager.getCurrentWindowHandle(sessionId);
            assertNotNull(mainWindow, "Should have main window handle");
            
            Set<String> allWindows = browserManager.getAllWindowHandles(sessionId);
            assertTrue(allWindows.contains(mainWindow), "All windows should include main window");
            assertEquals(1, allWindows.size(), "Should have one window initially");
            
            // Test new window/tab creation via JavaScript
            browserManager.executeScript(
                sessionId,
                "window.open('" + TEST_JSON_URL + "', '_blank');",
                List.of()
            );
            
            // Wait for new window
            boolean newWindowOpened = browserManager.waitForWindowCount(sessionId, 2, DEFAULT_TIMEOUT);
            assertTrue(newWindowOpened, "New window should open");
            
            Set<String> updatedWindows = browserManager.getAllWindowHandles(sessionId);
            assertEquals(2, updatedWindows.size(), "Should have two windows");
            
            // Switch to new window
            String newWindow = updatedWindows.stream()
                .filter(handle -> !handle.equals(mainWindow))
                .findFirst()
                .orElse(null);
            assertNotNull(newWindow, "Should find new window handle");
            
            boolean switched = browserManager.switchToWindow(sessionId, newWindow);
            assertTrue(switched, "Should switch to new window");
            
            // Verify we're in the new window
            String currentUrl = browserManager.getCurrentUrl(sessionId);
            assertEquals(TEST_JSON_URL, currentUrl);
            
            // Switch back to main window
            boolean switchedBack = browserManager.switchToWindow(sessionId, mainWindow);
            assertTrue(switchedBack, "Should switch back to main window");
            
            // Close the new window
            browserManager.switchToWindow(sessionId, newWindow);
            browserManager.closeCurrentWindow(sessionId);
            browserManager.switchToWindow(sessionId, mainWindow);
            
            // Verify window count
            Set<String> finalWindows = browserManager.getAllWindowHandles(sessionId);
            assertEquals(1, finalWindows.size(), "Should have one window after closing");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test WebDriver cookie and session management")
    void testWebDriverCookieAndSessionManagement() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test cookie operations
            Map<String, Object> cookie = Map.of(
                "name", "test-cookie",
                "value", "test-value",
                "domain", ".example.com",
                "path", "/",
                "secure", false,
                "httpOnly", false
            );
            
            boolean cookieAdded = browserManager.addCookie(sessionId, cookie);
            assertTrue(cookieAdded, "Should add cookie successfully");
            
            // Get cookie
            Map<String, Object> retrievedCookie = browserManager.getCookie(sessionId, "test-cookie");
            assertNotNull(retrievedCookie, "Should retrieve cookie");
            assertEquals("test-value", retrievedCookie.get("value"));
            
            // Get all cookies
            Set<Map<String, Object>> allCookies = browserManager.getAllCookies(sessionId);
            assertFalse(allCookies.isEmpty(), "Should have cookies");
            assertTrue(allCookies.stream().anyMatch(c -> "test-cookie".equals(c.get("name"))));
            
            // Delete specific cookie
            boolean cookieDeleted = browserManager.deleteCookie(sessionId, "test-cookie");
            assertTrue(cookieDeleted, "Should delete cookie");
            
            // Verify cookie deleted
            Map<String, Object> deletedCookie = browserManager.getCookie(sessionId, "test-cookie");
            assertNull(deletedCookie, "Cookie should be deleted");
            
            // Test session storage
            boolean sessionSet = browserManager.setSessionStorage(sessionId, "test-key", "test-session-value");
            assertTrue(sessionSet, "Should set session storage");
            
            String sessionValue = browserManager.getSessionStorage(sessionId, "test-key");
            assertEquals("test-session-value", sessionValue);
            
            // Test local storage
            boolean localSet = browserManager.setLocalStorage(sessionId, "test-local-key", "test-local-value");
            assertTrue(localSet, "Should set local storage");
            
            String localValue = browserManager.getLocalStorage(sessionId, "test-local-key");
            assertEquals("test-local-value", localValue);
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test WebDriver concurrent session handling")
    void testWebDriverConcurrentSessions() throws Exception {
        int sessionCount = 3;
        List<String> sessionIds = new ArrayList<>();
        CountDownLatch setupLatch = new CountDownLatch(sessionCount);
        CountDownLatch operationsLatch = new CountDownLatch(sessionCount);
        List<Exception> exceptions = Collections.synchronizedList(new ArrayList<>());
        
        try {
            // Create sessions concurrently
            for (int i = 0; i < sessionCount; i++) {
                final int sessionIndex = i;
                executorService.submit(() -> {
                    try {
                        String sessionId = browserManager.createBrowserSession(
                            "chrome",
                            Map.of(
                                "headless", true,
                                "target", TEST_BASE_URL + "?session=" + sessionIndex
                            )
                        );
                        synchronized (sessionIds) {
                            sessionIds.add(sessionId);
                        }
                        setupLatch.countDown();
                    } catch (Exception e) {
                        exceptions.add(e);
                        setupLatch.countDown();
                    }
                });
            }
            
            assertTrue(setupLatch.await(30, TimeUnit.SECONDS), "All sessions should be created");
            assertEquals(sessionCount, sessionIds.size(), "Should have all sessions");
            assertTrue(exceptions.isEmpty(), "No exceptions during session creation");
            
            // Perform operations concurrently
            for (int i = 0; i < sessionIds.size(); i++) {
                final String sessionId = sessionIds.get(i);
                final int index = i;
                
                executorService.submit(() -> {
                    try {
                        // Navigate
                        browserManager.navigateToUrl(sessionId, TEST_JSON_URL + "?concurrent=" + index);
                        
                        // Execute JavaScript
                        Object result = browserManager.executeScript(
                            sessionId,
                            "return window.location.search;",
                            List.of()
                        );
                        assertTrue(result.toString().contains("concurrent=" + index));
                        
                        // Test element operations
                        browserManager.executeScript(
                            sessionId,
                            "document.body.setAttribute('data-session', '" + index + "');",
                            List.of()
                        );
                        
                        String attr = (String) browserManager.executeScript(
                            sessionId,
                            "return document.body.getAttribute('data-session');",
                            List.of()
                        );
                        assertEquals(String.valueOf(index), attr);
                        
                    } catch (Exception e) {
                        exceptions.add(e);
                    } finally {
                        operationsLatch.countDown();
                    }
                });
            }
            
            assertTrue(operationsLatch.await(60, TimeUnit.SECONDS), "All operations should complete");
            assertTrue(exceptions.isEmpty(), "No exceptions during concurrent operations");
            
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
    @Order(9)
    @DisplayName("Test WebDriver error handling and recovery")
    void testWebDriverErrorHandling() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        try {
            // Test invalid URL handling
            boolean invalidNav = browserManager.navigateToUrl(sessionId, "invalid-url");
            assertFalse(invalidNav, "Invalid URL navigation should fail gracefully");
            
            // Test element not found handling
            Map<String, Object> notFound = browserManager.findElement(
                sessionId,
                "css",
                "#non-existent-element"
            );
            assertFalse((Boolean) notFound.get("found"), "Non-existent element should not be found");
            
            // Test JavaScript error handling
            assertThrows(Exception.class, () -> {
                browserManager.executeScript(
                    sessionId,
                    "throw new Error('Test error');",
                    List.of()
                );
            });
            
            // Test timeout handling
            assertThrows(Exception.class, () -> {
                browserManager.waitForElement(
                    sessionId,
                    "css",
                    "#will-never-exist",
                    Duration.ofMillis(100)
                );
            });
            
            // Test session recovery after error
            boolean recovered = browserManager.recoverSession(sessionId);
            assertTrue(recovered, "Session should recover after errors");
            
            // Verify session still works
            boolean normalNav = browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            assertTrue(normalNav, "Navigation should work after recovery");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(10)
    @DisplayName("Test WebDriver performance and resource usage")
    void testWebDriverPerformanceAndResources() throws Exception {
        long startTime = System.currentTimeMillis();
        
        // Test session creation performance
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of("headless", true, "target", TEST_BASE_URL)
        );
        
        long creationTime = System.currentTimeMillis() - startTime;
        assertTrue(creationTime < 15000, "Session creation should be under 15 seconds");
        
        try {
            // Test navigation performance
            long navStart = System.currentTimeMillis();
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            long navTime = System.currentTimeMillis() - navStart;
            assertTrue(navTime < 10000, "Navigation should be under 10 seconds");
            
            // Test JavaScript execution performance
            long jsStart = System.currentTimeMillis();
            for (int i = 0; i < 100; i++) {
                browserManager.executeScript(sessionId, "return " + i + ";", List.of());
            }
            long jsTime = System.currentTimeMillis() - jsStart;
            assertTrue(jsTime < 5000, "100 JS executions should be under 5 seconds");
            
            // Test memory usage
            long initialMemory = getCurrentMemoryUsage();
            
            // Perform memory-intensive operations
            for (int i = 0; i < 50; i++) {
                browserManager.executeScript(
                    sessionId,
                    "var div = document.createElement('div'); div.innerHTML = 'test-" + i + "'; document.body.appendChild(div);",
                    List.of()
                );
            }
            
            long afterOperationsMemory = getCurrentMemoryUsage();
            long memoryIncrease = afterOperationsMemory - initialMemory;
            
            // Memory increase should be reasonable (less than 100MB)
            assertTrue(memoryIncrease < 100_000_000, "Memory usage should be reasonable");
            
        } finally {
            long cleanupStart = System.currentTimeMillis();
            browserManager.closeBrowserSession(sessionId);
            long cleanupTime = System.currentTimeMillis() - cleanupStart;
            
            assertTrue(cleanupTime < 5000, "Session cleanup should be under 5 seconds");
        }
    }
    
    // Utility methods
    
    private boolean isBrowserSupported(BrowserType browserType) {
        // In real implementation, this would check for browser availability
        return browserType == BrowserType.CHROME || browserType == BrowserType.FIREFOX;
    }
    
    private Map<String, Object> getBrowserSpecificOptions(BrowserType browserType) {
        Map<String, Object> options = new HashMap<>();
        
        switch (browserType) {
            case CHROME:
                options.put("args", List.of("--no-sandbox", "--disable-dev-shm-usage"));
                options.put("prefs", Map.of("profile.default_content_setting_values.notifications", 2));
                break;
            case FIREFOX:
                options.put("prefs", Map.of("dom.webnotifications.enabled", false));
                options.put("args", List.of("-width", "1920", "-height", "1080"));
                break;
            case EDGE:
                options.put("useChromium", true);
                options.put("args", List.of("--no-first-run"));
                break;
        }
        
        return options;
    }
    
    private void assertBrowserSpecificCapabilities(BrowserType browserType, Map<String, Object> capabilities) {
        switch (browserType) {
            case CHROME:
                assertTrue(capabilities.get("browserName").toString().toLowerCase().contains("chrome"));
                break;
            case FIREFOX:
                assertTrue(capabilities.get("browserName").toString().toLowerCase().contains("firefox"));
                break;
            case EDGE:
                assertTrue(capabilities.get("browserName").toString().toLowerCase().contains("edge"));
                break;
        }
    }
    
    private long getCurrentMemoryUsage() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
