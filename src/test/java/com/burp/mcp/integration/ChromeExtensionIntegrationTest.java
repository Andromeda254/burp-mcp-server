package com.burp.mcp.integration;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.burp.mcp.browser.BrowserManager;
import com.burp.mcp.browser.BrowserManager.BrowserSession;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

import java.util.*;
import java.util.concurrent.*;
import java.time.Duration;

/**
 * Chrome Extension specific integration tests covering extension communication,
 * content script interactions, and integration with browser automation workflow.
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ChromeExtensionIntegrationTest {
    
    private static MontoyaApi api;
    private static Logging logging;
    
    private BrowserManager browserManager;
    private static ExecutorService executorService;
    
    // Test configuration
    private static final String TEST_BASE_URL = "https://example.com";
    private static final String TEST_FORM_URL = "https://httpbin.org/forms/post";
    private static final String TEST_LOGIN_URL = "https://httpbin.org/basic-auth/user/pass";
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    
    @BeforeAll
    static void setUpClass() {
        executorService = Executors.newCachedThreadPool();
        
        // Mock Burp API
        api = mock(MontoyaApi.class);
        logging = mock(Logging.class);
        when(api.logging()).thenReturn(logging);
        
        System.out.println("Chrome Extension integration test environment ready");
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
        
        // Skip tests if Chrome extension is not available
        assumeTrue(isChromeExtensionInstalled(), "Chrome extension not installed or available");
    }
    
    @AfterEach
    void tearDown() {
        if (browserManager != null) {
            browserManager.cleanupAllSessions();
        }
    }
    
    @Test
    @Order(1)
    @DisplayName("Test Chrome Extension initialization and communication")
    void testChromeExtensionInitialization() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false, // Extension needs non-headless mode
                "target", TEST_BASE_URL,
                "extensionEnabled", true,
                "extensionId", "burp-mcp-extension"
            )
        );
        
        try {
            // Verify extension is loaded
            boolean extensionLoaded = browserManager.isExtensionLoaded(sessionId, "burp-mcp-extension");
            assertTrue(extensionLoaded, "Chrome extension should be loaded");
            
            // Test basic extension communication
            Map<String, Object> extensionInfo = browserManager.executeExtensionCommand(
                sessionId,
                "getExtensionInfo",
                Map.of()
            );
            
            assertNotNull(extensionInfo, "Extension should respond to info request");
            assertTrue(extensionInfo.containsKey("name"), "Should include extension name");
            assertTrue(extensionInfo.containsKey("version"), "Should include extension version");
            assertEquals("BurpSuite MCP Extension", extensionInfo.get("name"));
            
            // Test extension health check
            Map<String, Object> healthStatus = browserManager.executeExtensionCommand(
                sessionId,
                "healthCheck",
                Map.of()
            );
            
            assertNotNull(healthStatus, "Health check should return status");
            assertEquals("healthy", healthStatus.get("status"));
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(2)
    @DisplayName("Test Chrome Extension page analysis capabilities")
    void testChromeExtensionPageAnalysis() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_FORM_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Navigate to form page
            browserManager.navigateToUrl(sessionId, TEST_FORM_URL);
            
            // Test page analysis via extension
            Map<String, Object> pageAnalysis = browserManager.executeExtensionCommand(
                sessionId,
                "analyzePage",
                Map.of("includeHeaders", true, "includeForms", true)
            );
            
            assertNotNull(pageAnalysis, "Page analysis should return results");
            assertTrue(pageAnalysis.containsKey("url"), "Should include current URL");
            assertEquals(TEST_FORM_URL, pageAnalysis.get("url"));
            
            // Test form detection
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> forms = (List<Map<String, Object>>) pageAnalysis.get("forms");
            assertNotNull(forms, "Should detect forms on page");
            assertFalse(forms.isEmpty(), "Should find at least one form");
            
            Map<String, Object> firstForm = forms.get(0);
            assertTrue(firstForm.containsKey("action"), "Form should have action");
            assertTrue(firstForm.containsKey("method"), "Form should have method");
            assertTrue(firstForm.containsKey("inputs"), "Form should have inputs");
            
            // Test input field analysis
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> inputs = (List<Map<String, Object>>) firstForm.get("inputs");
            assertFalse(inputs.isEmpty(), "Form should have input fields");
            
            boolean hasNameField = inputs.stream()
                .anyMatch(input -> "custname".equals(input.get("name")));
            assertTrue(hasNameField, "Should find customer name field");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(3)
    @DisplayName("Test Chrome Extension security analysis features")
    void testChromeExtensionSecurityAnalysis() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test security headers analysis
            Map<String, Object> securityAnalysis = browserManager.executeExtensionCommand(
                sessionId,
                "analyzeSecurityHeaders",
                Map.of("detailed", true)
            );
            
            assertNotNull(securityAnalysis, "Security analysis should return results");
            assertTrue(securityAnalysis.containsKey("headers"), "Should include headers analysis");
            assertTrue(securityAnalysis.containsKey("score"), "Should include security score");
            
            // Test HTTPS analysis
            if (TEST_BASE_URL.startsWith("https://")) {
                assertTrue(securityAnalysis.containsKey("tlsInfo"), "Should include TLS information");
                
                @SuppressWarnings("unchecked")
                Map<String, Object> tlsInfo = (Map<String, Object>) securityAnalysis.get("tlsInfo");
                assertTrue(tlsInfo.containsKey("protocol"), "Should include TLS protocol");
                assertTrue(tlsInfo.containsKey("cipher"), "Should include cipher suite");
            }
            
            // Test CSP analysis
            Map<String, Object> cspAnalysis = browserManager.executeExtensionCommand(
                sessionId,
                "analyzeCSP",
                Map.of()
            );
            
            assertNotNull(cspAnalysis, "CSP analysis should return results");
            assertTrue(cspAnalysis.containsKey("present"), "Should indicate CSP presence");
            
            // Test cookie security analysis
            Map<String, Object> cookieAnalysis = browserManager.executeExtensionCommand(
                sessionId,
                "analyzeCookies",
                Map.of()
            );
            
            assertNotNull(cookieAnalysis, "Cookie analysis should return results");
            assertTrue(cookieAnalysis.containsKey("cookies"), "Should include cookies list");
            assertTrue(cookieAnalysis.containsKey("securityScore"), "Should include security score");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(4)
    @DisplayName("Test Chrome Extension traffic monitoring")
    void testChromeExtensionTrafficMonitoring() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true,
                "monitorTraffic", true
            )
        );
        
        try {
            // Start traffic monitoring
            boolean monitoringStarted = browserManager.executeExtensionCommand(
                sessionId,
                "startTrafficMonitoring",
                Map.of("captureRequests", true, "captureResponses", true)
            ) != null;
            assertTrue(monitoringStarted, "Traffic monitoring should start successfully");
            
            // Navigate to generate traffic
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            browserManager.navigateToUrl(sessionId, TEST_FORM_URL);
            
            // Wait for traffic to be captured
            Thread.sleep(2000);
            
            // Get captured traffic
            Map<String, Object> trafficData = browserManager.executeExtensionCommand(
                sessionId,
                "getTrafficData",
                Map.of("limit", 10)
            );
            
            assertNotNull(trafficData, "Traffic data should be available");
            assertTrue(trafficData.containsKey("requests"), "Should include requests");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> requests = (List<Map<String, Object>>) trafficData.get("requests");
            assertFalse(requests.isEmpty(), "Should have captured requests");
            
            // Verify request structure
            Map<String, Object> firstRequest = requests.get(0);
            assertTrue(firstRequest.containsKey("url"), "Request should have URL");
            assertTrue(firstRequest.containsKey("method"), "Request should have method");
            assertTrue(firstRequest.containsKey("headers"), "Request should have headers");
            assertTrue(firstRequest.containsKey("timestamp"), "Request should have timestamp");
            
            // Test traffic filtering
            Map<String, Object> filteredTraffic = browserManager.executeExtensionCommand(
                sessionId,
                "filterTraffic",
                Map.of("urlPattern", "*.example.com", "method", "GET")
            );
            
            assertNotNull(filteredTraffic, "Filtered traffic should be available");
            
            // Stop traffic monitoring
            boolean monitoringStopped = browserManager.executeExtensionCommand(
                sessionId,
                "stopTrafficMonitoring",
                Map.of()
            ) != null;
            assertTrue(monitoringStopped, "Traffic monitoring should stop successfully");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(5)
    @DisplayName("Test Chrome Extension form interaction capabilities")
    void testChromeExtensionFormInteractions() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_FORM_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Navigate to form page
            browserManager.navigateToUrl(sessionId, TEST_FORM_URL);
            
            // Test form field detection
            Map<String, Object> formFields = browserManager.executeExtensionCommand(
                sessionId,
                "detectFormFields",
                Map.of("includeHidden", false)
            );
            
            assertNotNull(formFields, "Form fields should be detected");
            assertTrue(formFields.containsKey("fields"), "Should include fields list");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> fields = (List<Map<String, Object>>) formFields.get("fields");
            assertFalse(fields.isEmpty(), "Should find form fields");
            
            // Test automated form filling via extension
            Map<String, Object> fillData = Map.of(
                "custname", "Test Customer",
                "custtel", "123-456-7890",
                "custemail", "test@example.com",
                "size", "medium"
            );
            
            boolean formFilled = browserManager.executeExtensionCommand(
                sessionId,
                "fillForm",
                Map.of("formData", fillData, "submitAfterFill", false)
            ) != null;
            assertTrue(formFilled, "Form should be filled successfully");
            
            // Verify form was filled
            Map<String, Object> formValues = browserManager.executeExtensionCommand(
                sessionId,
                "getFormValues",
                Map.of()
            );
            
            assertNotNull(formValues, "Form values should be retrievable");
            assertEquals("Test Customer", formValues.get("custname"));
            assertEquals("test@example.com", formValues.get("custemail"));
            
            // Test form validation detection
            Map<String, Object> validationResult = browserManager.executeExtensionCommand(
                sessionId,
                "validateForm",
                Map.of()
            );
            
            assertNotNull(validationResult, "Form validation should return result");
            assertTrue(validationResult.containsKey("valid"), "Should indicate form validity");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(6)
    @DisplayName("Test Chrome Extension content script injection")
    void testChromeExtensionContentScriptInjection() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Navigate to test page
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            
            // Test content script injection
            Map<String, Object> injectionResult = browserManager.executeExtensionCommand(
                sessionId,
                "injectContentScript",
                Map.of(
                    "script", "document.body.setAttribute('data-extension', 'injected');",
                    "runAt", "document_end"
                )
            );
            
            assertNotNull(injectionResult, "Script injection should return result");
            assertTrue((Boolean) injectionResult.get("success"), "Script injection should succeed");
            
            // Verify script was executed
            String attribute = (String) browserManager.executeScript(
                sessionId,
                "return document.body.getAttribute('data-extension');",
                List.of()
            );
            assertEquals("injected", attribute);
            
            // Test CSS injection
            Map<String, Object> cssInjection = browserManager.executeExtensionCommand(
                sessionId,
                "injectCSS",
                Map.of(
                    "css", "body { border: 2px solid red !important; }",
                    "origin", "user"
                )
            );
            
            assertNotNull(cssInjection, "CSS injection should return result");
            assertTrue((Boolean) cssInjection.get("success"), "CSS injection should succeed");
            
            // Test script removal
            boolean scriptRemoved = browserManager.executeExtensionCommand(
                sessionId,
                "removeInjectedScript",
                Map.of("scriptId", injectionResult.get("scriptId"))
            ) != null;
            assertTrue(scriptRemoved, "Script should be removed successfully");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(7)
    @DisplayName("Test Chrome Extension authentication detection")
    void testChromeExtensionAuthenticationDetection() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_LOGIN_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Navigate to login page
            browserManager.navigateToUrl(sessionId, TEST_LOGIN_URL);
            
            // Test authentication challenge detection
            Map<String, Object> authDetection = browserManager.executeExtensionCommand(
                sessionId,
                "detectAuthentication",
                Map.of("includeBasicAuth", true, "includeFormAuth", true)
            );
            
            assertNotNull(authDetection, "Authentication detection should return result");
            assertTrue(authDetection.containsKey("authType"), "Should detect authentication type");
            assertTrue(authDetection.containsKey("detected"), "Should indicate if auth is detected");
            
            if ((Boolean) authDetection.get("detected")) {
                String authType = (String) authDetection.get("authType");
                assertTrue(Arrays.asList("basic", "digest", "form", "oauth").contains(authType.toLowerCase()));
            }
            
            // Test login form detection (if form-based auth)
            Map<String, Object> loginFormDetection = browserManager.executeExtensionCommand(
                sessionId,
                "detectLoginForm",
                Map.of()
            );
            
            assertNotNull(loginFormDetection, "Login form detection should return result");
            
            // Test session state monitoring
            Map<String, Object> sessionState = browserManager.executeExtensionCommand(
                sessionId,
                "monitorSessionState",
                Map.of("startMonitoring", true)
            );
            
            assertNotNull(sessionState, "Session state monitoring should return result");
            assertTrue(sessionState.containsKey("authenticated"), "Should indicate authentication state");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(8)
    @DisplayName("Test Chrome Extension event handling")
    void testChromeExtensionEventHandling() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Set up event listeners
            boolean listenersSetup = browserManager.executeExtensionCommand(
                sessionId,
                "setupEventListeners",
                Map.of(
                    "events", Arrays.asList("navigation", "form_submit", "request", "response"),
                    "bufferSize", 100
                )
            ) != null;
            assertTrue(listenersSetup, "Event listeners should be set up");
            
            // Navigate to generate events
            browserManager.navigateToUrl(sessionId, TEST_BASE_URL);
            browserManager.navigateToUrl(sessionId, TEST_FORM_URL);
            
            // Wait for events to be captured
            Thread.sleep(2000);
            
            // Retrieve captured events
            Map<String, Object> events = browserManager.executeExtensionCommand(
                sessionId,
                "getEvents",
                Map.of("limit", 10, "types", Arrays.asList("navigation"))
            );
            
            assertNotNull(events, "Events should be available");
            assertTrue(events.containsKey("events"), "Should include events list");
            
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> eventList = (List<Map<String, Object>>) events.get("events");
            assertFalse(eventList.isEmpty(), "Should have captured events");
            
            // Verify event structure
            Map<String, Object> firstEvent = eventList.get(0);
            assertTrue(firstEvent.containsKey("type"), "Event should have type");
            assertTrue(firstEvent.containsKey("timestamp"), "Event should have timestamp");
            assertTrue(firstEvent.containsKey("data"), "Event should have data");
            
            // Test event filtering
            Map<String, Object> filteredEvents = browserManager.executeExtensionCommand(
                sessionId,
                "filterEvents",
                Map.of("type", "navigation", "timeRange", Map.of("last", "5m"))
            );
            
            assertNotNull(filteredEvents, "Filtered events should be available");
            
            // Clean up event listeners
            boolean listenersCleanedUp = browserManager.executeExtensionCommand(
                sessionId,
                "cleanupEventListeners",
                Map.of()
            ) != null;
            assertTrue(listenersCleanedUp, "Event listeners should be cleaned up");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(9)
    @DisplayName("Test Chrome Extension error handling and recovery")
    void testChromeExtensionErrorHandling() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Test invalid command handling
            Map<String, Object> invalidCommand = browserManager.executeExtensionCommand(
                sessionId,
                "nonexistentCommand",
                Map.of()
            );
            
            // Should handle gracefully, not throw exception
            if (invalidCommand != null) {
                assertTrue(invalidCommand.containsKey("error"), "Should contain error information");
            }
            
            // Test command with invalid parameters
            Map<String, Object> invalidParams = browserManager.executeExtensionCommand(
                sessionId,
                "analyzePage",
                Map.of("invalidParam", "invalidValue")
            );
            
            // Should still work with valid defaults
            assertNotNull(invalidParams, "Should handle invalid parameters gracefully");
            
            // Test extension recovery after error
            Map<String, Object> recoveryTest = browserManager.executeExtensionCommand(
                sessionId,
                "getExtensionInfo",
                Map.of()
            );
            
            assertNotNull(recoveryTest, "Extension should recover from errors");
            assertEquals("healthy", recoveryTest.get("status"));
            
            // Test timeout handling
            CompletableFuture<Map<String, Object>> timeoutTest = CompletableFuture.supplyAsync(() -> {
                try {
                    return browserManager.executeExtensionCommand(
                        sessionId,
                        "longRunningOperation",
                        Map.of("duration", 30000) // 30 second operation
                    );
                } catch (Exception e) {
                    return Map.of("error", e.getMessage());
                }
            });
            
            // Should timeout reasonably
            assertThrows(TimeoutException.class, () -> {
                timeoutTest.get(5, TimeUnit.SECONDS);
            });
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    @Test
    @Order(10)
    @DisplayName("Test Chrome Extension performance and resource usage")
    void testChromeExtensionPerformance() throws Exception {
        String sessionId = browserManager.createBrowserSession(
            "chrome",
            Map.of(
                "headless", false,
                "target", TEST_BASE_URL,
                "extensionEnabled", true
            )
        );
        
        try {
            // Test extension command performance
            long startTime = System.currentTimeMillis();
            
            for (int i = 0; i < 10; i++) {
                Map<String, Object> result = browserManager.executeExtensionCommand(
                    sessionId,
                    "getExtensionInfo",
                    Map.of()
                );
                assertNotNull(result, "Extension command should work consistently");
            }
            
            long commandTime = System.currentTimeMillis() - startTime;
            assertTrue(commandTime < 5000, "10 extension commands should complete under 5 seconds");
            
            // Test resource usage monitoring
            Map<String, Object> resourceUsage = browserManager.executeExtensionCommand(
                sessionId,
                "getResourceUsage",
                Map.of()
            );
            
            assertNotNull(resourceUsage, "Resource usage should be available");
            assertTrue(resourceUsage.containsKey("memory"), "Should include memory usage");
            assertTrue(resourceUsage.containsKey("cpu"), "Should include CPU usage");
            
            // Test extension memory cleanup
            boolean cleanupPerformed = browserManager.executeExtensionCommand(
                sessionId,
                "performCleanup",
                Map.of("clearCache", true, "clearEvents", true)
            ) != null;
            assertTrue(cleanupPerformed, "Extension cleanup should succeed");
            
            // Verify cleanup effectiveness
            Map<String, Object> postCleanupUsage = browserManager.executeExtensionCommand(
                sessionId,
                "getResourceUsage",
                Map.of()
            );
            
            assertNotNull(postCleanupUsage, "Resource usage should still be available after cleanup");
            
        } finally {
            browserManager.closeBrowserSession(sessionId);
        }
    }
    
    // Utility methods
    
    private boolean isChromeExtensionInstalled() {
        try {
            // In real implementation, this would check for extension installation
            // For testing purposes, we'll assume it's available if Chrome is available
            return isSystemCapableOfExtensionTesting();
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean isSystemCapableOfExtensionTesting() {
        // Check if system can run Chrome with extensions (non-headless)
        String os = System.getProperty("os.name").toLowerCase();
        boolean hasDisplay = !Boolean.parseBoolean(System.getProperty("java.awt.headless", "true"));
        
        // For testing purposes, assume capability if not explicitly headless
        return hasDisplay || System.getProperty("chrome.extension.test.enabled", "false").equals("true");
    }
}
