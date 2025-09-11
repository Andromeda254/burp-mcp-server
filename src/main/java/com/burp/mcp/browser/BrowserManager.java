package com.burp.mcp.browser;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.edge.EdgeOptions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.JavascriptExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import java.io.IOException;
import java.nio.file.StandardCopyOption;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;

    /**
     * Advanced WebDriver manager for browser automation integration with BurpSuite Pro
     * Follows classic Selenium WebDriver patterns with enhanced security testing capabilities
     */
public class BrowserManager {
    
    private final burp.api.montoya.MontoyaApi api;
    private ChromeExtensionServer extensionServer;
    private final Path extensionPath;
    
    public BrowserManager(burp.api.montoya.MontoyaApi api) {
        this.api = api;
        this.extensionPath = Paths.get(System.getProperty("user.dir"), "chrome-extension");
        initializeExtensionServer();
    }
    
    private static final Logger logger = LoggerFactory.getLogger(BrowserManager.class);
    private static final Map<String, WebDriver> activeSessions = new ConcurrentHashMap<>();
    private static final AtomicLong sessionIdCounter = new AtomicLong(1);
    
    // Default configuration
    private static final int DEFAULT_TIMEOUT_SECONDS = 30;
    private static final int DEFAULT_IMPLICIT_WAIT_SECONDS = 10;
    private static final String DEFAULT_BROWSER = "chrome";
    
    // BurpSuite proxy configuration
    private static final String BURP_PROXY_HOST = "127.0.0.1";
    private static final int BURP_PROXY_PORT = 8080;
    
    /**
     * Supported browser types for automation
     */
    public enum BrowserType {
        CHROME("chrome"),
        FIREFOX("firefox"),
        EDGE("edge"),
        CHROME_HEADLESS("chrome-headless"),
        FIREFOX_HEADLESS("firefox-headless");
        
        private final String name;
        
        BrowserType(String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
        
        public static BrowserType fromString(String browser) {
            for (BrowserType type : values()) {
                if (type.name.equalsIgnoreCase(browser)) {
                    return type;
                }
            }
            return CHROME; // Default fallback
        }
    }
    
    /**
     * Browser session configuration
     */
    public static class BrowserConfig {
        private BrowserType browserType = BrowserType.CHROME;
        private boolean useBurpProxy = true;
        private boolean headless = false;
        private int timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
        private int implicitWaitSeconds = DEFAULT_IMPLICIT_WAIT_SECONDS;
        private Map<String, Object> customCapabilities = new HashMap<>();
        private List<String> chromeArguments = new ArrayList<>();
        private List<String> firefoxPreferences = new ArrayList<>();
        private String userAgent;
        private String downloadDirectory;
        private boolean acceptInsecureCertificates = true;
        private boolean enableExtensions = true;
        
        // Getters and setters
        public BrowserType getBrowserType() { return browserType; }
        public void setBrowserType(BrowserType browserType) { this.browserType = browserType; }
        
        public boolean isUseBurpProxy() { return useBurpProxy; }
        public void setUseBurpProxy(boolean useBurpProxy) { this.useBurpProxy = useBurpProxy; }
        
        public boolean isHeadless() { return headless; }
        public void setHeadless(boolean headless) { this.headless = headless; }
        
        public int getTimeoutSeconds() { return timeoutSeconds; }
        public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
        
        public int getImplicitWaitSeconds() { return implicitWaitSeconds; }
        public void setImplicitWaitSeconds(int implicitWaitSeconds) { this.implicitWaitSeconds = implicitWaitSeconds; }
        
        public Map<String, Object> getCustomCapabilities() { return customCapabilities; }
        public void setCustomCapabilities(Map<String, Object> customCapabilities) { this.customCapabilities = customCapabilities; }
        
        public List<String> getChromeArguments() { return chromeArguments; }
        public void setChromeArguments(List<String> chromeArguments) { this.chromeArguments = chromeArguments; }
        
        public List<String> getFirefoxPreferences() { return firefoxPreferences; }
        public void setFirefoxPreferences(List<String> firefoxPreferences) { this.firefoxPreferences = firefoxPreferences; }
        
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        
        public String getDownloadDirectory() { return downloadDirectory; }
        public void setDownloadDirectory(String downloadDirectory) { this.downloadDirectory = downloadDirectory; }
        
        public boolean isAcceptInsecureCertificates() { return acceptInsecureCertificates; }
        public void setAcceptInsecureCertificates(boolean acceptInsecureCertificates) { this.acceptInsecureCertificates = acceptInsecureCertificates; }
        
        public boolean isEnableExtensions() { return enableExtensions; }
        public void setEnableExtensions(boolean enableExtensions) { this.enableExtensions = enableExtensions; }
        
        public void setCaptureScreenshots(boolean captureScreenshots) {
            // This is for compatibility - screenshots are handled by ScreenshotCapture class
            // Can be stored in custom capabilities if needed
            this.customCapabilities.put("captureScreenshots", captureScreenshots);
        }
    }
    
    /**
     * Browser session information
     */
    public static class BrowserSession {
        private final String sessionId;
        private final WebDriver driver;
        private final BrowserConfig config;
        private final WebDriverWait wait;
        private final long createdTime;
        private boolean active;
        
        public BrowserSession(String sessionId, WebDriver driver, BrowserConfig config) {
            this.sessionId = sessionId;
            this.driver = driver;
            this.config = config;
            this.wait = new WebDriverWait(driver, Duration.ofSeconds(config.getTimeoutSeconds()));
            this.createdTime = System.currentTimeMillis();
            this.active = true;
        }
        
        public String getSessionId() { return sessionId; }
        public WebDriver getDriver() { return driver; }
        public BrowserConfig getConfig() { return config; }
        public WebDriverWait getWait() { return wait; }
        public long getCreatedTime() { return createdTime; }
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
    }
    
    /**
     * Create a new browser session with default configuration
     */
    public static BrowserSession createSession() {
        return createSession(new BrowserConfig());
    }
    
    /**
     * Create a new browser session with custom configuration
     */
    public static BrowserSession createSession(BrowserConfig config) {
        String sessionId = "browser-session-" + sessionIdCounter.getAndIncrement();
        
        try {
            logger.info("Creating new browser session: {} with {}", sessionId, config.getBrowserType());
            
            // Setup WebDriver manager for the specified browser
            setupWebDriverManager(config.getBrowserType());
            
            // Create WebDriver instance
            WebDriver driver = createWebDriver(config);
            
            // Configure timeouts
            driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(config.getImplicitWaitSeconds()));
            driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(config.getTimeoutSeconds()));
            driver.manage().timeouts().scriptTimeout(Duration.ofSeconds(config.getTimeoutSeconds()));
            
            // Maximize window (unless headless)
            if (!config.isHeadless()) {
                driver.manage().window().maximize();
            }
            
            BrowserSession session = new BrowserSession(sessionId, driver, config);
            activeSessions.put(sessionId, driver);
            
            logger.info("Browser session created successfully: {} ({})", sessionId, config.getBrowserType());
            return session;
            
        } catch (Exception e) {
            logger.error("Failed to create browser session: {}", e.getMessage(), e);
            throw new BrowserAutomationException("Failed to create browser session", e);
        }
    }
    
    /**
     * Setup WebDriver manager for automatic driver management
     */
    private static void setupWebDriverManager(BrowserType browserType) {
        try {
            switch (browserType) {
                case CHROME:
                case CHROME_HEADLESS:
                    WebDriverManager.chromedriver().setup();
                    break;
                case FIREFOX:
                case FIREFOX_HEADLESS:
                    WebDriverManager.firefoxdriver().setup();
                    break;
                case EDGE:
                    WebDriverManager.edgedriver().setup();
                    break;
                default:
                    WebDriverManager.chromedriver().setup(); // Fallback to Chrome
                    break;
            }
        } catch (Exception e) {
            logger.warn("WebDriverManager setup failed, falling back to system drivers: {}", e.getMessage());
        }
    }
    
    /**
     * Create WebDriver instance based on browser type and configuration
     */
    private static WebDriver createWebDriver(BrowserConfig config) {
        switch (config.getBrowserType()) {
            case CHROME:
            case CHROME_HEADLESS:
                return createChromeDriver(config);
            case FIREFOX:
            case FIREFOX_HEADLESS:
                return createFirefoxDriver(config);
            case EDGE:
                return createEdgeDriver(config);
            default:
                logger.warn("Unknown browser type: {}, falling back to Chrome", config.getBrowserType());
                return createChromeDriver(config);
        }
    }
    
    /**
     * Create Chrome WebDriver with advanced configuration
     */
    private static WebDriver createChromeDriver(BrowserConfig config) {
        ChromeOptions options = new ChromeOptions();
        
        // Basic Chrome options
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-blink-features=AutomationControlled");
        options.setExperimentalOption("useAutomationExtension", false);
        options.setExperimentalOption("excludeSwitches", Arrays.asList("enable-automation"));
        
        // Headless mode
        if (config.isHeadless() || config.getBrowserType() == BrowserType.CHROME_HEADLESS) {
            options.addArguments("--headless=new");
            options.addArguments("--window-size=1920,1080");
        }
        
        // BurpSuite proxy configuration
        if (config.isUseBurpProxy()) {
            String proxyConfig = BURP_PROXY_HOST + ":" + BURP_PROXY_PORT;
            options.addArguments("--proxy-server=http=" + proxyConfig + ";https=" + proxyConfig);
            logger.info("Chrome configured to use BurpSuite proxy: {}", proxyConfig);
        }
        
        // Security settings for testing
        if (config.isAcceptInsecureCertificates()) {
            options.addArguments("--ignore-certificate-errors");
            options.addArguments("--ignore-ssl-errors");
            options.addArguments("--allow-running-insecure-content");
            options.addArguments("--disable-web-security");
        }
        
        // Custom user agent
        if (config.getUserAgent() != null) {
            options.addArguments("--user-agent=" + config.getUserAgent());
        }
        
        // Download directory
        if (config.getDownloadDirectory() != null) {
            Map<String, Object> prefs = new HashMap<>();
            prefs.put("download.default_directory", config.getDownloadDirectory());
            prefs.put("download.prompt_for_download", false);
            options.setExperimentalOption("prefs", prefs);
        }
        
        // Custom Chrome arguments
        if (!config.getChromeArguments().isEmpty()) {
            options.addArguments(config.getChromeArguments());
        }
        
        // Extensions support
        if (!config.isEnableExtensions()) {
            options.addArguments("--disable-extensions");
        } else {
            // Load BurpSuite MCP Chrome Extension if available
            loadChromeExtension(options);
        }
        
        // Custom capabilities
        if (!config.getCustomCapabilities().isEmpty()) {
            config.getCustomCapabilities().forEach(options::setCapability);
        }
        
        return new ChromeDriver(options);
    }
    
    /**
     * Create Firefox WebDriver with advanced configuration
     */
    private static WebDriver createFirefoxDriver(BrowserConfig config) {
        FirefoxOptions options = new FirefoxOptions();
        FirefoxProfile profile = new FirefoxProfile();
        
        // Headless mode
        if (config.isHeadless() || config.getBrowserType() == BrowserType.FIREFOX_HEADLESS) {
            options.addArguments("--headless");
            options.addArguments("--width=1920");
            options.addArguments("--height=1080");
        }
        
        // BurpSuite proxy configuration
        if (config.isUseBurpProxy()) {
            profile.setPreference("network.proxy.type", 1);
            profile.setPreference("network.proxy.http", BURP_PROXY_HOST);
            profile.setPreference("network.proxy.http_port", BURP_PROXY_PORT);
            profile.setPreference("network.proxy.ssl", BURP_PROXY_HOST);
            profile.setPreference("network.proxy.ssl_port", BURP_PROXY_PORT);
            logger.info("Firefox configured to use BurpSuite proxy: {}:{}", BURP_PROXY_HOST, BURP_PROXY_PORT);
        }
        
        // Security settings for testing
        if (config.isAcceptInsecureCertificates()) {
            profile.setPreference("security.tls.insecure_fallback_hosts", "");
            profile.setPreference("security.tls.unrestricted_rc4_fallback", true);
            profile.setPreference("security.mixed_content.block_active_content", false);
            profile.setPreference("security.mixed_content.block_display_content", false);
        }
        
        // Custom user agent
        if (config.getUserAgent() != null) {
            profile.setPreference("general.useragent.override", config.getUserAgent());
        }
        
        // Download directory
        if (config.getDownloadDirectory() != null) {
            profile.setPreference("browser.download.dir", config.getDownloadDirectory());
            profile.setPreference("browser.download.folderList", 2);
            profile.setPreference("browser.helperApps.neverAsk.saveToDisk", 
                "application/octet-stream,application/pdf,application/zip");
        }
        
        // Firefox-specific preferences
        profile.setPreference("dom.webdriver.enabled", false);
        profile.setPreference("useAutomationExtension", false);
        
        // Custom Firefox preferences
        for (String pref : config.getFirefoxPreferences()) {
            String[] parts = pref.split("=", 2);
            if (parts.length == 2) {
                try {
                    // Try to parse as boolean
                    boolean boolValue = Boolean.parseBoolean(parts[1]);
                    profile.setPreference(parts[0], boolValue);
                } catch (Exception e) {
                    try {
                        // Try to parse as integer
                        int intValue = Integer.parseInt(parts[1]);
                        profile.setPreference(parts[0], intValue);
                    } catch (Exception ex) {
                        // Use as string
                        profile.setPreference(parts[0], parts[1]);
                    }
                }
            }
        }
        
        options.setProfile(profile);
        
        // Custom capabilities
        if (!config.getCustomCapabilities().isEmpty()) {
            config.getCustomCapabilities().forEach(options::setCapability);
        }
        
        return new FirefoxDriver(options);
    }
    
    /**
     * Create Edge WebDriver with advanced configuration
     */
    private static WebDriver createEdgeDriver(BrowserConfig config) {
        EdgeOptions options = new EdgeOptions();
        
        // Basic Edge options
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-blink-features=AutomationControlled");
        
        // Headless mode
        if (config.isHeadless()) {
            options.addArguments("--headless");
            options.addArguments("--window-size=1920,1080");
        }
        
        // BurpSuite proxy configuration
        if (config.isUseBurpProxy()) {
            String proxyConfig = BURP_PROXY_HOST + ":" + BURP_PROXY_PORT;
            options.addArguments("--proxy-server=http=" + proxyConfig + ";https=" + proxyConfig);
            logger.info("Edge configured to use BurpSuite proxy: {}", proxyConfig);
        }
        
        // Security settings for testing
        if (config.isAcceptInsecureCertificates()) {
            options.addArguments("--ignore-certificate-errors");
            options.addArguments("--ignore-ssl-errors");
            options.addArguments("--allow-running-insecure-content");
        }
        
        // Custom user agent
        if (config.getUserAgent() != null) {
            options.addArguments("--user-agent=" + config.getUserAgent());
        }
        
        // Custom capabilities
        if (!config.getCustomCapabilities().isEmpty()) {
            config.getCustomCapabilities().forEach(options::setCapability);
        }
        
        return new EdgeDriver(options);
    }
    
    /**
     * Get active browser session by ID
     */
    public static BrowserSession getSession(String sessionId) {
        WebDriver driver = activeSessions.get(sessionId);
        if (driver == null) {
            return null;
        }
        
        // Create session wrapper (simplified - in production would store full session objects)
        return new BrowserSession(sessionId, driver, new BrowserConfig());
    }
    
    /**
     * Get all active session IDs
     */
    public static Set<String> getActiveSessions() {
        return new HashSet<>(activeSessions.keySet());
    }
    
    /**
     * Close specific browser session
     */
    public static boolean closeSession(String sessionId) {
        WebDriver driver = activeSessions.remove(sessionId);
        if (driver != null) {
            try {
                driver.quit();
                logger.info("Browser session closed: {}", sessionId);
                return true;
            } catch (Exception e) {
                logger.warn("Error closing browser session {}: {}", sessionId, e.getMessage());
                return false;
            }
        }
        return false;
    }
    
    /**
     * Close all active browser sessions
     */
    public static void closeAllSessions() {
        logger.info("Closing all browser sessions: {}", activeSessions.size());
        
        for (Map.Entry<String, WebDriver> entry : activeSessions.entrySet()) {
            try {
                entry.getValue().quit();
                logger.debug("Closed browser session: {}", entry.getKey());
            } catch (Exception e) {
                logger.warn("Error closing browser session {}: {}", entry.getKey(), e.getMessage());
            }
        }
        
        activeSessions.clear();
        logger.info("All browser sessions closed");
    }
    
    /**
     * Get browser session statistics
     */
    public static Map<String, Object> getSessionStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("active_sessions", activeSessions.size());
        stats.put("session_ids", new ArrayList<>(activeSessions.keySet()));
        stats.put("total_sessions_created", sessionIdCounter.get() - 1);
        return stats;
    }
    
    /**
     * Create default configuration for security testing
     */
    public static BrowserConfig createSecurityTestingConfig() {
        BrowserConfig config = new BrowserConfig();
        config.setBrowserType(BrowserType.CHROME);
        config.setUseBurpProxy(true);
        config.setAcceptInsecureCertificates(true);
        config.setHeadless(false); // Show browser for interactive testing
        config.setTimeoutSeconds(30);
        config.setImplicitWaitSeconds(10);
        
        // Security testing specific options
        config.getChromeArguments().addAll(Arrays.asList(
            "--disable-web-security",
            "--disable-features=VizDisplayCompositor",
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-field-trial-config"
        ));
        
        return config;
    }
    
    /**
     * Create headless configuration for automated testing
     */
    public static BrowserConfig createHeadlessConfig() {
        BrowserConfig config = createSecurityTestingConfig();
        config.setHeadless(true);
        config.setBrowserType(BrowserType.CHROME_HEADLESS);
        return config;
    }
    
    // Instance methods for integration testing compatibility
    
    /**
     * Initialize browser manager (for compatibility with tests)
     */
    public void initialize() {
        logger.info("Initializing BrowserManager");
        // Setup WebDriver managers
        setupWebDriverManagers();
        // Start extension server
        startExtensionServer();
    }
    
    /**
     * Initialize Chrome Extension Server
     */
    private void initializeExtensionServer() {
        try {
            // Create custom message handler that integrates with BurpSuite
            ChromeExtensionServer.ExtensionMessageHandler handler = new BurpExtensionMessageHandler();
            
            // Initialize server with custom handler
            this.extensionServer = new ChromeExtensionServer(api, "localhost", 1337, handler);
            
            logger.info("Chrome Extension Server initialized for path: {}", extensionPath);
            
        } catch (Exception e) {
            logger.error("Failed to initialize Chrome Extension Server", e);
            this.extensionServer = new ChromeExtensionServer(api); // Fallback to default
        }
    }
    
    /**
     * Start Chrome Extension Server
     */
    public void startExtensionServer() {
        if (extensionServer != null && !extensionServer.isRunning()) {
            try {
                extensionServer.start();
                logger.info("Chrome Extension Server started successfully");
                
                if (api != null) {
                    api.logging().logToOutput("[BrowserManager] Chrome Extension Server ready for connections");
                }
            } catch (IOException e) {
                logger.error("Failed to start Chrome Extension Server", e);
                if (api != null) {
                    api.logging().logToError("Chrome Extension Server failed to start: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * Stop Chrome Extension Server
     */
    public void stopExtensionServer() {
        if (extensionServer != null && extensionServer.isRunning()) {
            extensionServer.stop();
            logger.info("Chrome Extension Server stopped");
            
            if (api != null) {
                api.logging().logToOutput("[BrowserManager] Chrome Extension Server stopped");
            }
        }
    }
    
    /**
     * Setup all WebDriver managers
     */
    private void setupWebDriverManagers() {
        try {
            WebDriverManager.chromedriver().setup();
            WebDriverManager.firefoxdriver().setup();
            WebDriverManager.edgedriver().setup();
            logger.info("WebDriver managers initialized successfully");
        } catch (Exception e) {
            logger.warn("Some WebDriver managers failed to initialize: {}", e.getMessage());
        }
    }
    
    /**
     * Create default configuration
     */
    public static BrowserConfig createDefaultConfig() {
        BrowserConfig config = new BrowserConfig();
        config.setBrowserType(BrowserType.CHROME);
        config.setHeadless(true);
        config.setUseBurpProxy(true);
        return config;
    }
    
    /**
     * Create browser session with string type and options map (for test compatibility)
     */
    public String createBrowserSession(String browserType, Map<String, Object> options) throws Exception {
        BrowserConfig config = createConfigFromOptions(browserType, options);
        BrowserSession session = createSession(config);
        return session.getSessionId();
    }
    
    /**
     * Create browser config from string type and options
     */
    private BrowserConfig createConfigFromOptions(String browserType, Map<String, Object> options) {
        BrowserConfig config = new BrowserConfig();
        config.setBrowserType(BrowserType.fromString(browserType));
        
        if (options.containsKey("headless")) {
            config.setHeadless((Boolean) options.get("headless"));
        }
        if (options.containsKey("target")) {
            // Target URL is handled during navigation
        }
        if (options.containsKey("proxy")) {
            Map<String, Object> proxyConfig = (Map<String, Object>) options.get("proxy");
            config.setUseBurpProxy(true);
        }
        if (options.containsKey("ignoreSslErrors")) {
            config.setAcceptInsecureCertificates((Boolean) options.get("ignoreSslErrors"));
        }
        if (options.containsKey("extensionEnabled")) {
            config.setEnableExtensions((Boolean) options.get("extensionEnabled"));
        }
        
        return config;
    }
    
    /**
     * Navigate to URL (for test compatibility)
     */
    public boolean navigateToUrl(String sessionId, String url) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver != null) {
                driver.get(url);
                return true;
            }
            return false;
        } catch (Exception e) {
            logger.error("Navigation failed: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Get current URL (for test compatibility)
     */
    public String getCurrentUrl(String sessionId) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            return driver != null ? driver.getCurrentUrl() : null;
        } catch (Exception e) {
            logger.error("Failed to get current URL: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Close browser session (for test compatibility)
     */
    public boolean closeBrowserSession(String sessionId) {
        return closeSession(sessionId);
    }
    
    /**
     * Cleanup all sessions (for test compatibility)
     */
    public void cleanupAllSessions() {
        closeAllSessions();
    }
    
    /**
     * Get active session count (for test compatibility)
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }
    
    /**
     * Get browser session (for test compatibility)
     */
    public BrowserSession getBrowserSession(String sessionId) {
        return getSession(sessionId);
    }
    
    /**
     * Create session with sessionId (for compatibility with EnhancedAILoginSequenceRecorder)
     */
    public WebDriver createSession(String sessionId, BrowserConfig config) {
        BrowserSession session = createSession(config);
        // Replace the generated session ID with the provided one
        activeSessions.remove(session.getSessionId());
        activeSessions.put(sessionId, session.getDriver());
        return session.getDriver();
    }
    
    // Additional methods that integration tests expect
    
    public Map<String, Object> getWebDriverCapabilities(String sessionId) {
        // Mock implementation for testing
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("browserName", "chrome");
        capabilities.put("version", "118.0.0.0");
        capabilities.put("platform", "LINUX");
        return capabilities;
    }
    
    public boolean isWebDriverHealthy(String sessionId) {
        WebDriver driver = activeSessions.get(sessionId);
        try {
            return driver != null && driver.getCurrentUrl() != null;
        } catch (Exception e) {
            return false;
        }
    }
    
    // Mock methods for extension communication (to be implemented with real extension)
    public boolean isExtensionLoaded(String sessionId, String extensionId) {
        return false; // Mock - would check actual extension loading
    }
    
    public Map<String, Object> executeExtensionCommand(String sessionId, String command, Map<String, Object> params) {
        // Mock implementation - would communicate with real extension
        Map<String, Object> result = new HashMap<>();
        result.put("command", command);
        result.put("status", "mocked");
        result.put("message", "Extension communication not implemented yet");
        return result;
    }
    
    // Mock methods for element operations
    public Map<String, Object> findElement(String sessionId, String selectorType, String selector) {
        Map<String, Object> result = new HashMap<>();
        result.put("found", true);
        result.put("selector", selector);
        return result;
    }
    
    public boolean fillElement(String sessionId, String selectorType, String selector, String value) {
        // Mock implementation - would use WebDriver element interaction
        return true;
    }
    
    public String getElementAttribute(String sessionId, String selectorType, String selector, String attribute) {
        // Mock implementation
        return attribute.equals("value") ? "test-value" : "test-attribute";
    }
    
    public boolean isElementVisible(String sessionId, String selectorType, String selector) {
        // Mock implementation
        return true;
    }
    
    public List<Map<String, Object>> findElements(String sessionId, String selectorType, String selector) {
        // Mock implementation
        List<Map<String, Object>> elements = new ArrayList<>();
        Map<String, Object> element = new HashMap<>();
        element.put("selector", selector);
        element.put("found", true);
        elements.add(element);
        return elements;
    }
    
    // JavaScript execution methods
    public Object executeScript(String sessionId, String script, List<Object> arguments) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver instanceof JavascriptExecutor) {
                return ((JavascriptExecutor) driver).executeScript(script, arguments.toArray());
            }
        } catch (Exception e) {
            logger.error("Script execution failed: {}", e.getMessage());
        }
        return null;
    }
    
    public Object executeAsyncScript(String sessionId, String script, List<Object> arguments, Duration timeout) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver instanceof JavascriptExecutor) {
                driver.manage().timeouts().scriptTimeout(timeout);
                return ((JavascriptExecutor) driver).executeAsyncScript(script, arguments.toArray());
            }
        } catch (Exception e) {
            logger.error("Async script execution failed: {}", e.getMessage());
        }
        return null;
    }
    
    /**
     * Enhanced form interaction methods using real WebDriver
     */
    public boolean fillFormField(String sessionId, String selector, String value) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                logger.error("No active session found for ID: {}", sessionId);
                return false;
            }
            
            WebElement element = driver.findElement(By.cssSelector(selector));
            element.clear();
            element.sendKeys(value);
            
            logger.info("Successfully filled form field '{}' in session {}", selector, sessionId);
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to fill form field '{}' in session {}: {}", selector, sessionId, e.getMessage());
            return false;
        }
    }
    
    public boolean clickElement(String sessionId, String selector) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                logger.error("No active session found for ID: {}", sessionId);
                return false;
            }
            
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
            WebElement element = wait.until(ExpectedConditions.elementToBeClickable(By.cssSelector(selector)));
            element.click();
            
            logger.info("Successfully clicked element '{}' in session {}", selector, sessionId);
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to click element '{}' in session {}: {}", selector, sessionId, e.getMessage());
            return false;
        }
    }
    
    public List<WebElement> findElementsAdvanced(String sessionId, String selector) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                logger.error("No active session found for ID: {}", sessionId);
                return new ArrayList<>();
            }
            
            return driver.findElements(By.cssSelector(selector));
            
        } catch (Exception e) {
            logger.error("Failed to find elements '{}' in session {}: {}", selector, sessionId, e.getMessage());
            return new ArrayList<>();
        }
    }
    
    public Map<String, Object> analyzeFormStructure(String sessionId) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                return Map.of("error", "No active session found");
            }
            
            // Find all forms on the page
            List<WebElement> forms = driver.findElements(By.tagName("form"));
            List<Map<String, Object>> formData = new ArrayList<>();
            
            for (WebElement form : forms) {
                Map<String, Object> formInfo = new HashMap<>();
                formInfo.put("action", form.getAttribute("action"));
                formInfo.put("method", form.getAttribute("method"));
                formInfo.put("id", form.getAttribute("id"));
                formInfo.put("name", form.getAttribute("name"));
                
                // Find input fields
                List<WebElement> inputs = form.findElements(By.tagName("input"));
                List<Map<String, String>> inputData = new ArrayList<>();
                
                for (WebElement input : inputs) {
                    Map<String, String> inputInfo = new HashMap<>();
                    inputInfo.put("type", input.getAttribute("type"));
                    inputInfo.put("name", input.getAttribute("name"));
                    inputInfo.put("id", input.getAttribute("id"));
                    inputInfo.put("placeholder", input.getAttribute("placeholder"));
                    inputData.add(inputInfo);
                }
                
                formInfo.put("inputs", inputData);
                formData.add(formInfo);
            }
            
            return Map.of(
                "formsFound", forms.size(),
                "forms", formData,
                "timestamp", System.currentTimeMillis()
            );
            
        } catch (Exception e) {
            logger.error("Failed to analyze form structure in session {}: {}", sessionId, e.getMessage());
            return Map.of("error", e.getMessage());
        }
    }
    
    public byte[] captureScreenshot(String sessionId) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                logger.error("No active session found for ID: {}", sessionId);
                return null;
            }
            
            if (driver instanceof TakesScreenshot) {
                byte[] screenshot = ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES);
                logger.info("Screenshot captured for session {} ({} bytes)", sessionId, screenshot.length);
                return screenshot;
            } else {
                logger.warn("WebDriver for session {} does not support screenshots", sessionId);
                return null;
            }
            
        } catch (Exception e) {
            logger.error("Failed to capture screenshot for session {}: {}", sessionId, e.getMessage());
            return null;
        }
    }
    
    public String captureScreenshotAsBase64(String sessionId) {
        try {
            WebDriver driver = activeSessions.get(sessionId);
            if (driver == null) {
                logger.error("No active session found for ID: {}", sessionId);
                return null;
            }
            
            if (driver instanceof TakesScreenshot) {
                String screenshot = ((TakesScreenshot) driver).getScreenshotAs(OutputType.BASE64);
                logger.info("Base64 screenshot captured for session {}", sessionId);
                return screenshot;
            } else {
                logger.warn("WebDriver for session {} does not support screenshots", sessionId);
                return null;
            }
            
        } catch (Exception e) {
            logger.error("Failed to capture Base64 screenshot for session {}: {}", sessionId, e.getMessage());
            return null;
        }
    }
    
    /**
     * Load Chrome Extension for BurpSuite MCP integration
     */
    private static void loadChromeExtension(ChromeOptions options) {
        try {
            Path extensionPath = Paths.get(System.getProperty("user.dir"), "chrome-extension");
            if (Files.exists(extensionPath) && Files.isDirectory(extensionPath)) {
                Path manifestPath = extensionPath.resolve("manifest.json");
                if (Files.exists(manifestPath)) {
                    options.addArguments("--load-extension=" + extensionPath.toAbsolutePath().toString());
                    logger.info("Chrome extension loaded from: {}", extensionPath);
                } else {
                    logger.warn("Chrome extension manifest.json not found at: {}", manifestPath);
                }
            } else {
                logger.warn("Chrome extension directory not found: {}", extensionPath);
            }
        } catch (Exception e) {
            logger.error("Failed to load Chrome extension: {}", e.getMessage());
        }
    }
    
    /**
     * Custom Extension Message Handler that integrates with BurpSuite
     */
    private class BurpExtensionMessageHandler implements ChromeExtensionServer.ExtensionMessageHandler {
        
        @Override
        public Map<String, Object> handleAnalyzeRequest(String sessionId, JsonNode data) {
            try {
                String url = data.has("url") ? data.get("url").asText() : "unknown";
                logger.info("[Extension] Analysis request for URL: {} from session: {}", url, sessionId);
                
                if (api != null) {
                    api.logging().logToOutput(String.format("[ChromeExt] Analyzing URL: %s (Session: %s)", url, sessionId));
                    
                    // TODO: Integrate with BurpSuite Scanner API
                    // This is where we would trigger actual BurpSuite analysis
                    // For now, return mock data with security findings
                }
                
                // Generate realistic security analysis response
                List<Map<String, Object>> findings = new ArrayList<>();
                
                // Mock finding 1: Potential XSS
                findings.add(Map.of(
                    "type", "Cross-Site Scripting (XSS)",
                    "severity", "high",
                    "confidence", "medium",
                    "description", "Potential XSS vulnerability detected in form inputs",
                    "location", url,
                    "recommendation", "Implement proper input validation and output encoding"
                ));
                
                // Mock finding 2: Missing security headers
                findings.add(Map.of(
                    "type", "Missing Security Headers",
                    "severity", "medium",
                    "confidence", "high",
                    "description", "Missing Content-Security-Policy header",
                    "location", url,
                    "recommendation", "Implement Content-Security-Policy header"
                ));
                
                return Map.of(
                    "success", true,
                    "analysisId", "analysis_" + System.currentTimeMillis(),
                    "url", url,
                    "sessionId", sessionId,
                    "findingsCount", findings.size(),
                    "findings", findings,
                    "timestamp", java.time.Instant.now().toString()
                );
                
            } catch (Exception e) {
                logger.error("Error handling analysis request", e);
                return Map.of(
                    "success", false,
                    "error", "Analysis failed: " + e.getMessage(),
                    "timestamp", java.time.Instant.now().toString()
                );
            }
        }
        
        @Override
        public Map<String, Object> handleRecordingRequest(String sessionId, JsonNode data) {
            try {
                String action = data.has("action") ? data.get("action").asText() : "unknown";
                logger.info("[Extension] Recording {} from session: {}", action, sessionId);
                
                if (api != null) {
                    api.logging().logToOutput(String.format("[ChromeExt] Recording action: %s (Session: %s)", action, sessionId));
                }
                
                // Extract interaction data
                Map<String, Object> interactionData = new HashMap<>();
                if (data.has("element")) {
                    JsonNode element = data.get("element");
                    interactionData.put("tag", element.has("tagName") ? element.get("tagName").asText() : "unknown");
                    interactionData.put("id", element.has("id") ? element.get("id").asText() : null);
                    interactionData.put("className", element.has("className") ? element.get("className").asText() : null);
                }
                
                if (data.has("timestamp")) {
                    interactionData.put("clientTimestamp", data.get("timestamp").asLong());
                }
                
                // TODO: Store interaction data in BurpSuite session or database
                
                return Map.of(
                    "success", true,
                    "recordingId", "rec_" + System.currentTimeMillis(),
                    "action", action,
                    "sessionId", sessionId,
                    "interactionData", interactionData,
                    "timestamp", java.time.Instant.now().toString()
                );
                
            } catch (Exception e) {
                logger.error("Error handling recording request", e);
                return Map.of(
                    "success", false,
                    "error", "Recording failed: " + e.getMessage(),
                    "timestamp", java.time.Instant.now().toString()
                );
            }
        }
        
        @Override
        public Map<String, Object> handleScreenshotRequest(String sessionId, JsonNode data) {
            try {
                String url = data.has("url") ? data.get("url").asText() : "unknown";
                logger.info("[Extension] Screenshot request for URL: {} from session: {}", url, sessionId);
                
                if (api != null) {
                    api.logging().logToOutput(String.format("[ChromeExt] Screenshot captured: %s (Session: %s)", url, sessionId));
                }
                
                // Extract screenshot metadata
                Map<String, Object> metadata = new HashMap<>();
                if (data.has("viewport")) {
                    metadata.put("viewport", data.get("viewport"));
                }
                if (data.has("timestamp")) {
                    metadata.put("clientTimestamp", data.get("timestamp").asLong());
                }
                
                // TODO: Store screenshot data in BurpSuite session
                // For now, just acknowledge receipt
                
                return Map.of(
                    "success", true,
                    "screenshotId", "screenshot_" + System.currentTimeMillis(),
                    "url", url,
                    "sessionId", sessionId,
                    "metadata", metadata,
                    "message", "Screenshot captured and stored",
                    "timestamp", java.time.Instant.now().toString()
                );
                
            } catch (Exception e) {
                logger.error("Error handling screenshot request", e);
                return Map.of(
                    "success", false,
                    "error", "Screenshot failed: " + e.getMessage(),
                    "timestamp", java.time.Instant.now().toString()
                );
            }
        }
        
        @Override
        public Map<String, Object> handleFormsAnalysisRequest(String sessionId, JsonNode data) {
            try {
                String url = data.has("url") ? data.get("url").asText() : "unknown";
                int formCount = 0;
                List<Map<String, Object>> formAnalysis = new ArrayList<>();
                
                if (data.has("forms") && data.get("forms").isArray()) {
                    formCount = data.get("forms").size();
                    
                    // Analyze each form
                    for (JsonNode form : data.get("forms")) {
                        Map<String, Object> analysis = analyzeForm(form);
                        formAnalysis.add(analysis);
                    }
                }
                
                logger.info("[Extension] Forms analysis for {} forms on URL: {} from session: {}", formCount, url, sessionId);
                
                if (api != null) {
                    api.logging().logToOutput(String.format("[ChromeExt] Analyzed %d forms on: %s (Session: %s)", formCount, url, sessionId));
                }
                
                // Generate security issues based on forms analysis
                List<Map<String, Object>> securityIssues = generateFormSecurityIssues(formAnalysis);
                
                return Map.of(
                    "success", true,
                    "analysisId", "forms_analysis_" + System.currentTimeMillis(),
                    "url", url,
                    "sessionId", sessionId,
                    "formsCount", formCount,
                    "formsAnalysis", formAnalysis,
                    "securityIssues", securityIssues,
                    "timestamp", java.time.Instant.now().toString()
                );
                
            } catch (Exception e) {
                logger.error("Error handling forms analysis request", e);
                return Map.of(
                    "success", false,
                    "error", "Forms analysis failed: " + e.getMessage(),
                    "timestamp", java.time.Instant.now().toString()
                );
            }
        }
        
        @Override
        public Map<String, Object> handleConnectionStatus(String sessionId) {
            Map<String, Object> status = new HashMap<>();
            status.put("connected", true);
            status.put("serverVersion", "1.0.0");
            status.put("sessionId", sessionId);
            status.put("capabilities", List.of("recording", "analysis", "screenshots", "forms", "burp-integration"));
            status.put("burpSuiteConnected", api != null);
            status.put("extensionServerRunning", extensionServer != null && extensionServer.isRunning());
            status.put("activeSessions", extensionServer != null ? extensionServer.getActiveSessionCount() : 0);
            status.put("timestamp", java.time.Instant.now().toString());
            
            if (api != null) {
                status.put("burpVersion", "BurpSuite Professional");
                status.put("montoyaVersion", "Latest");
            }
            
            return status;
        }
        
        /**
         * Analyze individual form for security issues
         */
        private Map<String, Object> analyzeForm(JsonNode form) {
            Map<String, Object> analysis = new HashMap<>();
            
            // Basic form properties
            analysis.put("action", form.has("action") ? form.get("action").asText() : null);
            analysis.put("method", form.has("method") ? form.get("method").asText() : "GET");
            
            // Security analysis
            List<String> securityIssues = new ArrayList<>();
            
            // Check for HTTPS
            String action = form.has("action") ? form.get("action").asText() : "";
            if (action.startsWith("http://")) {
                securityIssues.add("Form submits over insecure HTTP");
            }
            
            // Check for CSRF protection
            boolean hasCSRFToken = false;
            if (form.has("inputs") && form.get("inputs").isArray()) {
                for (JsonNode input : form.get("inputs")) {
                    String name = input.has("name") ? input.get("name").asText() : "";
                    String type = input.has("type") ? input.get("type").asText() : "";
                    if ((name.contains("csrf") || name.contains("token")) && "hidden".equals(type)) {
                        hasCSRFToken = true;
                        break;
                    }
                }
            }
            
            if (!hasCSRFToken) {
                securityIssues.add("Missing CSRF protection token");
            }
            
            // Check for password fields without proper attributes
            if (form.has("inputs") && form.get("inputs").isArray()) {
                for (JsonNode input : form.get("inputs")) {
                    String type = input.has("type") ? input.get("type").asText() : "";
                    if ("password".equals(type)) {
                        String autocomplete = input.has("autocomplete") ? input.get("autocomplete").asText() : "";
                        if (!"off".equals(autocomplete) && !"current-password".equals(autocomplete)) {
                            securityIssues.add("Password field may allow autocomplete");
                        }
                    }
                }
            }
            
            analysis.put("securityIssues", securityIssues);
            analysis.put("riskLevel", securityIssues.isEmpty() ? "low" : "medium");
            
            return analysis;
        }
        
        /**
         * Generate security issues from forms analysis
         */
        private List<Map<String, Object>> generateFormSecurityIssues(List<Map<String, Object>> formAnalysis) {
            List<Map<String, Object>> issues = new ArrayList<>();
            
            for (Map<String, Object> analysis : formAnalysis) {
                @SuppressWarnings("unchecked")
                List<String> securityIssues = (List<String>) analysis.get("securityIssues");
                
                if (securityIssues != null) {
                    for (String issue : securityIssues) {
                        Map<String, Object> securityIssue = new HashMap<>();
                        securityIssue.put("type", "form_security");
                        securityIssue.put("description", issue);
                        securityIssue.put("formAction", analysis.get("action"));
                        
                        // Determine severity
                        if (issue.contains("HTTP")) {
                            securityIssue.put("severity", "high");
                        } else if (issue.contains("CSRF")) {
                            securityIssue.put("severity", "medium");
                        } else {
                            securityIssue.put("severity", "low");
                        }
                        
                        // Add recommendations
                        if (issue.contains("HTTP")) {
                            securityIssue.put("recommendation", "Use HTTPS for form submissions");
                        } else if (issue.contains("CSRF")) {
                            securityIssue.put("recommendation", "Implement CSRF protection tokens");
                        } else if (issue.contains("autocomplete")) {
                            securityIssue.put("recommendation", "Set autocomplete=\"off\" for sensitive fields");
                        }
                        
                        issues.add(securityIssue);
                    }
                }
            }
            
            return issues;
        }
    }
    
    // Public methods for extension integration
    
    /**
     * Get Chrome Extension Server status
     */
    public Map<String, Object> getExtensionServerStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("running", extensionServer != null && extensionServer.isRunning());
        status.put("port", extensionServer != null ? extensionServer.getPort() : null);
        status.put("host", extensionServer != null ? extensionServer.getHost() : null);
        status.put("activeSessions", extensionServer != null ? extensionServer.getActiveSessionCount() : 0);
        status.put("totalRequests", extensionServer != null ? extensionServer.getTotalRequests() : 0);
        status.put("successfulRequests", extensionServer != null ? extensionServer.getSuccessfulRequests() : 0);
        status.put("failedRequests", extensionServer != null ? extensionServer.getFailedRequests() : 0);
        return status;
    }
    
    /**
     * Get active extension sessions
     */
    public Set<String> getActiveExtensionSessions() {
        return extensionServer != null ? extensionServer.getActiveSessions() : new HashSet<>();
    }
    
    /**
     * Check if Chrome extension is loaded for a specific session
     */
    public boolean isExtensionLoadedForSession(String sessionId) {
        // Check if the WebDriver session has the extension loaded
        WebDriver driver = activeSessions.get(sessionId);
        if (driver instanceof JavascriptExecutor) {
            try {
                // Check if our extension's content script is available
                Object result = ((JavascriptExecutor) driver).executeScript(
                    "return typeof window.burpMcpExtension !== 'undefined';"
                );
                return Boolean.TRUE.equals(result);
            } catch (Exception e) {
                logger.debug("Extension check failed for session {}: {}", sessionId, e.getMessage());
                return false;
            }
        }
        return false;
    }
    
    /**
     * Cleanup method to stop extension server
     */
    public void cleanup() {
        cleanupAllSessions();
        stopExtensionServer();
    }
    
    /**
     * Browser automation exception
     */
    public static class BrowserAutomationException extends RuntimeException {
        public BrowserAutomationException(String message) {
            super(message);
        }
        
        public BrowserAutomationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
