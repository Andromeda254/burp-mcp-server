# 🌐 Advanced Browser Integration & AI-Assisted Authentication

This document provides comprehensive browser integration capabilities with AI-assisted login sequence recording, session management, and automated authentication workflows using Montoya API.

## 🌟 Overview

The browser integration system delivers professional browser automation and analysis through:
- **Montoya API Browser Integration** - Native BurpSuite browser capabilities
- **AI-Assisted Login Recording** - Smart authentication sequence capture
- **Chrome Extension Support** - Direct integration with Burp Chrome extension
- **Session State Management** - Persistent authentication state handling
- **Automated Replay** - Intelligent sequence reproduction with variations

## 🏗️ System Architecture (Montoya API Compliant)

### 1. Montoya API Browser Integration
```java
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.WebKitContextMenuEvent;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

public class MontoyaBrowserIntegration {
    
    private final MontoyaApi api;
    private final SessionManager sessionManager;
    private final LoginSequenceRecorder loginRecorder;
    private final ChromeExtensionInterface chromeExtension;
    
    public MontoyaBrowserIntegration(MontoyaApi api) {
        this.api = api;
        this.sessionManager = new SessionManager(api);
        this.loginRecorder = new AILoginSequenceRecorder(api);
        this.chromeExtension = new ChromeExtensionInterface(api);
        
        // Register browser context menu integration
        api.userInterface().registerContextMenuItemsProvider(new BrowserContextMenuProvider());
        
        // Initialize browser automation capabilities
        initializeBrowserAutomation();
    }
    
    private void initializeBrowserAutomation() {
        api.logging().logToOutput("[BROWSER-INIT] Initializing browser integration...");
        
        try {
            // Setup Chrome extension communication if available
            if (chromeExtension.isAvailable()) {
                api.logging().logToOutput("[BROWSER-INIT] Chrome extension detected and connected");
                chromeExtension.initialize();
            }
            
            // Initialize session state tracking
            sessionManager.initialize();
            
            // Setup login sequence detection
            loginRecorder.initialize();
            
            api.logging().logToOutput("[BROWSER-INIT] Browser integration ready");
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Browser integration initialization failed: " + e.getMessage());
        }
    }
    
    public BrowserSession createManagedSession(BrowserConfig config) {
        try {
            api.logging().logToOutput(String.format(
                "[BROWSER-SESSION] Creating managed browser session for %s",
                config.getTargetUrl()
            ));
            
            var session = new BrowserSession(config, api);
            
            // Configure session with Montoya API integration
            session.setProxyConfiguration(api.proxy().options());
            session.setSessionTracking(sessionManager);
            session.setLoginRecorder(loginRecorder);
            
            // Enable AI-assisted behaviors
            if (config.isAIAssisted()) {
                session.enableAIBehaviors();
                api.logging().logToOutput("[BROWSER-SESSION] AI-assisted behaviors enabled");
            }
            
            // Start session monitoring
            sessionManager.startMonitoring(session);
            
            return session;
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Failed to create browser session: " + e.getMessage());
            throw new BrowserIntegrationException("Session creation failed", e);
        }
    }
}
```

### 2. AI-Assisted Login Sequence Recording
```java
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class AILoginSequenceRecorder {
    
    private final MontoyaApi api;
    private final LoginPatternAnalyzer patternAnalyzer;
    private final SequenceBuilder sequenceBuilder;
    private final AuthenticationDetector authDetector;
    
    public AILoginSequenceRecorder(MontoyaApi api) {
        this.api = api;
        this.patternAnalyzer = new LoginPatternAnalyzer(api);
        this.sequenceBuilder = new SequenceBuilder(api);
        this.authDetector = new AuthenticationDetector(api);
    }
    
    public void initialize() {
        // Register proxy listeners for login sequence detection
        api.proxy().registerRequestHandler(this::analyzeRequestForLoginSequence);
        api.proxy().registerResponseHandler(this::analyzeResponseForAuthenticationState);
        
        api.logging().logToOutput("[LOGIN-RECORDER] AI-assisted login recording initialized");
    }
    
    private RequestReceivedAction analyzeRequestForLoginSequence(ProxyHttpRequestResponse requestResponse) {
        var request = requestResponse.request();
        
        try {
            // Use AI pattern recognition to identify login-related requests
            var loginAnalysis = patternAnalyzer.analyzeRequest(request);
            
            if (loginAnalysis.isLoginRelated()) {
                api.logging().logToOutput(String.format(
                    "[LOGIN-DETECT] Login-related request detected: %s (confidence: %.2f)",
                    request.url(), loginAnalysis.getConfidence()
                ));
                
                // Start or continue login sequence recording
                var sequence = sequenceBuilder.processLoginRequest(request, loginAnalysis);
                
                if (sequence.isComplete()) {
                    api.logging().logToOutput("[LOGIN-SEQUENCE] Complete login sequence captured");
                    storeLoginSequence(sequence);
                }
            }
            
            return RequestReceivedAction.continueWith(request);
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Login sequence analysis failed: " + e.getMessage());
            return RequestReceivedAction.continueWith(request);
        }
    }
    
    private ResponseReceivedAction analyzeResponseForAuthenticationState(ProxyHttpRequestResponse requestResponse) {
        var response = requestResponse.response();
        var request = requestResponse.request();
        
        try {
            // Detect authentication state changes
            var authState = authDetector.analyzeAuthenticationState(response, request);
            
            if (authState.hasStateChange()) {
                api.logging().logToOutput(String.format(
                    "[AUTH-STATE] Authentication state change detected: %s -> %s",
                    authState.getPreviousState(), authState.getCurrentState()
                ));
                
                // Update current login sequence with authentication result
                sequenceBuilder.updateSequenceWithAuthResult(authState);
                
                // Extract session tokens and cookies
                var sessionData = extractSessionData(response);
                if (!sessionData.isEmpty()) {
                    api.logging().logToOutput("[SESSION-DATA] Session data extracted and stored");
                    storeSessionData(request.url(), sessionData);
                }
            }
            
            return ResponseReceivedAction.continueWith(response);
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Authentication state analysis failed: " + e.getMessage());
            return ResponseReceivedAction.continueWith(response);
        }
    }
    
    public LoginSequence recordInteractiveLogin(String targetUrl, LoginRecordingConfig config) {
        try {
            api.logging().logToOutput(String.format(
                "[INTERACTIVE-LOGIN] Starting interactive login recording for %s",
                targetUrl
            ));
            
            // Create recording session
            var recordingSession = new InteractiveRecordingSession(targetUrl, config, api);
            
            // Enable AI-guided recording
            if (config.isAIGuided()) {
                recordingSession.enableAIGuidance();
                api.logging().logToOutput("[INTERACTIVE-LOGIN] AI guidance enabled");
            }
            
            // Start recording
            var sequence = recordingSession.startRecording();
            
            // Monitor for completion
            while (!sequence.isComplete() && !recordingSession.isTimeout()) {
                Thread.sleep(100);
                sequence = recordingSession.getCurrentSequence();
            }
            
            if (sequence.isComplete()) {
                api.logging().logToOutput("[INTERACTIVE-LOGIN] Login sequence recording completed successfully");
                
                // Validate sequence with AI analysis
                var validation = validateLoginSequence(sequence);
                sequence.setValidationResult(validation);
                
                return sequence;
            } else {
                throw new LoginRecordingException("Recording timeout or incomplete sequence");
            }
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Interactive login recording failed: " + e.getMessage());
            throw new LoginRecordingException("Interactive recording failed", e);
        }
    }
    
    private LoginSequenceValidation validateLoginSequence(LoginSequence sequence) {
        var validation = new LoginSequenceValidation();
        
        try {
            // AI-powered sequence validation
            var aiAnalysis = patternAnalyzer.validateSequence(sequence);
            validation.setAiValidation(aiAnalysis);
            
            // Test sequence replay
            var replayResult = testSequenceReplay(sequence);
            validation.setReplayTest(replayResult);
            
            // Security analysis
            var securityAnalysis = analyzeSequenceSecurity(sequence);
            validation.setSecurityAnalysis(securityAnalysis);
            
            validation.setOverallScore(calculateValidationScore(validation));
            
            api.logging().logToOutput(String.format(
                "[SEQUENCE-VALIDATION] Login sequence validation complete (score: %.2f/100)",
                validation.getOverallScore()
            ));
            
            return validation;
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Login sequence validation failed: " + e.getMessage());
            return LoginSequenceValidation.failed(e.getMessage());
        }
    }
}
```

### 3. Chrome Extension Integration (Montoya API)
```java
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;

public class ChromeExtensionInterface {
    
    private final MontoyaApi api;
    private final CollaboratorClient collaborator;
    private final ExtensionCommunicator communicator;
    private boolean extensionAvailable = false;
    
    public ChromeExtensionInterface(MontoyaApi api) {
        this.api = api;
        this.collaborator = api.collaborator().createClient();
        this.communicator = new ExtensionCommunicator(api);
    }
    
    public boolean isAvailable() {
        return extensionAvailable;
    }
    
    public void initialize() {
        try {
            api.logging().logToOutput("[CHROME-EXT] Initializing Chrome extension interface...");
            
            // Attempt to establish communication with Chrome extension
            var connectionTest = testExtensionConnection();
            
            if (connectionTest.isSuccessful()) {
                extensionAvailable = true;
                
                // Setup communication channels
                setupCommunicationChannels();
                
                // Register extension capabilities
                registerExtensionCapabilities();
                
                api.logging().logToOutput("[CHROME-EXT] Chrome extension integration active");
            } else {
                api.logging().logToOutput("[CHROME-EXT] Chrome extension not available - using fallback methods");
            }
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Chrome extension initialization failed: " + e.getMessage());
            extensionAvailable = false;
        }
    }
    
    public BrowserAutomationResult automateLogin(LoginSequence sequence, BrowserSession session) {
        if (!extensionAvailable) {
            return fallbackLoginAutomation(sequence, session);
        }
        
        try {
            api.logging().logToOutput(String.format(
                "[CHROME-AUTOMATION] Automating login sequence with %d steps",
                sequence.getSteps().size()
            ));
            
            var automationConfig = new AutomationConfig();
            automationConfig.setSequence(sequence);
            automationConfig.setSession(session);
            automationConfig.setRetryPolicy(RetryPolicy.SMART_RETRY);
            
            // Send automation request to Chrome extension
            var automationRequest = buildAutomationRequest(automationConfig);
            var result = communicator.sendAutomationRequest(automationRequest);
            
            // Monitor automation progress
            while (result.isInProgress()) {
                Thread.sleep(500);
                result = communicator.getAutomationStatus(result.getTaskId());
                
                api.logging().logToOutput(String.format(
                    "[CHROME-AUTOMATION] Progress: %d%% (Step %d/%d)",
                    result.getProgressPercentage(),
                    result.getCurrentStep(),
                    result.getTotalSteps()
                ));
            }
            
            if (result.isSuccessful()) {
                api.logging().logToOutput("[CHROME-AUTOMATION] Login automation completed successfully");
                
                // Extract session data from automation result
                var sessionData = extractAutomationSessionData(result);
                session.updateSessionData(sessionData);
                
                return result;
            } else {
                api.logging().logToOutput("[CHROME-AUTOMATION] Login automation failed: " + result.getErrorMessage());
                return handleAutomationFailure(result, sequence, session);
            }
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Chrome extension automation failed: " + e.getMessage());
            return BrowserAutomationResult.failed(e.getMessage());
        }
    }
    
    public DOMAnalysisResult analyzePage(String url, AnalysisConfig config) {
        if (!extensionAvailable) {
            return fallbackPageAnalysis(url, config);
        }
        
        try {
            api.logging().logToOutput(String.format(
                "[CHROME-ANALYSIS] Analyzing page: %s",
                url
            ));
            
            var analysisRequest = new PageAnalysisRequest();
            analysisRequest.setUrl(url);
            analysisRequest.setConfig(config);
            analysisRequest.setIncludeDOM(config.isIncludeDOM());
            analysisRequest.setIncludeJavaScript(config.isAnalyzeJavaScript());
            analysisRequest.setIncludeFormData(config.isAnalyzeForms());
            
            var result = communicator.sendAnalysisRequest(analysisRequest);
            
            // Process analysis results
            var domAnalysis = processDOMAnalysis(result);
            
            api.logging().logToOutput(String.format(
                "[CHROME-ANALYSIS] Page analysis complete: %d forms, %d inputs, %d scripts found",
                domAnalysis.getFormCount(),
                domAnalysis.getInputCount(),
                domAnalysis.getScriptCount()
            ));
            
            return domAnalysis;
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Chrome extension page analysis failed: " + e.getMessage());
            return DOMAnalysisResult.failed(e.getMessage());
        }
    }
    
    private void setupCommunicationChannels() {
        // Setup bidirectional communication with Chrome extension
        // Using Collaborator for secure communication channel
        var payload = collaborator.generatePayload();
        
        communicator.setCollaboratorPayload(payload);
        communicator.setMessageHandler(this::handleExtensionMessage);
        
        api.logging().logToOutput(String.format(
            "[CHROME-EXT] Communication channel established: %s",
            payload.toString()
        ));
    }
    
    private void handleExtensionMessage(ExtensionMessage message) {
        try {
            api.logging().logToOutput(String.format(
                "[CHROME-EXT-MSG] Received message: %s",
                message.getType()
            ));
            
            switch (message.getType()) {
                case LOGIN_PROGRESS -> handleLoginProgress(message);
                case PAGE_CHANGE -> handlePageChange(message);
                case FORM_DETECTED -> handleFormDetection(message);
                case SESSION_UPDATE -> handleSessionUpdate(message);
                case ERROR_REPORT -> handleErrorReport(message);
                default -> {
                    api.logging().logToOutput("[CHROME-EXT-MSG] Unknown message type: " + message.getType());
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Extension message handling failed: " + e.getMessage());
        }
    }
}
```

### 4. Session State Management (Montoya API)
```java
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.sitemap.SiteMap;

public class MontoyaSessionManager {
    
    private final MontoyaApi api;
    private final SiteMap siteMap;
    private final Map<String, SessionState> activeSessions;
    private final SessionPersistence persistence;
    
    public MontoyaSessionManager(MontoyaApi api) {
        this.api = api;
        this.siteMap = api.siteMap();
        this.activeSessions = new ConcurrentHashMap<>();
        this.persistence = new SessionPersistence(api);
    }
    
    public void initialize() {
        api.logging().logToOutput("[SESSION-MGR] Initializing session management...");
        
        try {
            // Load persisted sessions
            var persistedSessions = persistence.loadSessions();
            activeSessions.putAll(persistedSessions);
            
            api.logging().logToOutput(String.format(
                "[SESSION-MGR] Loaded %d persisted sessions",
                persistedSessions.size()
            ));
            
            // Setup session monitoring
            setupSessionMonitoring();
            
            api.logging().logToOutput("[SESSION-MGR] Session management initialized");
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Session manager initialization failed: " + e.getMessage());
        }
    }
    
    public SessionState createSession(String sessionId, String baseUrl) {
        try {
            var sessionState = new SessionState(sessionId, baseUrl);
            
            // Initialize session with Montoya API integration
            sessionState.setSiteMapIntegration(siteMap);
            
            activeSessions.put(sessionId, sessionState);
            
            api.logging().logToOutput(String.format(
                "[SESSION-CREATE] New session created: %s for %s",
                sessionId, baseUrl
            ));
            
            return sessionState;
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Session creation failed: " + e.getMessage());
            throw new SessionManagementException("Failed to create session", e);
        }
    }
    
    public void updateSessionFromRequest(String sessionId, HttpRequest request) {
        var session = activeSessions.get(sessionId);
        if (session == null) {
            return;
        }
        
        try {
            // Extract and update cookies
            var cookies = extractCookies(request);
            session.updateCookies(cookies);
            
            // Update authentication headers
            var authHeaders = extractAuthHeaders(request);
            session.updateAuthHeaders(authHeaders);
            
            // Update session metadata
            session.updateLastAccess();
            session.addVisitedUrl(request.url());
            
            // Persist session changes
            persistence.persistSession(session);
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Session update failed: " + e.getMessage());
        }
    }
    
    public void updateSessionFromResponse(String sessionId, HttpResponse response) {
        var session = activeSessions.get(sessionId);
        if (session == null) {
            return;
        }
        
        try {
            // Process Set-Cookie headers
            var setCookies = extractSetCookies(response);
            for (var cookie : setCookies) {
                session.setCookie(cookie);
                
                api.logging().logToOutput(String.format(
                    "[SESSION-COOKIE] Updated cookie: %s (secure: %s, httpOnly: %s)",
                    cookie.name(), cookie.secure(), cookie.httpOnly()
                ));
            }
            
            // Analyze response for session indicators
            var sessionIndicators = analyzeSessionIndicators(response);
            if (sessionIndicators.hasSessionChange()) {
                api.logging().logToOutput("[SESSION-CHANGE] Session state change detected");
                session.updateSessionState(sessionIndicators.getNewState());
            }
            
            // Check for authentication status
            var authStatus = analyzeAuthStatus(response);
            if (authStatus != session.getAuthenticationStatus()) {
                session.setAuthenticationStatus(authStatus);
                api.logging().logToOutput(String.format(
                    "[SESSION-AUTH] Authentication status changed: %s",
                    authStatus
                ));
            }
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Session response update failed: " + e.getMessage());
        }
    }
    
    public SessionReplayResult replaySession(String sessionId, ReplayConfig config) {
        var session = activeSessions.get(sessionId);
        if (session == null) {
            return SessionReplayResult.failed("Session not found: " + sessionId);
        }
        
        try {
            api.logging().logToOutput(String.format(
                "[SESSION-REPLAY] Starting session replay: %s",
                sessionId
            ));
            
            var replayEngine = new SessionReplayEngine(api);
            var result = replayEngine.replaySession(session, config);
            
            if (result.isSuccessful()) {
                api.logging().logToOutput(String.format(
                    "[SESSION-REPLAY] Session replay completed: %d requests replayed",
                    result.getRequestsReplayed()
                ));
                
                // Update session with new state
                var newSession = result.getUpdatedSession();
                activeSessions.put(sessionId, newSession);
                persistence.persistSession(newSession);
            } else {
                api.logging().logToOutput(String.format(
                    "[SESSION-REPLAY] Session replay failed: %s",
                    result.getErrorMessage()
                ));
            }
            
            return result;
            
        } catch (Exception e) {
            api.logging().logToError("[ERROR] Session replay failed: " + e.getMessage());
            return SessionReplayResult.failed(e.getMessage());
        }
    }
}
```

## 🛠️ MCP Tool Integration (Montoya API Compliant)

### 1. Browser Session Management Tool
```java
// Add to McpProtocolHandler.java
private McpMessage handleManageBrowserSession(Object id, JsonNode arguments) {
    try {
        var action = arguments.get("action").asText();
        var sessionConfig = parseBrowserSessionConfig(arguments);
        
        var browserIntegration = new MontoyaBrowserIntegration(burpIntegration.getApi());
        
        switch (action.toLowerCase()) {
            case "create" -> {
                var session = browserIntegration.createManagedSession(sessionConfig);
                var response = formatBrowserSessionResponse(session, "created");
                
                return createSuccessResponse(id, Map.of(
                    "content", List.of(Map.of(
                        "type", "text",
                        "text", response
                    ))
                ));
            }
            case "list" -> {
                var sessions = browserIntegration.getActiveSessions();
                var response = formatActiveSessionsList(sessions);
                
                return createSuccessResponse(id, Map.of(
                    "content", List.of(Map.of(
                        "type", "text",
                        "text", response
                    ))
                ));
            }
            case "analyze" -> {
                var sessionId = arguments.get("sessionId").asText();
                var analysis = browserIntegration.analyzeSession(sessionId);
                var response = formatSessionAnalysis(analysis);
                
                return createSuccessResponse(id, Map.of(
                    "content", List.of(Map.of(
                        "type", "text",
                        "text", response
                    ))
                ));
            }
            default -> {
                return createErrorResponse(id, -32602, "Invalid action: " + action);
            }
        }
        
    } catch (Exception e) {
        logger.error("Browser session management failed", e);
        burpIntegration.getApi().logging().logToError("[ERROR] Browser session management failed: " + e.getMessage());
        
        return createErrorResponse(id, -32603, "Session management failed: " + e.getMessage());
    }
}

private String formatBrowserSessionResponse(BrowserSession session, String action) {
    var sb = new StringBuilder();
    sb.append("🌐 Browser Session ").append(action.toUpperCase()).append("\n");
    sb.append("=".repeat(50)).append("\n\n");
    
    sb.append("📋 Session Information:\n");
    sb.append("   Session ID: ").append(session.getSessionId()).append("\n");
    sb.append("   Target URL: ").append(session.getTargetUrl()).append("\n");
    sb.append("   Created: ").append(session.getCreatedAt()).append("\n");
    sb.append("   Status: ").append(session.getStatus()).append("\n\n");
    
    sb.append("🔧 Configuration:\n");
    sb.append("   Proxy Integration: ").append(session.isProxyEnabled() ? "Enabled" : "Disabled").append("\n");
    sb.append("   Session Tracking: ").append(session.isSessionTrackingEnabled() ? "Enabled" : "Disabled").append("\n");
    sb.append("   AI Assistance: ").append(session.isAIAssisted() ? "Enabled" : "Disabled").append("\n");
    sb.append("   Chrome Extension: ").append(session.isChromeExtensionConnected() ? "Connected" : "Not Connected").append("\n\n");
    
    if (session.hasLoginSequence()) {
        sb.append("🔑 Login Sequence:\n");
        sb.append("   Status: ").append(session.getLoginSequence().getStatus()).append("\n");
        sb.append("   Steps: ").append(session.getLoginSequence().getSteps().size()).append("\n");
        sb.append("   Validation Score: ").append(String.format("%.1f/100", session.getLoginSequence().getValidationScore())).append("\n\n");
    }
    
    sb.append("🚀 Available Actions:\n");
    sb.append("   - record_login: Record authentication sequence\n");
    sb.append("   - replay_session: Replay recorded session\n");
    sb.append("   - analyze_dom: Perform DOM analysis\n");
    sb.append("   - extract_session: Extract session data\n");
    
    return sb.toString();
}
```

### 2. Login Recording Tool
```java
private McpMessage handleRecordLogin(Object id, JsonNode arguments) {
    try {
        var targetUrl = arguments.get("targetUrl").asText();
        var recordingConfig = parseLoginRecordingConfig(arguments);
        
        var loginRecorder = new AILoginSequenceRecorder(burpIntegration.getApi());
        
        api.logging().logToOutput(String.format(
            "[LOGIN-RECORDING] Starting login recording for %s",
            targetUrl
        ));
        
        LoginSequence sequence;
        if (recordingConfig.isInteractive()) {
            // Interactive recording with AI guidance
            sequence = loginRecorder.recordInteractiveLogin(targetUrl, recordingConfig);
        } else {
            // Automatic recording based on traffic analysis
            sequence = loginRecorder.recordAutomaticLogin(targetUrl, recordingConfig);
        }
        
        // Store the recorded sequence
        var sequenceId = storeLoginSequence(sequence);
        
        var response = formatLoginSequenceResponse(sequence, sequenceId);
        
        // Report progress to monitor
        if (burpIntegration.getProgressMonitor() != null) {
            burpIntegration.getProgressMonitor().updateScanProgress(
                "login-recording-" + sequenceId,
                "LOGIN_SEQUENCE_RECORDED",
                100.0,
                0,
                0
            );
        }
        
        return createSuccessResponse(id, Map.of(
            "content", List.of(Map.of(
                "type", "text",
                "text", response
            ))
        ));
        
    } catch (Exception e) {
        logger.error("Login recording failed", e);
        burpIntegration.getApi().logging().logToError("[ERROR] Login recording failed: " + e.getMessage());
        
        return createErrorResponse(id, -32603, "Login recording failed: " + e.getMessage());
    }
}

private String formatLoginSequenceResponse(LoginSequence sequence, String sequenceId) {
    var sb = new StringBuilder();
    sb.append("🔑 Login Sequence Recorded\n");
    sb.append("=".repeat(50)).append("\n\n");
    
    sb.append("📋 Sequence Information:\n");
    sb.append("   Sequence ID: ").append(sequenceId).append("\n");
    sb.append("   Target URL: ").append(sequence.getTargetUrl()).append("\n");
    sb.append("   Steps: ").append(sequence.getSteps().size()).append("\n");
    sb.append("   Recording Method: ").append(sequence.getRecordingMethod()).append("\n\n");
    
    sb.append("🎯 Authentication Details:\n");
    sb.append("   Authentication Type: ").append(sequence.getAuthenticationType()).append("\n");
    sb.append("   Success Indicators: ").append(sequence.getSuccessIndicators().size()).append("\n");
    sb.append("   Session Tokens: ").append(sequence.getSessionTokens().size()).append("\n\n");
    
    sb.append("📊 Validation Results:\n");
    if (sequence.hasValidation()) {
        var validation = sequence.getValidationResult();
        sb.append("   Overall Score: ").append(String.format("%.1f/100", validation.getOverallScore())).append("\n");
        sb.append("   AI Analysis: ").append(validation.getAiValidation().getResult()).append("\n");
        sb.append("   Replay Test: ").append(validation.getReplayTest().isSuccessful() ? "PASSED" : "FAILED").append("\n");
        sb.append("   Security Score: ").append(String.format("%.1f/100", validation.getSecurityAnalysis().getScore())).append("\n\n");
    }
    
    sb.append("📝 Sequence Steps:\n");
    for (int i = 0; i < sequence.getSteps().size(); i++) {
        var step = sequence.getSteps().get(i);
        sb.append(String.format("   %d. %s -> %s\n", 
            i + 1, 
            step.getAction(), 
            step.getTarget()
        ));
    }
    
    sb.append("\n🚀 Available Actions:\n");
    sb.append("   - replay_login: Replay this login sequence\n");
    sb.append("   - modify_sequence: Modify sequence parameters\n");
    sb.append("   - export_sequence: Export for external use\n");
    sb.append("   - test_variations: Test with different credentials\n");
    
    return sb.toString();
}
```

### 3. Session Replay Tool
```java
private McpMessage handleReplaySession(Object id, JsonNode arguments) {
    try {
        var sessionId = arguments.get("sessionId").asText();
        var replayConfig = parseReplayConfig(arguments);
        
        var sessionManager = new MontoyaSessionManager(burpIntegration.getApi());
        
        api.logging().logToOutput(String.format(
            "[SESSION-REPLAY] Starting session replay: %s",
            sessionId
        ));
        
        var replayResult = sessionManager.replaySession(sessionId, replayConfig);
        
        var response = formatSessionReplayResponse(replayResult, sessionId);
        
        return createSuccessResponse(id, Map.of(
            "content", List.of(Map.of(
                "type", "text",
                "text", response
            ))
        ));
        
    } catch (Exception e) {
        logger.error("Session replay failed", e);
        burpIntegration.getApi().logging().logToError("[ERROR] Session replay failed: " + e.getMessage());
        
        return createErrorResponse(id, -32603, "Session replay failed: " + e.getMessage());
    }
}
```

## 🔧 Chrome Extension Communication Protocol

### 1. Extension Message Format
```javascript
// Chrome Extension Side (JavaScript)
const BurpMCPExtension = {
    
    // Send message to Burp MCP Server
    sendToBurp: function(message) {
        fetch('http://localhost:1337/chrome-extension', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Burp-MCP-Extension': 'chrome-extension-v1.0'
            },
            body: JSON.stringify({
                type: message.type,
                data: message.data,
                timestamp: Date.now(),
                tabId: chrome.tabs.getCurrent()?.id
            })
        }).then(response => response.json())
          .then(data => this.handleBurpResponse(data))
          .catch(error => console.error('Burp MCP communication error:', error));
    },
    
    // Handle automation requests from Burp
    handleAutomationRequest: function(request) {
        switch (request.type) {
            case 'RECORD_LOGIN':
                return this.recordLoginSequence(request.config);
            case 'REPLAY_SEQUENCE':
                return this.replayLoginSequence(request.sequence);
            case 'ANALYZE_DOM':
                return this.analyzePage(request.config);
            case 'EXTRACT_SESSION':
                return this.extractSessionData();
        }
    },
    
    // AI-assisted login recording
    recordLoginSequence: function(config) {
        const recorder = new LoginSequenceRecorder();
        
        recorder.onStep = (step) => {
            this.sendToBurp({
                type: 'LOGIN_STEP',
                data: {
                    step: step,
                    timestamp: Date.now(),
                    screenshot: this.captureScreenshot()
                }
            });
        };
        
        recorder.onComplete = (sequence) => {
            this.sendToBurp({
                type: 'LOGIN_COMPLETE',
                data: {
                    sequence: sequence,
                    sessionData: this.extractSessionData()
                }
            });
        };
        
        return recorder.start(config);
    }
};
```

This comprehensive browser integration implementation provides:

1. **Full Montoya API compliance** - Uses official Burp interfaces and patterns
2. **AI-assisted automation** - Intelligent login sequence recording and analysis
3. **Chrome extension integration** - Direct browser control capabilities
4. **Session management** - Persistent authentication state handling
5. **Robust error handling** - Comprehensive exception handling with API logging
6. **Security analysis** - Built-in security assessment of authentication flows
7. **Real-time monitoring** - Progress tracking and status updates

The implementation enables sophisticated browser automation workflows while maintaining full compatibility with BurpSuite Professional through the Montoya API.
