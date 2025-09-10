/**
 * Burp MCP Browser Integration - Background Service Worker
 * 
 * Handles communication between Chrome extension and Burp MCP Server,
 * manages extension state, and coordinates browser automation tasks.
 */

// Configuration
const CONFIG = {
    BURP_MCP_SERVER_URL: 'http://localhost:1337',
    HEALTH_CHECK_INTERVAL: 30000, // 30 seconds
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 2000, // 2 seconds
    SESSION_TIMEOUT: 7200000 // 2 hours
};

// Extension state
let extensionState = {
    connected: false,
    sessionId: null,
    serverVersion: null,
    lastHealthCheck: 0,
    activeTabs: new Map(),
    automationTasks: new Map()
};

// Initialize extension
chrome.runtime.onInstalled.addListener((details) => {
    console.log('[Burp MCP] Extension installed:', details.reason);
    
    if (details.reason === 'install') {
        initializeExtension();
    }
});

// Start extension when Chrome starts
chrome.runtime.onStartup.addListener(() => {
    console.log('[Burp MCP] Extension starting up');
    initializeExtension();
});

/**
 * Initialize the extension
 */
async function initializeExtension() {
    try {
        console.log('[Burp MCP] Initializing extension...');
        
        // Load saved state
        const saved = await chrome.storage.local.get(['sessionId', 'serverUrl']);
        if (saved.sessionId) {
            extensionState.sessionId = saved.sessionId;
        }
        
        // Connect to Burp MCP Server
        await connectToBurpServer();
        
        // Start health check timer
        startHealthChecking();
        
        // Setup tab monitoring
        setupTabMonitoring();
        
        console.log('[Burp MCP] Extension initialized successfully');
        
    } catch (error) {
        console.error('[Burp MCP] Extension initialization failed:', error);
        
        // Set badge to indicate error
        chrome.action.setBadgeText({ text: 'ERR' });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
    }
}

/**
 * Connect to Burp MCP Server
 */
async function connectToBurpServer() {
    try {
        console.log('[Burp MCP] Connecting to server...');
        
        const response = await fetch(`${CONFIG.BURP_MCP_SERVER_URL}/chrome-extension`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Burp-MCP-Extension': 'chrome-extension-v1.0'
            },
            body: JSON.stringify({
                type: 'connect',
                version: chrome.runtime.getManifest().version,
                timestamp: Date.now(),
                sessionId: extensionState.sessionId
            })
        });
        
        if (!response.ok) {
            throw new Error(`Server connection failed: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            extensionState.connected = true;
            extensionState.sessionId = data.sessionId;
            extensionState.serverVersion = data.serverVersion;
            
            // Save session ID
            await chrome.storage.local.set({ sessionId: data.sessionId });
            
            // Update badge
            chrome.action.setBadgeText({ text: '✓' });
            chrome.action.setBadgeBackgroundColor({ color: '#00AA00' });
            
            console.log('[Burp MCP] Connected to server:', data);
            
            // Notify all tabs about connection
            notifyTabsOfConnection();
            
        } else {
            throw new Error(data.error || 'Connection failed');
        }
        
    } catch (error) {
        console.error('[Burp MCP] Server connection failed:', error);
        extensionState.connected = false;
        
        // Update badge
        chrome.action.setBadgeText({ text: 'X' });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
        
        throw error;
    }
}

/**
 * Start health checking
 */
function startHealthChecking() {
    setInterval(async () => {
        try {
            await performHealthCheck();
        } catch (error) {
            console.error('[Burp MCP] Health check failed:', error);
            
            // Try to reconnect
            try {
                await connectToBurpServer();
            } catch (reconnectError) {
                console.error('[Burp MCP] Reconnection failed:', reconnectError);
            }
        }
    }, CONFIG.HEALTH_CHECK_INTERVAL);
}

/**
 * Perform health check
 */
async function performHealthCheck() {
    if (!extensionState.connected) {
        return;
    }
    
    const response = await fetch(`${CONFIG.BURP_MCP_SERVER_URL}/health`, {
        method: 'GET',
        headers: {
            'X-Burp-MCP-Extension': 'chrome-extension-v1.0'
        }
    });
    
    if (!response.ok) {
        throw new Error(`Health check failed: ${response.status}`);
    }
    
    const data = await response.json();
    extensionState.lastHealthCheck = Date.now();
    
    console.log('[Burp MCP] Health check successful:', data.status);
}

/**
 * Setup tab monitoring
 */
function setupTabMonitoring() {
    // Monitor tab updates
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
        if (changeInfo.status === 'complete' && tab.url) {
            await handleTabUpdate(tabId, tab);
        }
    });
    
    // Monitor tab removal
    chrome.tabs.onRemoved.addListener((tabId) => {
        extensionState.activeTabs.delete(tabId);
        console.log('[Burp MCP] Tab removed:', tabId);
    });
    
    // Monitor navigation
    chrome.webNavigation.onCompleted.addListener(async (details) => {
        if (details.frameId === 0) { // Main frame only
            await handleNavigation(details);
        }
    });
}

/**
 * Handle tab update
 */
async function handleTabUpdate(tabId, tab) {
    try {
        if (!extensionState.connected || !tab.url.startsWith('http')) {
            return;
        }
        
        // Track active tab
        extensionState.activeTabs.set(tabId, {
            url: tab.url,
            title: tab.title,
            lastUpdate: Date.now()
        });
        
        // Notify server of page load
        await sendToServer({
            type: 'page_loaded',
            sessionId: extensionState.sessionId,
            tabId: tabId,
            url: tab.url,
            title: tab.title,
            timestamp: Date.now()
        });
        
        console.log('[Burp MCP] Page loaded:', tab.url);
        
    } catch (error) {
        console.error('[Burp MCP] Tab update handling failed:', error);
    }
}

/**
 * Handle navigation
 */
async function handleNavigation(details) {
    try {
        if (!extensionState.connected) {
            return;
        }
        
        console.log('[Burp MCP] Navigation completed:', details.url);
        
    } catch (error) {
        console.error('[Burp MCP] Navigation handling failed:', error);
    }
}

/**
 * Send message to Burp MCP Server
 */
async function sendToServer(message) {
    if (!extensionState.connected) {
        throw new Error('Not connected to Burp MCP Server');
    }
    
    try {
        const response = await fetch(`${CONFIG.BURP_MCP_SERVER_URL}/chrome-extension`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Burp-MCP-Extension': 'chrome-extension-v1.0'
            },
            body: JSON.stringify(message)
        });
        
        if (!response.ok) {
            throw new Error(`Server request failed: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Server request failed');
        }
        
        return data;
        
    } catch (error) {
        console.error('[Burp MCP] Server communication failed:', error);
        throw error;
    }
}

/**
 * Handle messages from content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleContentScriptMessage(message, sender)
        .then(response => sendResponse({ success: true, data: response }))
        .catch(error => {
            console.error('[Burp MCP] Content script message handling failed:', error);
            sendResponse({ success: false, error: error.message });
        });
    
    return true; // Indicate async response
});

/**
 * Handle content script messages
 */
async function handleContentScriptMessage(message, sender) {
    console.log('[Burp MCP] Content script message:', message.type, 'from tab:', sender.tab?.id);
    
    if (!extensionState.connected) {
        throw new Error('Not connected to Burp MCP Server');
    }
    
    // Add session info to message
    message.sessionId = extensionState.sessionId;
    message.tabId = sender.tab?.id;
    message.timestamp = Date.now();
    
    switch (message.type) {
        case 'form_detected':
            return await handleFormDetected(message);
        
        case 'login_attempt':
            return await handleLoginAttempt(message);
        
        case 'auth_state_change':
            return await handleAuthStateChange(message);
        
        case 'screenshot':
            return await handleScreenshot(message);
        
        case 'dom_analysis':
            return await handleDOMAnalysis(message);
        
        case 'automation_request':
            return await handleAutomationRequest(message);
        
        case 'get_session_info':
            return getSessionInfo();
        
        default:
            console.warn('[Burp MCP] Unknown content script message type:', message.type);
            return { message: 'Unknown message type' };
    }
}

/**
 * Handle form detection
 */
async function handleFormDetected(message) {
    const response = await sendToServer({
        type: 'form_detected',
        sessionId: message.sessionId,
        tabId: message.tabId,
        form: message.form,
        timestamp: message.timestamp
    });
    
    console.log('[Burp MCP] Form detection processed:', message.form.id || 'unknown');
    return response;
}

/**
 * Handle login attempt
 */
async function handleLoginAttempt(message) {
    const response = await sendToServer({
        type: 'login_attempt',
        sessionId: message.sessionId,
        tabId: message.tabId,
        loginData: message.loginData,
        timestamp: message.timestamp
    });
    
    console.log('[Burp MCP] Login attempt processed');
    return response;
}

/**
 * Handle authentication state change
 */
async function handleAuthStateChange(message) {
    const response = await sendToServer({
        type: 'auth_state_change',
        sessionId: message.sessionId,
        tabId: message.tabId,
        state: message.state,
        previousState: message.previousState,
        timestamp: message.timestamp
    });
    
    console.log('[Burp MCP] Auth state change processed:', message.previousState, '->', message.state);
    return response;
}

/**
 * Handle screenshot
 */
async function handleScreenshot(message) {
    const response = await sendToServer({
        type: 'screenshot',
        sessionId: message.sessionId,
        tabId: message.tabId,
        screenshot: message.screenshot,
        context: message.context || 'manual',
        timestamp: message.timestamp
    });
    
    console.log('[Burp MCP] Screenshot processed:', message.context);
    return response;
}

/**
 * Handle DOM analysis
 */
async function handleDOMAnalysis(message) {
    const response = await sendToServer({
        type: 'dom_analysis',
        sessionId: message.sessionId,
        tabId: message.tabId,
        domAnalysis: message.domAnalysis,
        timestamp: message.timestamp
    });
    
    console.log('[Burp MCP] DOM analysis processed');
    return response;
}

/**
 * Handle automation request
 */
async function handleAutomationRequest(message) {
    try {
        const taskId = generateTaskId();
        
        // Store automation task
        extensionState.automationTasks.set(taskId, {
            id: taskId,
            action: message.action,
            parameters: message.parameters,
            tabId: message.tabId,
            status: 'queued',
            createdAt: Date.now()
        });
        
        // Send to server
        const response = await fetch(`${CONFIG.BURP_MCP_SERVER_URL}/automation`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Burp-MCP-Extension': 'chrome-extension-v1.0'
            },
            body: JSON.stringify({
                action: message.action,
                sessionId: message.sessionId,
                tabId: message.tabId,
                parameters: message.parameters,
                taskId: taskId,
                timestamp: message.timestamp
            })
        });
        
        if (!response.ok) {
            throw new Error(`Automation request failed: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Update task status
        const task = extensionState.automationTasks.get(taskId);
        if (task) {
            task.status = data.success ? 'completed' : 'failed';
            task.result = data;
            task.completedAt = Date.now();
        }
        
        console.log('[Burp MCP] Automation request processed:', message.action, 'Task:', taskId);
        return { taskId, ...data };
        
    } catch (error) {
        console.error('[Burp MCP] Automation request failed:', error);
        throw error;
    }
}

/**
 * Get session information
 */
function getSessionInfo() {
    return {
        connected: extensionState.connected,
        sessionId: extensionState.sessionId,
        serverVersion: extensionState.serverVersion,
        lastHealthCheck: extensionState.lastHealthCheck,
        activeTabs: Array.from(extensionState.activeTabs.entries()).map(([tabId, info]) => ({
            tabId,
            ...info
        })),
        automationTasks: Array.from(extensionState.automationTasks.values())
    };
}

/**
 * Notify tabs of connection status
 */
async function notifyTabsOfConnection() {
    try {
        const tabs = await chrome.tabs.query({ active: true });
        
        for (const tab of tabs) {
            if (tab.url && tab.url.startsWith('http')) {
                try {
                    await chrome.tabs.sendMessage(tab.id, {
                        type: 'burp_mcp_connected',
                        sessionId: extensionState.sessionId,
                        connected: extensionState.connected
                    });
                } catch (error) {
                    // Tab might not have content script loaded yet
                    console.debug('[Burp MCP] Could not notify tab:', tab.id);
                }
            }
        }
    } catch (error) {
        console.error('[Burp MCP] Failed to notify tabs:', error);
    }
}

/**
 * Generate unique task ID
 */
function generateTaskId() {
    return 'task_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Handle extension icon click
 */
chrome.action.onClicked.addListener(async (tab) => {
    console.log('[Burp MCP] Extension icon clicked for tab:', tab.id);
    
    // Toggle connection or show status
    if (!extensionState.connected) {
        try {
            await connectToBurpServer();
        } catch (error) {
            console.error('[Burp MCP] Manual connection failed:', error);
        }
    }
});

// Export for debugging
globalThis.burpMcpExtension = {
    state: extensionState,
    connect: connectToBurpServer,
    sendToServer,
    getSessionInfo
};

console.log('[Burp MCP] Background service worker loaded');