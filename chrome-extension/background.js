/**
 * BurpSuite MCP Security Analyzer - Background Service Worker
 * Handles communication between Chrome Extension and BurpSuite Professional
 * Follows Chrome Extension Manifest V3 service worker patterns
 */

// Configuration
const BURP_MCP_CONFIG = {
    SERVER_URL: 'http://localhost:1337',
    BURP_PROXY_URL: 'http://127.0.0.1:8080',
    API_TIMEOUT: 30000,
    RECONNECT_INTERVAL: 5000,
    MAX_RECONNECT_ATTEMPTS: 5
};

// State management
let connectionState = {
    connected: false,
    reconnectAttempts: 0,
    lastConnectionTime: null,
    sessionData: {}
};

let recordingState = {
    isRecording: false,
    recordingId: null,
    startTime: null,
    interactions: [],
    forms: [],
    screenshots: []
};

/**
 * Service Worker Initialization
 */
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('[BurpMCP] Extension installed/updated:', details.reason);
    
    // Initialize storage
    await initializeStorage();
    
    // Set up initial badge
    updateBadge('init', 'Initializing');
    
    // Attempt initial connection to BurpSuite
    attemptBurpConnection();
    
    // Set up periodic connection checks
    setUpConnectionMonitoring();
});

chrome.runtime.onStartup.addListener(() => {
    console.log('[BurpMCP] Extension startup');
    attemptBurpConnection();
});

/**
 * Initialize extension storage
 */
async function initializeStorage() {
    const defaultSettings = {
        burpServerUrl: BURP_MCP_CONFIG.SERVER_URL,
        autoConnect: true,
        recordingEnabled: true,
        screenshotEnabled: true,
        formAnalysisEnabled: true,
        debugMode: false
    };
    
    const stored = await chrome.storage.sync.get(defaultSettings);
    await chrome.storage.sync.set(stored);
    
    console.log('[BurpMCP] Storage initialized:', stored);
}

/**
 * BurpSuite Connection Management
 */
async function attemptBurpConnection() {
    try {
        updateBadge('conn', 'Connecting');
        
        const settings = await chrome.storage.sync.get(['burpServerUrl', 'debugMode']);
        const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
        
        // Test connection to BurpSuite MCP Server
        const response = await fetch(`${serverUrl}/status`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'BurpSuite-MCP-Extension/1.0.0'
            },
            signal: AbortSignal.timeout(BURP_MCP_CONFIG.API_TIMEOUT)
        });
        
        if (response.ok) {
            const status = await response.json();
            connectionState.connected = true;
            connectionState.lastConnectionTime = Date.now();
            connectionState.reconnectAttempts = 0;
            connectionState.sessionData = status;
            
            updateBadge('ok', 'Connected');
            console.log('[BurpMCP] Connected to BurpSuite:', status);
            
            // Notify content scripts of connection
            broadcastMessage({
                type: 'CONNECTION_STATUS',
                connected: true,
                serverInfo: status
            });
            
        } else {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        
    } catch (error) {
        connectionState.connected = false;
        connectionState.reconnectAttempts++;
        
        console.warn(`[BurpMCP] Connection attempt ${connectionState.reconnectAttempts} failed:`, error.message);
        updateBadge('err', 'Disconnected');
        
        // Schedule reconnection if haven't exceeded max attempts
        if (connectionState.reconnectAttempts < BURP_MCP_CONFIG.MAX_RECONNECT_ATTEMPTS) {
            setTimeout(attemptBurpConnection, BURP_MCP_CONFIG.RECONNECT_INTERVAL);
        } else {
            console.error('[BurpMCP] Max reconnection attempts exceeded');
            updateBadge('fail', 'Connection Failed');
        }
    }
}

/**
 * Set up periodic connection monitoring
 */
function setUpConnectionMonitoring() {
    // Check connection every 30 seconds
    setInterval(async () => {
        if (connectionState.connected) {
            // Ping server to verify connection is still alive
            try {
                const settings = await chrome.storage.sync.get(['burpServerUrl']);
                const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
                
                const response = await fetch(`${serverUrl}/ping`, {
                    method: 'GET',
                    signal: AbortSignal.timeout(5000)
                });
                
                if (!response.ok) {
                    throw new Error('Ping failed');
                }
            } catch (error) {
                console.warn('[BurpMCP] Connection lost, attempting reconnection...');
                connectionState.connected = false;
                connectionState.reconnectAttempts = 0;
                attemptBurpConnection();
            }
        }
    }, 30000);
}

/**
 * Message handling from content scripts and popup
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('[BurpMCP] Received message:', message.type, 'from:', sender.tab?.url || 'extension');
    
    switch (message.type) {
        case 'GET_CONNECTION_STATUS':
            sendResponse({
                connected: connectionState.connected,
                sessionData: connectionState.sessionData,
                recordingState: recordingState
            });
            break;
            
        case 'START_RECORDING':
            handleStartRecording(message.data, sender, sendResponse);
            break;
            
        case 'STOP_RECORDING':
            handleStopRecording(sender, sendResponse);
            break;
            
        case 'CAPTURE_SCREENSHOT':
            handleCaptureScreenshot(message.data, sender, sendResponse);
            break;
            
        case 'ANALYZE_FORMS':
            handleAnalyzeForms(message.data, sender, sendResponse);
            break;
            
        case 'SEND_TO_BURP':
            handleSendToBurp(message.data, sender, sendResponse);
            break;
            
        case 'RECORD_INTERACTION':
            handleRecordInteraction(message.data, sender);
            sendResponse({ success: true });
            break;
            
        default:
            console.warn('[BurpMCP] Unknown message type:', message.type);
            sendResponse({ error: 'Unknown message type' });
            break;
    }
    
    return true; // Indicate we will respond asynchronously
});

/**
 * Recording Management
 */
async function handleStartRecording(data, sender, sendResponse) {
    if (recordingState.isRecording) {
        sendResponse({ error: 'Recording already in progress' });
        return;
    }
    
    recordingState.isRecording = true;
    recordingState.recordingId = generateRecordingId();
    recordingState.startTime = Date.now();
    recordingState.interactions = [];
    recordingState.forms = [];
    recordingState.screenshots = [];
    
    console.log('[BurpMCP] Started recording:', recordingState.recordingId);
    
    // Notify content scripts to start recording
    broadcastMessage({
        type: 'RECORDING_STARTED',
        recordingId: recordingState.recordingId,
        config: data
    });
    
    updateBadge('rec', 'Recording');
    
    sendResponse({
        success: true,
        recordingId: recordingState.recordingId
    });
}

async function handleStopRecording(sender, sendResponse) {
    if (!recordingState.isRecording) {
        sendResponse({ error: 'No recording in progress' });
        return;
    }
    
    const recordingData = {
        recordingId: recordingState.recordingId,
        startTime: recordingState.startTime,
        endTime: Date.now(),
        duration: Date.now() - recordingState.startTime,
        interactions: recordingState.interactions,
        forms: recordingState.forms,
        screenshots: recordingState.screenshots,
        url: sender.tab?.url
    };
    
    // Send recording data to BurpSuite
    try {
        await sendRecordingToBurp(recordingData);
        console.log('[BurpMCP] Recording sent to BurpSuite:', recordingState.recordingId);
    } catch (error) {
        console.error('[BurpMCP] Failed to send recording to BurpSuite:', error);
    }
    
    // Reset recording state
    recordingState.isRecording = false;
    recordingState.recordingId = null;
    recordingState.startTime = null;
    recordingState.interactions = [];
    recordingState.forms = [];
    recordingState.screenshots = [];
    
    // Update badge
    updateBadge(connectionState.connected ? 'ok' : 'err', 
                connectionState.connected ? 'Connected' : 'Disconnected');
    
    // Notify content scripts
    broadcastMessage({
        type: 'RECORDING_STOPPED'
    });
    
    sendResponse({
        success: true,
        recordingData: recordingData
    });
}

function handleRecordInteraction(data, sender) {
    if (!recordingState.isRecording) {
        return;
    }
    
    const interaction = {
        timestamp: Date.now(),
        type: data.type,
        element: data.element,
        value: data.value,
        url: sender.tab?.url,
        coordinates: data.coordinates,
        metadata: data.metadata || {}
    };
    
    recordingState.interactions.push(interaction);
    console.log('[BurpMCP] Recorded interaction:', interaction.type, 'on', interaction.element);
}

/**
 * Screenshot Capture
 */
async function handleCaptureScreenshot(data, sender, sendResponse) {
    try {
        const screenshot = await chrome.tabs.captureVisibleTab(
            sender.tab.windowId,
            { format: 'png', quality: 90 }
        );
        
        const screenshotData = {
            timestamp: Date.now(),
            url: sender.tab.url,
            title: sender.tab.title,
            image: screenshot,
            metadata: data || {}
        };
        
        // Add to recording if active
        if (recordingState.isRecording) {
            recordingState.screenshots.push(screenshotData);
        }
        
        // Send to BurpSuite
        if (connectionState.connected) {
            await sendScreenshotToBurp(screenshotData);
        }
        
        console.log('[BurpMCP] Screenshot captured for:', sender.tab.url);
        
        sendResponse({
            success: true,
            screenshot: screenshotData
        });
        
    } catch (error) {
        console.error('[BurpMCP] Screenshot capture failed:', error);
        sendResponse({
            success: false,
            error: error.message
        });
    }
}

/**
 * Form Analysis
 */
async function handleAnalyzeForms(data, sender, sendResponse) {
    try {
        const formsData = {
            timestamp: Date.now(),
            url: sender.tab.url,
            forms: data.forms || [],
            analysis: data.analysis || {}
        };
        
        // Add to recording if active
        if (recordingState.isRecording) {
            recordingState.forms.push(formsData);
        }
        
        // Send to BurpSuite for security analysis
        if (connectionState.connected) {
            const analysisResult = await sendFormsAnalysisToBurp(formsData);
            sendResponse({
                success: true,
                analysis: analysisResult
            });
        } else {
            sendResponse({
                success: false,
                error: 'Not connected to BurpSuite'
            });
        }
        
        console.log('[BurpMCP] Forms analyzed:', data.forms?.length || 0, 'forms');
        
    } catch (error) {
        console.error('[BurpMCP] Form analysis failed:', error);
        sendResponse({
            success: false,
            error: error.message
        });
    }
}

/**
 * BurpSuite Communication
 */
async function handleSendToBurp(data, sender, sendResponse) {
    if (!connectionState.connected) {
        sendResponse({ error: 'Not connected to BurpSuite' });
        return;
    }
    
    try {
        const settings = await chrome.storage.sync.get(['burpServerUrl']);
        const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
        
        const response = await fetch(`${serverUrl}/api/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                ...data,
                timestamp: Date.now(),
                source: 'chrome-extension',
                tabUrl: sender.tab?.url
            }),
            signal: AbortSignal.timeout(BURP_MCP_CONFIG.API_TIMEOUT)
        });
        
        if (response.ok) {
            const result = await response.json();
            sendResponse({
                success: true,
                result: result
            });
        } else {
            throw new Error(`BurpSuite API error: ${response.status}`);
        }
        
    } catch (error) {
        console.error('[BurpMCP] BurpSuite communication failed:', error);
        sendResponse({
            success: false,
            error: error.message
        });
    }
}

async function sendRecordingToBurp(recordingData) {
    const settings = await chrome.storage.sync.get(['burpServerUrl']);
    const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
    
    const response = await fetch(`${serverUrl}/api/recording`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(recordingData),
        signal: AbortSignal.timeout(BURP_MCP_CONFIG.API_TIMEOUT)
    });
    
    if (!response.ok) {
        throw new Error(`Failed to send recording: ${response.status}`);
    }
    
    return await response.json();
}

async function sendScreenshotToBurp(screenshotData) {
    const settings = await chrome.storage.sync.get(['burpServerUrl']);
    const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
    
    const response = await fetch(`${serverUrl}/api/screenshot`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(screenshotData),
        signal: AbortSignal.timeout(BURP_MCP_CONFIG.API_TIMEOUT)
    });
    
    if (!response.ok) {
        throw new Error(`Failed to send screenshot: ${response.status}`);
    }
    
    return await response.json();
}

async function sendFormsAnalysisToBurp(formsData) {
    const settings = await chrome.storage.sync.get(['burpServerUrl']);
    const serverUrl = settings.burpServerUrl || BURP_MCP_CONFIG.SERVER_URL;
    
    const response = await fetch(`${serverUrl}/api/forms-analysis`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formsData),
        signal: AbortSignal.timeout(BURP_MCP_CONFIG.API_TIMEOUT)
    });
    
    if (!response.ok) {
        throw new Error(`Failed to send forms analysis: ${response.status}`);
    }
    
    return await response.json();
}

/**
 * Utility Functions
 */
function updateBadge(type, tooltip) {
    const badges = {
        'init': { text: '●', color: '#FFA500', title: tooltip },
        'conn': { text: '○', color: '#FFD700', title: tooltip },
        'ok': { text: '●', color: '#00FF00', title: tooltip },
        'err': { text: '●', color: '#FF6B47', title: tooltip },
        'fail': { text: '●', color: '#FF0000', title: tooltip },
        'rec': { text: '●', color: '#FF1493', title: tooltip }
    };
    
    const badge = badges[type] || badges['err'];
    
    chrome.action.setBadgeText({ text: badge.text });
    chrome.action.setBadgeBackgroundColor({ color: badge.color });
    chrome.action.setTitle({ title: `BurpSuite MCP - ${badge.title}` });
}

async function broadcastMessage(message) {
    try {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
            chrome.tabs.sendMessage(tab.id, message).catch(err => {
                // Ignore errors for tabs that don't have content scripts
            });
        }
    } catch (error) {
        console.warn('[BurpMCP] Failed to broadcast message:', error);
    }
}

function generateRecordingId() {
    return 'rec_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

/**
 * Keyboard Command Handlers
 */
chrome.commands.onCommand.addListener(async (command) => {
    console.log('[BurpMCP] Keyboard command:', command);
    
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!activeTab) return;
    
    switch (command) {
        case 'capture-screenshot':
            chrome.tabs.sendMessage(activeTab.id, {
                type: 'TRIGGER_SCREENSHOT'
            });
            break;
            
        case 'start-recording':
            if (recordingState.isRecording) {
                chrome.tabs.sendMessage(activeTab.id, { type: 'TRIGGER_STOP_RECORDING' });
            } else {
                chrome.tabs.sendMessage(activeTab.id, { type: 'TRIGGER_START_RECORDING' });
            }
            break;
            
        case 'analyze-forms':
            chrome.tabs.sendMessage(activeTab.id, {
                type: 'TRIGGER_ANALYZE_FORMS'
            });
            break;
    }
});

/**
 * Tab Events
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && recordingState.isRecording) {
        // Record navigation if recording is active
        recordingState.interactions.push({
            timestamp: Date.now(),
            type: 'navigation',
            url: tab.url,
            title: tab.title,
            metadata: { changeInfo }
        });
    }
});

/**
 * Web Request Monitoring (for recording)
 */
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        if (recordingState.isRecording && details.type === 'main_frame') {
            recordingState.interactions.push({
                timestamp: Date.now(),
                type: 'request',
                url: details.url,
                method: details.method,
                metadata: {
                    requestId: details.requestId,
                    type: details.type,
                    initiator: details.initiator
                }
            });
        }
    },
    { urls: ['<all_urls>'] },
    ['requestBody']
);

// Keep service worker alive
chrome.runtime.onConnect.addListener((port) => {
    console.log('[BurpMCP] Port connected:', port.name);
});

console.log('[BurpMCP] Background service worker initialized');
