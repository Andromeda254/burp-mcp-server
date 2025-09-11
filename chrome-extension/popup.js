/**
 * BurpSuite MCP Security Analyzer - Popup JavaScript
 * Handles popup UI interactions and communication with background script
 */

// DOM elements
const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const reconnectBtn = document.getElementById('reconnectBtn');
const errorMessage = document.getElementById('errorMessage');
const loadingIndicator = document.getElementById('loadingIndicator');
const recordingIndicator = document.getElementById('recordingIndicator');
const recordingTime = document.getElementById('recordingTime');

// Action buttons
const captureScreenshotBtn = document.getElementById('captureScreenshotBtn');
const analyzeFormsBtn = document.getElementById('analyzeFormsBtn');
const startRecordingBtn = document.getElementById('startRecordingBtn');
const stopRecordingBtn = document.getElementById('stopRecordingBtn');
const openBurpBtn = document.getElementById('openBurpBtn');

// Stats elements
const formsAnalyzed = document.getElementById('formsAnalyzed');
const interactionsRecorded = document.getElementById('interactionsRecorded');
const screenshotsTaken = document.getElementById('screenshotsTaken');
const securityFindingsCount = document.getElementById('securityFindings');

// Analysis sections
const formAnalysis = document.getElementById('formAnalysis');
const formCount = document.getElementById('formCount');
const formDetails = document.getElementById('formDetails');
const securityFindings = document.getElementById('securityFindings');
const findingsList = document.getElementById('findingsList');

// Options and help
const optionsLink = document.getElementById('optionsLink');
const helpLink = document.getElementById('helpLink');

// State
let connectionState = {
    connected: false,
    reconnectAttempts: 0
};

let recordingState = {
    isRecording: false,
    startTime: null,
    timer: null
};

let sessionStats = {
    formsFound: 0,
    interactions: 0,
    screenshots: 0,
    findings: 0
};

/**
 * Initialize popup
 */
document.addEventListener('DOMContentLoaded', async () => {
    console.log('[BurpMCP Popup] Initializing popup UI');
    
    // Setup event listeners
    setupEventListeners();
    
    // Load initial state
    await loadInitialState();
    
    // Update UI based on current state
    updateUI();
    
    console.log('[BurpMCP Popup] Popup initialized');
});

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Connection management
    reconnectBtn.addEventListener('click', handleReconnect);
    
    // Action buttons
    captureScreenshotBtn.addEventListener('click', handleCaptureScreenshot);
    analyzeFormsBtn.addEventListener('click', handleAnalyzeForms);
    startRecordingBtn.addEventListener('click', handleStartRecording);
    stopRecordingBtn.addEventListener('click', handleStopRecording);
    openBurpBtn.addEventListener('click', handleOpenBurp);
    
    // Options and help
    optionsLink.addEventListener('click', handleOpenOptions);
    helpLink.addEventListener('click', handleOpenHelp);
    
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        handleBackgroundMessage(message, sender, sendResponse);
    });
}

/**
 * Load initial state from background script
 */
async function loadInitialState() {
    try {
        const response = await sendMessage({ type: 'GET_CONNECTION_STATUS' });
        
        if (response) {
            connectionState = {
                connected: response.connected,
                sessionData: response.sessionData
            };
            
            if (response.recordingState) {
                recordingState = {
                    isRecording: response.recordingState.isRecording,
                    startTime: response.recordingState.startTime,
                    recordingId: response.recordingState.recordingId
                };
                
                if (recordingState.isRecording && recordingState.startTime) {
                    startRecordingTimer();
                }
            }
        }
    } catch (error) {
        console.error('[BurpMCP Popup] Failed to load initial state:', error);
        showError('Failed to load extension state');
    }
}

/**
 * Update UI based on current state
 */
function updateUI() {
    // Update connection status
    updateConnectionStatus();
    
    // Update recording state
    updateRecordingState();
    
    // Update button states
    updateButtonStates();
    
    // Update stats
    updateStats();
}

/**
 * Update connection status display
 */
function updateConnectionStatus() {
    if (connectionState.connected) {
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'Connected to BurpSuite';
        reconnectBtn.style.display = 'none';
        hideError();
    } else {
        statusDot.className = 'status-dot';
        statusText.textContent = 'Disconnected';
        reconnectBtn.style.display = 'block';
    }
}

/**
 * Update recording state display
 */
function updateRecordingState() {
    if (recordingState.isRecording) {
        recordingIndicator.classList.add('active');
        startRecordingBtn.style.display = 'none';
        stopRecordingBtn.style.display = 'block';
        
        if (!recordingState.timer && recordingState.startTime) {
            startRecordingTimer();
        }
    } else {
        recordingIndicator.classList.remove('active');
        startRecordingBtn.style.display = 'block';
        stopRecordingBtn.style.display = 'none';
        
        if (recordingState.timer) {
            clearInterval(recordingState.timer);
            recordingState.timer = null;
        }
    }
}

/**
 * Update button states based on connection
 */
function updateButtonStates() {
    const isConnected = connectionState.connected;
    
    captureScreenshotBtn.disabled = !isConnected;
    analyzeFormsBtn.disabled = !isConnected;
    startRecordingBtn.disabled = !isConnected || recordingState.isRecording;
    stopRecordingBtn.disabled = !recordingState.isRecording;
}

/**
 * Update statistics display
 */
function updateStats() {
    formsAnalyzed.textContent = sessionStats.formsFound;
    interactionsRecorded.textContent = sessionStats.interactions;
    screenshotsTaken.textContent = sessionStats.screenshots;
    securityFindingsCount.textContent = sessionStats.findings;
}

/**
 * Handle reconnection
 */
async function handleReconnect() {
    try {
        showLoading();
        
        await sendMessage({ type: 'RECONNECT' });
        
        // Wait a moment for connection attempt
        setTimeout(async () => {
            await loadInitialState();
            updateUI();
            hideLoading();
        }, 2000);
        
    } catch (error) {
        console.error('[BurpMCP Popup] Reconnection failed:', error);
        showError('Reconnection failed');
        hideLoading();
    }
}

/**
 * Handle screenshot capture
 */
async function handleCaptureScreenshot() {
    try {
        captureScreenshotBtn.disabled = true;
        showLoading('Capturing screenshot...');
        
        const response = await sendMessage({ 
            type: 'CAPTURE_SCREENSHOT',
            data: { 
                includeMetadata: true,
                fullPage: false 
            }
        });
        
        if (response && response.success) {
            sessionStats.screenshots++;
            updateStats();
            showSuccess('Screenshot captured successfully');
        } else {
            showError('Screenshot capture failed');
        }
        
    } catch (error) {
        console.error('[BurpMCP Popup] Screenshot capture failed:', error);
        showError('Screenshot capture failed');
    } finally {
        captureScreenshotBtn.disabled = false;
        hideLoading();
    }
}

/**
 * Handle form analysis
 */
async function handleAnalyzeForms() {
    try {
        analyzeFormsBtn.disabled = true;
        showLoading('Analyzing forms...');
        
        const response = await sendMessage({ 
            type: 'ANALYZE_FORMS',
            data: { 
                includeSecurityAnalysis: true 
            }
        });
        
        if (response && response.success) {
            sessionStats.formsFound = response.data.formsFound || 0;
            sessionStats.findings += response.data.securityFindings || 0;
            
            updateStats();
            displayFormAnalysis(response.data);
            
            if (response.data.securityFindings > 0) {
                displaySecurityFindings(response.data.findings);
            }
            
            showSuccess(`Found ${response.data.formsFound} forms`);
        } else {
            showError('Form analysis failed');
        }
        
    } catch (error) {
        console.error('[BurpMCP Popup] Form analysis failed:', error);
        showError('Form analysis failed');
    } finally {
        analyzeFormsBtn.disabled = false;
        hideLoading();
    }
}

/**
 * Handle start recording
 */
async function handleStartRecording() {
    try {
        startRecordingBtn.disabled = true;
        showLoading('Starting recording...');
        
        const response = await sendMessage({ 
            type: 'START_RECORDING',
            data: { 
                captureScreenshots: true,
                analyzeInteractions: true 
            }
        });
        
        if (response && response.success) {
            recordingState = {
                isRecording: true,
                startTime: Date.now(),
                recordingId: response.recordingId
            };
            
            updateRecordingState();
            showSuccess('Recording started');
        } else {
            showError('Failed to start recording');
        }
        
    } catch (error) {
        console.error('[BurpMCP Popup] Failed to start recording:', error);
        showError('Failed to start recording');
    } finally {
        startRecordingBtn.disabled = false;
        hideLoading();
    }
}

/**
 * Handle stop recording
 */
async function handleStopRecording() {
    try {
        stopRecordingBtn.disabled = true;
        showLoading('Stopping recording...');
        
        const response = await sendMessage({ 
            type: 'STOP_RECORDING',
            data: { 
                recordingId: recordingState.recordingId 
            }
        });
        
        if (response && response.success) {
            sessionStats.interactions += response.data.totalInteractions || 0;
            sessionStats.screenshots += response.data.screenshotsTaken || 0;
            
            recordingState = {
                isRecording: false,
                startTime: null,
                recordingId: null
            };
            
            updateRecordingState();
            updateStats();
            showSuccess(`Recording saved: ${response.data.totalInteractions} interactions`);
        } else {
            showError('Failed to stop recording');
        }
        
    } catch (error) {
        console.error('[BurpMCP Popup] Failed to stop recording:', error);
        showError('Failed to stop recording');
    } finally {
        stopRecordingBtn.disabled = false;
        hideLoading();
    }
}

/**
 * Handle open BurpSuite
 */
function handleOpenBurp() {
    const burpUrl = 'http://127.0.0.1:8080/';
    chrome.tabs.create({ url: burpUrl });
}

/**
 * Handle open options
 */
function handleOpenOptions() {
    chrome.runtime.openOptionsPage();
}

/**
 * Handle open help
 */
function handleOpenHelp() {
    const helpUrl = chrome.runtime.getURL('help.html');
    chrome.tabs.create({ url: helpUrl });
}

/**
 * Display form analysis results
 */
function displayFormAnalysis(data) {
    if (data.formsFound > 0) {
        formCount.textContent = `${data.formsFound} forms detected`;
        
        const details = data.forms.map(form => {
            return `<div style="margin: 5px 0; padding: 5px; background: rgba(255,255,255,0.1); border-radius: 4px;">
                <strong>${form.action || 'No action'}</strong><br>
                Method: ${form.method || 'GET'} | Fields: ${form.inputs?.length || 0}
            </div>`;
        }).join('');
        
        formDetails.innerHTML = details;
        formAnalysis.style.display = 'block';
    } else {
        formAnalysis.style.display = 'none';
    }
}

/**
 * Display security findings
 */
function displaySecurityFindings(findings) {
    if (findings && findings.length > 0) {
        const findingsHtml = findings.map(finding => 
            `<div class="finding-item">${finding.message || finding}</div>`
        ).join('');
        
        findingsList.innerHTML = findingsHtml;
        securityFindings.classList.add('show');
    } else {
        securityFindings.classList.remove('show');
    }
}

/**
 * Start recording timer
 */
function startRecordingTimer() {
    if (recordingState.timer) {
        clearInterval(recordingState.timer);
    }
    
    recordingState.timer = setInterval(() => {
        if (recordingState.startTime) {
            const elapsed = Date.now() - recordingState.startTime;
            const minutes = Math.floor(elapsed / 60000);
            const seconds = Math.floor((elapsed % 60000) / 1000);
            
            recordingTime.textContent = 
                `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }, 1000);
}

/**
 * Handle messages from background script
 */
function handleBackgroundMessage(message, sender, sendResponse) {
    console.log('[BurpMCP Popup] Received background message:', message.type);
    
    switch (message.type) {
        case 'CONNECTION_STATUS_CHANGED':
            connectionState.connected = message.connected;
            updateConnectionStatus();
            updateButtonStates();
            break;
            
        case 'RECORDING_STATUS_CHANGED':
            recordingState = message.recordingState;
            updateRecordingState();
            break;
            
        case 'STATS_UPDATED':
            Object.assign(sessionStats, message.stats);
            updateStats();
            break;
            
        case 'ERROR':
            showError(message.error);
            break;
            
        case 'SUCCESS':
            showSuccess(message.message);
            break;
    }
    
    sendResponse({ received: true });
}

/**
 * Send message to background script
 */
function sendMessage(message) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else {
                resolve(response);
            }
        });
    });
}

/**
 * Show loading indicator
 */
function showLoading(message = 'Loading...') {
    loadingIndicator.querySelector('div:last-child').textContent = message;
    loadingIndicator.style.display = 'block';
}

/**
 * Hide loading indicator
 */
function hideLoading() {
    loadingIndicator.style.display = 'none';
}

/**
 * Show error message
 */
function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.add('show');
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        hideError();
    }, 5000);
}

/**
 * Hide error message
 */
function hideError() {
    errorMessage.classList.remove('show');
}

/**
 * Show success message (temporary)
 */
function showSuccess(message) {
    // Create temporary success indicator
    const successDiv = document.createElement('div');
    successDiv.style.cssText = `
        background: rgba(46, 213, 115, 0.2);
        border: 1px solid #2ed573;
        padding: 8px;
        border-radius: 6px;
        margin-bottom: 10px;
        font-size: 12px;
        color: #2ed573;
    `;
    successDiv.textContent = message;
    
    errorMessage.parentNode.insertBefore(successDiv, errorMessage);
    
    // Remove after 3 seconds
    setTimeout(() => {
        if (successDiv.parentNode) {
            successDiv.parentNode.removeChild(successDiv);
        }
    }, 3000);
}

/**
 * Handle keyboard shortcuts
 */
document.addEventListener('keydown', (event) => {
    if (event.ctrlKey || event.metaKey) {
        switch (event.key) {
            case 's':
                event.preventDefault();
                handleCaptureScreenshot();
                break;
            case 'r':
                event.preventDefault();
                if (recordingState.isRecording) {
                    handleStopRecording();
                } else {
                    handleStartRecording();
                }
                break;
            case 'f':
                event.preventDefault();
                handleAnalyzeForms();
                break;
        }
    }
});

console.log('[BurpMCP Popup] Popup script loaded');
