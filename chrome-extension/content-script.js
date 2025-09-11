/**
 * BurpSuite MCP Security Analyzer - Content Script
 * Handles form detection, user interaction recording, and DOM analysis
 * Injected into all web pages for comprehensive security analysis
 */

// Content script state
let isRecording = false;
let recordingConfig = {};
let injectedScript = null;
let formWatchers = new Map();
let interactionObservers = [];

/**
 * Initialize content script
 */
function initialize() {
    console.log('[BurpMCP Content] Initializing content script for:', window.location.href);
    
    // Set up communication with background script
    setupBackgroundCommunication();
    
    // Set up DOM monitoring
    setupDOMMonitoring();
    
    // Analyze initial page state
    analyzeInitialPage();
    
    // Inject security analyzer script
    injectSecurityAnalyzer();
    
    console.log('[BurpMCP Content] Content script initialized');
}

/**
 * Communication with background script
 */
function setupBackgroundCommunication() {
    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log('[BurpMCP Content] Received message:', message.type);
        
        switch (message.type) {
            case 'CONNECTION_STATUS':
                handleConnectionStatus(message);
                sendResponse({ received: true });
                break;
                
            case 'RECORDING_STARTED':
                handleRecordingStarted(message);
                sendResponse({ received: true });
                break;
                
            case 'RECORDING_STOPPED':
                handleRecordingStopped(message);
                sendResponse({ received: true });
                break;
                
            case 'TRIGGER_SCREENSHOT':
                triggerScreenshot();
                sendResponse({ received: true });
                break;
                
            case 'TRIGGER_START_RECORDING':
                triggerStartRecording();
                sendResponse({ received: true });
                break;
                
            case 'TRIGGER_STOP_RECORDING':
                triggerStopRecording();
                sendResponse({ received: true });
                break;
                
            case 'TRIGGER_ANALYZE_FORMS':
                triggerAnalyzeForms();
                sendResponse({ received: true });
                break;
                
            default:
                sendResponse({ error: 'Unknown message type' });
                break;
        }
        
        return true;
    });
    
    // Request initial connection status
    chrome.runtime.sendMessage({
        type: 'GET_CONNECTION_STATUS'
    }, (response) => {
        if (response) {
            handleConnectionStatus({
                connected: response.connected,
                serverInfo: response.sessionData
            });
        }
    });
}

/**
 * DOM Monitoring Setup
 */
function setupDOMMonitoring() {
    // Monitor for new forms being added to the page
    const formObserver = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Check for new forms
                        const forms = node.tagName === 'FORM' ? [node] : node.querySelectorAll('form');
                        forms.forEach(form => setupFormWatcher(form));
                        
                        // Check for input fields outside forms
                        const inputs = node.querySelectorAll('input, textarea, select');
                        inputs.forEach(input => setupInputWatcher(input));
                    }
                });
            }
        });
    });
    
    formObserver.observe(document, {
        childList: true,
        subtree: true
    });
    
    interactionObservers.push(formObserver);
}

/**
 * Initial page analysis
 */
function analyzeInitialPage() {
    // Analyze existing forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => setupFormWatcher(form));
    
    // Analyze standalone input fields
    const inputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)');
    inputs.forEach(input => setupInputWatcher(input));
    
    // Analyze page structure for security implications
    analyzePageSecurity();
}

/**
 * Form watcher setup
 */
function setupFormWatcher(form) {
    if (formWatchers.has(form)) {
        return; // Already watching this form
    }
    
    const formData = analyzeForm(form);
    formWatchers.set(form, formData);
    
    // Add event listeners for form interactions
    form.addEventListener('submit', (event) => {
        handleFormSubmit(event, form, formData);
    }, { passive: true });
    
    form.addEventListener('change', (event) => {
        handleFormChange(event, form, formData);
    }, { passive: true });
    
    // Watch for input events on form fields
    const fields = form.querySelectorAll('input, textarea, select');
    fields.forEach(field => {
        field.addEventListener('input', (event) => {
            handleFieldInput(event, form, formData);
        }, { passive: true });
        
        field.addEventListener('focus', (event) => {
            handleFieldFocus(event, form, formData);
        }, { passive: true });
        
        field.addEventListener('blur', (event) => {
            handleFieldBlur(event, form, formData);
        }, { passive: true });
    });
    
    console.log('[BurpMCP Content] Form watcher setup for:', formData.name || formData.id || 'anonymous form');
}

/**
 * Input watcher setup (for standalone inputs)
 */
function setupInputWatcher(input) {
    input.addEventListener('input', (event) => {
        handleStandaloneInput(event, input);
    }, { passive: true });
    
    input.addEventListener('change', (event) => {
        handleStandaloneInput(event, input);
    }, { passive: true });
}

/**
 * Form analysis
 */
function analyzeForm(form) {
    const formData = {
        id: form.id || null,
        name: form.name || null,
        action: form.action || window.location.href,
        method: (form.method || 'GET').toUpperCase(),
        enctype: form.enctype || 'application/x-www-form-urlencoded',
        target: form.target || '_self',
        autocomplete: form.autocomplete || 'on',
        novalidate: form.noValidate || false,
        fields: [],
        securityFlags: {},
        timestamp: Date.now()
    };
    
    // Analyze form fields
    const fields = form.querySelectorAll('input, textarea, select, button');
    fields.forEach((field, index) => {
        const fieldData = analyzeFormField(field, index);
        formData.fields.push(fieldData);
    });
    
    // Security analysis
    formData.securityFlags = analyzeFormSecurity(form, formData);
    
    return formData;
}

/**
 * Form field analysis
 */
function analyzeFormField(field, index) {
    const fieldData = {
        index: index,
        tagName: field.tagName.toLowerCase(),
        type: field.type || 'text',
        name: field.name || null,
        id: field.id || null,
        className: field.className || null,
        placeholder: field.placeholder || null,
        required: field.required || false,
        disabled: field.disabled || false,
        readonly: field.readOnly || false,
        autocomplete: field.autocomplete || null,
        pattern: field.pattern || null,
        minLength: field.minLength || null,
        maxLength: field.maxLength || null,
        min: field.min || null,
        max: field.max || null,
        step: field.step || null,
        multiple: field.multiple || false,
        accept: field.accept || null,
        value: '', // Don't capture actual values for security
        securityFlags: {}
    };
    
    // Security analysis for field
    fieldData.securityFlags = analyzeFieldSecurity(field, fieldData);
    
    return fieldData;
}

/**
 * Form security analysis
 */
function analyzeFormSecurity(form, formData) {
    const flags = {};
    
    // Check for HTTPS submission
    flags.httpsSubmission = formData.action.startsWith('https://');
    
    // Check for sensitive field types
    const sensitiveFields = formData.fields.filter(field => 
        field.type === 'password' || 
        field.name?.toLowerCase().includes('password') ||
        field.name?.toLowerCase().includes('credit') ||
        field.name?.toLowerCase().includes('ssn') ||
        field.type === 'email'
    );
    flags.hasSensitiveFields = sensitiveFields.length > 0;
    flags.sensitiveFieldCount = sensitiveFields.length;
    
    // Check for autocomplete on sensitive fields
    const sensitiveFieldsWithAutocomplete = sensitiveFields.filter(field => 
        field.autocomplete !== 'off' && field.autocomplete !== 'new-password'
    );
    flags.sensitiveAutocompleteEnabled = sensitiveFieldsWithAutocomplete.length > 0;
    
    // Check for CSRF protection
    const csrfField = formData.fields.find(field => 
        field.type === 'hidden' && (
            field.name?.toLowerCase().includes('csrf') ||
            field.name?.toLowerCase().includes('token') ||
            field.name?.toLowerCase().includes('_token')
        )
    );
    flags.hasCSRFProtection = !!csrfField;
    
    // Check for client-side validation
    const fieldsWithValidation = formData.fields.filter(field => 
        field.required || field.pattern || field.minLength || field.maxLength
    );
    flags.hasClientValidation = fieldsWithValidation.length > 0;
    
    // Check for file uploads
    const fileFields = formData.fields.filter(field => field.type === 'file');
    flags.hasFileUpload = fileFields.length > 0;
    flags.fileUploadCount = fileFields.length;
    
    // Risk assessment
    let riskScore = 0;
    if (!flags.httpsSubmission && flags.hasSensitiveFields) riskScore += 30;
    if (flags.sensitiveAutocompleteEnabled) riskScore += 20;
    if (!flags.hasCSRFProtection) riskScore += 15;
    if (flags.hasFileUpload) riskScore += 10;
    
    flags.riskScore = riskScore;
    flags.riskLevel = riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';
    
    return flags;
}

/**
 * Field security analysis
 */
function analyzeFieldSecurity(field, fieldData) {
    const flags = {};
    
    // Check for sensitive field types
    flags.isSensitive = (
        fieldData.type === 'password' ||
        fieldData.type === 'email' ||
        fieldData.name?.toLowerCase().includes('password') ||
        fieldData.name?.toLowerCase().includes('credit') ||
        fieldData.name?.toLowerCase().includes('ssn') ||
        fieldData.name?.toLowerCase().includes('social')
    );
    
    // Check autocomplete settings
    flags.autocompleteEnabled = fieldData.autocomplete !== 'off';
    flags.autocompleteRecommendation = flags.isSensitive && flags.autocompleteEnabled;
    
    // Check for validation
    flags.hasValidation = !!(fieldData.required || fieldData.pattern || fieldData.minLength || fieldData.maxLength);
    
    // Check for potential XSS vectors
    flags.potentialXSSVector = (
        fieldData.type === 'text' || 
        fieldData.tagName === 'textarea'
    ) && !fieldData.pattern;
    
    return flags;
}

/**
 * Page security analysis
 */
function analyzePageSecurity() {
    const analysis = {
        timestamp: Date.now(),
        url: window.location.href,
        protocol: window.location.protocol,
        forms: formWatchers.size,
        securityHeaders: {},
        securityIssues: []
    };
    
    // Check for mixed content
    if (window.location.protocol === 'https:') {
        const httpResources = document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]');
        if (httpResources.length > 0) {
            analysis.securityIssues.push({
                type: 'mixed_content',
                severity: 'MEDIUM',
                count: httpResources.length,
                description: 'HTTP resources loaded on HTTPS page'
            });
        }
    }
    
    // Check for inline scripts
    const inlineScripts = document.querySelectorAll('script:not([src])');
    if (inlineScripts.length > 0) {
        analysis.securityIssues.push({
            type: 'inline_scripts',
            severity: 'LOW',
            count: inlineScripts.length,
            description: 'Inline JavaScript detected'
        });
    }
    
    // Send analysis to background script
    chrome.runtime.sendMessage({
        type: 'SEND_TO_BURP',
        data: {
            type: 'page_analysis',
            analysis: analysis
        }
    });
}

/**
 * Event Handlers
 */
function handleConnectionStatus(message) {
    if (message.connected) {
        console.log('[BurpMCP Content] Connected to BurpSuite');
        showConnectionIndicator('connected');
    } else {
        console.log('[BurpMCP Content] Disconnected from BurpSuite');
        showConnectionIndicator('disconnected');
    }
}

function handleRecordingStarted(message) {
    isRecording = true;
    recordingConfig = message.config || {};
    console.log('[BurpMCP Content] Recording started:', message.recordingId);
    showRecordingIndicator(true);
    
    // Set up additional recording listeners
    setupRecordingListeners();
}

function handleRecordingStopped(message) {
    isRecording = false;
    recordingConfig = {};
    console.log('[BurpMCP Content] Recording stopped');
    showRecordingIndicator(false);
    
    // Clean up recording listeners
    cleanupRecordingListeners();
}

function handleFormSubmit(event, form, formData) {
    console.log('[BurpMCP Content] Form submit:', formData.name || formData.id);
    
    // Record interaction if recording is active
    if (isRecording) {
        recordInteraction({
            type: 'form_submit',
            element: getElementSelector(form),
            formData: {
                id: formData.id,
                name: formData.name,
                action: formData.action,
                method: formData.method,
                fieldCount: formData.fields.length,
                securityFlags: formData.securityFlags
            },
            coordinates: getElementCoordinates(form),
            metadata: {
                url: window.location.href,
                timestamp: Date.now()
            }
        });
    }
    
    // Send form analysis to BurpSuite
    chrome.runtime.sendMessage({
        type: 'ANALYZE_FORMS',
        data: {
            forms: [formData],
            analysis: {
                event: 'submit',
                timestamp: Date.now()
            }
        }
    });
}

function handleFormChange(event, form, formData) {
    if (isRecording) {
        recordInteraction({
            type: 'form_change',
            element: getElementSelector(event.target),
            value: sanitizeValue(event.target.value),
            formData: {
                id: formData.id,
                name: formData.name
            },
            coordinates: getElementCoordinates(event.target)
        });
    }
}

function handleFieldInput(event, form, formData) {
    if (isRecording) {
        recordInteraction({
            type: 'field_input',
            element: getElementSelector(event.target),
            fieldType: event.target.type,
            formData: {
                id: formData.id,
                name: formData.name
            },
            coordinates: getElementCoordinates(event.target)
        });
    }
}

function handleFieldFocus(event, form, formData) {
    if (isRecording) {
        recordInteraction({
            type: 'field_focus',
            element: getElementSelector(event.target),
            fieldType: event.target.type,
            formData: {
                id: formData.id,
                name: formData.name
            },
            coordinates: getElementCoordinates(event.target)
        });
    }
}

function handleFieldBlur(event, form, formData) {
    if (isRecording) {
        recordInteraction({
            type: 'field_blur',
            element: getElementSelector(event.target),
            fieldType: event.target.type,
            formData: {
                id: formData.id,
                name: formData.name
            },
            coordinates: getElementCoordinates(event.target)
        });
    }
}

function handleStandaloneInput(event, input) {
    if (isRecording) {
        recordInteraction({
            type: 'standalone_input',
            element: getElementSelector(input),
            fieldType: input.type,
            coordinates: getElementCoordinates(input)
        });
    }
}

/**
 * Recording listeners setup
 */
function setupRecordingListeners() {
    // Add click listeners
    document.addEventListener('click', handleRecordedClick, true);
    document.addEventListener('keydown', handleRecordedKeydown, true);
    document.addEventListener('scroll', handleRecordedScroll, { passive: true });
    
    console.log('[BurpMCP Content] Recording listeners activated');
}

function cleanupRecordingListeners() {
    document.removeEventListener('click', handleRecordedClick, true);
    document.removeEventListener('keydown', handleRecordedKeydown, true);
    document.removeEventListener('scroll', handleRecordedScroll);
    
    console.log('[BurpMCP Content] Recording listeners deactivated');
}

function handleRecordedClick(event) {
    recordInteraction({
        type: 'click',
        element: getElementSelector(event.target),
        coordinates: { x: event.clientX, y: event.clientY },
        metadata: {
            button: event.button,
            ctrlKey: event.ctrlKey,
            shiftKey: event.shiftKey,
            altKey: event.altKey
        }
    });
}

function handleRecordedKeydown(event) {
    // Only record special keys, not regular typing
    if (event.key.length > 1) { // Special keys like Enter, Tab, Escape, etc.
        recordInteraction({
            type: 'keydown',
            element: getElementSelector(event.target),
            key: event.key,
            coordinates: getElementCoordinates(event.target),
            metadata: {
                ctrlKey: event.ctrlKey,
                shiftKey: event.shiftKey,
                altKey: event.altKey
            }
        });
    }
}

function handleRecordedScroll(event) {
    // Throttle scroll events
    if (!handleRecordedScroll.lastCall || Date.now() - handleRecordedScroll.lastCall > 1000) {
        recordInteraction({
            type: 'scroll',
            coordinates: { x: window.scrollX, y: window.scrollY },
            metadata: {
                scrollWidth: document.documentElement.scrollWidth,
                scrollHeight: document.documentElement.scrollHeight
            }
        });
        handleRecordedScroll.lastCall = Date.now();
    }
}

/**
 * Trigger functions for keyboard commands
 */
function triggerScreenshot() {
    chrome.runtime.sendMessage({
        type: 'CAPTURE_SCREENSHOT',
        data: {
            trigger: 'keyboard_shortcut',
            url: window.location.href,
            timestamp: Date.now()
        }
    });
}

function triggerStartRecording() {
    chrome.runtime.sendMessage({
        type: 'START_RECORDING',
        data: {
            trigger: 'keyboard_shortcut',
            url: window.location.href
        }
    });
}

function triggerStopRecording() {
    chrome.runtime.sendMessage({
        type: 'STOP_RECORDING'
    });
}

function triggerAnalyzeForms() {
    const allForms = Array.from(formWatchers.values());
    chrome.runtime.sendMessage({
        type: 'ANALYZE_FORMS',
        data: {
            forms: allForms,
            analysis: {
                trigger: 'keyboard_shortcut',
                timestamp: Date.now(),
                url: window.location.href
            }
        }
    });
}

/**
 * Utility functions
 */
function recordInteraction(data) {
    chrome.runtime.sendMessage({
        type: 'RECORD_INTERACTION',
        data: data
    });
}

function getElementSelector(element) {
    if (!element || element === document) return 'document';
    
    // Try to get a unique selector
    if (element.id) return `#${element.id}`;
    
    let selector = element.tagName.toLowerCase();
    
    if (element.className) {
        selector += '.' + element.className.split(' ').join('.');
    }
    
    if (element.name) {
        selector += `[name="${element.name}"]`;
    }
    
    // Add position if needed for uniqueness
    const parent = element.parentElement;
    if (parent) {
        const siblings = parent.children;
        const index = Array.from(siblings).indexOf(element);
        if (index > 0) {
            selector += `:nth-child(${index + 1})`;
        }
    }
    
    return selector;
}

function getElementCoordinates(element) {
    if (!element || !element.getBoundingClientRect) {
        return { x: 0, y: 0 };
    }
    
    const rect = element.getBoundingClientRect();
    return {
        x: Math.round(rect.left + rect.width / 2),
        y: Math.round(rect.top + rect.height / 2)
    };
}

function sanitizeValue(value) {
    // Don't record actual sensitive values
    if (!value) return '';
    
    if (value.length > 50) {
        return '[LONG_VALUE]';
    }
    
    // Check if value looks sensitive
    if (/password|secret|token|key|ssn|credit/i.test(value)) {
        return '[SENSITIVE_VALUE]';
    }
    
    return value.length > 0 ? '[VALUE_ENTERED]' : '';
}

/**
 * UI Indicators
 */
function showConnectionIndicator(status) {
    // Remove existing indicator
    const existingIndicator = document.getElementById('burp-mcp-connection-indicator');
    if (existingIndicator) {
        existingIndicator.remove();
    }
    
    // Create new indicator
    const indicator = document.createElement('div');
    indicator.id = 'burp-mcp-connection-indicator';
    indicator.className = `burp-mcp-indicator burp-mcp-${status}`;
    indicator.textContent = status === 'connected' ? '🔒 BurpSuite Connected' : '⚠️ BurpSuite Disconnected';
    
    document.body.appendChild(indicator);
    
    // Auto-hide after 3 seconds
    setTimeout(() => {
        if (indicator.parentNode) {
            indicator.remove();
        }
    }, 3000);
}

function showRecordingIndicator(recording) {
    const existingIndicator = document.getElementById('burp-mcp-recording-indicator');
    if (existingIndicator) {
        existingIndicator.remove();
    }
    
    if (recording) {
        const indicator = document.createElement('div');
        indicator.id = 'burp-mcp-recording-indicator';
        indicator.className = 'burp-mcp-indicator burp-mcp-recording';
        indicator.textContent = '🔴 Recording...';
        
        document.body.appendChild(indicator);
    }
}

/**
 * Inject security analyzer script
 */
function injectSecurityAnalyzer() {
    if (injectedScript) return;
    
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('security-analyzer.js');
    script.id = 'burp-mcp-security-analyzer';
    
    (document.head || document.documentElement).appendChild(script);
    injectedScript = script;
    
    console.log('[BurpMCP Content] Security analyzer script injected');
}

/**
 * Initialize when DOM is ready
 */
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
