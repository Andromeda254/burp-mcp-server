/**
 * Burp MCP Browser Integration - Content Script
 * 
 * Runs on all web pages to detect forms, authentication states,
 * and provide browser automation capabilities for Burp MCP Server.
 */

// Content script state
let contentState = {
    initialized: false,
    connected: false,
    sessionId: null,
    currentAuthState: 'UNKNOWN',
    observing: false,
    forms: new Map(),
    lastAnalysis: 0
};

// Configuration
const CONTENT_CONFIG = {
    ANALYSIS_DEBOUNCE: 1000, // 1 second
    SCREENSHOT_QUALITY: 0.8,
    MAX_FORMS_TO_TRACK: 10,
    AUTH_STATE_KEYWORDS: {
        LOGIN: ['login', 'signin', 'sign in', 'log in', 'authenticate', 'auth'],
        AUTHENTICATED: ['logout', 'log out', 'sign out', 'profile', 'dashboard', 'welcome', 'account'],
        ERROR: ['error', 'invalid', 'incorrect', 'failed', 'wrong', 'denied']
    }
};

// Initialize content script
(function initialize() {
    if (contentState.initialized) {
        return;
    }
    
    console.log('[Burp MCP Content] Initializing on:', window.location.href);
    
    try {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeContentScript);
        } else {
            initializeContentScript();
        }
        
    } catch (error) {
        console.error('[Burp MCP Content] Initialization failed:', error);
    }
})();

/**
 * Initialize content script functionality
 */
function initializeContentScript() {
    if (contentState.initialized) {
        return;
    }
    
    try {
        contentState.initialized = true;
        
        console.log('[Burp MCP Content] Starting initialization...');
        
        // Setup page monitoring
        setupPageMonitoring();
        
        // Setup form monitoring
        setupFormMonitoring();
        
        // Setup authentication monitoring
        setupAuthenticationMonitoring();
        
        // Listen for messages from background script
        chrome.runtime.onMessage.addListener(handleBackgroundMessage);
        
        // Request session info from background
        requestSessionInfo();
        
        // Perform initial page analysis
        setTimeout(performPageAnalysis, 500);
        
        console.log('[Burp MCP Content] Initialization complete');
        
    } catch (error) {
        console.error('[Burp MCP Content] Initialization failed:', error);
    }
}

/**
 * Setup page monitoring
 */
function setupPageMonitoring() {
    // Monitor page changes
    if ('MutationObserver' in window) {
        const observer = new MutationObserver(debounce(() => {
            if (contentState.connected) {
                performPageAnalysis();
            }
        }, CONTENT_CONFIG.ANALYSIS_DEBOUNCE));
        
        observer.observe(document.body || document.documentElement, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['class', 'id', 'style']
        });
        
        contentState.observing = true;
        console.log('[Burp MCP Content] Page monitoring enabled');
    }
    
    // Monitor URL changes (SPA navigation)
    let lastUrl = window.location.href;
    setInterval(() => {
        if (window.location.href !== lastUrl) {
            lastUrl = window.location.href;
            console.log('[Burp MCP Content] URL changed:', lastUrl);
            
            if (contentState.connected) {
                setTimeout(performPageAnalysis, 500);
            }
        }
    }, 1000);
}

/**
 * Setup form monitoring
 */
function setupFormMonitoring() {
    // Monitor form submissions
    document.addEventListener('submit', (event) => {
        if (contentState.connected) {
            handleFormSubmission(event);
        }
    }, true);
    
    // Monitor input changes in forms
    document.addEventListener('input', (event) => {
        if (event.target.type === 'password' && contentState.connected) {
            handlePasswordInput(event);
        }
    }, true);
    
    // Monitor form focus events
    document.addEventListener('focusin', (event) => {
        if (isFormField(event.target) && contentState.connected) {
            handleFormFieldFocus(event);
        }
    }, true);
    
    console.log('[Burp MCP Content] Form monitoring enabled');
}

/**
 * Setup authentication monitoring
 */
function setupAuthenticationMonitoring() {
    // Monitor authentication-related clicks
    document.addEventListener('click', (event) => {
        if (contentState.connected && isAuthenticationElement(event.target)) {
            handleAuthenticationClick(event);
        }
    }, true);
    
    console.log('[Burp MCP Content] Authentication monitoring enabled');
}

/**
 * Perform page analysis
 */
async function performPageAnalysis() {
    if (!contentState.connected || Date.now() - contentState.lastAnalysis < CONTENT_CONFIG.ANALYSIS_DEBOUNCE) {
        return;
    }
    
    try {
        contentState.lastAnalysis = Date.now();
        
        console.log('[Burp MCP Content] Performing page analysis...');
        
        // Analyze forms
        const forms = analyzeForms();
        
        // Analyze authentication state
        const authState = analyzeAuthenticationState();
        
        // Analyze DOM for security patterns
        const domAnalysis = analyzeDOMForSecurity();
        
        // Check for authentication state changes
        if (authState !== contentState.currentAuthState) {
            const previousState = contentState.currentAuthState;
            contentState.currentAuthState = authState;
            
            await sendToBackground({
                type: 'auth_state_change',
                state: authState,
                previousState: previousState
            });
        }
        
        // Report DOM analysis
        if (domAnalysis.hasFindings) {
            await sendToBackground({
                type: 'dom_analysis',
                domAnalysis: domAnalysis
            });
        }
        
        // Report new forms
        for (const [formId, form] of forms.entries()) {
            if (!contentState.forms.has(formId)) {
                contentState.forms.set(formId, form);
                
                if (form.isLoginForm) {
                    await sendToBackground({
                        type: 'form_detected',
                        form: form
                    });
                }
            }
        }
        
    } catch (error) {
        console.error('[Burp MCP Content] Page analysis failed:', error);
    }
}

/**
 * Analyze forms on the page
 */
function analyzeForms() {
    const forms = new Map();
    const formElements = document.querySelectorAll('form');
    
    formElements.forEach((form, index) => {
        try {
            const formId = form.id || `form_${index}`;
            const formData = {
                id: formId,
                action: form.action || window.location.href,
                method: form.method || 'GET',
                isLoginForm: false,
                fields: [],
                hasPasswordField: false,
                hasUsernameField: false
            };
            
            // Analyze form fields
            const inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                const field = {
                    name: input.name || '',
                    type: input.type || 'text',
                    id: input.id || '',
                    placeholder: input.placeholder || '',
                    required: input.required || false
                };
                
                formData.fields.push(field);
                
                // Check for login-related fields
                if (input.type === 'password') {
                    formData.hasPasswordField = true;
                }
                
                if (input.type === 'email' || input.type === 'text' && 
                    (input.name.toLowerCase().includes('user') || 
                     input.name.toLowerCase().includes('email') || 
                     input.name.toLowerCase().includes('login'))) {
                    formData.hasUsernameField = true;
                }
            });
            
            // Determine if this is a login form
            formData.isLoginForm = formData.hasPasswordField && formData.hasUsernameField;
            
            // Check form action for login patterns
            if (formData.action.toLowerCase().includes('login') || 
                formData.action.toLowerCase().includes('signin') ||
                formData.action.toLowerCase().includes('auth')) {
                formData.isLoginForm = true;
            }
            
            forms.set(formId, formData);
            
        } catch (error) {
            console.error('[Burp MCP Content] Form analysis failed:', error);
        }
    });
    
    return forms;
}

/**
 * Analyze authentication state
 */
function analyzeAuthenticationState() {
    try {
        const pageText = document.body ? document.body.innerText.toLowerCase() : '';
        const pageHtml = document.documentElement.outerHTML.toLowerCase();
        const url = window.location.href.toLowerCase();
        
        // Check for logout elements (indicates authenticated)
        const logoutElements = document.querySelectorAll('a[href*="logout"], a[href*="signout"], button:contains("logout"), button:contains("sign out")');
        if (logoutElements.length > 0) {
            return 'AUTHENTICATED';
        }
        
        // Check for authentication keywords
        for (const keyword of CONTENT_CONFIG.AUTH_STATE_KEYWORDS.AUTHENTICATED) {
            if (pageText.includes(keyword) || url.includes(keyword)) {
                return 'AUTHENTICATED';
            }
        }
        
        // Check for error messages
        for (const keyword of CONTENT_CONFIG.AUTH_STATE_KEYWORDS.ERROR) {
            if (pageText.includes(keyword) && (pageText.includes('login') || pageText.includes('password'))) {
                return 'AUTHENTICATION_FAILED';
            }
        }
        
        // Check for login elements
        for (const keyword of CONTENT_CONFIG.AUTH_STATE_KEYWORDS.LOGIN) {
            if (pageText.includes(keyword) || url.includes(keyword)) {
                return 'LOGIN_PAGE';
            }
        }
        
        // Check for password fields (indicates login page)
        const passwordFields = document.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
            return 'LOGIN_PAGE';
        }
        
        return 'UNAUTHENTICATED';
        
    } catch (error) {
        console.error('[Burp MCP Content] Authentication state analysis failed:', error);
        return 'UNKNOWN';
    }
}

/**
 * Analyze DOM for security patterns
 */
function analyzeDOMForSecurity() {
    try {
        const analysis = {
            hasFindings: false,
            hasPasswordFields: false,
            hasLoginKeywords: [],
            hasUserProfile: false,
            hasLogoutButton: false,
            authenticatedKeywords: [],
            securityIssues: []
        };
        
        // Check for password fields
        const passwordFields = document.querySelectorAll('input[type="password"]');
        analysis.hasPasswordFields = passwordFields.length > 0;
        
        // Check for login keywords
        const pageText = document.body ? document.body.innerText.toLowerCase() : '';
        CONTENT_CONFIG.AUTH_STATE_KEYWORDS.LOGIN.forEach(keyword => {
            if (pageText.includes(keyword)) {
                analysis.hasLoginKeywords.push(keyword);
            }
        });
        
        // Check for authenticated user elements
        CONTENT_CONFIG.AUTH_STATE_KEYWORDS.AUTHENTICATED.forEach(keyword => {
            if (pageText.includes(keyword)) {
                analysis.authenticatedKeywords.push(keyword);
            }
        });
        
        // Check for user profile indicators
        const profileElements = document.querySelectorAll('[class*="profile"], [class*="user"], [id*="profile"], [id*="user"]');
        analysis.hasUserProfile = profileElements.length > 0;
        
        // Check for logout button
        const logoutElements = document.querySelectorAll('a[href*="logout"], button:contains("logout")');
        analysis.hasLogoutButton = logoutElements.length > 0;
        
        // Check for security issues
        
        // 1. Plain HTTP on login pages
        if (analysis.hasPasswordFields && window.location.protocol === 'http:') {
            analysis.securityIssues.push({
                type: 'INSECURE_LOGIN',
                description: 'Login form on non-HTTPS page',
                severity: 'HIGH'
            });
        }
        
        // 2. Password fields without autocomplete="off"
        passwordFields.forEach(field => {
            if (field.getAttribute('autocomplete') !== 'off') {
                analysis.securityIssues.push({
                    type: 'PASSWORD_AUTOCOMPLETE',
                    description: 'Password field allows autocomplete',
                    severity: 'MEDIUM'
                });
            }
        });
        
        // Set hasFindings flag
        analysis.hasFindings = analysis.hasPasswordFields || 
                              analysis.hasLoginKeywords.length > 0 || 
                              analysis.authenticatedKeywords.length > 0 ||
                              analysis.securityIssues.length > 0;
        
        return analysis;
        
    } catch (error) {
        console.error('[Burp MCP Content] DOM security analysis failed:', error);
        return { hasFindings: false };
    }
}

/**
 * Handle form submission
 */
async function handleFormSubmission(event) {
    try {
        const form = event.target;
        const formData = new FormData(form);
        const loginData = {};
        
        let hasPassword = false;
        let hasUsername = false;
        
        // Extract form data
        for (const [name, value] of formData.entries()) {
            const input = form.querySelector(`[name="${name}"]`);
            
            if (input && input.type === 'password') {
                hasPassword = true;
                loginData.hasPassword = true;
            } else if (input && (input.type === 'email' || input.type === 'text')) {
                // Potential username field
                if (name.toLowerCase().includes('user') || 
                    name.toLowerCase().includes('email') || 
                    name.toLowerCase().includes('login')) {
                    hasUsername = true;
                    loginData.username = value;
                }
            }
        }
        
        // If this looks like a login attempt
        if (hasPassword && hasUsername) {
            loginData.url = window.location.href;
            loginData.formAction = form.action || window.location.href;
            loginData.formMethod = form.method || 'POST';
            
            await sendToBackground({
                type: 'login_attempt',
                loginData: loginData
            });
            
            console.log('[Burp MCP Content] Login attempt detected');
        }
        
    } catch (error) {
        console.error('[Burp MCP Content] Form submission handling failed:', error);
    }
}

/**
 * Handle password input
 */
function handlePasswordInput(event) {
    try {
        // Mark that password is being entered
        console.log('[Burp MCP Content] Password input detected');
        
    } catch (error) {
        console.error('[Burp MCP Content] Password input handling failed:', error);
    }
}

/**
 * Handle form field focus
 */
function handleFormFieldFocus(event) {
    try {
        const field = event.target;
        console.log('[Burp MCP Content] Form field focused:', field.name, field.type);
        
    } catch (error) {
        console.error('[Burp MCP Content] Form field focus handling failed:', error);
    }
}

/**
 * Handle authentication-related clicks
 */
async function handleAuthenticationClick(event) {
    try {
        const element = event.target;
        const text = element.textContent || element.value || '';
        
        console.log('[Burp MCP Content] Authentication element clicked:', text.trim());
        
        // Could trigger authentication state change analysis
        setTimeout(performPageAnalysis, 1000);
        
    } catch (error) {
        console.error('[Burp MCP Content] Authentication click handling failed:', error);
    }
}

/**
 * Handle messages from background script
 */
function handleBackgroundMessage(message, sender, sendResponse) {
    console.log('[Burp MCP Content] Background message:', message.type);
    
    try {
        switch (message.type) {
            case 'burp_mcp_connected':
                contentState.connected = message.connected;
                contentState.sessionId = message.sessionId;
                
                if (message.connected) {
                    console.log('[Burp MCP Content] Connected to Burp MCP Server');
                    setTimeout(performPageAnalysis, 500);
                } else {
                    console.log('[Burp MCP Content] Disconnected from Burp MCP Server');
                }
                break;
                
            case 'automation_command':
                handleAutomationCommand(message)
                    .then(result => sendResponse({ success: true, result }))
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true; // Async response
                
            case 'take_screenshot':
                takeScreenshot(message.context)
                    .then(result => sendResponse({ success: true, result }))
                    .catch(error => sendResponse({ success: false, error: error.message }));
                return true; // Async response
                
            default:
                console.warn('[Burp MCP Content] Unknown background message:', message.type);
        }
        
        sendResponse({ success: true });
        
    } catch (error) {
        console.error('[Burp MCP Content] Background message handling failed:', error);
        sendResponse({ success: false, error: error.message });
    }
}

/**
 * Handle automation commands
 */
async function handleAutomationCommand(message) {
    const { action, parameters } = message;
    
    console.log('[Burp MCP Content] Automation command:', action, parameters);
    
    switch (action) {
        case 'fill_form':
            return await automateFormFill(parameters);
        
        case 'click_element':
            return await automateClick(parameters);
        
        case 'wait_for_element':
            return await automateWait(parameters);
        
        case 'navigate':
            return await automateNavigation(parameters);
        
        default:
            throw new Error(`Unknown automation action: ${action}`);
    }
}

/**
 * Automate form filling
 */
async function automateFormFill(parameters) {
    const { selector, data } = parameters;
    
    const form = document.querySelector(selector);
    if (!form) {
        throw new Error(`Form not found: ${selector}`);
    }
    
    let fillCount = 0;
    
    // Fill form fields
    for (const [fieldName, value] of Object.entries(data)) {
        const field = form.querySelector(`[name="${fieldName}"], #${fieldName}`);
        if (field) {
            field.value = value;
            field.dispatchEvent(new Event('input', { bubbles: true }));
            fillCount++;
        }
    }
    
    return { 
        message: `Filled ${fillCount} form fields`,
        fillCount,
        formSelector: selector
    };
}

/**
 * Automate element clicking
 */
async function automateClick(parameters) {
    const { selector } = parameters;
    
    const element = document.querySelector(selector);
    if (!element) {
        throw new Error(`Element not found: ${selector}`);
    }
    
    element.click();
    
    return {
        message: `Clicked element: ${selector}`,
        elementText: element.textContent || element.value || ''
    };
}

/**
 * Automate waiting for elements
 */
async function automateWait(parameters) {
    const { selector, timeout = 5000 } = parameters;
    
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        
        const checkElement = () => {
            const element = document.querySelector(selector);
            
            if (element) {
                resolve({
                    message: `Element found: ${selector}`,
                    waitTime: Date.now() - startTime
                });
            } else if (Date.now() - startTime > timeout) {
                reject(new Error(`Element not found within timeout: ${selector}`));
            } else {
                setTimeout(checkElement, 100);
            }
        };
        
        checkElement();
    });
}

/**
 * Automate navigation
 */
async function automateNavigation(parameters) {
    const { url } = parameters;
    
    window.location.href = url;
    
    return {
        message: `Navigating to: ${url}`
    };
}

/**
 * Take screenshot
 */
async function takeScreenshot(context = 'manual') {
    try {
        // Use html2canvas if available, or request from background
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        
        // Simple screenshot placeholder - in real implementation would use html2canvas
        ctx.fillStyle = '#f0f0f0';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#333';
        ctx.font = '16px Arial';
        ctx.fillText('Screenshot: ' + window.location.href, 10, 30);
        ctx.fillText('Context: ' + context, 10, 50);
        ctx.fillText('Time: ' + new Date().toLocaleString(), 10, 70);
        
        const screenshotData = canvas.toDataURL('image/png', CONTENT_CONFIG.SCREENSHOT_QUALITY);
        
        // Send to background script
        const response = await sendToBackground({
            type: 'screenshot',
            screenshot: screenshotData,
            context: context
        });
        
        return response;
        
    } catch (error) {
        console.error('[Burp MCP Content] Screenshot failed:', error);
        throw error;
    }
}

/**
 * Request session info from background
 */
async function requestSessionInfo() {
    try {
        const response = await sendToBackground({ type: 'get_session_info' });
        
        if (response.data) {
            contentState.connected = response.data.connected;
            contentState.sessionId = response.data.sessionId;
        }
        
    } catch (error) {
        console.error('[Burp MCP Content] Failed to get session info:', error);
    }
}

/**
 * Send message to background script
 */
function sendToBackground(message) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
            } else if (response && response.success) {
                resolve(response);
            } else {
                reject(new Error(response?.error || 'Background communication failed'));
            }
        });
    });
}

// Utility functions

/**
 * Check if element is a form field
 */
function isFormField(element) {
    return element && (
        element.tagName === 'INPUT' ||
        element.tagName === 'SELECT' ||
        element.tagName === 'TEXTAREA'
    );
}

/**
 * Check if element is authentication-related
 */
function isAuthenticationElement(element) {
    if (!element) return false;
    
    const text = (element.textContent || element.value || '').toLowerCase();
    const className = (element.className || '').toLowerCase();
    const id = (element.id || '').toLowerCase();
    
    const authKeywords = ['login', 'signin', 'logout', 'signout', 'sign in', 'sign out', 'log in', 'log out'];
    
    return authKeywords.some(keyword => 
        text.includes(keyword) || className.includes(keyword) || id.includes(keyword)
    );
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

console.log('[Burp MCP Content] Content script loaded on:', window.location.href);