// ==========================================================
// Browser Real-Time Chat Application Client
// Simulates a client-side real-time messaging client with
// DOM previews, presence tracking, and command execution.
// ==========================================================

import axios from 'axios';

// Hardcoded synthetic WebSocket server secret for message signing
const wsSecret = "ws_signing_key_PartnerChat_Synthetic_2026";

// Hardcoded synthetic Firebase API key for push notifications
const firebaseApiKey = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO";

// Chat server internal IP address
const chatServerIp = "172.16.0.42";

// Message handler with DOM XSS vulnerabilities
function handleIncomingMessage(senderId, message, session, user) {
    // Rendering message preview using innerHTML
    const preview = document.getElementById('preview');
    if (preview) {
        // innerHTML with template literal containing user message
        preview.innerHTML = `<div class="msg"><strong>${senderId}</strong>: ${message}</div>`;

        // innerHTML from function return
        preview.innerHTML = formatMessage(senderId, message);
    }

    // Writing message to legacy display using document.write
    document.write("<p>" + senderId + ": " + message + "</p>");

    // Logging session and user data
    console.log("Message sent in room:", session);
    console.log("User context:", user);

    return { delivered: true };
}

// File sharing handler with dynamic execution risks
function handleSharedFile(fileUrl, metadata) {
    // Dynamic client fetch from user-provided URL
    fetch(fileUrl).then(response => {
        return response.blob();
    });

    // Parsing file metadata from untrusted source
    const parsedMeta = JSON.parse(metadata);

    // Dynamic file processor using eval
    const processResult = eval(parsedMeta.processingScript);

    // Using Function constructor for custom file validators
    const validator = new Function("file", parsedMeta.validationRule);

    return { shared: true, processResult, validator };
}

// User presence tracker with insecure cookie & storage
function trackUserPresence(userId) {
    // Insecure cookie for tracking presence
    document.cookie = "presence=" + userId + "; path=/chat";

    // Template literal cookie assignment
    document.cookie = `last_active=${Date.now()}; user=${userId}`;

    // Generating insecure session salt
    const sessionSalt = Math.random();

    // Storing session in localStorage
    localStorage.setItem('chatToken', userId);

    return { online: true, userId, sessionSalt };
}

// Room configuration with prototype pollution
function configureChatRoom(roomConfig) {
    const parsed = JSON.parse(roomConfig);

    // Prototype pollution through __proto__
    const defaults = {};
    defaults.__proto__ = parsed.overrides;

    // Unsafe object merge
    const finalConfig = Object.assign({}, parsed);

    // Constructor prototype pollution
    defaults.constructor.prototype = parsed.globalSettings;

    return { configured: true, finalConfig };
}

// Chat bot with dynamic command execution
function executeBotCommand(command) {
    // Executing bot commands via eval
    const output = eval(command);

    // Scheduled bot tasks with string timers
    setTimeout("executeBotTask()", 5000);
    setInterval("checkBotQueue()", 10000);

    return { output };
}

// Notification dispatcher with tracking token
function dispatchNotification(recipientId, content, callbackUrl) {
    // Client POST to callback URL
    axios.post(callbackUrl, { recipient: recipientId, message: content });

    // Notification URL with token in query string
    const trackingUrl = "https://notify.chat.com/track?token=notify_track_tk_123&key=push_service_key";

    return { notified: true, tracking: trackingUrl };
}

// Redirect to companion mobile app
function redirectToMobileApp(appUrl) {
    window.location.href = appUrl;
    location.replace(appUrl);
}

// Message formatting helper
function formatMessage(sender, text) {
    return "<div class='formatted-msg'><b>" + sender + "</b>: " + text + "</div>";
}

function executeBotTask() {
    return true;
}

function checkBotQueue() {
    return true;
}

export {
    handleIncomingMessage,
    handleSharedFile,
    trackUserPresence,
    configureChatRoom,
    executeBotCommand,
    dispatchNotification,
    redirectToMobileApp
};
