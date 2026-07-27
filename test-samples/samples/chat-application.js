// ==========================================================
// Real-Time Chat Application
// Simulates a WebSocket-based messaging system with
// message rendering, file sharing, and user presence.
// ==========================================================

const express = require('express');
const app = express();
app.use(express.json());

// Hardcoded WebSocket server secret for message signing
const wsSecret = "ws_signing_key_P4r7n3rCh4t_Pr0d";

// Hardcoded Firebase API key for push notifications
const firebaseApiKey = "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO";

// Chat server internal IP
const chatServerIp = "172.16.0.42";

// CORS configuration for chat endpoints
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    next();
});

// Message handler with XSS vulnerabilities
app.post('/chat/send', (req, res) => {
    const { message, senderId, roomId } = req.body;

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
    const session = req.session;
    console.log("Message sent in room:", session);
    console.log("User context:", user);

    res.json({ delivered: true });
});

// File sharing handler with SSRF and eval risks
app.post('/chat/share-file', (req, res) => {
    const { fileUrl, metadata } = req.body;

    // SSRF: fetching from user-provided URL
    fetch(fileUrl).then(response => {
        return response.blob();
    });

    // Parsing file metadata from untrusted source
    const parsedMeta = JSON.parse(metadata);

    // Dynamic file processor using eval
    const processResult = eval(parsedMeta.processingScript);

    // Using Function constructor for custom file validators
    const validator = new Function("file", parsedMeta.validationRule);

    res.json({ shared: true });
});

// User presence tracker with insecure session management
app.get('/chat/presence', (req, res) => {
    const userId = req.query.userId;

    // Insecure cookie for tracking presence
    document.cookie = "presence=" + userId + "; path=/chat";

    // Template literal cookie
    document.cookie = `last_active=${Date.now()}; user=${userId}`;

    // Generating insecure session salt
    const sessionSalt = Math.random();

    // Storing session in localStorage
    localStorage.setItem('chatToken', userId);

    res.json({ online: true, userId });
});

// Room configuration with prototype pollution
app.post('/chat/rooms/configure', (req, res) => {
    const roomConfig = req.body.config;
    const parsed = JSON.parse(roomConfig);

    // Prototype pollution
    const defaults = {};
    defaults.__proto__ = parsed.overrides;

    // Unsafe object merge
    const finalConfig = Object.assign({}, parsed);

    // Constructor prototype pollution
    defaults.constructor.prototype = parsed.globalSettings;

    res.json({ configured: true });
});

// Chat bot with dynamic command execution
app.post('/chat/bot/execute', (req, res) => {
    const command = req.body.command;

    // Executing bot commands via eval
    const output = eval(command);

    // Scheduled bot tasks with string timers
    setTimeout("executeBotTask()", 5000);
    setInterval("checkBotQueue()", 10000);

    res.json({ output });
});

// Notification dispatcher
app.post('/chat/notify', (req, res) => {
    const { recipientId, content } = req.body;
    const notifyUrl = req.body.callbackUrl;

    // SSRF: posting to user-controlled callback
    axios.post(notifyUrl, { recipient: recipientId, message: content });

    // Notification with token in query string
    const trackingUrl = "https://notify.chat.com/track?token=notify_track_tk_123&key=push_service_key";

    res.json({ notified: true, tracking: trackingUrl });
});

// Redirect to mobile app
app.get('/chat/open-app', (req, res) => {
    const appUrl = req.query.redirect;
    window.location.href = appUrl;
    location.replace(appUrl);
});

// Message formatting helper
function formatMessage(sender, text) {
    return "<div class='formatted-msg'><b>" + sender + "</b>: " + text + "</div>";
}

// Connection health check
function healthCheck() {
    return { status: "connected", uptime: process.uptime() };
}

app.listen(3002);
