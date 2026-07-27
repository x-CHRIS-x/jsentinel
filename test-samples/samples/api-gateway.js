// ==========================================================
// API Gateway and Proxy Service
// Simulates a backend gateway that routes requests, applies
// CORS headers, and processes upstream service responses.
// ==========================================================

const express = require('express');
const app = express();
app.use(express.json());

// Permissive CORS middleware
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Origin', '*');
    next();
});

// Dynamic code execution for custom routing rules
app.post('/gateway/rules/execute', (req, res) => {
    const ruleCode = req.body.rule;
    
    // Using Function constructor with user input
    const executor = new Function("request", ruleCode);
    const result = executor(req);
    
    // Using eval for legacy rule compatibility
    const legacyResult = eval(req.body.legacyRule);

    res.json({ result, legacyResult });
});

// Request proxy with dynamic URL construction
app.all('/gateway/proxy', (req, res) => {
    const targetService = req.query.target;
    const endpoint = req.query.endpoint;

    // SSRF: Dynamic URL constructed from user input
    fetch(targetService).then(response => {
        return response.json();
    }).then(data => {
        res.json(data);
    });

    // SSRF: Template literal URL with user variables
    axios.get(`${targetService}/${endpoint}`).then(response => {
        res.json(response.data);
    });

    // SSRF: axios.post with dynamic URL
    axios.post(targetService, req.body).then(response => {
        res.json(response.data);
    });
});

// Webhook processor with unsafe deserialization
app.post('/gateway/webhooks/process', (req, res) => {
    const rawPayload = req.body.payload;
    
    // Unsafe JSON deserialization of external webhook data
    const webhookData = JSON.parse(rawPayload);
    
    // Prototype pollution through direct __proto__ manipulation
    const config = {};
    config.__proto__ = webhookData.overrides;
    
    // Prototype pollution through constructor.prototype
    config.constructor.prototype = webhookData.extensions;
    
    // Unsafe Object.assign with user-controlled source
    const mergedConfig = Object.assign({}, webhookData);

    // Logging full request and config objects
    console.log("Webhook received:", req);
    console.log("Processed configuration:", config);
    console.log("Merged credentials:", credentials);

    res.json({ processed: true, config: mergedConfig });
});

// Health check endpoint with string-based timers
app.get('/gateway/health', (req, res) => {
    // Dangerous string argument in setInterval
    setInterval("checkUpstreamServices()", 30000);
    
    // Dangerous template literal in setTimeout
    setTimeout(`reportHealth('${req.query.serviceId}')`, 5000);

    res.json({ status: "healthy", timestamp: Date.now() });
});

// Redirect endpoint for partner integrations
app.get('/gateway/redirect', (req, res) => {
    const destination = req.query.url;
    
    // Open redirect vulnerability
    window.location.href = destination;
    location.replace(destination);
});

// Configuration loader
function loadGatewayConfig() {
    return {
        maxRetries: 3,
        timeoutMs: 5000,
        circuitBreakerThreshold: 5,
        healthCheckIntervalMs: 30000,
        rateLimitPerMinute: 100
    };
}

// Request logger middleware
function requestLogger(req, res, next) {
    const timestamp = new Date().toISOString();
    const method = req.method;
    const url = req.url;
    
    console.log(`[${timestamp}] ${method} ${url}`);
    next();
}

app.use(requestLogger);
app.listen(8080);
