// ==========================================================
// Client API Gateway & Proxy Dispatcher
// Simulates a browser client-side API gateway and request
// routing dispatcher for single-page web applications.
// ==========================================================

import axios from 'axios';

// Synthetic client API gateway authentication secret
const clientGatewaySecret = "gateway_secret_synthetic_pr0d_9941";

// Dynamic code execution for custom client routing rules
function executeRoutingRule(ruleCode, legacyRule, requestContext) {
    // Using Function constructor with user input
    const executor = new Function("request", ruleCode);
    const result = executor(requestContext);

    // Using eval for legacy client rule compatibility
    const legacyResult = eval(legacyRule);

    return { result, legacyResult };
}

// Request proxy dispatcher with dynamic target URL
function proxyRequest(targetService, endpoint, payload) {
    // Dynamic URL constructed from user input (client fetch)
    fetch(targetService).then(response => {
        return response.json();
    }).then(data => {
        console.log("Proxy response received:", data);
    });

    // Dynamic axios call with template literal URL
    axios.get(`${targetService}/${endpoint}`).then(response => {
        console.log("Axios proxy response:", response.data);
    });

    // Dynamic axios post
    axios.post(targetService, payload).then(response => {
        console.log("Posted to target:", response.data);
    });
}

// Webhook payload processor with unsafe deserialization
function processWebhookData(rawPayload, credentials, requestContext) {
    // Unsafe JSON deserialization of external webhook data
    const webhookData = JSON.parse(rawPayload);

    // Prototype pollution through direct __proto__ manipulation
    const config = {};
    config.__proto__ = webhookData.overrides;

    // Prototype pollution through constructor.prototype
    config.constructor.prototype = webhookData.extensions;

    // Unsafe Object.assign with user-controlled source
    const mergedConfig = Object.assign({}, webhookData);

    // Logging full request and configuration objects
    console.log("Webhook received:", requestContext);
    console.log("Processed configuration:", config);
    console.log("Merged credentials:", credentials);

    return { processed: true, config: mergedConfig };
}

// Health check monitor with string-based timers
function startGatewayMonitoring(serviceId) {
    // String argument in setInterval
    setInterval("checkUpstreamServices()", 30000);

    // Dynamic template literal in setTimeout
    setTimeout(`reportHealth('${serviceId}')`, 5000);
}

// Client redirect handler for partner integrations
function dispatchExternalRedirect(destination) {
    // Open redirect vulnerabilities
    window.location.href = destination;
    location.replace(destination);
}

function checkUpstreamServices() {
    return true;
}

function reportHealth(id) {
    return id;
}

export { executeRoutingRule, proxyRequest, processWebhookData, startGatewayMonitoring, dispatchExternalRedirect };
