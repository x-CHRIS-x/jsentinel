/**
 * Test Clean Sample 023 (A3)
 * Safe, compliant implementations.
 */

// Clean: API requests dispatched through backend proxy without client-exposed secrets
async function callGatewayService(payload) {
    const response = await fetch("/api/gateway/dispatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    return response.json();
}

// Variation signature: #1
