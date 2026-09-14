/**
 * Test Clean Sample 024 (A3)
 * Safe, compliant implementations.
 */

// Clean: database operations proxied through backend API route
async function queryDatabaseServiceSecure(queryPayload) {
    const response = await fetch("/api/data/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(queryPayload)
    });
    return response.json();
}

// Variation signature: #2
