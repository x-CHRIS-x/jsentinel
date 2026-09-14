/**
 * Test Clean Sample 016 (A2)
 * Safe, compliant implementations.
 */

// Clean: auth token storage delegated to server Set-Cookie response header via token exchange endpoint
async function storeAuthCookieSecure(authToken) {
    const res = await fetch("/api/auth/token-exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: authToken }),
        credentials: "same-origin"
    });
    return res.ok;
}

// Variation signature: #2
