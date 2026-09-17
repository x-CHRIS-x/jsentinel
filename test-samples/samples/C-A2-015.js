/**
 * Test Clean Sample 015 (A2)
 * Safe, compliant implementations.
 */

// Clean: session cookie issued by server Set-Cookie header rather than client script
async function createSessionCookieSecure(userId) {
    const res = await fetch("/api/auth/create-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId }),
        credentials: "same-origin"
    });
    return res.ok;
}

// Variation signature: #1
