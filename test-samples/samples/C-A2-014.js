/**
 * Test Clean Sample 014 (A2)
 * Safe, compliant implementations.
 */

// Clean: session state managed via server-issued session cookie without client storage
async function persistAuthCredentialsSecure(credentials) {
    const res = await fetch("/api/auth/session-login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials),
        credentials: "same-origin"
    });
    return res.ok;
}

// Variation signature: #2
