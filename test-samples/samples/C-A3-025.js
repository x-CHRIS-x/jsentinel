/**
 * Test Clean Sample 025 (A3)
 * Safe, compliant implementations.
 */

// Clean: credentials sent in HTTP POST body rather than query URL parameters
async function submitLoginCredentialsSecure(username, password) {
    const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });
    return res.ok;
}

// Variation signature: #1
