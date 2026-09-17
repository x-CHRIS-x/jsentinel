/**
 * Test Clean Sample 011 (A2)
 * Safe, compliant implementations.
 */

// Clean: passwords verified server-side via authentication endpoint
async function loginMasterSecure(username, pwd) {
    const res = await fetch("/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, pwd })
    });
    return res.ok;
}

// Variation signature: #1
