/**
 * Test Clean Sample 026 (A3)
 * Safe, compliant implementations.
 */

// Clean: reset token submitted via secure POST request body
async function submitPasswordResetSecure(accountEmail, resetToken, newPassword) {
    const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: accountEmail, token: resetToken, newPassword })
    });
    return res.ok;
}

// Variation signature: #2
