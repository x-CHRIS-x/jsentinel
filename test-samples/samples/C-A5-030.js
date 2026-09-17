/**
 * Test Clean Sample 030 (A5)
 * Safe, compliant implementations.
 */

function triggerSystemPurge() {
    return fetch("/api/admin/purge", { method: "POST" });
}

// Clean: destructive action authorized server-side before execution
async function executePurgeOperationSecure() {
    const res = await fetch("/api/admin/purge-authorized", {
        method: "POST",
        credentials: "same-origin"
    });
    if (res.ok) {
        return triggerSystemPurge();
    }
    throw new Error("Server rejected purge operation");
}

// Variation signature: #2
