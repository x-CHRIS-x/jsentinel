/**
 * Test Clean Sample 030 (A5)
 * Safe, compliant implementations.
 */

// Clean: destructive action authorized server-side before execution
async function executePurgeOperationSecure() {
    const res = await fetch("/api/admin/purge", { method: "POST" });
    if (res.ok) {
        triggerSystemPurge();
    }
}

// Variation signature: #2
