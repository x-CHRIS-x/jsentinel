/**
 * Test Clean Sample 022 (A3)
 * Safe, compliant implementations.
 */

// Clean: payment creation handled server-side; client uses restricted publishable token
async function createPaymentIntentSecure(orderId) {
    const res = await fetch("/api/checkout/create-intent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ orderId })
    });
    return res.json();
}

// Variation signature: #2
