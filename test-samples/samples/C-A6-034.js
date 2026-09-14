/**
 * Test Clean Sample 034 (A6)
 * Safe, compliant implementations.
 */

// Clean: cross-window message handler validating event origin before processing
const trustedOrigins = ["https://trusted.portal.example.com"];
function listenForRemoteCommandsSecure() {
    window.addEventListener("message", function(event) {
        if (!trustedOrigins.includes(event.origin)) return;
        if (event.data && typeof event.data.action === "string") {
            handleSafeAction(event.data.action);
        }
    });
}

// Variation signature: #2
