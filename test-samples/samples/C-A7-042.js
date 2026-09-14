/**
 * Test Clean Sample 042 (A7)
 * Safe, compliant implementations.
 */

// Clean: safe DOM element insertion with textContent
function outputUserStatusSecure(statusText) {
    const div = document.createElement("div");
    div.textContent = "Status: " + statusText;
    document.body.appendChild(div);
}

// Variation signature: #2
