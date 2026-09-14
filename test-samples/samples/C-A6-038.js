/**
 * Test Clean Sample 038 (A6)
 * Safe, compliant implementations.
 */

// Clean: encrypted HTTPS script source URL
const scriptSourceUrlSecure = "https://cdn.encrypted.internal-services.com/library.js";
function injectExternalScriptSecure() {
    const s = document.createElement("script");
    s.src = scriptSourceUrlSecure;
    document.head.appendChild(s);
}

// Variation signature: #2
