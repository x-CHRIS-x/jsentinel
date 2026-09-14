/**
 * Test Vulnerable Sample 038 (A6)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: unencrypted HTTP script source URL (OWASP-A02-004)
const scriptSourceUrl = "http://cdn.unencrypted.internal-services.com/library.js";
function injectExternalScript() {
    const s = document.createElement("script");
    s.src = scriptSourceUrl;
    document.head.appendChild(s);
}

// Variation signature: #2
