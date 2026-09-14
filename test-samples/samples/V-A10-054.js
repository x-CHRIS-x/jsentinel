/**
 * Test Vulnerable Sample 054 (A10)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dynamic script inclusion from arbitrary user-controlled URL (CWE-829)
function loadExternalPlugin(untrustedScriptUrl) {
    const script = document.createElement("script");
    script.src = untrustedScriptUrl;
    document.head.appendChild(script);
}

// Variation signature: #2
