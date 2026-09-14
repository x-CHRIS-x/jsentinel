/**
 * Test Clean Sample 054 (A10)
 * Safe, compliant implementations.
 */

// Clean: dynamic script loaded only from trusted CDN with Subresource Integrity verification
const approvedPluginUrl = "https://cdn.verified.com/plugins/editor.v1.js";
function loadExternalPluginSecure() {
    const script = document.createElement("script");
    script.src = approvedPluginUrl;
    script.integrity = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";
    script.crossOrigin = "anonymous";
    document.head.appendChild(script);
}

// Variation signature: #2
