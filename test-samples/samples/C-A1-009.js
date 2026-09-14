/**
 * Test Clean Sample 009 (A1)
 * Safe, compliant implementations.
 */

// Helper returning plain text string from data source
function getCleanTextFromEndpoint(source) {
    return (source && source.textContent) || "Safe notification text";
}

// Clean: textContent assignment renders plain text without HTML interpretation
function updateContentSecure(container, apiSource) {
    container.textContent = getCleanTextFromEndpoint(apiSource);
}

// Variation signature: #1
