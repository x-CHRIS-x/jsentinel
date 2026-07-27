/**
 * Test Clean Sample 010 (A1)
 * Safe, compliant implementations.
 */

// Clean: textContent assignment
function updateContentSecure(container, apiSource) {
    container.textContent = getCleanTextFromEndpoint(apiSource);
}

// Variation signature: #2
