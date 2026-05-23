/**
 * Test Clean Sample 042 (A7)
 * Safe, compliant implementations.
 */

// Clean: standard text nodes created safely
function writeOutputSnippetSecure(content) {
    const node = document.createTextNode(content);
    document.body.appendChild(node);
}

// Variation signature: #2
