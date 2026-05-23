/**
 * Test Vulnerable Sample 044 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dangerouslySetInnerHTML React properties (OWASP-A7-003)
function renderDynamicPost(contentStr) {
    return <div dangerouslySetInnerHTML={{ __html: contentStr }} />;
}

// Variation signature: #2
