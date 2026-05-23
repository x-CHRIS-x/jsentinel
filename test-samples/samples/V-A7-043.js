/**
 * Test Vulnerable Sample 043 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dangerouslySetInnerHTML React properties (OWASP-A7-003)
function renderDynamicPost(contentStr) {
    return <div dangerouslySetInnerHTML={{ __html: contentStr }} />;
}

// Variation signature: #1
