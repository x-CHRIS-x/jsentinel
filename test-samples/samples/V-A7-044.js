/**
 * Test Vulnerable Sample 044 (A7)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: dangerouslySetInnerHTML React properties in article banner (OWASP-A7-003)
function renderArticleBanner(bannerHtml) {
    return <section dangerouslySetInnerHTML={{ __html: bannerHtml }} className="banner" />;
}

// Variation signature: #2
