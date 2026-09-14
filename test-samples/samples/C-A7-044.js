/**
 * Test Clean Sample 044 (A7)
 * Safe, compliant implementations.
 */

// Clean: React element children safely interpolating text
function renderArticleBannerSecure(bannerText) {
    return <section className="banner">{bannerText}</section>;
}

// Variation signature: #2
