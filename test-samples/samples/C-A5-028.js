/**
 * Test Clean Sample 028 (A5)
 * Safe, compliant implementations.
 */

// Clean: domain allowlist verification before location.replace
const trustedPartnerDomains = ["https://partner.example.com", "https://auth.example.com"];
function navigateToPartnerSiteSecure(partnerUrl) {
    if (trustedPartnerDomains.includes(partnerUrl)) {
        window.location.replace(partnerUrl);
    }
}

// Variation signature: #2
