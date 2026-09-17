/**
 * Test Vulnerable Sample 010 (A1)
 * Demonstrates OWASP vulnerabilities.
 */

// Helper returning raw notification markup from external feed
function fetchNotificationMarkup(notificationFeed) {
    return (notificationFeed && notificationFeed.body) || "<b onmouseover=alert(1)>Notice</b>";
}

// Vulnerable: function return value assigned directly to innerHTML (OWASP-A1-005)
function displayNotificationBanner(bannerElement, feedSource) {
    bannerElement.innerHTML = fetchNotificationMarkup(feedSource);
}

// Variation signature: #2
