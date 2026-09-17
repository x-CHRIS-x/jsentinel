/**
 * Test Clean Sample 010 (A1)
 * Safe, compliant implementations.
 */

// Helper returning plain text notification message
function fetchNotificationText(notificationFeed) {
    return (notificationFeed && notificationFeed.message) || "Standard notification";
}

// Clean: plain text notification assigned to textContent
function displayNotificationBannerSecure(bannerElement, feedSource) {
    bannerElement.textContent = fetchNotificationText(feedSource);
}

// Variation signature: #2
