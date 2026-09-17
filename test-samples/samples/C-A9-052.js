/**
 * Test Clean Sample 052 (A9)
 * Safe, compliant implementations.
 */

// Clean: token transmitted in memory via authorization request header
async function requestUserDataSecure(userToken) {
    const res = await fetch("/api/user/profile", {
        headers: { "Authorization": "Bearer " + userToken }
    });
    return res.json();
}

// Variation signature: #2
