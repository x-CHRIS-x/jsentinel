/**
 * Test Vulnerable Sample 018 (A2)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: Math.random for security tokens (OWASP-A2-004)
function generateUserOtpSecret() {
    const otp = Math.random().toString().substring(2, 8);
    const otp_key = "secret_" + Math.random().toString(36);
    return { otp, otp_key };
}

// Variation signature: #2
