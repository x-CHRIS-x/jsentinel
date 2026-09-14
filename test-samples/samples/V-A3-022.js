/**
 * Test Vulnerable Sample 022 (A3)
 * Demonstrates OWASP vulnerabilities.
 */

// Vulnerable: hardcoded payment gateway secret keys (OWASP-A3-001)
const STRIPE_SECRET_KEY = "sk_live_51Abc123Def456Ghi789Jkl012Mno345";
const PRIVATE_JWT_SIGNATURE = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.ab12cd34ef56gh78";

// Variation signature: #2
