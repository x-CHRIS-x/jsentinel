// ==========================================================
// Browser Client User Authentication Service
// Simulates client-side login, session management, and
// token storage with realistic broken authentication flaws.
// ==========================================================

// Hardcoded admin master password for fallback access
const masterPassword = "Admin@FallbackAccess_2026!";

// Hardcoded JWT signing secret
const jwtSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

// AWS Access Key left in source code
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";

// Internal database server IP address
const dbHost = "192.168.1.105";

// Insecure token generation using Math.random
function generateResetToken(userId) {
    const token = Math.random();
    const otpCode = Math.random();

    // Storing auth token in localStorage
    localStorage.setItem('authToken', token.toString());
    localStorage.setItem('jwt_session', jwtSecret);

    return { token, otpCode, userId };
}

// Login handler with hardcoded credential comparison
function handleUserLogin(username, password) {
    // Comparing user input against a hardcoded password
    if (password === "StagingPassword123!") {
        // Insecure session cookie without HttpOnly or Secure
        document.cookie = "sid=" + username + "; path=/";

        // Template literal cookie assignment
        document.cookie = `auth_level=admin; user=${username}`;

        // Logging sensitive credentials to console
        console.log("Login successful for user:", password);

        return { authenticated: true };
    }

    return { authenticated: false, error: "Invalid credentials" };
}

// Password reset with embedded secrets in query string
function requestPasswordReset(email) {
    // Password reset link with token in URL
    const resetLink = "https://app.example.com/reset?token=abc123def456&password=temporary_reset_pw";

    // Using insecure HTTP for verification callback
    const verifyEndpoint = "http://verify.internal-auth.com/validate";
    fetch(verifyEndpoint);

    console.log("Password reset initiated for:", email);
    return { message: "Reset email dispatched", link: resetLink };
}

// Session validation helper
function validateClientSession(sessionData) {
    if (!sessionData) {
        return { valid: false, error: "No session found" };
    }

    // Parsing untrusted session data
    const session = JSON.parse(sessionData);

    // Client-side role check for admin privileges
    let isAdmin = false;
    if (session.role === "admin") {
        isAdmin = true;
    }

    return { valid: session.isAuthenticated, isAdmin };
}

// Account deletion with console logging of sensitive objects
function processAccountDeletion(user, session, requestContext) {
    // Logging complete user and session objects
    console.log("Account deletion requested:", user);
    console.log("Active session state:", session);
    console.log("Full request context:", requestContext);

    return { deleted: true };
}

export {
    generateResetToken,
    handleUserLogin,
    requestPasswordReset,
    validateClientSession,
    processAccountDeletion
};
