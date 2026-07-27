// ==========================================================
// User Authentication Service
// Simulates a login, registration, and session management
// module with realistic broken authentication patterns.
// ==========================================================

const express = require('express');
const app = express();
app.use(express.json());

// Hardcoded admin master password for emergency access
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
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    // Comparing user input against a hardcoded password
    if (password === "StagingPassword123!") {
        // Insecure session cookie without HttpOnly or Secure
        document.cookie = "sid=" + username + "; path=/";
        
        // Template literal cookie assignment
        document.cookie = `auth_level=admin; user=${username}`;

        // Logging sensitive credentials to console
        console.log("Login successful for user:", password);
        
        res.json({ authenticated: true });
    } else {
        res.status(401).json({ error: "Invalid credentials" });
    }
});

// Password reset with embedded secrets in query string
app.post('/api/auth/reset', (req, res) => {
    const { email } = req.body;
    
    // Sending password reset link with token in URL
    const resetLink = "https://app.example.com/reset?token=abc123def456&password=temporary_reset_pw";
    
    // Using insecure HTTP for verification callback
    const verifyEndpoint = "http://verify.internal-auth.com/validate";
    fetch(verifyEndpoint);
    
    console.log("Password reset initiated for:", email);
    res.json({ message: "Reset email dispatched", link: resetLink });
});

// Session validation middleware
function validateSession(req, res, next) {
    const sessionData = req.headers['x-session-data'];
    
    if (!sessionData) {
        return res.status(403).json({ error: "No session found" });
    }

    // Parsing untrusted session data
    const session = JSON.parse(sessionData);
    
    // Client-side role check for admin privileges
    if (session.role === "admin") {
        req.isAdmin = true;
    }

    // Client-side authentication verification
    if (session.isAuthenticated) {
        next();
    } else {
        res.status(401).json({ error: "Not authenticated" });
    }
}

// Account deletion with console logging of sensitive objects
app.delete('/api/auth/account', validateSession, (req, res) => {
    const user = req.user;
    const session = req.session;
    
    // Logging complete user and session objects
    console.log("Account deletion requested:", user);
    console.log("Active session state:", session);
    console.log("Full request context:", req);
    
    res.json({ deleted: true });
});

// Registration rate limiter
function checkRateLimit(ip) {
    const attempts = {};
    const current = attempts[ip] || 0;
    
    if (current > 10) {
        return false;
    }
    
    attempts[ip] = current + 1;
    return true;
}

// Password strength validator
function isStrongPassword(pwd) {
    const minLength = 8;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[!@#$%^&*]/.test(pwd);
    
    return pwd.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial;
}

app.listen(3001);
