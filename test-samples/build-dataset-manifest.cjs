/**
 * Dataset Manifest Builder (Phase 04 Batch B)
 * 
 * Generates test-samples/dataset-manifest.json covering all 116 dataset files:
 * - 108 controlled benchmark files (54 V, 54 C) marked 'controlled-reviewed' (or 'pilot-reviewed' for the 12 pilots)
 * - 8 simulated browser application scenarios marked 'pending-batch-c'
 */

const fs = require('fs');
const path = require('path');
const { scanCode } = require('../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../vscode-extension/src/scanner/rules.js');
const { controlledPairs, PILOT_FILES } = require('./generate-samples.cjs');

const samplesDir = path.join(__dirname, 'samples');
const manifestPath = path.join(__dirname, 'dataset-manifest.json');

// Metadata dictionary for all 54 pairs
const pairMetadata = {
  // A1
  '001': {
    pairId: 'PAIR-001-EVAL',
    primaryModule: 'injection.js',
    cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-001',
    severity: 'CRITICAL',
    vDesc: 'Executes dynamic string concatenation directly via eval().',
    cDesc: 'Safely parses JSON without code execution.',
    trustBoundary: 'Untrusted user input string passed directly into execution context.',
    attackerInput: 'String containing arbitrary JavaScript statements concatenated into eval() argument.',
    execEnv: 'Browser JavaScript execution context.',
    impact: 'CRITICAL: Arbitrary code execution in client session (XSS / DOM execution).',
    safePartner: 'Parses input with JSON.parse() and validates structure without executing code.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval'
    ],
    vLimitation: null,
    cLimitation: 'Known scanner limitation: scanner rule OWASP-A08-001 emits false positive on benign JSON.parse() calls.'
  },
  '002': {
    pairId: 'PAIR-002-EVAL-CALC',
    primaryModule: 'injection.js',
    cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-001',
    severity: 'CRITICAL',
    vDesc: 'Dynamically calculates user formula string via eval().',
    cDesc: 'Calculates numeric values via tokenized arithmetic evaluation.',
    trustBoundary: 'User-provided mathematical formula string.',
    attackerInput: 'Formula string containing breakout payload (e.g. 1; alert(1)).',
    execEnv: 'Browser JavaScript arithmetic calculation routine.',
    impact: 'CRITICAL: Arbitrary JavaScript execution via arithmetic expression breakout.',
    safePartner: 'Coerces arguments to safe numbers and performs standard arithmetic operations.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '003': {
    pairId: 'PAIR-003-SETTIMEOUT',
    primaryModule: 'injection.js',
    cwe: 'CWE-95: Eval Injection (Dynamic Timer Evaluation)',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-002',
    severity: 'HIGH',
    vDesc: 'Passes dynamic string to setTimeout, triggering implicit code evaluation.',
    cDesc: 'Passes a direct function reference to setTimeout.',
    trustBoundary: 'Dynamic callback string identifier.',
    attackerInput: 'Callback string containing executable code (e.g. alert(1)).',
    execEnv: 'Browser timer loop.',
    impact: 'HIGH: Implicit code evaluation executes attacker payload after delay.',
    safePartner: 'Validates that task argument is a function reference and invokes it directly.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/setTimeout'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '004': {
    pairId: 'PAIR-004-SETINTERVAL',
    primaryModule: 'injection.js',
    cwe: 'CWE-95: Eval Injection (Dynamic Timer Evaluation)',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-002',
    severity: 'HIGH',
    vDesc: 'Passes dynamic string concatenation to setInterval.',
    cDesc: 'Passes an arrow function closure to setInterval.',
    trustBoundary: 'Dynamic polling action string argument.',
    attackerInput: 'Action code string containing script injection payload.',
    execEnv: 'Browser recurring interval timer.',
    impact: 'HIGH: Recurring implicit code evaluation executing attacker payload.',
    safePartner: 'Passes an anonymous arrow function invoking the callback function safely.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/setInterval'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '005': {
    pairId: 'PAIR-005-FUNCTION-CONSTRUCTOR',
    primaryModule: 'injection.js',
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-003',
    severity: 'CRITICAL',
    vDesc: 'Compiles dynamic formula string into executable code using new Function().',
    cDesc: 'Uses a predefined operator lookup table instead of compiling code.',
    trustBoundary: 'Dynamic formula string parameter.',
    attackerInput: 'Arbitrary function body payload executing in global scope.',
    execEnv: 'Browser Function constructor compilation.',
    impact: 'CRITICAL: Dynamic function construction allows arbitrary code execution in global context.',
    safePartner: 'Resolves operation name from an object dictionary of approved mathematical functions.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '006': {
    pairId: 'PAIR-006-FUNCTION-FILTER',
    primaryModule: 'injection.js',
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-003',
    severity: 'CRITICAL',
    vDesc: 'Compiles dynamic array filter predicate via new Function().',
    cDesc: 'Uses parameterized array filtering with callback function.',
    trustBoundary: 'Dynamic filter predicate string.',
    attackerInput: 'Filter predicate string containing malicious statements.',
    execEnv: 'Browser array filtering loop.',
    impact: 'CRITICAL: Arbitrary code execution during array element evaluation.',
    safePartner: 'Uses standard parameterized comparison logic without compiling code.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/95.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '007': {
    pairId: 'PAIR-007-TEMPLATE-HTML',
    primaryModule: 'injection.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-004',
    severity: 'HIGH',
    vDesc: 'Assigns template literal containing interpolated username directly to innerHTML.',
    cDesc: 'Assigns greeting string to textContent, ensuring character-data rendering.',
    trustBoundary: 'Username string from external user profile input.',
    attackerInput: 'Username string containing markup tags and event handlers (<img src=x onerror=alert(1)>).',
    execEnv: 'Browser DOM content rendering.',
    impact: 'HIGH: Embedded markup in template literal executes event handlers in victim session.',
    safePartner: 'Assigns string to textContent, rendering values as plain text without HTML parsing.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent',
      'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML',
      'https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '008': {
    pairId: 'PAIR-008-TEMPLATE-PROFILE',
    primaryModule: 'injection.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-004',
    severity: 'HIGH',
    vDesc: 'Assigns template literal containing user bio text directly to innerHTML.',
    cDesc: 'Creates DOM element and assigns bio text to textContent.',
    trustBoundary: 'User bio string parameter.',
    attackerInput: 'Bio text containing malicious HTML tags and scripts.',
    execEnv: 'Browser profile rendering area.',
    impact: 'HIGH: Stored or reflected XSS via unneutralized markup interpolation in innerHTML.',
    safePartner: 'Creates span element and assigns bio text to textContent, avoiding HTML parser.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '009': {
    pairId: 'PAIR-009-FUNCTION-RESULT-HTML',
    primaryModule: 'injection.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-005',
    severity: 'HIGH',
    vDesc: 'Assigns return value of external endpoint helper directly to innerHTML.',
    cDesc: 'Assigns return value of clean text helper to textContent.',
    trustBoundary: 'External endpoint data source parameter.',
    attackerInput: 'Helper function returns markup payload with event handler semantics.',
    execEnv: 'Browser DOM update cycle.',
    impact: 'HIGH: External endpoint markup execution via innerHTML assignment.',
    safePartner: 'Retrieves text via getCleanTextFromEndpoint and assigns to textContent.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent',
      'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML',
      'https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '010': {
    pairId: 'PAIR-010-FUNCTION-RESULT-BANNER',
    primaryModule: 'injection.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-005',
    severity: 'HIGH',
    vDesc: 'Assigns return value of notification markup helper to innerHTML.',
    cDesc: 'Assigns return value of notification text helper to textContent.',
    trustBoundary: 'Notification feed data source.',
    attackerInput: 'Notification feed body containing event-handler markup (<b onmouseover=alert(1)>).',
    execEnv: 'Browser notification banner DOM element.',
    impact: 'HIGH: DOM XSS via unneutralized notification feed markup assigned to innerHTML.',
    safePartner: 'Extracts message property and assigns to textContent for safe text display.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A2
  '011': {
    pairId: 'PAIR-011-HARDCODED-PASSWORD',
    primaryModule: 'auth.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-001',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded admin fallback password string in client source code.',
    cDesc: 'Authenticates password via server-side verification endpoint.',
    trustBoundary: 'Client application bundle inspection boundary.',
    attackerInput: 'Reverse engineering or source inspection of client bundle.',
    execEnv: 'Client-side script verification.',
    impact: 'CRITICAL: Static credential extraction granting unauthorized administrative access.',
    safePartner: 'Submits credentials to server API route; password verified server-side.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '012': {
    pairId: 'PAIR-012-RECOVERY-KEY',
    primaryModule: 'auth.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-001',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded emergency recovery auth key in client script.',
    cDesc: 'Delegates emergency access verification to secure server challenge.',
    trustBoundary: 'Client-side bundle inspection.',
    attackerInput: 'Inspection of client script containing static recovery key.',
    execEnv: 'Client recovery access routine.',
    impact: 'CRITICAL: Bypasses authentication challenge using embedded recovery key.',
    safePartner: 'Challenges are submitted to server; secret keys are never distributed to client.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '013': {
    pairId: 'PAIR-013-LOCALSTORAGE-TOKEN',
    primaryModule: 'auth.js',
    cwe: 'CWE-922: Insecure Storage of Sensitive Information',
    owasp: 'A07:2021-Identification and Authentication Failures',
    ruleId: 'OWASP-A07-001',
    severity: 'HIGH',
    vDesc: 'Stores sensitive JWT session token in unencrypted localStorage.',
    cDesc: 'Stores transient session token in module-scoped memory closure.',
    trustBoundary: 'Client Web Storage accessible to any script executing on same origin.',
    attackerInput: 'Any cross-site script injection or third-party script on origin.',
    execEnv: 'Browser localStorage storage area.',
    impact: 'HIGH: Any script executing on origin can read and exfiltrate persistent session token.',
    safePartner: 'Retains token in transient memory closure; token is not written to disk or web storage.',
    refs: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://cwe.mitre.org/data/definitions/922.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '014': {
    pairId: 'PAIR-014-LOCALSTORAGE-CREDENTIAL',
    primaryModule: 'auth.js',
    cwe: 'CWE-922: Insecure Storage of Sensitive Information',
    owasp: 'A07:2021-Identification and Authentication Failures',
    ruleId: 'OWASP-A07-001',
    severity: 'HIGH',
    vDesc: 'Stores authentication credential token in localStorage.',
    cDesc: 'Session managed via server-issued session cookie without client storage.',
    trustBoundary: 'Client Web Storage persistent data boundary.',
    attackerInput: 'Malicious third-party library or XSS on origin reading localStorage.',
    execEnv: 'Browser localStorage API.',
    impact: 'HIGH: Credential exposure to unauthorized scripts on same origin.',
    safePartner: 'Delegates session authentication to HTTP API; avoids client-side token storage.',
    refs: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://cwe.mitre.org/data/definitions/922.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '015': {
    pairId: 'PAIR-015-INSECURE-COOKIE',
    primaryModule: 'auth.js',
    cwe: "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-002',
    severity: 'MEDIUM',
    vDesc: 'Writes session cookie via document.cookie without Secure or HttpOnly protection.',
    cDesc: 'Delegates session cookie creation to backend server Set-Cookie response header.',
    trustBoundary: 'Network transport and client script cookie boundary.',
    attackerInput: 'Man-in-the-middle network interception or client script reading document.cookie.',
    execEnv: 'Browser document.cookie DOM API.',
    impact: 'MEDIUM: Unencrypted transmission and client-side cookie theft.',
    safePartner: 'Server issues HttpOnly, Secure session cookie via HTTP response headers per RFC 6265.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/614.html',
      'https://datatracker.ietf.org/doc/html/rfc6265#section-5.3',
      'https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '016': {
    pairId: 'PAIR-016-COOKIE-PREFERENCE',
    primaryModule: 'auth.js',
    cwe: "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-002',
    severity: 'MEDIUM',
    vDesc: 'Writes auth token directly to document.cookie without Secure attribute.',
    cDesc: 'Writes non-sensitive UI preference cookie with Secure and SameSite attributes.',
    trustBoundary: 'Client-side cookie storage model.',
    attackerInput: 'Unencrypted cleartext network transmission.',
    execEnv: 'Browser document.cookie interface.',
    impact: 'MEDIUM: Insecure cleartext transmission of cookie data.',
    safePartner: 'Stores non-sensitive UI preference using Secure and SameSite; does not attempt invalid JS HttpOnly write.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/614.html',
      'https://datatracker.ietf.org/doc/html/rfc6265#section-5.3'
    ],
    vLimitation: null,
    cLimitation: 'Known scanner false positive: scanner rule OWASP-A02-002 flags document.cookie whenever httponly substring is absent, even though JS cannot set HttpOnly cookies per RFC 6265 Section 5.3 Step 10.'
  },
  '017': {
    pairId: 'PAIR-017-INSECURE-RANDOM',
    primaryModule: 'auth.js',
    cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-003',
    severity: 'HIGH',
    vDesc: 'Uses Math.random() to generate one-time password (OTP) secrets and keys.',
    cDesc: 'Uses Web Crypto API crypto.getRandomValues() for cryptographic random numbers.',
    trustBoundary: 'PRNG state predictability boundary.',
    attackerInput: 'Observing sequence of generated random values to predict internal PRNG state.',
    execEnv: 'Browser JavaScript runtime V8 PRNG.',
    impact: 'HIGH: Attackers can predict future OTP secrets, enabling session hijack or MFA bypass.',
    safePartner: 'Uses crypto.getRandomValues() backed by OS-level entropy pool.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/338.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '018': {
    pairId: 'PAIR-018-RANDOM-NONCE',
    primaryModule: 'auth.js',
    cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-003',
    severity: 'HIGH',
    vDesc: 'Uses Math.random() to generate CSRF nonce and session tokens.',
    cDesc: 'Uses crypto.randomUUID() to generate standard cryptographic UUIDv4 nonces.',
    trustBoundary: 'CSRF token uniqueness and unpredictability.',
    attackerInput: 'Predicting sequence of Math.random nonces to forge CSRF requests.',
    execEnv: 'Browser security token generation routine.',
    impact: 'HIGH: CSRF token forgery leading to unauthorized state-changing operations.',
    safePartner: 'Generates UUIDv4 using standard Web Crypto API crypto.randomUUID().',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/338.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Crypto/randomUUID'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A02-003 inspects variable names matching token/secret/password, missing nonceVal identifier.',
    cLimitation: null
  },
  '019': {
    pairId: 'PAIR-019-PLAINTEXT-HTTP',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-004',
    severity: 'MEDIUM',
    vDesc: 'Communicates with authentication API over unencrypted HTTP URL.',
    cDesc: 'Communicates with authentication API over encrypted HTTPS protocol.',
    trustBoundary: 'Network wire boundary between browser and backend API.',
    attackerInput: 'Eavesdropping on local network, Wi-Fi, or upstream network routes.',
    execEnv: 'Browser Fetch API network transport.',
    impact: 'MEDIUM: Cleartext interception of credentials, session cookies, and payloads.',
    safePartner: 'Enforces HTTPS protocol for all endpoint communications.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/319.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '020': {
    pairId: 'PAIR-020-TELEMETRY-HTTP',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-004',
    severity: 'MEDIUM',
    vDesc: 'Sends telemetry event payloads over unencrypted HTTP connection.',
    cDesc: 'Sends telemetry event payloads over encrypted HTTPS connection.',
    trustBoundary: 'Network transit path.',
    attackerInput: 'Network traffic inspection and packet sniffing.',
    execEnv: 'Browser Fetch API.',
    impact: 'MEDIUM: Exposure of user activity events and internal telemetry.',
    safePartner: 'Configures telemetry endpoint with HTTPS scheme.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/319.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A3
  '021': {
    pairId: 'PAIR-021-STATIC-JWT',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-005',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded AWS access secret and static JWT token signatures embedded in client code.',
    cDesc: 'Upload operations dispatched through authenticated backend endpoint without client keys.',
    trustBoundary: 'Client code bundle distribution boundary.',
    attackerInput: 'Inspection of downloaded client bundle.',
    execEnv: 'Browser static script asset.',
    impact: 'CRITICAL: Unauthorized access to cloud storage infrastructure and JWT forgery.',
    safePartner: 'Uploads to backend API endpoint; AWS credentials remain secured on server.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '022': {
    pairId: 'PAIR-022-PAYMENT-SECRET',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-005',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded Stripe secret key and private JWT signature token in client script.',
    cDesc: 'Payment intent created on server; client receives only transient intent token.',
    trustBoundary: 'Client asset distribution.',
    attackerInput: 'Source inspection of client bundle.',
    execEnv: 'Browser payment processing script.',
    impact: 'CRITICAL: Full compromise of payment gateway account and ability to perform unauthorized charges/refunds.',
    safePartner: 'Creates payment intents on server; client code never handles secret keys.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '023': {
    pairId: 'PAIR-023-API-SECRETS',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-006',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded application secret key and gateway token in client code.',
    cDesc: 'API requests dispatched through backend proxy route without client-exposed secrets.',
    trustBoundary: 'Client application distribution boundary.',
    attackerInput: 'Static code inspection of client bundle.',
    execEnv: 'Browser client API caller.',
    impact: 'CRITICAL: Direct credential extraction permitting unauthorized gateway operations.',
    safePartner: 'Calls internal backend proxy route (/api/gateway/dispatch), keeping secrets on server.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '024': {
    pairId: 'PAIR-024-DATABASE-KEY',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-006',
    severity: 'CRITICAL',
    vDesc: 'Hardcoded database API key and webhook secret in client script.',
    cDesc: 'Database operations proxied through secure backend API route.',
    trustBoundary: 'Client bundle inspection.',
    attackerInput: 'Extracting API keys from client-side script files.',
    execEnv: 'Browser database client.',
    impact: 'CRITICAL: Direct database access or webhook forging using leaked keys.',
    safePartner: 'Client dispatches queries to backend API route; server handles database credentials.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/798.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '025': {
    pairId: 'PAIR-025-URL-CREDENTIALS',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-598: Use of GET Request Method With Sensitive Query Strings',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-007',
    severity: 'MEDIUM',
    vDesc: 'Transmits username and password credentials in GET query URL string.',
    cDesc: 'Submits login credentials in encrypted HTTPS POST request body.',
    trustBoundary: 'URL visibility boundary (browser history, server access logs, Referer headers).',
    attackerInput: 'Accessing browser history, proxy logs, or Referer header downstream.',
    execEnv: 'Browser URL navigation and network stack.',
    impact: 'MEDIUM: Credentials leaked to access logs, browser history, and third-party referrers.',
    safePartner: 'Transmits credentials in JSON body of POST request over HTTPS.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/598.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '026': {
    pairId: 'PAIR-026-URL-RESET-TOKEN',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-598: Use of GET Request Method With Sensitive Query Strings',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-007',
    severity: 'MEDIUM',
    vDesc: 'Transmits password reset token in GET query URL parameters.',
    cDesc: 'Submits password reset token in secure POST request body.',
    trustBoundary: 'URL string exposure boundary.',
    attackerInput: 'Inspecting browser history or server access log files.',
    execEnv: 'Browser URL construction.',
    impact: 'MEDIUM: Account takeover via reset token leakage in URL query parameters.',
    safePartner: 'Sends reset token in POST body payload to authentication endpoint.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/598.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A5
  '027': {
    pairId: 'PAIR-027-REDIRECT',
    primaryModule: 'accessControl.js',
    cwe: "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-001',
    severity: 'HIGH',
    vDesc: 'Assigns unvalidated target URL directly to window.location.href.',
    cDesc: 'Validates target URL against allowlist of approved domains before redirecting.',
    trustBoundary: 'External user-controlled URL input parameter.',
    attackerInput: 'Malicious external phishing URL provided as navigation target.',
    execEnv: 'Browser window navigation.',
    impact: 'HIGH: Open redirect facilitating credential harvesting and phishing attacks.',
    safePartner: 'Enforces allowlist check against allowedDomains before updating location.href.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/601.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Window/location'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '028': {
    pairId: 'PAIR-028-REDIRECT-REPLACE',
    primaryModule: 'accessControl.js',
    cwe: "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-001',
    severity: 'HIGH',
    vDesc: 'Navigates to unvalidated partner URL using window.location.replace.',
    cDesc: 'Verifies partner URL against domain allowlist before calling location.replace.',
    trustBoundary: 'External redirect path parameter.',
    attackerInput: 'Malicious domain URL passed to navigation function.',
    execEnv: 'Browser window navigation history replace.',
    impact: 'HIGH: Open redirection without history trace to malicious site.',
    safePartner: 'Validates destination domain against trustedPartnerDomains allowlist.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/601.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '029': {
    pairId: 'PAIR-029-CLIENT-ROLE',
    primaryModule: 'accessControl.js',
    cwe: 'CWE-602: Client-Side Enforcement of Server-Side Security',
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-002',
    severity: 'MEDIUM',
    vDesc: 'Guards administrative component rendering using client-side role check.',
    cDesc: 'Requests authorized component permissions from server API.',
    trustBoundary: 'Client-side JavaScript state vs server authorization boundary.',
    attackerInput: 'Tampering with client-side userContext object properties in DevTools.',
    execEnv: 'Browser UI rendering logic.',
    impact: 'MEDIUM: Unauthorized UI component rendering and administrative interface exposure.',
    safePartner: 'Fetches authorized components from server API; server enforces access control.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/602.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '030': {
    pairId: 'PAIR-030-CLIENT-PERMISSION',
    primaryModule: 'accessControl.js',
    cwe: 'CWE-602: Client-Side Enforcement of Server-Side Security',
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-002',
    severity: 'MEDIUM',
    vDesc: 'Guards destructive system purge operation using client-side permission flag.',
    cDesc: 'Executes purge operation via server API endpoint validating session permissions.',
    trustBoundary: 'Client-side permission check.',
    attackerInput: 'Overriding client-side permission property (userState.hasPurgePermission = true).',
    execEnv: 'Browser admin action trigger.',
    impact: 'MEDIUM: Unauthorized triggering of destructive system operations.',
    safePartner: 'Dispatches request to server endpoint; server verifies session authorization.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/602.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A6
  '031': {
    pairId: 'PAIR-031-CONSOLE-PASSWORD',
    primaryModule: 'misconfig.js',
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    owasp: 'A05:2021-Security Misconfiguration',
    ruleId: 'OWASP-A05-001',
    severity: 'MEDIUM',
    vDesc: 'Prints user password string directly to browser console log.',
    cDesc: 'Logs benign user identifier without sensitive password credential.',
    trustBoundary: 'Browser developer console and diagnostic log export boundary.',
    attackerInput: 'Inspecting browser console output or harvesting log exports.',
    execEnv: 'Browser console logging facility.',
    impact: 'MEDIUM: Plaintext password exposure in console logs and error monitoring services.',
    safePartner: 'Logs user identity only, never logging passwords or credentials.',
    refs: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://cwe.mitre.org/data/definitions/532.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/console'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '032': {
    pairId: 'PAIR-032-CONSOLE-SECRET',
    primaryModule: 'misconfig.js',
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    owasp: 'A05:2021-Security Misconfiguration',
    ruleId: 'OWASP-A05-001',
    severity: 'MEDIUM',
    vDesc: 'Prints authentication secret key string to browser console warning.',
    cDesc: 'Logs non-sensitive session confirmation message.',
    trustBoundary: 'Browser diagnostic logging.',
    attackerInput: 'Inspecting console log streams in shared or monitored environments.',
    execEnv: 'Browser console warning output.',
    impact: 'MEDIUM: Credential leakage in diagnostic logs.',
    safePartner: 'Logs session status without printing secret key values.',
    refs: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://cwe.mitre.org/data/definitions/532.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '033': {
    pairId: 'PAIR-033-POSTMESSAGE-WILDCARD',
    primaryModule: 'accessControl.js',
    cwe: 'CWE-345: Insufficient Verification of Data Authenticity (Wildcard Target Origin)',
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-001',
    severity: 'HIGH',
    vDesc: 'Transmits sensitive authentication token via window.postMessage with wildcard * target origin.',
    cDesc: 'Transmits authentication token with strict target origin restriction.',
    trustBoundary: 'Cross-origin window messaging boundary.',
    attackerInput: 'Malicious framing window intercepting wildcard postMessage.',
    execEnv: 'Browser cross-window communication.',
    impact: 'HIGH: Sensitive session token leaked to arbitrary third-party embedding frames.',
    safePartner: 'Specifies exact trusted target origin domain in postMessage call.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/345.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage'
    ],
    vLimitation: 'Known scanner miss: JSentinel does not currently implement a dedicated postMessage targetOrigin check.',
    cLimitation: null
  },
  '034': {
    pairId: 'PAIR-034-POSTMESSAGE-INBOUND',
    primaryModule: 'injection.js',
    cwe: 'CWE-346: Origin Validation Error in Message Event Listener',
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A03-001',
    severity: 'CRITICAL',
    vDesc: 'Listens for cross-window messages and executes event data command using eval() without origin validation.',
    cDesc: 'Validates event.origin against allowlist and executes structured actions without eval().',
    trustBoundary: 'Cross-origin inbound message event boundary.',
    attackerInput: 'Any external web page sending postMessage to current window.',
    execEnv: 'Browser message event listener.',
    impact: 'CRITICAL: Arbitrary script execution triggered by external cross-origin web pages.',
    safePartner: 'Validates event.origin against trustedOrigins and handles only structured safe actions.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/346.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '035': {
    pairId: 'PAIR-035-CONSOLE-REQUEST-OBJECT',
    primaryModule: 'misconfig.js',
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    owasp: 'A05:2021-Security Misconfiguration',
    ruleId: 'OWASP-A05-003',
    severity: 'MEDIUM',
    vDesc: 'Prints full request object containing sensitive headers and parameters to console log.',
    cDesc: 'Logs only specific non-sensitive request path string.',
    trustBoundary: 'Console diagnostic output.',
    attackerInput: 'Inspecting console log outputs.',
    execEnv: 'Browser console logging.',
    impact: 'MEDIUM: Unintentional exposure of session cookies, auth headers, and body tokens.',
    safePartner: 'Logs only explicit non-sensitive property (req.path).',
    refs: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://cwe.mitre.org/data/definitions/532.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '036': {
    pairId: 'PAIR-036-CONSOLE-AUTH-CONTEXT',
    primaryModule: 'misconfig.js',
    cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
    owasp: 'A05:2021-Security Misconfiguration',
    ruleId: 'OWASP-A05-003',
    severity: 'MEDIUM',
    vDesc: 'Prints full user authentication context object to console error output.',
    cDesc: 'Logs only non-sensitive error status code.',
    trustBoundary: 'Browser diagnostic error logging.',
    attackerInput: 'Error telemetry and console inspection.',
    execEnv: 'Browser console.error().',
    impact: 'MEDIUM: Full credential and user context leakage in error log outputs.',
    safePartner: 'Logs only non-sensitive numeric status code.',
    refs: [
      'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      'https://cwe.mitre.org/data/definitions/532.html'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A05-003 checks req/session variables, missing authContext parameter.',
    cLimitation: null
  },
  '037': {
    pairId: 'PAIR-037-UNENCRYPTED-WEBSOCKET',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-004',
    severity: 'MEDIUM',
    vDesc: 'Connects to WebSocket telemetry service over unencrypted ws:// protocol.',
    cDesc: 'Connects to WebSocket telemetry service over encrypted wss:// protocol.',
    trustBoundary: 'WebSocket network transport layer.',
    attackerInput: 'Network traffic interception on local or transit network.',
    execEnv: 'Browser WebSocket API.',
    impact: 'MEDIUM: Cleartext WebSocket traffic interception and token hijacking.',
    safePartner: 'Enforces encrypted wss:// WebSocket protocol.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/319.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/WebSocket'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A02-004 checks http:// URL strings, missing ws:// protocol schemes.',
    cLimitation: null
  },
  '038': {
    pairId: 'PAIR-038-UNENCRYPTED-SCRIPT',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-004',
    severity: 'MEDIUM',
    vDesc: 'Injects external script using unencrypted http:// URL source.',
    cDesc: 'Injects external script using encrypted https:// URL source.',
    trustBoundary: 'Script resource loading boundary (Mixed Content / MitM).',
    attackerInput: 'Network man-in-the-middle tampering with script response over HTTP.',
    execEnv: 'Browser DOM script element execution.',
    impact: 'MEDIUM: Arbitrary script injection via cleartext network script tampering.',
    safePartner: 'Loads external script assets exclusively over HTTPS.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/319.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A7
  '039': {
    pairId: 'PAIR-039-GENERAL-HTML',
    primaryModule: 'xss.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-006',
    severity: 'HIGH',
    vDesc: 'Assigns badge HTML markup directly to element.innerHTML.',
    cDesc: 'Assigns badge string to element.textContent.',
    trustBoundary: 'User-provided badge markup parameter.',
    attackerInput: 'Badge HTML string containing malicious script tags or event handlers.',
    execEnv: 'Browser DOM innerHTML parsing.',
    impact: 'HIGH: Direct DOM XSS via unneutralized markup assignment.',
    safePartner: 'Assigns badge string to textContent, rendering as plain text character data.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent',
      'https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML',
      'https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '040': {
    pairId: 'PAIR-040-USER-COMMENT-HTML',
    primaryModule: 'xss.js',
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-006',
    severity: 'HIGH',
    vDesc: 'Assigns user comment markup string directly to container.innerHTML.',
    cDesc: 'Creates safe paragraph element and assigns comment text to textContent.',
    trustBoundary: 'User comment text parameter.',
    attackerInput: 'Comment text containing HTML injection payloads.',
    execEnv: 'Browser comment rendering DOM container.',
    impact: 'HIGH: Stored or reflected XSS via innerHTML assignment.',
    safePartner: 'Creates DOM node with createElement and sets textContent, avoiding HTML parser.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-element-innerhtml',
      'https://dom.spec.whatwg.org/#dom-node-textcontent'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '041': {
    pairId: 'PAIR-041-DOCUMENT-WRITE',
    primaryModule: 'xss.js',
    cwe: 'CWE-79: Cross-site Scripting via DOM Write',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-007',
    severity: 'CRITICAL',
    vDesc: 'Writes untrusted content string directly to document via document.write().',
    cDesc: 'Creates safe text node via document.createTextNode() and appends to document body.',
    trustBoundary: 'Dynamic content string parameter.',
    attackerInput: 'Content string containing HTML markup and scripts.',
    execEnv: 'Browser document stream write.',
    impact: 'CRITICAL: Direct DOM injection during document loading or execution.',
    safePartner: 'Creates text node using createTextNode, ensuring character data rendering.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Document/write'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '042': {
    pairId: 'PAIR-042-DOCUMENT-WRITELN',
    primaryModule: 'xss.js',
    cwe: 'CWE-79: Cross-site Scripting via DOM Write',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-007',
    severity: 'CRITICAL',
    vDesc: 'Writes user status markup to document via document.writeln().',
    cDesc: 'Creates safe div element and assigns status text to textContent.',
    trustBoundary: 'User status text parameter.',
    attackerInput: 'Status text containing script injection payload.',
    execEnv: 'Browser document stream write.',
    impact: 'CRITICAL: Direct script injection into document DOM stream.',
    safePartner: 'Creates DOM element and assigns to textContent.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A03-007 checks document.write, missing document.writeln calls.',
    cLimitation: null
  },
  '043': {
    pairId: 'PAIR-043-REACT-DANGEROUSLY',
    primaryModule: 'xss.js',
    cwe: 'CWE-79: Cross-site Scripting in React Framework',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-008',
    severity: 'HIGH',
    vDesc: 'Renders dynamic post content via React dangerouslySetInnerHTML property.',
    cDesc: 'Renders post content via standard React JSX text interpolation.',
    trustBoundary: 'Dynamic post content string.',
    attackerInput: 'Post content containing malicious HTML markup and script tags.',
    execEnv: 'React virtual DOM reconciliation and DOM mount.',
    impact: 'HIGH: React XSS bypass via raw HTML injection.',
    safePartner: 'Uses standard React JSX children interpolation {contentStr}, which automatically escapes HTML entities.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html',
      'https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '044': {
    pairId: 'PAIR-044-REACT-BANNER',
    primaryModule: 'xss.js',
    cwe: 'CWE-79: Cross-site Scripting in React Framework',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-008',
    severity: 'HIGH',
    vDesc: 'Renders article banner using React dangerouslySetInnerHTML.',
    cDesc: 'Renders article banner using standard React JSX text children.',
    trustBoundary: 'Article banner markup string.',
    attackerInput: 'Banner markup containing embedded script injection payloads.',
    execEnv: 'React component render phase.',
    impact: 'HIGH: DOM XSS via raw HTML injection in React section.',
    safePartner: 'Renders banner as text child within React section component.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/79.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A8
  '045': {
    pairId: 'PAIR-045-JSON-PARSE',
    primaryModule: 'deserialization.js',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-001',
    severity: 'LOW',
    vDesc: 'Parses untrusted JSON input string without schema verification.',
    cDesc: 'Parses JSON and verifies structural schema before processing.',
    trustBoundary: 'External serialized JSON payload string.',
    attackerInput: 'Malformed or hostile JSON payload with unexpected properties.',
    execEnv: 'Browser JSON parser.',
    impact: 'LOW: Insecure deserialization and unexpected application state injection.',
    safePartner: 'Validates parsed JSON against strict schema specification.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/502.html'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '046': {
    pairId: 'PAIR-046-JSON-PREFERENCES',
    primaryModule: 'deserialization.js',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-001',
    severity: 'LOW',
    vDesc: 'Parses user configuration JSON without property type validation.',
    cDesc: 'Parses JSON followed by explicit primitive property type validation.',
    trustBoundary: 'User settings JSON string parameter.',
    attackerInput: 'JSON string containing unexpected prototype properties or invalid types.',
    execEnv: 'Browser preferences parser.',
    impact: 'LOW: State confusion and unexpected type injection in client configuration.',
    safePartner: 'Explicitly picks and validates theme (string) and fontSize (number) fields.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/502.html'
    ],
    vLimitation: null,
    cLimitation: 'Known scanner limitation: scanner rule OWASP-A08-001 emits false positive on benign JSON.parse() calls.'
  },
  '047': {
    pairId: 'PAIR-047-PROTO-PROPERTY',
    primaryModule: 'deserialization.js',
    cwe: "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Prototype Pollution')",
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-002',
    severity: 'HIGH',
    vDesc: 'Directly modifies target.__proto__ using unvalidated customKey and value.',
    cDesc: 'Uses Object.create(null) to create a dictionary with no prototype chain.',
    trustBoundary: 'Dynamic property key parameter.',
    attackerInput: 'Property key string modifying shared Object.prototype properties.',
    execEnv: 'Browser JavaScript object prototype chain.',
    impact: 'HIGH: Prototype pollution altering inherited object behavior across the runtime.',
    safePartner: 'Creates target object using Object.create(null), eliminating __proto__ accessor.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/1321.html',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/create'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '048': {
    pairId: 'PAIR-048-CONSTRUCTOR-PROTO',
    primaryModule: 'deserialization.js',
    cwe: "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Prototype Pollution')",
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-002',
    severity: 'HIGH',
    vDesc: 'Modifies targetObj.constructor.prototype using dynamic property name.',
    cDesc: 'Uses Map data structure to store key-value mappings safely.',
    trustBoundary: 'Dynamic object attribute name parameter.',
    attackerInput: 'PropName targeting constructor prototype properties.',
    execEnv: 'Browser object constructor prototype.',
    impact: 'HIGH: Prototype pollution corrupting all instances sharing the constructor prototype.',
    safePartner: 'Uses JavaScript Map data structure, which isolates keys from prototype chain.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/1321.html',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Map'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '049': {
    pairId: 'PAIR-049-OBJECT-MERGE',
    primaryModule: 'deserialization.js',
    cwe: "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Prototype Pollution')",
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-003',
    severity: 'MEDIUM',
    vDesc: 'Directly merges untrusted user payload into defaultConfig target via Object.assign.',
    cDesc: 'Filters __proto__, constructor, and prototype properties and merges into fresh object {}.',
    trustBoundary: 'Untrusted user payload object parameter.',
    attackerInput: 'JSON-parsed object with own __proto__ property modifying Object.prototype.',
    execEnv: 'Browser configuration merge routine.',
    impact: 'MEDIUM: In-place target mutation and prototype pollution via Object.assign.',
    safePartner: 'Sanitizes properties stripping prototype keys and merges into a fresh empty object {}.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/1321.html',
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign'
    ],
    vLimitation: null,
    cLimitation: null
  },
  '050': {
    pairId: 'PAIR-050-OBJECT-ASSIGN-SETTINGS',
    primaryModule: 'deserialization.js',
    cwe: "CWE-1321: Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Prototype Pollution')",
    owasp: 'A08:2021-Software and Data Integrity Failures',
    ruleId: 'OWASP-A08-003',
    severity: 'MEDIUM',
    vDesc: 'Merges untrusted user options directly into baseSettings via Object.assign.',
    cDesc: 'Uses explicit property picking allowlist before merging configuration.',
    trustBoundary: 'Untrusted options object parameter.',
    attackerInput: 'Options object containing hostile prototype keys.',
    execEnv: 'Browser settings manager.',
    impact: 'MEDIUM: Target object corruption and potential prototype pollution.',
    safePartner: 'Picks only explicitly allowed keys (theme, accentColor, layoutMode) into fresh object.',
    refs: [
      'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
      'https://cwe.mitre.org/data/definitions/1321.html'
    ],
    vLimitation: null,
    cLimitation: null
  },

  // A9
  '051': {
    pairId: 'PAIR-051-SESSIONSTORAGE-TOKEN',
    primaryModule: 'auth.js',
    cwe: 'CWE-922: Insecure Storage of Sensitive Information',
    owasp: 'A07:2021-Identification and Authentication Failures',
    ruleId: 'OWASP-A07-001',
    severity: 'HIGH',
    vDesc: 'Stores sensitive bearer token in unencrypted sessionStorage.',
    cDesc: 'Stores transient bearer token in memory closure variable.',
    trustBoundary: 'Browser Web Storage boundary.',
    attackerInput: 'Any script executing on origin reading sessionStorage.',
    execEnv: 'Browser sessionStorage interface.',
    impact: 'HIGH: Bearer token theft by injected or malicious third-party scripts.',
    safePartner: 'Keeps token in private memory variable without writing to browser web storage.',
    refs: [
      'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
      'https://cwe.mitre.org/data/definitions/922.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A07-001 checks localStorage, missing sessionStorage calls.',
    cLimitation: null
  },
  '052': {
    pairId: 'PAIR-052-URL-FRAGMENT-TOKEN',
    primaryModule: 'sensitiveData.js',
    cwe: 'CWE-598: Sensitive Token Exposure in URL Fragment',
    owasp: 'A02:2021-Cryptographic Failures',
    ruleId: 'OWASP-A02-007',
    severity: 'MEDIUM',
    vDesc: 'Publishes access token in window.location.hash URL fragment.',
    cDesc: 'Transmits access token via in-memory Authorization request header.',
    trustBoundary: 'URL fragment visibility in browser history and Referer headers.',
    attackerInput: 'Inspecting browser URL bar, history, or Referer headers.',
    execEnv: 'Browser window navigation state.',
    impact: 'MEDIUM: Authentication token leaked via browser history and external navigation.',
    safePartner: 'Passes access token in HTTP Authorization header in memory.',
    refs: [
      'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
      'https://cwe.mitre.org/data/definitions/598.html'
    ],
    vLimitation: 'Known scanner miss: rule OWASP-A02-007 checks query string concatenation, missing location.hash assignments.',
    cLimitation: null
  },

  // A10
  '053': {
    pairId: 'PAIR-053-CLIENT-REQUEST-CREDENTIALS',
    primaryModule: 'accessControl.js',
    cwe: 'CWE-20: Improper Input Validation (Client Request Forgery with Ambient Credentials)',
    owasp: 'A01:2021-Broken Access Control',
    ruleId: 'OWASP-A01-001',
    severity: 'HIGH',
    vDesc: 'Fetches arbitrary user-supplied URL with ambient credentials included.',
    cDesc: 'Validates target URL against allowlist of authorized origins before fetching.',
    trustBoundary: 'External user-supplied request destination URL.',
    attackerInput: 'Attacker-controlled URL destination receiving victim session credentials.',
    execEnv: 'Browser Fetch API.',
    impact: 'HIGH: Credential leakage and client-side request forgery to unauthorized endpoints.',
    safePartner: 'Parses destination URL and enforces origin allowlist before dispatching fetch.',
    refs: [
      'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
      'https://cwe.mitre.org/data/definitions/20.html',
      'https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API'
    ],
    vLimitation: 'Known scanner miss: JSentinel does not implement a client-side open fetch check.',
    cLimitation: null
  },
  '054': {
    pairId: 'PAIR-054-DYNAMIC-SCRIPT-INJECTION',
    primaryModule: 'xss.js',
    cwe: 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere',
    owasp: 'A03:2021-Injection',
    ruleId: 'OWASP-A03-006',
    severity: 'CRITICAL',
    vDesc: 'Dynamically injects external script element pointing to unvalidated user-controlled URL.',
    cDesc: 'Loads script only from approved CDN with Subresource Integrity (SRI) hash verification.',
    trustBoundary: 'External script inclusion boundary.',
    attackerInput: 'Untrusted script source URL hosting malicious JavaScript payload.',
    execEnv: 'Browser DOM script element execution.',
    impact: 'CRITICAL: Full execution of arbitrary untrusted third-party script in victim session.',
    safePartner: 'Loads pre-approved script URL with cryptographic SRI integrity hash verification.',
    refs: [
      'https://owasp.org/Top10/A03_2021-Injection/',
      'https://cwe.mitre.org/data/definitions/829.html',
      'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'
    ],
    vLimitation: 'Known scanner miss: JSentinel does not implement dynamic script.src detection.',
    cLimitation: null
  }
};

// Build manifest
const manifestFiles = [];

for (const pair of controlledPairs) {
  const meta = pairMetadata[pair.id];
  const vFileName = `V-${pair.cat}-${pair.id}.js`;
  const cFileName = `C-${pair.cat}-${pair.id}.js`;
  const isPilot = PILOT_FILES.has(vFileName);

  const vCode = fs.readFileSync(path.join(samplesDir, vFileName), 'utf8');
  const cCode = fs.readFileSync(path.join(samplesDir, cFileName), 'utf8');

  const vScan = scanCode(vCode, vFileName, allRules);
  const cScan = scanCode(cCode, cFileName, allRules);

  // Build Vulnerable Entry
  const expectedVFindings = vScan.issues.map(iss => ({
    ruleId: iss.id,
    owasp2021Category: meta.owasp,
    severity: iss.severity,
    location: {
      line: iss.line,
      column: iss.column
    },
    weaknessDescription: iss.message || meta.vDesc
  }));

  manifestFiles.push({
    fileName: vFileName,
    filePath: `test-samples/samples/${vFileName}`,
    sampleId: `V-${pair.cat}-${pair.id}`,
    pairId: meta.pairId,
    primaryModule: meta.primaryModule,
    label: 'vulnerable',
    legacyClassification: {
      legacyLabel: 'vulnerable',
      source: 'filename-prefix'
    },
    intendedBehavior: meta.vDesc,
    securityGroundTruth: {
      isVulnerable: true,
      flawType: meta.cwe,
      rationale: meta.vDesc,
      sourceReferences: meta.refs
    },
    threatModelAndAssumptions: {
      trustBoundary: meta.trustBoundary,
      attackerControlledInput: meta.attackerInput,
      executionEnvironment: meta.execEnv,
      impactSupportingSeverity: meta.impact,
      safePartnerAssumptions: meta.safePartner
    },
    expectedScannerFindings: expectedVFindings,
    developmentUse: true,
    developmentUseRationale: 'Included in Phase 01-03 baseline regression suite and engine parity harnesses.',
    reviewStatus: {
      coverage: isPilot ? 'pilot-reviewed' : 'controlled-reviewed',
      aiReviewer: 'Agy (Gemini 3.8 Flash High)',
      humanReview: 'PENDING'
    },
    ambiguityOrKnownLimitations: meta.vLimitation || 'Reviewed controlled benchmark sample.'
  });

  // Build Clean Entry
  manifestFiles.push({
    fileName: cFileName,
    filePath: `test-samples/samples/${cFileName}`,
    sampleId: `C-${pair.cat}-${pair.id}`,
    pairId: meta.pairId,
    primaryModule: meta.primaryModule,
    label: 'clean',
    legacyClassification: {
      legacyLabel: 'clean',
      source: 'filename-prefix'
    },
    intendedBehavior: meta.cDesc,
    securityGroundTruth: {
      isVulnerable: false,
      flawType: null,
      rationale: meta.cDesc,
      sourceReferences: meta.refs
    },
    threatModelAndAssumptions: {
      trustBoundary: meta.trustBoundary,
      attackerControlledInput: 'Remediated; input is sanitized, validated, or isolated from sensitive execution sinks.',
      executionEnvironment: meta.execEnv,
      impactSupportingSeverity: 'NONE: Remediated pattern prevents vulnerability execution.',
      safePartnerAssumptions: meta.safePartner
    },
    expectedScannerFindings: [], // Ideal scanner expectations for clean files
    developmentUse: true,
    developmentUseRationale: 'Included in Phase 01-03 baseline regression suite and engine parity harnesses.',
    reviewStatus: {
      coverage: isPilot ? 'pilot-reviewed' : 'controlled-reviewed',
      aiReviewer: 'Agy (Gemini 3.8 Flash High)',
      humanReview: 'PENDING'
    },
    ambiguityOrKnownLimitations: meta.cLimitation || 'Verified secure remediation.'
  });
}

// 8 Scenario Files (Preserved with pending-batch-c status)
const scenarioFiles = [
  'admin-dashboard.jsx',
  'api-gateway.js',
  'chat-application.js',
  'data-pipeline.js',
  'ecommerce-checkout.js',
  'payment-processor.js',
  'student-portal.jsx',
  'user-auth-service.js'
];

for (const scName of scenarioFiles) {
  manifestFiles.push({
    fileName: scName,
    filePath: `test-samples/samples/${scName}`,
    sampleId: scName,
    pairId: null,
    primaryModule: 'scenario',
    label: 'unreviewed',
    legacyClassification: {
      legacyLabel: 'scenario',
      source: 'filename'
    },
    intendedBehavior: 'Simulated browser application workload (pending Phase 04 Batch C review).',
    securityGroundTruth: {
      isVulnerable: null,
      flawType: null,
      rationale: 'Pending formal scenario migration and multi-flaw audit in Batch C; excluded from controlled benchmark confusion matrix.',
      sourceReferences: []
    },
    threatModelAndAssumptions: null,
    expectedScannerFindings: null,
    developmentUse: true,
    developmentUseRationale: 'Included in Phase 01-03 baseline regression suite and engine parity harnesses.',
    reviewStatus: {
      coverage: 'pending-batch-c',
      aiReviewer: null,
      humanReview: 'PENDING'
    },
    ambiguityOrKnownLimitations: 'Unreviewed baseline scenario file. Preserved byte-for-byte pending Phase 04 Batch C.'
  });
}

// Sort manifest files alphabetically by fileName
manifestFiles.sort((a, b) => a.fileName.localeCompare(b.fileName));

const manifest = {
  manifestVersion: '1.0.0-draft',
  phase: 'Phase 04 Batch B',
  baseCommit: 'ca154776e3896fe4cc6db883b46d9caaf0d23089',
  datasetSummary: {
    totalFiles: 116,
    controlledPairsCount: 54,
    controlledFilesCount: 108,
    scenarioFilesCount: 8,
    reviewedPilotFilesCount: 12,
    reviewedControlledFilesCount: 108,
    pendingReviewFilesCount: 8
  },
  coverageStatus: {
    partialCoverageExplicit: false,
    controlledReviewedCount: 108,
    pendingBatchCCount: 8,
    statement: 'All 54 controlled V/C pairs (108 files) have undergone full ground-truth review, threat modeling, and scanner expectation documentation in Batch B. The eight simulated browser application scenarios remain preserved byte-for-byte and are explicitly marked pending Phase 04 Batch C.'
  },
  files: manifestFiles
};

fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(`Generated dataset manifest with ${manifestFiles.length} files (${manifest.datasetSummary.reviewedControlledFilesCount} controlled reviewed, ${manifest.datasetSummary.pendingReviewFilesCount} scenarios pending Batch C).`);
