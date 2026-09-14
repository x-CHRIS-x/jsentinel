# Phase 04 Batch C Scenario Ground Truth and Disposition Self-Check

Date: September 14, 2026.
Branch: `ao/jsentinel-24/phase04-dataset-pilot`.
Harness: AO worker `jsentinel-24`, Agy with Gemini 3.8 Flash (High).
Manager: Astra coordinator (`jsentinel-4`). Verifier: Opus HOLD.
Base Commit: `c650be9f2b73e2e381fd90342343ca9153abe2e4` (accepted base chain `ca15477`).

## 1. Executive Summary and Manager Corrections

Following integrated manager review of commit `38c1562`, this self-check details the bounded corrections applied to the Phase 04 Batch C simulated scenario dataset and manifest:

1. **Elimination of Copied Scanner Output as Ground Truth:**
   In the previous build, raw scanner detections were indiscriminately mirrored into expected findings. In this correction, every scanner signal was re-evaluated against concrete trust boundaries, attacker control, exploit prerequisites, and demonstrable security impact.

2. **Categorization of Non-Vulnerability Scanner Signals:**
   Syntactic pattern hits that do not constitute exploitable browser vulnerabilities were removed from `expectedScannerFindings`. These include:
   - Client role checks that only log to console (`admin-dashboard.jsx` line 16, `student-portal.jsx` line 30).
   - Non-secret internal IP address strings (`chat-application.js` line 16, `data-pipeline.js` line 19, `payment-processor.js` line 15, `user-auth-service.js` line 17).
   - Public AWS Access Key identifiers without secret keys (`user-auth-service.js` line 14).
   - Generic `JSON.parse()` calls without unsafe consumers (`api-gateway.js` line 47, `chat-application.js` lines 48 and 78, `data-pipeline.js` lines 44 and 85, `ecommerce-checkout.js` lines 38 and 69, `payment-processor.js` line 64, `user-auth-service.js` line 70).
   - Logging of non-sensitive request or configuration objects.
   All of these signals remain accurately recorded in `observedScannerFindings`, but are excluded from benchmark ground truth expectations.

3. **Callable Helper Assumptions vs Demonstrated Application Flows:**
   For functions containing dangerous sinks, we explicitly distinguish whether the flaw is demonstrated in the active component flow or whether it represents a callable helper assumption:
   - In `admin-dashboard.jsx`, `renderLegacyWidget` is invoked in the demonstrated UI flow with a fixed constant string (`"System Status: Online"`), making that call site fixed-safe. As an isolated callable helper, however, it accepts arbitrary untrusted markup into `document.write()`.
   - In `admin-dashboard.jsx`, `renderNotification`, `updateSidebar`, and `navigateToPartner` represent callable helper sinks that are not bound to demonstrated JSX actions.
   - In `student-portal.jsx`, `MessagePreview` and `courseHtml` rendering represent active demonstrated flows, while `renderGradeCard` and `loadAnnouncement` represent callable helper sinks.

4. **Grounding of Advisories in Package Import Registries:**
   Component review advisories (`OWASP-A06-001`) are grounded strictly in the third-party packages imported by each file. Seven of the eight scenarios import third-party packages (14 advisories total). `user-auth-service.js` imports zero third-party packages and correctly defines 0 advisories.

5. **Severity and Threat Models for Unsupported Browser Weaknesses:**
   All 6 genuine browser weaknesses without scanner rules now define explicit `severity`, `severityAssumptions`, `trustBoundary`, `attackerControlledInput`, and `securityImpact`. The uncredited dynamic GET fetch in `admin-dashboard.jsx` was removed because it carried no ambient credentials, exfiltrated no state, and had no concrete security impact.

6. **Controlled Dataset Terminology:**
   The controlled benchmark is consistently designated as the "controlled V/C dataset" rather than a blanket "single-flaw" set, preserving the distinction between sample-level labels and multi-expectation findings (such as `V-A8-045.js`).

## 2. Itemized Scenario Dispositions

### Scenario 1: `admin-dashboard.jsx` (SCENARIO-001)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 8:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid informational advisory. |
| Line 16:4 | `OWASP-A01-002` | A01:2021 | Omitted from Expected | `if (currentUser.role === "admin")` only executes `console.log`. No access control gate or privilege escalation occurs. Scanner heuristic hit preserved in observed findings. |
| Line 43:21 | `OWASP-A03-008` | A03:2021 | Expected Finding | `dangerouslySetInnerHTML={{ __html: rawHtml }}` in `AnalyticsWidget`. Active demonstrated flow rendering server announcements. High severity DOM XSS. |
| Line 53:12 | `OWASP-A03-004` | A03:2021 | Expected Finding | `container.innerHTML = ...` with template literal. Callable helper assumption in `renderNotification`. High severity DOM XSS. |
| Line 56:12 | `OWASP-A03-005` | A03:2021 | Expected Finding | `container.innerHTML = ...` from function return. Callable helper assumption in `renderNotification`. High severity DOM XSS. |
| Line 62:8 | `OWASP-A03-007` | A03:2021 | Expected Finding | `document.write(...)` in `renderLegacyWidget`. Fixed-safe in demonstrated flow (called with `"System Status: Online"`), but critical DOM injection sink under callable helper assumption. |
| Line 69:12 | `OWASP-A03-006` | A03:2021 | Expected Finding | `sidebar.innerHTML = ...` in `updateSidebar`. Callable helper assumption concatenating menu items. High severity DOM XSS. |
| Line 81:8 | `OWASP-A01-001` | A01:2021 | Expected Finding | `window.location.href = destination` in `handleExternalLink`. Callable helper open redirect; demonstrated UI passes static relative link `"/partner"`. |
| Line 87:8 | `OWASP-A01-001` | A01:2021 | Expected Finding | `location.replace(partnerUrl)` in `navigateToPartner`. Callable helper reading unvalidated `currentUser.partnerRedirect`. High severity open redirect. |

- Expected Vulnerability Findings: 7
- Expected Advisories: 1
- Unsupported Weaknesses: 0 (Dynamic GET fetch removed due to absence of ambient credentials or exfiltration impact).

### Scenario 2: `api-gateway.js` (SCENARIO-002)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 7:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid informational advisory. |
| Line 10:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded client API gateway secret key in source code. Critical credential exposure. |
| Line 15:21 | `OWASP-A03-003` | A03:2021 | Expected Finding | `new Function("request", ruleCode)`. Critical arbitrary code execution on untrusted routing rules. |
| Line 19:25 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(legacyRule)`. Critical arbitrary code execution on legacy routing rules. |
| Line 39:4 | `ruleId: null` | A10:2021 | Unsupported Weakness | Client-side POST dispatching caller payload to unvalidated `targetService`. Severity: MEDIUM. SSRF / intranet exfiltration. |
| Line 47:24 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(rawPayload)`. Parsing by itself is not an exploitable flaw. Retained in observed findings. |
| Line 51:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Direct `__proto__` assignment with webhook overrides. High severity prototype pollution. |
| Line 54:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Direct `constructor.prototype` assignment with webhook extensions. High severity prototype pollution. |
| Line 61:4 | `OWASP-A05-003` | A05:2021 | Omitted from Expected | `console.log(config)`. Logging non-sensitive config object. |
| Line 62:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | `console.log(credentials)`. Logging credentials object containing authentication secrets. Medium severity sensitive data exposure. |
| Line 70:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setInterval()`. High severity string-to-code timer evaluation. |
| Line 73:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | Template literal in `setTimeout()`. High severity string-to-code timer evaluation. |
| Line 79:4 | `OWASP-A01-001` | A01:2021 | Expected Finding | `window.location.href = destination`. High severity open redirect. |
| Line 80:4 | `OWASP-A01-001` | A01:2021 | Expected Finding | `location.replace(destination)`. High severity open redirect. |

- Expected Vulnerability Findings: 10
- Expected Advisories: 1
- Unsupported Weaknesses: 1 (Client POST to dynamic targetService).

### Scenario 3: `chat-application.js` (SCENARIO-003)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 7:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid informational advisory. |
| Line 10:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded WebSocket signing key in source code. Critical credential exposure. |
| Line 13:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded Firebase API key in source code. Critical credential exposure. |
| Line 16:21 | `OWASP-A02-005` | A02:2021 | Omitted from Expected | Internal IP address constant (`172.16.0.42`). Non-secret network constant; not an exploitable vulnerability. |
| Line 24:8 | `OWASP-A03-004` | A03:2021 | Expected Finding | `preview.innerHTML = ...` with template literal containing unescaped message. High severity DOM XSS. |
| Line 27:8 | `OWASP-A03-005` | A03:2021 | Expected Finding | `preview.innerHTML = formatMessage(...)`. High severity DOM XSS. |
| Line 31:4 | `OWASP-A03-007` | A03:2021 | Expected Finding | `document.write(...)` rendering unescaped message. Critical DOM injection. |
| Line 34:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Logging room session object containing tokens to console. Medium severity. |
| Line 35:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Logging user profile object to console. Medium severity. |
| Line 48:23 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(metadata)`. Syntactic warning only. |
| Line 51:24 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(parsedMeta.processingScript)`. Critical arbitrary code execution on untrusted metadata. |
| Line 54:22 | `OWASP-A03-003` | A03:2021 | Expected Finding | `new Function("file", parsedMeta.validationRule)`. Critical code execution. |
| Line 62:4 | `OWASP-A02-002` | A02:2021 | Expected Finding | Presence cookie written without Secure or HttpOnly flags. Medium severity. |
| Line 65:4 | `OWASP-A02-002` | A02:2021 | Expected Finding | Active user cookie written via template literal without security flags. Medium severity. |
| Line 68:22 | `OWASP-A02-003` | A02:2021 | Expected Finding | Insecure `Math.random()` used to generate session salt. High severity PRNG weakness. |
| Line 71:4 | `OWASP-A07-001` | A07:2021 | Expected Finding | Plaintext chat token stored in `localStorage`. High severity storage weakness. |
| Line 78:19 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(roomConfig)`. Syntactic warning only. |
| Line 82:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through direct `__proto__` assignment with room overrides. High severity. |
| Line 88:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through `constructor.prototype` assignment with global settings. High severity. |
| Line 96:17 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(command)` executing bot commands. Critical arbitrary code execution. |
| Line 99:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setTimeout()` for bot task. High severity string timer. |
| Line 100:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setInterval()` for bot queue. High severity string timer. |
| Line 108:4 | `ruleId: null` | A10:2021 | Unsupported Weakness | Client-side POST notification to arbitrary unvalidated `callbackUrl`. Severity: MEDIUM. |
| Line 111:23 | `OWASP-A02-007` | A02:2021 | Expected Finding | Tracking token and service key exposed in query string. Medium severity. |
| Line 118:4 | `OWASP-A01-001` | A01:2021 | Expected Finding | `window.location.href = appUrl`. High severity open redirect. |
| Line 119:4 | `OWASP-A01-001` | A01:2021 | Expected Finding | `location.replace(appUrl)`. High severity open redirect. |

- Expected Vulnerability Findings: 21
- Expected Advisories: 1
- Unsupported Weaknesses: 1 (Notification dispatch to dynamic callbackUrl).

### Scenario 4: `data-pipeline.js` (SCENARIO-004)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 7:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `lodash`. Valid advisory. |
| Line 8:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid advisory. |
| Line 9:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `mongoose`. Valid advisory. |
| Line 10:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `jsonwebtoken`. Valid advisory. |
| Line 13:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded pipeline encryption key in source code. Critical credential exposure. |
| Line 16:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded MongoDB connection URI with embedded password. Critical credential exposure. |
| Line 19:22 | `OWASP-A02-005` | A02:2021 | Omitted from Expected | Internal IP address constant (`10.0.2.15`). Non-secret constant. |
| Line 32:21 | `OWASP-A03-003` | A03:2021 | Expected Finding | `new Function("record", ...)` with dynamic query filter. Critical code execution. |
| Line 44:18 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(transformRules)`. Syntactic warning only. |
| Line 51:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through `__proto__` with schemaOverrides. High severity. |
| Line 64:22 | `OWASP-A02-007` | A02:2021 | Expected Finding | Warehouse API key and master secret exposed in export URL query string. Medium severity. |
| Line 67:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Logging credentials object directly to console. Medium severity. |
| Line 71:4 | `ruleId: null` | A10:2021 | Unsupported Weakness | Export completion webhook dispatched to unvalidated `credentials.webhookUrl`. Severity: MEDIUM. |
| Line 79:20 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(validationExpression)` for record validation. Critical code execution. |
| Line 85:18 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(patchData)`. Syntactic warning only. |
| Line 88:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through `constructor.prototype` with globalDefaults. High severity. |
| Line 99:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setInterval()` for pipeline health. High severity string timer. |
| Line 102:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setTimeout()` for batch cleanup. High severity string timer. |

- Expected Vulnerability Findings: 10
- Expected Advisories: 4
- Unsupported Weaknesses: 1 (Webhook callback to credentials.webhookUrl).

### Scenario 5: `ecommerce-checkout.js` (SCENARIO-005)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 7:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid advisory. |
| Line 10:6 | `ruleId: null` | A02:2021 | Unsupported Weakness | Hardcoded Stripe API key token skipped by scanner due to "test" substring filter. Severity: HIGH. |
| Line 13:6 | `OWASP-A02-001` | A02:2021 | Expected Finding | Hardcoded database password for orders. Critical credential exposure. |
| Line 16:23 | `OWASP-A02-004` | A02:2021 | Expected Finding | Insecure plaintext HTTP URL for payment charge endpoint. Medium severity. |
| Line 21:21 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(formula)` in cart discount calculation. Critical arbitrary code execution. |
| Line 28:4 | `OWASP-A02-002` | A02:2021 | Expected Finding | Checkout session cookie set via concatenation without Secure flag. Medium severity. |
| Line 31:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String code in `setTimeout()` for analytics ping. High severity string timer. |
| Line 38:19 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(orderData.metadata)`. Syntactic warning only. |
| Line 42:4 | `OWASP-A05-001` | A05:2021 | Expected Finding | Logging sensitive payment token variable directly to console. Medium severity. |
| Line 45:23 | `OWASP-A02-007` | A02:2021 | Expected Finding | Receipt URL includes payment token and verification key in query string. Medium severity. |
| Line 69:22 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(rawPayload)`. Syntactic warning only. |

- Expected Vulnerability Findings: 7
- Expected Advisories: 1
- Unsupported Weaknesses: 1 (Hardcoded Stripe live key suppressed by "test" filter).

### Scenario 6: `payment-processor.js` (SCENARIO-006)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 7:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `axios`. Valid advisory. |
| Line 10:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded merchant live API key. Critical credential exposure. |
| Line 11:6 | `OWASP-A02-001` | A02:2021 | Expected Finding | Hardcoded payment processor production password. Critical credential exposure. |
| Line 12:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded webhook secret for callback verification. Critical credential exposure. |
| Line 15:20 | `OWASP-A02-005` | A02:2021 | Omitted from Expected | Internal IP address constant (`10.128.0.55`). Non-secret constant. |
| Line 18:23 | `OWASP-A02-004` | A02:2021 | Expected Finding | Insecure plaintext HTTP payment callback endpoint. Medium severity. |
| Line 23:10 | `OWASP-A02-003` | A02:2021 | Expected Finding | Insecure `Math.random()` used to generate transactionKey. High severity PRNG weakness. |
| Line 26:4 | `OWASP-A02-002` | A02:2021 | Expected Finding | Payment session cookie set without Secure flag. Medium severity. |
| Line 29:4 | `OWASP-A07-001` | A07:2021 | Expected Finding | Sensitive paymentAuthToken stored in plaintext `localStorage`. High severity. |
| Line 33:4 | `OWASP-A05-001` | A05:2021 | Expected Finding | Logging merchant apiKey variable directly to console. Medium severity. |
| Line 45:25 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(refundPolicy)` on refund policy rules. Critical arbitrary code execution. |
| Line 48:26 | `OWASP-A03-003` | A03:2021 | Expected Finding | `new Function("amount", ...)` to evaluate fee formula. Critical code execution. |
| Line 52:28 | `OWASP-A02-007` | A02:2021 | Expected Finding | Refund webhook secret and verification token exposed in notification URL. Medium severity. |
| Line 56:4 | `ruleId: null` | A10:2021 | Unsupported Weakness | Client-side refund notification dispatched to unvalidated `webhookUrl`. Severity: MEDIUM. |
| Line 64:25 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(rawData)`. Syntactic warning only. |
| Line 68:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through direct `__proto__` with transaction overrides. High severity. |
| Line 74:4 | `OWASP-A08-002` | A08:2021 | Expected Finding | Prototype pollution through `constructor.prototype` with transaction config. High severity. |
| Line 77:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Logging sensitive reconciliation credentials object to console. Medium severity. |
| Line 78:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Logging sensitive session details to console. Medium severity. |
| Line 79:4 | `OWASP-A05-003` | A05:2021 | Omitted from Expected | Logging generic `requestContext` object to console. |
| Line 89:8 | `OWASP-A03-004` | A03:2021 | Expected Finding | `container.innerHTML = ...` with template literal containing receipt data. High severity DOM XSS. |
| Line 96:8 | `OWASP-A03-005` | A03:2021 | Expected Finding | `container.innerHTML = renderReceiptTemplate(...)`. High severity DOM XSS. |
| Line 100:4 | `OWASP-A03-007` | A03:2021 | Expected Finding | `document.write(...)` rendering receipt HTML. Critical DOM injection. |
| Line 106:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setInterval()` for recurring charges. High severity string timer. |
| Line 107:4 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setTimeout()` for payment reminder. High severity string timer. |
| Line 112:4 | `OWASP-A01-001` | A01:2021 | Expected Finding | `window.location.href = portalUrl`. High severity open redirect. |

- Expected Vulnerability Findings: 21
- Expected Advisories: 1
- Unsupported Weaknesses: 1 (Refund notification to dynamic webhookUrl).

### Scenario 7: `student-portal.jsx` (SCENARIO-007)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 9:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `serialize-javascript`. Valid advisory. |
| Line 10:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `markdown-it`. Valid advisory. |
| Line 11:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `js-yaml`. Valid advisory. |
| Line 12:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `node-fetch`. Valid advisory. |
| Line 13:0 | `OWASP-A06-001` | A06:2021 | Expected Advisory | Third-party client import: `vm2`. Valid advisory. |
| Line 16:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded student portal API key. Critical credential exposure. |
| Line 19:6 | `OWASP-A02-001` | A02:2021 | Expected Finding | Hardcoded database password for grade records. Critical credential exposure. |
| Line 22:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded enrollment system token. Critical credential exposure. |
| Line 30:4 | `OWASP-A01-002` | A01:2021 | Omitted from Expected | `if (student.isAdmin)` only gates `console.log`. No authorization gate or privilege escalation. Scanner heuristic hit preserved in observed findings. |
| Line 37:8 | `ruleId: null` | A01:2021 | Unsupported Weakness | `window.location.href = student.loginRedirectUrl` on unauthenticated gate. Severity: HIGH. Open redirect to attacker-controlled URL. |
| Line 58:12 | `OWASP-A03-004` | A03:2021 | Expected Finding | `card.innerHTML = ...` with template literal. Callable helper assumption in `renderGradeCard`. High severity DOM XSS. |
| Line 69:12 | `OWASP-A03-005` | A03:2021 | Expected Finding | `descriptionEl.innerHTML = ...` from function. Callable helper assumption in `renderCourseDescription`. High severity DOM XSS. |
| Line 75:8 | `OWASP-A03-007` | A03:2021 | Expected Finding | `document.write(...)`. Callable helper assumption in `loadAnnouncement`. Critical DOM injection. |
| Line 83:21 | `OWASP-A03-008` | A03:2021 | Expected Finding | `dangerouslySetInnerHTML` in `MessagePreview`. Active demonstrated flow rendering message body. High severity DOM XSS. |
| Line 90:8 | `OWASP-A02-002` | A02:2021 | Expected Finding | Enrollment session cookie set without Secure flag. Medium severity. |
| Line 93:8 | `OWASP-A07-001` | A07:2021 | Expected Finding | Plaintext enrollment token stored in `localStorage`. High severity storage weakness. |
| Line 96:8 | `OWASP-A03-002` | A03:2021 | Expected Finding | String argument in `setTimeout()` for enrollment confirmation. High severity string timer. |
| Line 101:20 | `OWASP-A03-001` | A03:2021 | Expected Finding | `eval(formula)` in GPA calculator. Critical arbitrary code execution. |
| Line 107:27 | `OWASP-A03-003` | A03:2021 | Expected Finding | `new Function("grades", weights)` for grade weighting. Critical code execution. |
| Line 113:14 | `OWASP-A02-003` | A02:2021 | Expected Finding | Insecure `Math.random()` used for enrollment OTP. High severity PRNG weakness. |
| Line 136:21 | `OWASP-A03-008` | A03:2021 | Expected Finding | `dangerouslySetInnerHTML` rendering course catalog HTML. Active demonstrated flow. High severity DOM XSS. |

- Expected Vulnerability Findings: 14
- Expected Advisories: 5
- Unsupported Weaknesses: 1 (Open redirect on unauthenticated gate).

### Scenario 8: `user-auth-service.js` (SCENARIO-008)

| Location | Rule Signal | Category | Disposition | Context / Rationale |
| --- | --- | --- | --- | --- |
| Line 8:6 | `OWASP-A02-001` | A02:2021 | Expected Finding | Hardcoded admin master password in source code. Critical credential exposure. |
| Line 11:6 | `OWASP-A02-006` | A02:2021 | Expected Finding | Hardcoded JWT signing secret in source code. Critical credential exposure. |
| Line 11:18 | `OWASP-A02-005` | A02:2021 | Expected Finding | Hardcoded JWT token string detected in source code. Critical credential exposure. |
| Line 14:21 | `OWASP-A02-005` | A02:2021 | Omitted from Expected | AWS Access Key ID (`AKIAIOSFODNN7EXAMPLE`) without secret access key. Public identifier, not an authenticating credential. |
| Line 17:15 | `OWASP-A02-005` | A02:2021 | Omitted from Expected | Internal IP address constant (`192.168.1.105`). Non-secret constant. |
| Line 21:10 | `OWASP-A02-003` | A02:2021 | Expected Finding | Insecure `Math.random()` used to generate password reset token. High severity PRNG weakness. |
| Line 22:10 | `OWASP-A02-003` | A02:2021 | Expected Finding | Insecure `Math.random()` used to generate password reset OTP. High severity PRNG weakness. |
| Line 25:4 | `OWASP-A07-001` | A07:2021 | Expected Finding | Plaintext auth token stored in `localStorage`. High severity storage weakness. |
| Line 26:4 | `OWASP-A07-001` | A07:2021 | Expected Finding | Plaintext JWT session stored in `localStorage`. High severity storage weakness. |
| Line 36:8 | `OWASP-A02-002` | A02:2021 | Expected Finding | Session cookie set via concatenation without HttpOnly or Secure flags. Medium severity. |
| Line 39:8 | `OWASP-A02-002` | A02:2021 | Expected Finding | Admin authorization cookie set via template literal without security flags. Medium severity. |
| Line 42:8 | `OWASP-A05-001` | A05:2021 | Expected Finding | Plaintext password logged directly to console upon successful login. Medium severity. |
| Line 53:22 | `OWASP-A02-007` | A02:2021 | Expected Finding | Password reset link exposes reset token and temporary password in query parameters. Medium severity. |
| Line 56:27 | `OWASP-A02-004` | A02:2021 | Expected Finding | Insecure cleartext HTTP endpoint for authentication verification callback. Medium severity. |
| Line 70:20 | `OWASP-A08-001` | A08:2021 | Omitted from Expected | `JSON.parse(sessionData)`. Syntactic warning only. |
| Line 74:4 | `OWASP-A01-002` | A01:2021 | Expected Finding | Client-side authorization check: `validateClientSession` assigns `isAdmin = true` based on untrusted client role. Medium severity authorization bypass. |
| Line 84:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Sensitive user profile object logged directly to console during account deletion. Medium severity. |
| Line 85:4 | `OWASP-A05-003` | A05:2021 | Expected Finding | Active session state object logged directly to console during account deletion. Medium severity. |
| Line 86:4 | `OWASP-A05-003` | A05:2021 | Omitted from Expected | Logging generic `requestContext` object to console. |

- Expected Vulnerability Findings: 15
- Expected Advisories: 0 (File imports zero third-party packages; grounded in source).
- Unsupported Weaknesses: 0.

---

## 3. Totals and Manifest Consistency

Across all 8 simulated browser scenarios:
- **Total Expected Vulnerabilities:** 7 + 10 + 21 + 10 + 7 + 21 + 14 + 15 = **105** genuine vulnerabilities.
- **Total Expected Advisories:** 1 + 1 + 1 + 4 + 1 + 1 + 5 + 0 = **14** advisories (derived from third-party package imports).
- **Total Unsupported Browser Weaknesses:** 0 + 1 + 1 + 1 + 1 + 1 + 1 + 0 = **6** weaknesses (all with explicit severity, assumptions, and exploit conditions).
- **Total Omitted False Positive Heuristics:** 14 scanner pattern hits correctly classified as non-vulnerabilities and retained exclusively in `observedScannerFindings`.

## 4. Controlled Dataset Invariance Verification

- All 108 controlled benchmark files remain 100% byte-identical to commit `c650be9`.
- Verified against `documents/research-phases/checks/04-batch-c-controlled-108-hashes.json` (108/108 match).
- All 12 pilot files match their committed pilot hashes (12/12 match).
- Test 8 confirms complete observation invariance: mock scanner alterations affect only `observedScannerFindings` across all 116 files.

## 5. Verification Commands and Exit Codes

| Command Line | Exit Code | Result |
| --- | :---: | --- |
| `node test-samples/generate-samples.cjs --check` | 0 | 116 matches, 0 mismatches out of 116 checked. |
| `node --test validation/pilot-manifest.test.mjs` | 0 | 8 of 8 tests passed (~939ms). |
| `node --test validation/*.test.mjs validation/*.test.cjs` | 0 | 48 of 48 tests passed (~4000ms, zero regressions). |
| `npm run lint` | 0 | Clean pass; 0 ESLint errors or warnings. |
| `npm --prefix vscode-extension run lint` | 0 | Clean pass; 0 ESLint errors or warnings. |
| `npm run build` | 0 | Clean Vite build in 1.81s; 233 modules transformed. |

## 6. Disclosed Limitations and Scope Boundaries

In accordance with research phase boundaries, the following were explicitly **NOT RUN**:
1. Live browser DOM event execution / layout rendering: NOT RUN.
2. Live backend server verification and server RBAC enforcement: NOT RUN.
3. Formal benchmark accuracy scoring, precision, recall, and F1 calculations: NOT RUN (reserved for Phase 05/07).
4. Thesis chapter edits: NOT RUN.
5. Remote git push: NOT RUN.

---

## 7. Post-Commit 2afe0ff/e21f77f Ground Truth Corrections and Erratum

Following manager review of commits `2afe0ff` and `e21f77f`, this section records the bounded scenario ground truth corrections, an erratum on historical evidence counts, and the final 137-issue reconciliation table.

### 7.1 Erratum on Historical Evidence Totals

In commits `2afe0ff` and `e21f77f`, initial omissions were documented, but the summary text contained an arithmetic inconsistency: 9 generic `JSON.parse` instances were itemized in the body, but summarized as 6 in the handoff, and total omissions were summarized as 14 when raw scanner output actually generated 137 issues.

This erratum establishes the authoritative counts derived directly from code semantics and manifest records:
- Raw scanner output across the 8 scenarios produces exactly **137** issues.
- Curated Expected Findings (genuine exploitable browser vulnerabilities): **75**.
- Curated Expected Advisories (`OWASP-A06-001` grounded in third-party package imports): **14**.
- Curated Omitted Pattern Hits (AST heuristic detections without vulnerability context): **48**.
- Curated Unsupported Browser Weaknesses (no scanner rule; explicit threat models): **6**.
- Mathematical Reconciliation: **75 + 14 + 48 = 137** observed scanner detections. Every single issue is fully accounted for.

### 7.2 Code-Based Dispositions for Manager Review Findings

1. **`chat-application.js` Semantics:**
   - **Line 13 (`firebaseApiKey`):** Hardcoded Firebase Web API key (`AIzaSy...`). Per official Google Firebase documentation, web API keys are public project identifiers used for routing, not private secrets. Without server-side privilege escalation, this client identifier is not an authenticating credential leak. Omitted from expected findings.
   - **Lines 62 & 65 (Presence & Timestamp Cookies):** `document.cookie` assignments for `presence` and `last_active`. Non-sensitive UI state and timestamp telemetry. Client-side JavaScript cannot set `HttpOnly` per RFC 6265 Section 5.3, and these cookies carry no authentication role. Omitted from expected findings.
   - **Line 68 (`sessionSalt = Math.random()`):** Pseudorandom value returned in an object with no demonstrated security-sensitive consumer (no cryptographic key derivation, signature, or nonce operation). Omitted from expected findings.
   - **Line 71 (`localStorage.setItem('chatToken', userId)`):** Stores non-sensitive `userId` under key `'chatToken'`. The key name alone does not establish a sensitive bearer credential. Omitted from expected findings.

2. **Fixed String Timers:**
   - Static string literals in `setInterval("checkPipelineHealth()", 60000)` and `setTimeout("cleanupStaleBatches()", 300000)` lack variable interpolation and attacker control. While flagged by scanner rule `OWASP-A03-002` as code smells, they cannot be exploited for arbitrary code injection.
   - Exactly 9 fixed string timers are omitted from expected findings across the 8 scenarios (`api-gateway.js` line 70, `chat-application.js` lines 99 and 100, `data-pipeline.js` lines 99 and 102, `ecommerce-checkout.js` line 31, `payment-processor.js` lines 106 and 107, and `student-portal.jsx` line 96).
   - Exactly 1 dynamic string timer is retained as an expected finding: `api-gateway.js` line 73 (`setTimeout(\`reportHealth('\${serviceId}')\`, 5000)`), because it interpolates user-controlled `serviceId`, allowing string-to-code breakout.

3. **Prototype Assignments with Unused Targets:**
   - Direct assignments to `__proto__` or `constructor.prototype` on locally scoped, newly created empty objects (`const defaults = {}`, `const schema = {}`, `const config = {}`).
   - Under ECMAScript prototype setter semantics (ES6+), assigning `obj.__proto__ = ...` sets the [[Prototype]] of the instance, but does not mutate global `Object.prototype`.
   - Assigning `obj.constructor.prototype = ...` targets non-writable `Object.prototype`, which is a runtime no-op.
   - Furthermore, these target objects are unused local variables that are never queried for property lookups.
   - 8 prototype assignment pattern hits omitted from expected findings: `api-gateway.js` lines 51 and 54, `chat-application.js` lines 82 and 88, `data-pipeline.js` lines 51 and 88, and `payment-processor.js` lines 68 and 74.

4. **Generic Diagnostic Logging:**
   - `console.log` statements logging generic parameters (`session`, `user`, `credentials`, `config`) without demonstrated secret or credential payloads.
   - 9 generic logging pattern hits omitted from expected findings: `api-gateway.js` lines 61 and 62, `chat-application.js` lines 34 and 35, `data-pipeline.js` line 67, `payment-processor.js` lines 77 and 78, and `user-auth-service.js` lines 84 and 85.
   - Legitimate sensitive data logs retained: `ecommerce-checkout.js` line 42 (`paymentToken`), `payment-processor.js` line 33 (`apiKey`), and `user-auth-service.js` line 42 (`password`).

5. **Callable Helper Assumptions vs Fixed-Safe Demonstrated Flows:**
   - In `admin-dashboard.jsx`: `renderLegacyWidget` at line 115 is invoked with constant string `"System Status: Online"`, making that demonstrated call site fixed-safe; the helper function sink (`document.write`) is documented as a callable helper DOM injection sink.
   - `handleExternalLink` at line 118 passes static relative path `"/partner"`, making the demonstrated call site fixed-safe; open redirect sink documented as a callable helper.
   - `renderNotification`, `updateSidebar`, and `navigateToPartner` documented as uninvoked callable helpers.
   - In `student-portal.jsx`: `MessagePreview` (line 83) and `courseHtml` (line 136) are active demonstrated flows; `renderGradeCard` (line 58), `renderCourseDescription` (line 69), and `loadAnnouncement` (line 75) are callable helper sinks.

### 7.3 Final 137-Issue Itemized Reconciliation Table

| Scenario File | Expected Findings | Expected Advisories | Omitted Pattern Hits | Unsupported Weaknesses | Total Observed Scanner Issues |
| --- | :---: | :---: | :---: | :---: | :---: |
| `admin-dashboard.jsx` | 7 | 1 | 1 (L16 role log) | 0 | 9 |
| `api-gateway.js` | 6 | 1 | 6 (L47 json, L51 proto, L54 proto, L61 log, L62 log, L70 timer) | 1 (L39 POST) | 13 |
| `chat-application.js` | 10 | 1 | 14 (L13 firebase, L16 ip, L34 log, L35 log, L48 json, L62 cookie, L65 cookie, L68 salt, L71 token, L78 json, L82 proto, L88 proto, L99 timer, L100 timer) | 1 (L108 script) | 25 |
| `data-pipeline.js` | 5 | 4 | 8 (L19 ip, L44 json, L51 proto, L67 log, L85 json, L88 proto, L99 timer, L102 timer) | 1 (L71 POST) | 17 |
| `ecommerce-checkout.js` | 6 | 1 | 4 (L31 timer, L38 json, L45:80 duplicate query param, L69 json) | 1 (L10 postMsg) | 11 |
| `payment-processor.js` | 15 | 1 | 8 (L15 ip, L64 json, L68 proto, L74 proto, L77 log, L78 log, L106 timer, L107 timer) | 1 (L56 fetch) | 24 |
| `student-portal.jsx` | 13 | 5 | 2 (L30 role log, L96 timer) | 1 (L37 script) | 20 |
| `user-auth-service.js` | 13 | 0 | 5 (L14 aws, L17 ip, L70 json, L84 log, L85 log) | 0 | 18 |
| **Totals** | **75** | **14** | **48** | **6** | **137** |

This completes the Batch C scenario ground truth corrections and evidence reconciliation. All work stops here for integrated coordinator review (`jsentinel-4`).

