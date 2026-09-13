import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { scanFile } from '../src/utils/scannerEngine.js';

const require = createRequire(import.meta.url);
const { scanCode } = require('../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../vscode-extension/src/scanner/rules.js');
const modules = ['injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization', 'knownVulns', 'accessControl'];
const rules = (await Promise.all(modules.map(name => import(`../src/scanner/rules/${name}.js`)))).flatMap(mod => Object.values(mod).flat());

const scanBoth = async (code, name = 'example.js') => [
  await scanFile({ name, text: async () => code }, rules),
  scanCode(code, name, allRules)
];

// Helper to check whether OWASP-A01-001 was detected
const checkOpenRedirect = (result) => {
  assert.equal(result.hasError, false);
  return result.issues.filter(i => i.id === 'OWASP-A01-001');
};

test('criterion 1: rejected !allowed.includes(target) branch is never safe', async () => {
  const rejectedCases = [
    // Direct negated includes in if consequent
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Negated with parenthesized includes
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!(allowed.includes(target))) {
         location.replace(target);
       }
     }`,
    // Target redirected in else branch of positive check
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         console.log("safe");
       } else {
         window.location.href = target;
       }
     }`,
    // indexOf === -1 rejection branch
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.indexOf(target) === -1) {
         window.location.href = target;
       }
     }`,
    // indexOf < 0 rejection branch
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.indexOf(target) < 0) {
         location.replace(target);
       }
     }`
  ];

  for (const code of rejectedCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 1, `Expected finding for rejected branch in:\n${code}`);
    }
  }
});

test('criterion 2: unrelated validator names and OR conditions not sufficient', async () => {
  const invalidValidatorCases = [
    // Unrelated function calls
    `function redirect(target) {
       if (validate(target)) {
         window.location.href = target;
       }
     }`,
    `function redirect(target) {
       if (check(target)) {
         location.replace(target);
       }
     }`,
    `function redirect(target) {
       if (test(target)) {
         window.location.href = target;
       }
     }`,
    `function redirect(target) {
       if (customValidator.isValid(target)) {
         window.location.href = target;
       }
     }`,
    // OR conditions combining allowlist with other expressions
    `const allowed = ["https://example.com"];
     function redirect(target, isAdmin) {
       if (allowed.includes(target) || isAdmin) {
         window.location.href = target;
       }
     }`,
    `const allowed = ["https://example.com"];
     function redirect(target, fallback) {
       if (fallback || allowed.includes(target)) {
         location.replace(target);
       }
     }`,
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.includes(target) || true) {
         window.location.href = target;
       }
     }`
  ];

  for (const code of invalidValidatorCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 1, `Expected finding for invalid validator/OR condition in:\n${code}`);
    }
  }
});

test('criterion 3: reassignment, shadowing, mutation, and different branch must not justify suppression', async () => {
  const unsafeMutationCases = [
    // Target reassigned after check inside if
    `const allowed = ["https://example.com"];
     function redirect(target, untrusted) {
       if (allowed.includes(target)) {
         target = untrusted;
         window.location.href = target;
       }
     }`,
    // Target reassigned after early return guard
    `const allowed = ["https://example.com"];
     function redirect(target, untrusted) {
       if (!allowed.includes(target)) return;
       target = untrusted;
       window.location.href = target;
     }`,
    // Shadowing: inner scope shadows checked target
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         function inner(target) {
           window.location.href = target;
         }
         inner("https://malicious.com");
       }
     }`,
    // Allowlist mutated via push
    `const allowed = ["https://example.com"];
     allowed.push(untrusted);
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Allowlist mutated via index assignment
    `const allowed = ["https://example.com"];
     allowed[1] = untrusted;
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Allowlist reassigned
    `let allowed = ["https://example.com"];
     allowed = untrustedList;
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Allowlist contains non-literal/dynamic element
    `const allowed = ["https://example.com", dynamicHost];
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Different branch: check is in separate if statement without early exit
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         console.log("allowed");
       }
       window.location.href = target;
     }`,
    // Check on a different variable
    `const allowed = ["https://example.com"];
     function redirect(target, other) {
       if (allowed.includes(other)) {
         window.location.href = target;
       }
     }`
  ];

  for (const code of unsafeMutationCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 1, `Expected finding for mutation/shadowing/different-branch in:\n${code}`);
    }
  }
});

test('criterion 4: supported permitted destination cases behave correctly in both scanners', async () => {
  const safeAllowedCases = [
    // Local unchanged array, matching if consequent
    `const allowed = ["https://app.example.com", "https://api.example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = target;
       }
     }`,
    // Top-level unchanged array (matches C-A5-027 pattern)
    `const allowedDomains = ["https://app.example.com", "https://api.example.com"];
     function redirectToExternalSecure(targetUrl) {
       if (allowedDomains.includes(targetUrl)) {
         window.location.href = targetUrl;
       }
     }`,
    // Location replace caller
    `const allowed = ["https://app.example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         location.replace(target);
       }
     }`,
    // window.location.replace caller
    `const allowed = ["https://app.example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.replace(target);
       }
     }`,
    // Template literal sink with validated identifier
    `const allowed = ["https://app.example.com"];
     function redirect(target) {
       if (allowed.includes(target)) {
         window.location.href = \`\${target}\`;
       }
     }`,
    // Inverted check where sink is in the matching alternate (else) branch
    `const allowed = ["https://app.example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         throw new Error("untrusted");
       } else {
         window.location.href = target;
       }
     }`
  ];

  for (const code of safeAllowedCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 0, `Expected NO finding for safe allowed case in:\n${code}`);
    }
  }
});

test('criterion 5: rejection and early return supported only when clearly preventing rejected target reaching sink', async () => {
  const safeEarlyReturnCases = [
    // If not allowed, return (block statement)
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         return;
       }
       window.location.href = target;
     }`,
    // If not allowed, return (single statement without block)
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) return;
       window.location.href = target;
     }`,
    // If not allowed, return value
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         return false;
       }
       location.replace(target);
     }`,
    // If not allowed, throw error
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         throw new Error("Destination not allowed");
       }
       window.location.href = target;
     }`,
    // Parenthesized negated includes with return
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!(allowed.includes(target))) {
         return;
       }
       window.location.href = target;
     }`
  ];

  for (const code of safeEarlyReturnCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 0, `Expected NO finding for safe early return in:\n${code}`);
    }
  }

  const unsafeEarlyReturnCases = [
    // Non-returning rejection guard (just logging)
    `const allowed = ["https://example.com"];
     function redirect(target) {
       if (!allowed.includes(target)) {
         console.warn("Invalid destination");
       }
       window.location.href = target;
     }`,
    // Conditional return inside rejection guard
    `const allowed = ["https://example.com"];
     function redirect(target, shouldBypass) {
       if (!allowed.includes(target)) {
         if (!shouldBypass) {
           return;
         }
       }
       window.location.href = target;
     }`
  ];

  for (const code of unsafeEarlyReturnCases) {
    for (const res of await scanBoth(code)) {
      const issues = checkOpenRedirect(res);
      assert.equal(issues.length, 1, `Expected finding for unsafe non-early-return in:\n${code}`);
    }
  }
});

test('active callers parity: assignment and call expression callers agree in both engines', async () => {
  const callers = [
    // Assignment caller: window.location.href
    `const allowed = ["https://example.com"];
     function nav(dest) {
       if (allowed.includes(dest)) {
         window.location.href = dest;
       }
     }`,
    // Assignment caller: location.href
    `const allowed = ["https://example.com"];
     function nav(dest) {
       if (allowed.includes(dest)) {
         location.href = dest;
       }
     }`,
    // Call caller: location.replace
    `const allowed = ["https://example.com"];
     function nav(dest) {
       if (allowed.includes(dest)) {
         location.replace(dest);
       }
     }`,
    // Call caller: window.location.replace
    `const allowed = ["https://example.com"];
     function nav(dest) {
       if (allowed.includes(dest)) {
         window.location.replace(dest);
       }
     }`
  ];

  for (const code of callers) {
    const [webRes, extRes] = await scanBoth(code);
    assert.deepEqual(checkOpenRedirect(webRes), checkOpenRedirect(extRes));
    assert.equal(checkOpenRedirect(webRes).length, 0);
  }
});

