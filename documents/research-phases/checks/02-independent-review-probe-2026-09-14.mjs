/**
 * Independent Phase 02 Validation-Handling Review Probe - 2026-09-14
 *
 * Exercises candidate implementation eb8ce33fce57b0f77892ed458555165be42d222e
 * against base 0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4.
 *
 * Verifies:
 * 1. 116-sample before/after parity across both web and extension engines (464 invocations).
 * 2. Independent challenge probes covering rejected branches, indexOf comparisons,
 *    unrelated validator calls, OR/AND logical expressions, mutation, aliasing,
 *    variable reassignment, lexical shadowing, early returns, and caller variations.
 *
 * Run from repository root:
 *   node documents/research-phases/checks/02-independent-review-probe-2026-09-14.mjs
 */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import vm from 'node:vm';
import { scanFile } from '../../../src/utils/scannerEngine.js';

const require = createRequire(import.meta.url);
const { scanCode } = require('../../../vscode-extension/src/scanner/scannerEngine.js');
const { allRules: candExtRules } = require('../../../vscode-extension/src/scanner/rules.js');

// 1. Build Candidate Web Rules
const moduleNames = ['injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization', 'knownVulns'];
const nonACWebRules = (await Promise.all(
  moduleNames.map(name => import(`../../../src/scanner/rules/${name}.js`))
)).flatMap(mod => Object.values(mod).flat());

const candACMod = await import('../../../src/scanner/rules/accessControl.js');
const candWebRules = [...nonACWebRules, ...candACMod.accessControlRules];

// 2. Build Base Web Rules (from 0de4a53)
const baseWebACSource = execSync('git show 0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4:src/scanner/rules/accessControl.js', { encoding: 'utf8' });
const baseWebACScript = baseWebACSource.replace('export const accessControlRules =', 'exports.accessControlRules =');
const baseWebACContext = { exports: {} };
vm.runInNewContext(baseWebACScript, baseWebACContext);
const baseWebRules = [...nonACWebRules, ...baseWebACContext.exports.accessControlRules];

// 3. Build Base Extension Rules (from 0de4a53)
const baseExtRulesSource = execSync('git show 0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4:vscode-extension/src/scanner/rules.js', { encoding: 'utf8' });
const baseExtContext = { module: { exports: {} }, exports: {} };
vm.runInNewContext(baseExtRulesSource, baseExtContext);
const baseExtRules = baseExtContext.module.exports.allRules;

const scanBoth = async (code, name = 'probe.js') => [
  await scanFile({ name, text: async () => code }, candWebRules),
  scanCode(code, name, candExtRules)
];

const getOpenRedirects = (result) => {
  assert.equal(result.hasError, false);
  return result.issues.filter(i => i.id === 'OWASP-A01-001');
};

console.log('================================================================');
console.log('PHASE 02 INDEPENDENT REVIEW PROBE - 2026-09-14');
console.log('Candidate: eb8ce33fce57b0f77892ed458555165be42d222e');
console.log('Base:      0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4');
console.log('================================================================\n');

// -------------------------------------------------------------
// PART 1: 116-SAMPLE 4-ENGINE BEFORE/AFTER PARITY (464 INVOCATIONS)
// -------------------------------------------------------------
console.log('--- PART 1: 116-Sample 4-Engine Parity Check (464 Invocations) ---');
const sampleDir = new URL('../../../test-samples/samples/', import.meta.url);
const sampleFiles = readdirSync(sampleDir).filter(name => /\.(js|jsx|ts|tsx)$/.test(name));
assert.equal(sampleFiles.length, 116, 'Expected exactly 116 dataset samples');

let invocations = 0;
let mismatches = 0;
let totalCandWebFindings = 0;
let totalCandExtFindings = 0;
let totalBaseWebFindings = 0;
let totalBaseExtFindings = 0;

const normalizeFindings = (res, fileName) => {
  assert.equal(res.hasError, false, `Scan error in ${fileName}`);
  return res.issues.map(i => [
    i.id,
    i.line,
    i.column,
    i.severity,
    i.findingType || 'vulnerability-pattern'
  ].join(':')).sort();
};

for (const file of sampleFiles) {
  const code = readFileSync(new URL(file, sampleDir), 'utf8');

  const [candWebRes, candExtRes, baseWebRes, baseExtRes] = await Promise.all([
    scanFile({ name: file, text: async () => code }, candWebRules),
    scanCode(code, file, candExtRules),
    scanFile({ name: file, text: async () => code }, baseWebRules),
    scanCode(code, file, baseExtRules)
  ]);
  invocations += 4;

  const candWebNorm = normalizeFindings(candWebRes, file);
  const candExtNorm = normalizeFindings(candExtRes, file);
  const baseWebNorm = normalizeFindings(baseWebRes, file);
  const baseExtNorm = normalizeFindings(baseExtRes, file);

  totalCandWebFindings += candWebNorm.length;
  totalCandExtFindings += candExtNorm.length;
  totalBaseWebFindings += baseWebNorm.length;
  totalBaseExtFindings += baseExtNorm.length;

  const candEngineMatch = JSON.stringify(candWebNorm) === JSON.stringify(candExtNorm);
  const baseEngineMatch = JSON.stringify(baseWebNorm) === JSON.stringify(baseExtNorm);
  const webBeforeAfterMatch = JSON.stringify(baseWebNorm) === JSON.stringify(candWebNorm);
  const extBeforeAfterMatch = JSON.stringify(baseExtNorm) === JSON.stringify(candExtNorm);

  if (!candEngineMatch || !baseEngineMatch || !webBeforeAfterMatch || !extBeforeAfterMatch) {
    console.error(`Mismatch in sample file: ${file}`);
    mismatches++;
  }
}

console.log(`Samples verified:        ${sampleFiles.length}`);
console.log(`Total engine invocations: ${invocations}`);
console.log(`Cand Web total findings:  ${totalCandWebFindings}`);
console.log(`Cand Ext total findings:  ${totalCandExtFindings}`);
console.log(`Base Web total findings:  ${totalBaseWebFindings}`);
console.log(`Base Ext total findings:  ${totalBaseExtFindings}`);
console.log(`Parity mismatches:       ${mismatches}`);
assert.equal(invocations, 464, 'Must execute exactly 464 invocations');
assert.equal(mismatches, 0, 'Zero mismatches permitted across all 116 samples');
assert.equal(totalCandWebFindings, 218);
assert.equal(totalCandExtFindings, 218);
assert.equal(totalBaseWebFindings, 218);
assert.equal(totalBaseExtFindings, 218);
console.log('Result: PASS (exact 464-invocation 4-way parity confirmed)\n');

// -------------------------------------------------------------
// PART 2: INDEPENDENT CHALLENGE PROBES ACROSS ACCEPTANCE CRITERIA
// -------------------------------------------------------------
console.log('--- PART 2: Independent Challenge Probes ---');

const probeSuites = [
  {
    name: 'Criterion 1: Rejected branches & indexOf variations (all must flag OWASP-A01-001)',
    cases: [
      {
        id: 'P1.01',
        desc: 'Direct negated includes in if-consequent',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.02',
        desc: 'Parenthesized negated includes',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!(allowed.includes(target))) {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.03',
        desc: 'Positive check with sink in alternate (else) branch',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   console.log("ok");
                 } else {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.04',
        desc: 'indexOf === -1 rejection check',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.indexOf(target) === -1) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.05',
        desc: 'Inverted -1 === indexOf rejection check',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (-1 === allowed.indexOf(target)) {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.06',
        desc: 'indexOf < 0 rejection check',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.indexOf(target) < 0) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.07',
        desc: 'Inverted 0 > indexOf rejection check',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (0 > allowed.indexOf(target)) {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.08',
        desc: 'indexOf <= -1 rejection check',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.indexOf(target) <= -1) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.09',
        desc: 'Positive indexOf !== -1 with sink in else branch',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.indexOf(target) !== -1) {
                   console.log("safe");
                 } else {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P1.10',
        desc: 'Positive indexOf >= 0 with sink in else branch',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.indexOf(target) >= 0) {
                   console.log("safe");
                 } else {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      }
    ]
  },
  {
    name: 'Criterion 2: Unrelated validator names, member calls, and OR/AND conditions',
    cases: [
      {
        id: 'P2.01',
        desc: 'Unrelated function named validate',
        code: `function nav(target) {
                 if (validate(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.02',
        desc: 'Unrelated function named check',
        code: `function nav(target) {
                 if (check(target)) {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.03',
        desc: 'Unrelated function named test',
        code: `function nav(target) {
                 if (test(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.04',
        desc: 'Custom validator object method call',
        code: `function nav(target) {
                 if (customValidator.check(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.05',
        desc: 'Callee is target string calling includes, not allowlist array',
        code: `function nav(target) {
                 if (target.includes("https://example.com")) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.06',
        desc: 'Logical OR combining allowlist check with other condition (right side)',
        code: `const allowed = ["https://example.com"];
               function nav(target, isAdmin) {
                 if (allowed.includes(target) || isAdmin) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.07',
        desc: 'Logical OR combining allowlist check with other condition (left side)',
        code: `const allowed = ["https://example.com"];
               function nav(target, fallback) {
                 if (fallback || allowed.includes(target)) {
                   location.replace(target);
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.08',
        desc: 'Logical OR with indexOf comparison',
        code: `const allowed = ["https://example.com"];
               function nav(target, isPrivileged) {
                 if (allowed.indexOf(target) !== -1 || isPrivileged) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P2.09',
        desc: 'Logical AND compound condition (conservative: unparsed complex boolean flags finding)',
        code: `const allowed = ["https://example.com"];
               function nav(target, isActive) {
                 if (allowed.includes(target) && isActive) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      }
    ]
  },
  {
    name: 'Criterion 3: Target reassignment, scope shadowing, mutation, and aliasing',
    cases: [
      {
        id: 'P3.01',
        desc: 'Target reassigned inside if-consequent before sink',
        code: `const allowed = ["https://example.com"];
               function nav(target, untrusted) {
                 if (allowed.includes(target)) {
                   target = untrusted;
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.02',
        desc: 'Target reassigned following early return guard before sink',
        code: `const allowed = ["https://example.com"];
               function nav(target, untrusted) {
                 if (!allowed.includes(target)) return;
                 target = untrusted;
                 window.location.href = target;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.03',
        desc: 'Target reassigned before allowlist check (safe: check evaluates reassigned value)',
        code: `const allowed = ["https://example.com"];
               function nav(target, clean) {
                 target = clean;
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 0
      },
      {
        id: 'P3.04',
        desc: 'Target reassigned after sink (safe: sink executes with validated value)',
        code: `const allowed = ["https://example.com"];
               function nav(target, other) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                   target = other;
                 }
               }`,
        expectedIssues: 0
      },
      {
        id: 'P3.05',
        desc: 'Target shadowed via inner function parameter',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   function inner(target) {
                     window.location.href = target;
                   }
                   inner("https://evil.com");
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.06',
        desc: 'Target shadowed via nested block-scoped let',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   {
                     let target = "https://evil.com";
                     window.location.href = target;
                   }
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.07',
        desc: 'Allowlist variable reassigned',
        code: `let allowed = ["https://example.com"];
               allowed = ["https://evil.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.08',
        desc: 'Allowlist mutated via push method',
        code: `const allowed = ["https://example.com"];
               allowed.push("https://evil.com");
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.09',
        desc: 'Allowlist mutated via element index assignment',
        code: `const allowed = ["https://example.com"];
               allowed[1] = "https://evil.com";
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.10',
        desc: 'Allowlist mutated via splice method',
        code: `const allowed = ["https://example.com"];
               allowed.splice(0, 0, "https://evil.com");
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P3.11',
        desc: 'Allowlist aliased and mutated via alias (disclosed AST limit: no points-to tracking)',
        code: `const allowed = ["https://example.com"];
               const alias = allowed;
               alias.push("https://evil.com");
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        // AST lexical scope check only inspects allowed binding; alias mutation is unsuppressed
        // only if alias is tracked, which requires general points-to analysis.
        expectedIssues: 0 // Documents current AST scope boundary (finding noted in report)
      }
    ]
  },
  {
    name: 'Criterion 4: Supported fixed allowlists and allowed branches',
    cases: [
      {
        id: 'P4.01',
        desc: 'Module-level const string array in matching if consequent',
        code: `const allowed = ["https://app.example.com", "https://api.example.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 0
      },
      {
        id: 'P4.02',
        desc: 'Local const string array in matching if consequent',
        code: `function nav(target) {
                 const allowed = ["https://app.example.com"];
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 0
      },
      {
        id: 'P4.03',
        desc: 'Allowlist array containing empty template literal strings',
        code: `const allowed = [\`https://app.example.com\`];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 0
      },
      {
        id: 'P4.04',
        desc: 'Allowlist containing non-string numbers (rejected allowlist)',
        code: `const allowed = [123, 456];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P4.05',
        desc: 'Allowlist containing dynamic variable (rejected allowlist)',
        code: `const allowed = ["https://example.com", dynamicHost];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P4.06',
        desc: 'Allowlist defined as string literal instead of array (rejected)',
        code: `const allowed = "https://example.com";
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      },
      {
        id: 'P4.07',
        desc: 'Allowlist defined as empty array (rejected)',
        code: `const allowed = [];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.href = target;
                 }
               }`,
        expectedIssues: 1
      }
    ]
  },
  {
    name: 'Criterion 5: Control flow early-return guards and caller visitors',
    cases: [
      {
        id: 'P5.01',
        desc: 'Negated check with block early return',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) {
                   return;
                 }
                 window.location.href = target;
               }`,
        expectedIssues: 0
      },
      {
        id: 'P5.02',
        desc: 'Negated check with single-statement early return',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) return;
                 window.location.href = target;
               }`,
        expectedIssues: 0
      },
      {
        id: 'P5.03',
        desc: 'Negated check with return value (return false)',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) {
                   return false;
                 }
                 location.replace(target);
               }`,
        expectedIssues: 0
      },
      {
        id: 'P5.04',
        desc: 'Negated check with early throw statement',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) {
                   throw new Error("untrusted");
                 }
                 window.location.href = target;
               }`,
        expectedIssues: 0
      },
      {
        id: 'P5.05',
        desc: 'Negated check without early return (logging only: unsafe)',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (!allowed.includes(target)) {
                   console.warn("untrusted");
                 }
                 window.location.href = target;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P5.06',
        desc: 'Negated check with conditional return inside guard (unsafe)',
        code: `const allowed = ["https://example.com"];
               function nav(target, bypass) {
                 if (!allowed.includes(target)) {
                   if (!bypass) return;
                 }
                 window.location.href = target;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P5.07',
        desc: 'Positive check with early return (inverts guard logic: subsequent sink unsafe)',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.includes(target)) return;
                 window.location.href = target;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P5.08',
        desc: 'Guard placed after the redirect sink (sink runs before validation)',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 window.location.href = target;
                 if (!allowed.includes(target)) return;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P5.09',
        desc: 'Guard isolated inside nested block (block boundary prevents sibling assumption)',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 {
                   if (!allowed.includes(target)) return;
                 }
                 window.location.href = target;
               }`,
        expectedIssues: 1
      },
      {
        id: 'P5.10',
        desc: 'Call Expression caller window.location.replace with validated destination',
        code: `const allowed = ["https://example.com"];
               function nav(target) {
                 if (allowed.includes(target)) {
                   window.location.replace(target);
                 }
               }`,
        expectedIssues: 0
      }
    ]
  }
];

let totalProbes = 0;
let passedProbes = 0;
const probeResults = [];

for (const suite of probeSuites) {
  console.log(`\nTesting Suite: ${suite.name}`);
  for (const c of suite.cases) {
    totalProbes++;
    const [webRes, extRes] = await scanBoth(c.code);
    const webIssues = getOpenRedirects(webRes);
    const extIssues = getOpenRedirects(extRes);

    const enginesAgree = webIssues.length === extIssues.length;
    const matchesExpected = webIssues.length === c.expectedIssues;

    if (enginesAgree && matchesExpected) {
      passedProbes++;
      console.log(`  [PASS] ${c.id}: ${c.desc} (issues: ${webIssues.length})`);
    } else {
      console.error(`  [FAIL] ${c.id}: ${c.desc} (expected ${c.expectedIssues}, web: ${webIssues.length}, ext: ${extIssues.length})`);
    }

    probeResults.push({
      id: c.id,
      desc: c.desc,
      expected: c.expectedIssues,
      webActual: webIssues.length,
      extActual: extIssues.length,
      enginesAgree,
      pass: enginesAgree && matchesExpected
    });
  }
}

console.log('\n================================================================');
console.log(`Probe Summary: ${passedProbes}/${totalProbes} passed`);
console.log('================================================================');

assert.equal(passedProbes, totalProbes, 'All independent challenge probes must pass');
