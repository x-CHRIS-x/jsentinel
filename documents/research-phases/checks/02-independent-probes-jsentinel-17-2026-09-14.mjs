/**
 * Independent Verification Probes - Phase 02
 * Verifier: jsentinel-17 (Sonnet 4.6 Thinking, fresh context)
 * Date: 2026-09-14
 * Candidate: eb8ce33fce57b0f77892ed458555165be42d222e
 *
 * These probes are INDEPENDENT of the worker self-check tests.
 * They challenge edge cases, boundary conditions, and logical soundness.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import * as babelParser from '@babel/parser';
import _traverse from '@babel/traverse';
const babelTraverse = _traverse.default || _traverse;

const candidateRoot = 'C:/Users/johnc/.gemini/antigravity-cli/brain/9ba646f0-7d69-42c1-ae8c-277c5542870a/scratch/candidate-wt';
const webSrc = readFileSync(`${candidateRoot}/src/scanner/rules/accessControl.js`, 'utf8');
const extSrc = readFileSync(`${candidateRoot}/vscode-extension/src/scanner/rules.js`, 'utf8');

// ---- INDEPENDENT PROBES ----

test('PROBE-01: Babel emits NumericLiteral for integer literals (indexOf boundary)', () => {
  // The indexOf handler checks `otherNode.type === 'NumericLiteral'`
  // This is correct for @babel/parser. Verify with actual parse.
  const code = `const x = allowed.indexOf(target) !== -1;`;
  const ast = babelParser.parse(code, { sourceType: 'module' });
  let numericType = null;
  babelTraverse(ast, {
    NumericLiteral(p) { numericType = p.node.type; }
  });
  assert.equal(numericType, 'NumericLiteral', '@babel/parser emits NumericLiteral - indexOf handler is correct');
});

test('PROBE-02: parseValidationCondition has NO LogicalExpression handler (OR block)', () => {
  // Critical security property: OR conditions (||) must NOT be allowed to validate.
  // If parseValidationCondition handled LogicalExpression, `allowed.includes(t) || isAdmin`
  // could suppress a real vulnerability.
  const parseCondStart = webSrc.indexOf('function parseValidationCondition');
  const parseCondEnd = webSrc.indexOf('\nfunction doesConsequentUnconditionallyExit');
  const parseCondBody = webSrc.substring(parseCondStart, parseCondEnd);

  assert.equal(
    parseCondBody.includes('LogicalExpression'),
    false,
    'CRITICAL: parseValidationCondition must NOT handle LogicalExpression (OR bypass)'
  );
  // Also check extension parity
  const extParseCondStart = extSrc.indexOf('function parseValidationCondition');
  const extParseCondEnd = extSrc.indexOf('\nfunction doesConsequentUnconditionallyExit');
  const extParseCondBody = extSrc.substring(extParseCondStart, extParseCondEnd);
  assert.equal(
    extParseCondBody.includes('LogicalExpression'),
    false,
    'Extension: parseValidationCondition must NOT handle LogicalExpression'
  );
});

test('PROBE-03: double negation !! is conservatively treated as unsafe (not a hole)', () => {
  // if (!!allowed.includes(target)) { window.location.href = target; }
  // outer ! → calls inner with !includes(target)
  // inner ! → finds includes → returns POSITIVE
  // inner ! returns NEGATED (not POSITIVE)
  // outer ! check: inner.kind === 'POSITIVE'? No → returns null
  // Result: no suppression. Conservative false positive but NOT a security hole.
  const parseCondStart = webSrc.indexOf('function parseValidationCondition');
  const parseCondEnd = webSrc.indexOf('\nfunction doesConsequentUnconditionallyExit');
  const parseCondBody = webSrc.substring(parseCondStart, parseCondEnd);

  // Verify only POSITIVE can be flipped to NEGATED by !
  assert.ok(parseCondBody.includes("inner.kind === 'POSITIVE'"), 'Only POSITIVE flips to NEGATED');
  // Verify NEGATED is not handled (no double negation support = safe)
  const negatedHandlerCount = (parseCondBody.match(/inner\.kind === 'NEGATED'/g) || []).length;
  assert.equal(negatedHandlerCount, 0, 'NEGATED is not re-flipped - double negation is not recognized (conservative)');
});

test('PROBE-04: isDescendant correctly terminates at path root (null parentPath)', () => {
  // isDescendant must terminate. Walk: cur = childPath, advance via parentPath.
  // At root, parentPath is null, loop condition 'while (cur)' exits.
  const descStart = webSrc.indexOf('function isDescendant');
  const descEnd = webSrc.indexOf('\nfunction getValidAllowlistBinding');
  const descBody = webSrc.substring(descStart, descEnd);

  assert.ok(descBody.includes('while (cur)'), 'Loop condition: while (cur)');
  assert.ok(descBody.includes('cur = cur.parentPath'), 'Advances via parentPath');
  // No break/return inside except on match - terminates at null
  assert.ok(!descBody.includes('while (true)'), 'Not an infinite loop');
});

test('PROBE-05: function scope boundary stops Pattern 1 cross-function suppression', () => {
  // Pattern 1 while loop must call isFunction() and break to prevent:
  //   function outer(target) {
  //     if (allowed.includes(target)) {
  //       function inner(target) { window.location.href = target; } // different binding!
  //     }
  //   }
  const isValidatedStart = webSrc.indexOf('function isValidated');
  const pattern1End = webSrc.indexOf('// Pattern 2:');
  const pattern1 = webSrc.substring(isValidatedStart, pattern1End);

  assert.ok(pattern1.includes('isFunction()'), 'Pattern 1 checks isFunction()');
  assert.ok(pattern1.includes('break'), 'Pattern 1 breaks at function boundary');
});

test('PROBE-06: Pattern 2 exception safety - getStatementParent wrapped in try/catch', () => {
  const pattern2 = webSrc.substring(webSrc.indexOf('// Pattern 2:'));
  assert.ok(pattern2.includes('try {'), 'try block for getStatementParent');
  assert.ok(pattern2.includes('} catch'), 'catch block present');
  assert.ok(pattern2.includes('stmt = null'), 'catch nulls stmt on error');
});

test('PROBE-07: exactly 3 files changed between base and candidate', () => {
  const diffOutput = execSync(
    'git diff --name-only 0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4 eb8ce33fce57b0f77892ed458555165be42d222e',
    { cwd: candidateRoot, encoding: 'utf8' }
  ).trim().split('\n').filter(Boolean);

  const expected = [
    'src/scanner/rules/accessControl.js',
    'validation/validation-handling.test.mjs',
    'vscode-extension/src/scanner/rules.js'
  ].sort();

  assert.deepEqual(diffOutput.sort(), expected, 'Exactly 3 expected files changed');
});

test('PROBE-08: no test-samples, dataset, or App.jsx changes in candidate diff', () => {
  const diffOutput = execSync(
    'git diff --name-only 0de4a53aaeb51a787ac5b480e5dbea4942e2f1d4 eb8ce33fce57b0f77892ed458555165be42d222e',
    { cwd: candidateRoot, encoding: 'utf8' }
  ).trim().split('\n').filter(Boolean);

  const forbidden = diffOutput.filter(f =>
    f.includes('test-samples') ||
    f.includes('App.jsx') ||
    f.includes('App.css') ||
    f.includes('data/') ||
    f.includes('guidance') ||
    f.includes('package.json')
  );
  assert.deepEqual(forbidden, [], `No forbidden production/dataset files changed: ${forbidden}`);
});

test('PROBE-09: critical helper functions present in both web and extension scanners', () => {
  const required = [
    'function isDescendant',
    'function getValidAllowlistBinding',
    'function parseValidationCondition',
    'function doesConsequentUnconditionallyExit',
    'function isTargetReassignedInPath',
    'function isValidated'
  ];

  for (const fn of required) {
    assert.ok(webSrc.includes(fn), `Web: ${fn} present`);
    assert.ok(extSrc.includes(fn), `Ext: ${fn} present`);
  }
});

test('PROBE-10: critical logic occurrence counts match between web and extension', () => {
  const checks = [
    "cond.kind === 'POSITIVE'",
    "cond.kind === 'NEGATED'",
    "doesConsequentUnconditionallyExit",
    "isTargetReassignedInPath",
    "parseValidationCondition",
    "getValidAllowlistBinding",
    "isDescendant",
    "isFunction()",
    "getStatementParent",
    "inMatchingBranch"
  ];

  for (const check of checks) {
    const re = new RegExp(check.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    const webCount = (webSrc.match(re) || []).length;
    const extCount = (extSrc.match(re) || []).length;
    assert.equal(webCount, extCount, `"${check}" count: web=${webCount}, ext=${extCount}`);
  }
});

test('PROBE-11: isValidated callers - only AssignmentExpression and CallExpression in both scanners', () => {
  // Count isValidated call sites in both files
  const webCalls = (webSrc.match(/isValidated\(/g) || []).length;
  const extCalls = (extSrc.match(/isValidated\(/g) || []).length;

  // Web: function definition (1) + 4 call sites (AssignmentExpr x2 for href+template, CallExpr x2)
  // In the code we see: path/right.name, expr.name (x2 in each visitor) = 4 total
  assert.ok(webCalls >= 4, `Web has at least 4 isValidated references, got ${webCalls}`);
  // Extension should have the same call structure
  assert.equal(webCalls, extCalls, `Web (${webCalls}) and ext (${extCalls}) have equal isValidated references`);
});

test('PROBE-12: syntax parse of both changed files succeeds without errors', () => {
  for (const [name, src] of [['accessControl.js', webSrc]]) {
    let error = null;
    try {
      babelParser.parse(src, { sourceType: 'module', plugins: ['jsx'], errorRecovery: false });
    } catch (e) {
      error = e;
    }
    assert.equal(error, null, `${name} parses without syntax errors`);
  }

  // Extension file is CommonJS-style (no export keyword at top)
  let error = null;
  try {
    babelParser.parse(extSrc, { sourceType: 'module', plugins: ['jsx'], errorRecovery: false });
  } catch (e) {
    error = e;
  }
  assert.equal(error, null, 'rules.js parses without syntax errors');
});

test('PROBE-13: indexOf >= 0 form is correctly mapped to POSITIVE', () => {
  // allowed.indexOf(target) >= 0 → POSITIVE (found)
  // The code: compVal=0, op='>=' → POSITIVE
  const parseCondStart = webSrc.indexOf('function parseValidationCondition');
  const parseCondEnd = webSrc.indexOf('\nfunction doesConsequentUnconditionallyExit');
  const parseCondBody = webSrc.substring(parseCondStart, parseCondEnd);

  assert.ok(parseCondBody.includes("op === '>='"), '>= operator handled');
  assert.ok(parseCondBody.includes("compVal === 0"), 'compVal=0 case present');
  assert.ok(
    parseCondBody.includes("if (op === '>=') return { kind: 'POSITIVE'"),
    "indexOf >= 0 correctly maps to POSITIVE"
  );
});

test('PROBE-14: doesConsequentUnconditionallyExit only checks last statement in block', () => {
  // CRITICAL: The function checks the LAST statement in a BlockStatement.
  // This means: { console.log('x'); return; } → true (last is return)
  // And: { return; console.log('x'); } → false (last is ExpressionStatement)
  // Wait - { return; console.log('x'); } → last is ExpressionStatement → false
  // But actually unreachable code after return... The implementation is CONSERVATIVE:
  // it only checks the last statement, which means:
  //   if (!allowed.includes(target)) { return; someCode(); } 
  //   → lastStmt is someCode() ExpressionStatement → doesExit = false
  // This is a FALSE POSITIVE (conservative, safe behavior)
  const exitFnStart = webSrc.indexOf('function doesConsequentUnconditionallyExit');
  const exitFnEnd = webSrc.indexOf('\nfunction isTargetReassignedInPath');
  const exitFnBody = webSrc.substring(exitFnStart, exitFnEnd);

  // Verify it checks the LAST statement (body[body.length - 1])
  assert.ok(exitFnBody.includes('body[body.length - 1]'), 'Checks last statement in block');
  assert.ok(exitFnBody.includes('ReturnStatement'), 'Handles ReturnStatement');
  assert.ok(exitFnBody.includes('ThrowStatement'), 'Handles ThrowStatement');
  // Note: single-statement return (no block) is also handled at top of function
  assert.ok(
    exitFnBody.includes("node.type === 'ReturnStatement' || node.type === 'ThrowStatement'"),
    'Handles bare return/throw (no block wrapper)'
  );
});

test('PROBE-15: allowlist must be non-empty array (elements.length === 0 guard)', () => {
  // const allowed = []; → empty array → getValidAllowlistBinding returns null
  // This prevents `if (allowed.includes(target))` with an empty allowlist from suppressing
  const getAllowFnStart = webSrc.indexOf('function getValidAllowlistBinding');
  const getAllowFnEnd = webSrc.indexOf('\nfunction parseValidationCondition');
  const getAllowFnBody = webSrc.substring(getAllowFnStart, getAllowFnEnd);

  assert.ok(
    getAllowFnBody.includes('init.elements.length === 0'),
    'Empty allowlist arrays are rejected'
  );
});
