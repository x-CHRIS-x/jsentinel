import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import * as babelParser from '@babel/parser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const require = createRequire(import.meta.url);
const { scanCode } = require('../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../vscode-extension/src/scanner/rules.js');
const { scanFile } = await import('../src/utils/scannerEngine.js');

const moduleNames = [
  'injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization',
  'knownVulns', 'accessControl'
];
const webRules = (await Promise.all(moduleNames.map(name =>
  import(`../src/scanner/rules/${name}.js`)
))).flatMap(module => Object.values(module).flat());

const PILOT_FILES = [
  'V-A5-027.js', 'C-A5-027.js',
  'V-A3-023.js', 'C-A3-023.js',
  'V-A1-007.js', 'C-A1-007.js',
  'V-A1-009.js', 'C-A1-009.js',
  'V-A7-039.js', 'C-A7-039.js',
  'V-A8-049.js', 'C-A8-049.js'
];

test('1. Total 116 dataset files preserved and untouched 104 match baseline hashes', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  const files = fs.readdirSync(samplesDir);
  assert.equal(files.length, 116, 'Total files in test-samples/samples must be exactly 116');

  const vFiles = files.filter(f => f.startsWith('V-'));
  const cFiles = files.filter(f => f.startsWith('C-'));
  const sFiles = files.filter(f => !f.startsWith('V-') && !f.startsWith('C-'));

  assert.equal(vFiles.length, 54, 'Exactly 54 vulnerable samples');
  assert.equal(cFiles.length, 54, 'Exactly 54 clean samples');
  assert.equal(sFiles.length, 8, 'Exactly 8 scenario samples');

  // Verify baseline hash file
  const hashFile = path.join(rootDir, 'documents', 'research-phases', 'checks', '04-baseline-hashes.json');
  assert.ok(fs.existsSync(hashFile), '04-baseline-hashes.json must exist');
  const baseline = JSON.parse(fs.readFileSync(hashFile, 'utf8'));

  // All 104 unreviewed files must match their baseline SHA-256 hashes exactly
  const pilotSet = new Set(PILOT_FILES);
  for (const entry of baseline.files) {
    if (!pilotSet.has(entry.fileName)) {
      const currentContent = fs.readFileSync(path.join(samplesDir, entry.fileName));
      const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
      assert.equal(currentHash, entry.sha256, `Untouched file ${entry.fileName} must match baseline hash`);
    }
  }
});

test('2. Manifest ground truth schema, threat models, and explicit unreviewed status', () => {
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  assert.ok(fs.existsSync(manifestPath), 'dataset-manifest.json must exist');

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.phase, 'Phase 04 Batch A');
  assert.equal(manifest.datasetSummary.totalFiles, 116);
  assert.equal(manifest.datasetSummary.reviewedPilotFilesCount, 12);
  assert.equal(manifest.datasetSummary.pendingReviewFilesCount, 104);
  assert.equal(manifest.coverageStatus.partialCoverageExplicit, true);

  assert.equal(manifest.files.length, 116, 'Manifest must contain all 116 entries');

  const reviewedFiles = manifest.files.filter(f => f.reviewStatus.coverage === 'pilot-reviewed');
  assert.equal(reviewedFiles.length, 12, 'Exactly 12 files are pilot-reviewed');

  const pendingFiles = manifest.files.filter(f => f.reviewStatus.coverage !== 'pilot-reviewed');
  assert.equal(pendingFiles.length, 104, 'Exactly 104 files are pending review');

  // Verify pilot ground truth and threat modeling schema
  for (const pf of reviewedFiles) {
    assert.ok(pf.sampleId, `${pf.fileName} must have sampleId`);
    assert.ok(pf.pairId, `${pf.fileName} must have pairId`);
    assert.ok(pf.primaryModule, `${pf.fileName} must have primaryModule`);
    assert.ok(pf.intendedBehavior, `${pf.fileName} must have intendedBehavior`);
    assert.ok(pf.securityGroundTruth.rationale, `${pf.fileName} must have security ground truth rationale`);
    assert.ok(Array.isArray(pf.securityGroundTruth.sourceReferences), `${pf.fileName} must have sourceReferences array`);
    assert.ok(pf.securityGroundTruth.sourceReferences.length > 0, `${pf.fileName} must have sourceReferences`);

    // Threat model & scenario assumptions
    assert.ok(pf.threatModelAndAssumptions.trustBoundary, `${pf.fileName} must define trustBoundary`);
    assert.ok(pf.threatModelAndAssumptions.attackerControlledInput, `${pf.fileName} must define attackerControlledInput`);
    assert.ok(pf.threatModelAndAssumptions.executionEnvironment, `${pf.fileName} must define executionEnvironment`);
    assert.ok(pf.threatModelAndAssumptions.impactSupportingSeverity, `${pf.fileName} must define impactSupportingSeverity`);
    assert.ok(pf.threatModelAndAssumptions.safePartnerAssumptions, `${pf.fileName} must define safePartnerAssumptions`);

    // Clean pilot files must have expectedScannerFindings as empty array [] (verified zero findings)
    if (pf.label === 'clean') {
      assert.deepEqual(pf.expectedScannerFindings, [], `${pf.fileName} clean pilot must have expectedScannerFindings: []`);
    } else {
      assert.ok(pf.expectedScannerFindings.length > 0, `${pf.fileName} vulnerable pilot must have findings`);
    }

    assert.equal(pf.reviewStatus.aiReviewer, 'Agy (Gemini 3.8 Flash High)');
    assert.equal(pf.reviewStatus.humanReview, 'PENDING');
  }

  // Verify pending files: isVulnerable is null, expectedScannerFindings is null (distinguishable from []), developmentUse documented
  for (const pend of pendingFiles) {
    assert.equal(pend.securityGroundTruth.isVulnerable, null, `${pend.fileName} isVulnerable must be null until reviewed`);
    assert.equal(pend.expectedScannerFindings, null, `${pend.fileName} expectedScannerFindings must be null (unknown, not verified none)`);
    assert.ok(pend.legacyClassification.legacyLabel, `${pend.fileName} must preserve legacyLabel`);
    assert.equal(pend.legacyClassification.source, 'filename-prefix');
    assert.equal(pend.developmentUse, true);
    assert.ok(pend.developmentUseRationale, `${pend.fileName} must have developmentUseRationale`);
  }
});

test('3. All 12 pilot sample files parse cleanly with Babel AST parser', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  for (const fileName of PILOT_FILES) {
    const filePath = path.join(samplesDir, fileName);
    const code = fs.readFileSync(filePath, 'utf8');
    assert.doesNotThrow(() => {
      babelParser.parse(code, {
        sourceType: 'module',
        plugins: ['jsx']
      });
    }, `File ${fileName} must be syntactically valid JavaScript`);
  }
});

test('4. Bounded runtime execution of actual pilot sample code in isolated VM contexts', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');

  // A. Redirects (PAIR-027): Execute actual sample code V-A5-027.js and C-A5-027.js
  // Disclosed fixture context: minimal mock window object tracking window.location.href.
  {
    const vCode = fs.readFileSync(path.join(samplesDir, 'V-A5-027.js'), 'utf8');
    const vWindow = { location: { href: 'https://app.example.com/initial' } };
    const vContext = vm.createContext({ window: vWindow });
    vm.runInContext(vCode, vContext);

    // Call actual sample function redirectToExternal loaded from V-A5-027.js
    assert.equal(typeof vContext.redirectToExternal, 'function', 'V-A5-027 must declare redirectToExternal');
    vContext.redirectToExternal('https://phishing.evil.com/login');
    assert.equal(vWindow.location.href, 'https://phishing.evil.com/login',
      'V-A5-027 unconditionally navigates to unvalidated external destination');

    const cCode = fs.readFileSync(path.join(samplesDir, 'C-A5-027.js'), 'utf8');
    const cWindow = { location: { href: 'https://app.example.com/initial' } };
    const cContext = vm.createContext({ window: cWindow });
    vm.runInContext(cCode, cContext);

    // Call actual sample function redirectToExternalSecure loaded from C-A5-027.js
    assert.equal(typeof cContext.redirectToExternalSecure, 'function', 'C-A5-027 must declare redirectToExternalSecure');
    // Non-allowlisted destination rejected: location remains initial
    cContext.redirectToExternalSecure('https://phishing.evil.com/login');
    assert.equal(cWindow.location.href, 'https://app.example.com/initial',
      'C-A5-027 rejects non-allowlisted destination');
    // Allowlisted destination accepted: location updates
    cContext.redirectToExternalSecure('https://api.example.com');
    assert.equal(cWindow.location.href, 'https://api.example.com',
      'C-A5-027 permits navigation to allowlisted destination');
  }

  // B. Object Merge (PAIR-049): Execute actual sample code V-A8-049.js and C-A8-049.js
  // Evaluates prototype pollution on target using JSON-parsed own __proto__ payload.
  {
    const untrustedPayload = JSON.parse('{"__proto__": {"pollutedPilot": true}}');

    // Vulnerable: V-A8-049.js uses Object.assign(defaultConfig, userPayload)
    const vCode = fs.readFileSync(path.join(samplesDir, 'V-A8-049.js'), 'utf8');
    const vContext = vm.createContext({ Object, JSON });
    vm.runInContext(vCode, vContext);

    assert.equal(typeof vContext.mergeConfigurations, 'function', 'V-A8-049 must declare mergeConfigurations');
    const vTarget = { theme: 'dark' };
    vContext.mergeConfigurations(vTarget, untrustedPayload);
    assert.equal(vTarget.pollutedPilot, true,
      'V-A8-049 Object.assign copies own __proto__ property, mutating target prototype chain');

    // Clean: C-A8-049.js uses sanitizeInputProperties and merges into fresh object {}
    const cCode = fs.readFileSync(path.join(samplesDir, 'C-A8-049.js'), 'utf8');
    const cContext = vm.createContext({ Object, JSON });
    vm.runInContext(cCode, cContext);

    assert.equal(typeof cContext.mergeConfigurationsSecure, 'function', 'C-A8-049 must declare mergeConfigurationsSecure');
    assert.equal(typeof cContext.sanitizeInputProperties, 'function', 'C-A8-049 must declare sanitizeInputProperties');
    const cTarget = { theme: 'dark' };
    const cleanResult = cContext.mergeConfigurationsSecure(cTarget, untrustedPayload);
    assert.equal(cTarget.pollutedPilot, undefined,
      'C-A8-049 base config target is not mutated in-place');
    assert.equal(cleanResult.pollutedPilot, undefined,
      'C-A8-049 clean result excludes polluted prototype properties');
    assert.equal(Object.prototype.hasOwnProperty.call(cleanResult, '__proto__'), false,
      'C-A8-049 clean result does not contain own __proto__ property');
  }

  // C. Function-Result Helper and Sink Contracts (PAIR-009): Execute V-A1-009.js and C-A1-009.js
  // Disclosed fixture context: records property assignments to sink properties.
  {
    const vCode = fs.readFileSync(path.join(samplesDir, 'V-A1-009.js'), 'utf8');
    const vContext = vm.createContext({});
    vm.runInContext(vCode, vContext);

    assert.equal(typeof vContext.getRawHtmlFromEndpoint, 'function', 'V-A1-009 must declare getRawHtmlFromEndpoint');
    assert.equal(typeof vContext.updateContent, 'function', 'V-A1-009 must declare updateContent');

    // Helper returns attacker-controlled markup string
    const attackMarkup = '<img src=x onerror=alert(1)>';
    const returnedMarkup = vContext.getRawHtmlFromEndpoint({ htmlContent: attackMarkup });
    assert.equal(returnedMarkup, attackMarkup, 'V-A1-009 helper returns raw markup from endpoint source');

    // updateContent assigns helper return value to container.innerHTML sink property
    const vContainer = { innerHTML: '' };
    vContext.updateContent(vContainer, { htmlContent: attackMarkup });
    assert.equal(vContainer.innerHTML, attackMarkup,
      'V-A1-009 transports unneutralized markup payload directly to innerHTML sink');

    const cCode = fs.readFileSync(path.join(samplesDir, 'C-A1-009.js'), 'utf8');
    const cContext = vm.createContext({});
    vm.runInContext(cCode, cContext);

    assert.equal(typeof cContext.getCleanTextFromEndpoint, 'function', 'C-A1-009 must declare getCleanTextFromEndpoint');
    assert.equal(typeof cContext.updateContentSecure, 'function', 'C-A1-009 must declare updateContentSecure');

    // Helper returns plain text string
    const cleanText = 'Safe notification text';
    const returnedText = cContext.getCleanTextFromEndpoint({ textContent: cleanText });
    assert.equal(returnedText, cleanText, 'C-A1-009 helper returns plain text string');

    // updateContentSecure assigns helper return value to container.textContent sink property
    const cContainer = { textContent: '' };
    cContext.updateContentSecure(cContainer, { textContent: cleanText });
    assert.equal(cContainer.textContent, cleanText,
      'C-A1-009 transports plain text string to textContent sink');
  }

  // D. Disclosed Boundary for Live Browser DOM Execution:
  // Live browser parsing, DOM Element tree construction, and script/event dispatch (such as
  // onerror event execution during image load failure) require a browser rendering engine and
  // are explicitly NOT RUN in this Node.js test harness. Asserting string property assignment
  // proves sink data transport and helper contracts; authoritative security distinction
  // between innerHTML (HTML parser execution per HTML Living Standard Section 4.12.1.2) and
  // textContent (character data rendering per HTML Living Standard Section 2.5.3) is established
  // via web platform specifications and AST code structure, not tautological mock objects.
});

test('5. Scanner observations match expected findings (distinct from ground truth proof)', async () => {
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');

  for (const fileName of PILOT_FILES) {
    const manifestEntry = manifest.files.find(f => f.fileName === fileName);
    assert.ok(manifestEntry, `Manifest entry found for ${fileName}`);

    const filePath = path.join(samplesDir, fileName);
    const code = fs.readFileSync(filePath, 'utf8');

    const extResult = scanCode(code, fileName, allRules);
    const webResult = await scanFile({ name: fileName, text: async () => code }, webRules);

    assert.equal(extResult.hasError, false, `${fileName} extension scan hasError must be false`);
    assert.equal(webResult.hasError, false, `${fileName} web scan hasError must be false`);

    // Verify expected findings count
    const expected = manifestEntry.expectedScannerFindings;
    assert.equal(extResult.issues.length, expected.length, `${fileName} extension issues count mismatch`);
    assert.equal(webResult.issues.length, expected.length, `${fileName} web issues count mismatch`);

    for (let i = 0; i < expected.length; i++) {
      const exp = expected[i];
      const extIssue = extResult.issues[i];
      const webIssue = webResult.issues[i];

      assert.equal(extIssue.id, exp.ruleId, `${fileName} issue ${i} ID mismatch`);
      assert.equal(webIssue.id, exp.ruleId, `${fileName} web issue ${i} ID mismatch`);

      assert.equal(extIssue.severity, exp.severity, `${fileName} issue ${i} severity mismatch`);
      assert.equal(webIssue.severity, exp.severity, `${fileName} web issue ${i} severity mismatch`);

      assert.equal(extIssue.line, exp.location.line, `${fileName} issue ${i} line mismatch`);
      assert.equal(webIssue.line, exp.location.line, `${fileName} web issue ${i} line mismatch`);

      assert.equal(extIssue.column, exp.location.column, `${fileName} issue ${i} column mismatch`);
      assert.equal(webIssue.column, exp.location.column, `${fileName} web issue ${i} column mismatch`);
    }
  }
});
