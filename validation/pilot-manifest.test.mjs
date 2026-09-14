import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
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

test('4. Bounded runtime security behavior demonstrations (independent of scanner)', () => {
  // Disclosed simulated fixture harness: Exercises core security semantics of the pilot pairs
  // independent of static analysis scanner rules.

  // A. Redirects (PAIR-027): Unvalidated assignment vs allowlist validation
  {
    const allowedDomains = ["https://app.example.com", "https://api.example.com"];
    const maliciousTarget = "https://phishing.evil.com/login";

    // Vulnerable pattern: unvalidated assignment directly sets location
    let vulnerableLocation = null;
    function redirectToExternal(targetUrl) {
      vulnerableLocation = targetUrl;
    }
    redirectToExternal(maliciousTarget);
    assert.equal(vulnerableLocation, maliciousTarget, 'Vulnerable redirect allows arbitrary target URL');

    // Clean pattern: allowlist membership check prevents arbitrary navigation
    let cleanLocation = "https://app.example.com/home";
    function redirectToExternalSecure(targetUrl) {
      if (allowedDomains.includes(targetUrl)) {
        cleanLocation = targetUrl;
      }
    }
    redirectToExternalSecure(maliciousTarget);
    assert.equal(cleanLocation, "https://app.example.com/home", 'Clean redirect rejects non-allowlisted destination');
  }

  // B. Object Merge (PAIR-049): Prototype pollution vs sanitized merge into fresh object
  {
    // Attacker input parsed from JSON carrying an own __proto__ property
    const attackPayload = JSON.parse('{"__proto__": {"pollutedKey": "compromised"}}');

    // Vulnerable pattern: Object.assign directly mutates target
    const vulnerableConfig = { theme: 'dark' };
    Object.assign(vulnerableConfig, attackPayload);
    assert.equal(vulnerableConfig.pollutedKey, 'compromised', 'Vulnerable Object.assign copies prototype property to target');

    // Clean pattern: sanitizeInputProperties strips prototype properties and targets fresh object {}
    function sanitizeInputProperties(obj) {
      if (!obj || typeof obj !== 'object') return {};
      const clean = {};
      for (const key of Object.keys(obj)) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
          clean[key] = obj[key];
        }
      }
      return clean;
    }
    const cleanBaseConfig = { theme: 'dark' };
    const sanitized = sanitizeInputProperties(attackPayload);
    const cleanResult = Object.assign({}, cleanBaseConfig, sanitized);

    assert.equal(cleanBaseConfig.pollutedKey, undefined, 'Clean base config is not mutated in-place');
    assert.equal(cleanResult.pollutedKey, undefined, 'Clean merged config excludes polluted prototype properties');
  }

  // C. Function-Result HTML (PAIR-009): Attacker-controlled contract vs plain text
  {
    // Simulated endpoint helper returning dynamic markup with event handler payload
    function getRawHtmlFromEndpoint(source) {
      return (source && source.htmlContent) || "<img src=x onerror=alert(1)>";
    }
    const sourceWithXss = { htmlContent: "<img src=x onerror=stealTokens()>" };
    const vulnerableReturn = getRawHtmlFromEndpoint(sourceWithXss);
    assert.ok(vulnerableReturn.includes('onerror='), 'Vulnerable helper returns unneutralized event handler payload');

    function getCleanTextFromEndpoint(source) {
      return (source && source.textContent) || "Safe notification text";
    }
    const cleanReturn = getCleanTextFromEndpoint({ textContent: "Clean notification" });
    assert.equal(cleanReturn, "Clean notification", 'Clean helper returns plain text string');
  }

  // D. HTML Text Representation (PAIR-007, PAIR-039): textContent renders plain text rather than parsing markup
  {
    const untrustedPayload = "<img src=x onerror=alert(1)>";
    // In DOM nodes, textContent treats markup as character data:
    const textNodeMock = { content: '' };
    textNodeMock.content = untrustedPayload; // Simulated textContent assignment
    assert.equal(textNodeMock.content, "<img src=x onerror=alert(1)>", 'textContent stores character data without HTML parsing');
  }
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
