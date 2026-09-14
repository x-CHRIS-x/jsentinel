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

const PILOT_HASHES = {
  'V-A5-027.js': '102c5f42615175b8d4c67533f83d472ac4905eaf4ee96215f908a193dc987ee3',
  'C-A5-027.js': '664fa83fe850b77a04837cabfe4151db81d9b60a25b9b35c4e2ff9923e20b0dc',
  'V-A3-023.js': '7f6b0c5425c2fac8fb5383b72987e74703b9032a78994bc8ecf9967eeab93357',
  'C-A3-023.js': 'edef15bf96c01e9718e8777e1899117115b162d7bf3c6052be8203d64f29de84',
  'V-A1-007.js': 'e2a7e07d93a335267d01900b435d1b4f66e0b128fecaae35e011194e9d18eda4',
  'C-A1-007.js': 'ebf989d38ec99089decb8f9d7c29f55844cb0880cc5d96a4e702ba70c40837b3',
  'V-A1-009.js': '49e36a47469c63c436e4944518190d62b59a93382af60a3342a7b5b5163bd14c',
  'C-A1-009.js': '20c97e0954e0286a64c610607f6b448375744afed37529601da50f2df55819d6',
  'V-A7-039.js': '4a3fe5cc126186b8ea61561afec6e4655c5fe0785bac8932e45bdc255b4d0aad',
  'C-A7-039.js': '69478b8c252dd2c2803d873d568859e053195d0c08bdae2c8a4963b041923e59',
  'V-A8-049.js': 'f97d172dfe6be3a35fb06d6d18b7134b8e87e46618be10e8c8a386df45d5c436',
  'C-A8-049.js': '3b3b24c35dfc88efdea1be6d55800fca8d77d66e19e6a4d6498c02d1a1e777c1'
};

test('1. Total 116 dataset files: 108 controlled and 8 scenarios with baseline hash preservation', () => {
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

  // All 8 scenario files must match their baseline SHA-256 hashes byte-for-byte
  for (const entry of baseline.files) {
    if (!entry.fileName.startsWith('V-') && !entry.fileName.startsWith('C-')) {
      const currentContent = fs.readFileSync(path.join(samplesDir, entry.fileName));
      const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
      assert.equal(currentHash, entry.sha256, `Scenario file ${entry.fileName} must match baseline hash`);
    }
  }

  // All 12 pilot files must match their committed pilot hashes byte-for-byte
  for (const [pName, expectedHash] of Object.entries(PILOT_HASHES)) {
    const currentContent = fs.readFileSync(path.join(samplesDir, pName));
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
    assert.equal(currentHash, expectedHash, `Pilot file ${pName} must match committed pilot hash`);
  }
});

test('2. Manifest ground truth schema, threat models, and Batch B controlled review status', () => {
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  assert.ok(fs.existsSync(manifestPath), 'dataset-manifest.json must exist');

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.phase, 'Phase 04 Batch B');
  assert.equal(manifest.datasetSummary.totalFiles, 116);
  assert.equal(manifest.datasetSummary.controlledFilesCount, 108);
  assert.equal(manifest.datasetSummary.scenarioFilesCount, 8);
  assert.equal(manifest.datasetSummary.reviewedControlledFilesCount, 108);
  assert.equal(manifest.datasetSummary.pendingReviewFilesCount, 8);

  assert.equal(manifest.files.length, 116, 'Manifest must contain all 116 entries');

  const controlledFiles = manifest.files.filter(f => f.reviewStatus.coverage !== 'pending-batch-c');
  assert.equal(controlledFiles.length, 108, 'Exactly 108 files are controlled reviewed');

  const scenarioFiles = manifest.files.filter(f => f.reviewStatus.coverage === 'pending-batch-c');
  assert.equal(scenarioFiles.length, 8, 'Exactly 8 files are pending Batch C review');

  // Verify controlled ground truth and threat modeling schema
  for (const cf of controlledFiles) {
    assert.ok(cf.sampleId, `${cf.fileName} must have sampleId`);
    assert.ok(cf.pairId, `${cf.fileName} must have pairId`);
    assert.ok(cf.primaryModule, `${cf.fileName} must have primaryModule`);
    assert.ok(cf.intendedBehavior, `${cf.fileName} must have intendedBehavior`);
    assert.ok(cf.securityGroundTruth.rationale, `${cf.fileName} must have security ground truth rationale`);
    assert.ok(Array.isArray(cf.securityGroundTruth.sourceReferences), `${cf.fileName} must have sourceReferences array`);
    assert.ok(cf.securityGroundTruth.sourceReferences.length > 0, `${cf.fileName} must have sourceReferences`);

    // Threat model & scenario assumptions
    assert.ok(cf.threatModelAndAssumptions.trustBoundary, `${cf.fileName} must define trustBoundary`);
    assert.ok(cf.threatModelAndAssumptions.attackerControlledInput, `${cf.fileName} must define attackerControlledInput`);
    assert.ok(cf.threatModelAndAssumptions.executionEnvironment, `${cf.fileName} must define executionEnvironment`);
    assert.ok(cf.threatModelAndAssumptions.impactSupportingSeverity, `${cf.fileName} must define impactSupportingSeverity`);
    assert.ok(cf.threatModelAndAssumptions.safePartnerAssumptions, `${cf.fileName} must define safePartnerAssumptions`);

    if (cf.label === 'clean') {
      assert.equal(cf.securityGroundTruth.isVulnerable, false, `${cf.fileName} clean ground truth isVulnerable must be false`);
      assert.deepEqual(cf.expectedScannerFindings, [], `${cf.fileName} clean must have expectedScannerFindings: []`);
    } else {
      assert.equal(cf.securityGroundTruth.isVulnerable, true, `${cf.fileName} vulnerable ground truth isVulnerable must be true`);
      assert.ok(cf.securityGroundTruth.flawType, `${cf.fileName} vulnerable must define flawType CWE`);
    }

    assert.equal(cf.reviewStatus.aiReviewer, 'Agy (Gemini 3.8 Flash High)');
    assert.equal(cf.reviewStatus.humanReview, 'PENDING');
  }

  // Verify scenario files: isVulnerable is null, expectedScannerFindings is null
  for (const sc of scenarioFiles) {
    assert.equal(sc.securityGroundTruth.isVulnerable, null, `${sc.fileName} isVulnerable must be null until Batch C`);
    assert.equal(sc.expectedScannerFindings, null, `${sc.fileName} expectedScannerFindings must be null`);
    assert.equal(sc.reviewStatus.coverage, 'pending-batch-c');
    assert.equal(sc.developmentUse, true);
  }
});

test('3. All 116 dataset files parse cleanly with Babel AST parser', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  const files = fs.readdirSync(samplesDir).filter(name => /\.(js|jsx)$/.test(name));
  assert.equal(files.length, 116);
  for (const fileName of files) {
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
