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

  // Verify baseline hash file exists for historical provenance
  const baselineHashFile = path.join(rootDir, 'documents', 'research-phases', 'checks', '04-baseline-hashes.json');
  assert.ok(fs.existsSync(baselineHashFile), '04-baseline-hashes.json must exist');

  // Verify controlled 108 hash file (preserved from starting commit c650be9)
  const controlledHashFile = path.join(rootDir, 'documents', 'research-phases', 'checks', '04-batch-c-controlled-108-hashes.json');
  assert.ok(fs.existsSync(controlledHashFile), '04-batch-c-controlled-108-hashes.json must exist');
  const controlledData = JSON.parse(fs.readFileSync(controlledHashFile, 'utf8'));
  assert.equal(Object.keys(controlledData.hashes).length, 108, 'Must verify 108 controlled files');

  for (const [fileName, expectedHash] of Object.entries(controlledData.hashes)) {
    const currentContent = fs.readFileSync(path.join(samplesDir, fileName));
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
    assert.equal(currentHash, expectedHash, `Controlled file ${fileName} must match starting commit hash`);
  }

  // Verify scenario 8 hash file
  const scenarioHashFile = path.join(rootDir, 'documents', 'research-phases', 'checks', '04-batch-c-scenario-hashes.json');
  assert.ok(fs.existsSync(scenarioHashFile), '04-batch-c-scenario-hashes.json must exist');
  const scenarioData = JSON.parse(fs.readFileSync(scenarioHashFile, 'utf8'));
  assert.equal(Object.keys(scenarioData.scenarioHashes).length, 8, 'Must verify 8 scenario files');

  for (const [fileName, expectedHash] of Object.entries(scenarioData.scenarioHashes)) {
    const currentContent = fs.readFileSync(path.join(samplesDir, fileName));
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
    assert.equal(currentHash, expectedHash, `Scenario file ${fileName} must match Batch C scenario hash`);
  }

  // All 12 pilot files must match their committed pilot hashes byte-for-byte
  for (const [pName, expectedHash] of Object.entries(PILOT_HASHES)) {
    const currentContent = fs.readFileSync(path.join(samplesDir, pName));
    const currentHash = crypto.createHash('sha256').update(currentContent).digest('hex');
    assert.equal(currentHash, expectedHash, `Pilot file ${pName} must match committed pilot hash`);
  }
});

test('2. Manifest ground truth schema, threat models, and Batch C complete review status', () => {
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  assert.ok(fs.existsSync(manifestPath), 'dataset-manifest.json must exist');

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.phase, 'Phase 04 Batch C');
  assert.equal(manifest.datasetSummary.totalFiles, 116);
  assert.equal(manifest.datasetSummary.controlledFilesCount, 108);
  assert.equal(manifest.datasetSummary.scenarioFilesCount, 8);
  assert.equal(manifest.datasetSummary.reviewedControlledFilesCount, 108);
  assert.equal(manifest.datasetSummary.reviewedScenarioFilesCount, 8);
  assert.equal(manifest.datasetSummary.pendingReviewFilesCount, 0);

  assert.equal(manifest.files.length, 116, 'Manifest must contain all 116 entries');

  const controlledFiles = manifest.files.filter(f => f.primaryModule !== 'scenario');
  assert.equal(controlledFiles.length, 108, 'Exactly 108 files are controlled reviewed');

  const scenarioFiles = manifest.files.filter(f => f.primaryModule === 'scenario');
  assert.equal(scenarioFiles.length, 8, 'Exactly 8 files are scenario workloads');

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

  // Verify scenario files in Batch C: isVulnerable is true, expectedScannerFindings non-empty array
  for (const sc of scenarioFiles) {
    assert.equal(sc.securityGroundTruth.isVulnerable, true, `${sc.fileName} isVulnerable must be true`);
    assert.ok(Array.isArray(sc.expectedScannerFindings), `${sc.fileName} expectedScannerFindings must be an array`);
    assert.ok(sc.expectedScannerFindings.length > 0, `${sc.fileName} expectedScannerFindings must be non-empty`);
    assert.ok(Array.isArray(sc.expectedAdvisories), `${sc.fileName} expectedAdvisories must be an array`);
    assert.ok(Array.isArray(sc.unsupportedWeaknesses), `${sc.fileName} unsupportedWeaknesses must be an array`);
    assert.equal(sc.reviewStatus.coverage, 'scenario-reviewed');
    assert.equal(sc.developmentUse, true);
    assert.ok(sc.browserContext, `${sc.fileName} must define browserContext`);
    assert.ok(sc.threatModelAndAssumptions.trustBoundary, `${sc.fileName} must define trustBoundary`);
    assert.ok(sc.threatModelAndAssumptions.attackerControlledInput, `${sc.fileName} must define attackerControlledInput`);
    assert.ok(sc.threatModelAndAssumptions.executionEnvironment, `${sc.fileName} must define executionEnvironment`);
    assert.ok(sc.threatModelAndAssumptions.impactSupportingSeverity, `${sc.fileName} must define impactSupportingSeverity`);
    assert.ok(sc.threatModelAndAssumptions.safePartnerAssumptions, `${sc.fileName} must define safePartnerAssumptions`);
    assert.equal(sc.reviewStatus.aiReviewer, 'Agy (Gemini 3.8 Flash High)');
    assert.equal(sc.reviewStatus.humanReview, 'PENDING');
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
  // between innerHTML (Dynamic markup insertion per WHATWG HTML Living Standard Section 8.4) and
  // textContent (Interface Node attribute per WHATWG DOM Standard Section 4.2.3) is established
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

test('6. Batch B bounded corrections: isolated VM execution of updated clean helpers and contracts', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  // 1. Partial coverage explicit flag and scenario status
  assert.equal(manifest.coverageStatus.partialCoverageExplicit, false, 'partialCoverageExplicit must be false when all 116 files are reviewed');
  assert.equal(manifest.datasetSummary.scenarioFilesCount, 8);
  assert.equal(manifest.datasetSummary.reviewedPilotFilesCount, 12);
  assert.equal(manifest.datasetSummary.reviewedControlledFilesCount, 108);
  assert.equal(manifest.datasetSummary.reviewedScenarioFilesCount, 8);

  // 2. Verified 12 pilot metadata preservation
  const pilotManifestFiles = manifest.files.filter(f => f.reviewStatus.coverage === 'pilot-reviewed');
  assert.equal(pilotManifestFiles.length, 12, 'Exactly 12 files must retain pilot-reviewed status');

  // 3. developmentUseRationale distinguishes baseline vs newly updated Batch B files
  const batchBFiles = manifest.files.filter(f => f.reviewStatus.coverage === 'controlled-reviewed');
  assert.equal(batchBFiles.length, 96, 'Exactly 96 non-pilot controlled files in Batch B');
  for (const f of batchBFiles) {
    assert.ok(f.developmentUseRationale.includes('updated in Phase 04 Batch B'),
      `${f.fileName} must state updated in Phase 04 Batch B in developmentUseRationale`);
  }

  // 4. Crypto OTP & Secret Key (C-A2-017): 256-bit secret key and 6-digit OTP
  {
    const code = fs.readFileSync(path.join(samplesDir, 'C-A2-017.js'), 'utf8');
    const context = vm.createContext({ crypto: crypto.webcrypto, Uint8Array, Uint32Array, String, Array });
    vm.runInContext(code, context);

    assert.equal(typeof context.generateUserOtpSecretSecure, 'function');
    const result = context.generateUserOtpSecretSecure();
    assert.match(result.otp, /^\d{6}$/, 'OTP must be 6 decimal digits');
    assert.ok(result.otp_key.startsWith('secure_'), 'otp_key must start with secure_');
    const hexKey = result.otp_key.slice('secure_'.length);
    assert.equal(hexKey.length, 64, '256-bit secret key formatted as 64 hex characters (32 bytes entropy)');
  }

  // 5. Schema Validation & Privilege Isolation (C-A8-045)
  {
    const code = fs.readFileSync(path.join(samplesDir, 'C-A8-045.js'), 'utf8');
    const context = vm.createContext({ JSON, Error });
    vm.runInContext(code, context);

    assert.equal(typeof context.validateSessionSchema, 'function', 'validateSessionSchema must be defined');
    assert.equal(typeof context.loadSessionStateSecure, 'function', 'loadSessionStateSecure must be defined');

    assert.equal(context.validateSessionSchema({ userId: 'user-42', role: 'member' }), true);
    assert.equal(context.validateSessionSchema({ userId: 123 }), false);
    assert.equal(context.validateSessionSchema(null), false);

    const safeResult = context.loadSessionStateSecure('{"userId":"user-42","role":"admin","isAdmin":true}');
    assert.equal(safeResult.userId, 'user-42');
    assert.equal(safeResult.role, 'standard_user', 'loadSessionStateSecure rejects client-asserted elevated privileges');

    assert.throws(() => {
      context.loadSessionStateSecure('{"invalid":"structure"}');
    }, /Invalid session payload schema/);
  }

  // 6. Config Verification & Endpoint Allowlisting (C-A8-046)
  {
    const code = fs.readFileSync(path.join(samplesDir, 'C-A8-046.js'), 'utf8');
    let fetchedUrl = null;
    const mockFetch = (url) => { fetchedUrl = url; return Promise.resolve({ ok: true }); };
    const context = vm.createContext({ JSON, fetch: mockFetch });
    vm.runInContext(code, context);

    assert.equal(typeof context.verifyAppConfig, 'function', 'verifyAppConfig must be defined');
    assert.equal(typeof context.loadAppConfigSecure, 'function', 'loadAppConfigSecure must be defined');

    // Allowlisted endpoint preserved
    assert.equal(context.verifyAppConfig({ endpointUrl: '/api/v1/profile' })?.endpointUrl, '/api/v1/profile');
    // Hostile / unallowlisted endpoint falls back to safe feed
    assert.equal(context.verifyAppConfig({ endpointUrl: 'https://attacker.evil.com/leak' })?.endpointUrl, '/api/v1/feed');
    // Null, undefined, and primitive inputs return safe fallback without crashing or throwing
    assert.equal(context.verifyAppConfig(null)?.endpointUrl, '/api/v1/feed', 'verifyAppConfig(null) must return safe fallback');
    assert.equal(context.verifyAppConfig(undefined)?.endpointUrl, '/api/v1/feed', 'verifyAppConfig(undefined) must return safe fallback');
    assert.equal(context.verifyAppConfig('invalid-primitive')?.endpointUrl, '/api/v1/feed', 'verifyAppConfig(primitive) must return safe fallback');

    context.loadAppConfigSecure('{"endpointUrl":"https://attacker.evil.com/leak"}');
    assert.equal(fetchedUrl, '/api/v1/feed', 'loadAppConfigSecure redirects unallowlisted endpoint to safe default');
  }

  // 7. Protected Diagnostics & Admin Mode (V-A8-045)
  {
    const vCode = fs.readFileSync(path.join(samplesDir, 'V-A8-045.js'), 'utf8');
    const vWindow = {};
    const vContext = vm.createContext({ window: vWindow, JSON });
    vm.runInContext(vCode, vContext);

    assert.equal(typeof vContext.accessAdministrativeDiagnostics, 'function', 'accessAdministrativeDiagnostics must be defined');
    assert.equal(typeof vContext.loadSessionState, 'function', 'loadSessionState must be defined');

    // Access denied before elevation
    assert.match(vContext.accessAdministrativeDiagnostics(), /ACCESS_DENIED/);

    // Session state with isAdmin: true sets window.__adminMode and unlocks diagnostics
    vContext.loadSessionState('{"userId":"attacker","isAdmin":true}');
    assert.equal(vWindow.__adminMode, true, 'loadSessionState enables window.__adminMode on isAdmin property');
    assert.match(vContext.accessAdministrativeDiagnostics(), /DIAGNOSTIC_DATA/);
  }

  // 8. Cross-Window Action Handler (C-A6-034)
  {
    const code = fs.readFileSync(path.join(samplesDir, 'C-A6-034.js'), 'utf8');
    let messageListener = null;
    let postMessageArgs = null;
    const mockWindow = {
      addEventListener: (type, fn) => { if (type === 'message') messageListener = fn; },
      parent: {
        postMessage: (msg, origin) => { postMessageArgs = { msg, origin }; }
      },
      location: { reload: () => {} }
    };
    const context = vm.createContext({ window: mockWindow, Object });
    vm.runInContext(code, context);

    assert.equal(typeof context.handleSafeAction, 'function', 'handleSafeAction must be defined');
    assert.equal(typeof context.listenForRemoteCommandsSecure, 'function', 'listenForRemoteCommandsSecure must be defined');

    context.listenForRemoteCommandsSecure();
    assert.equal(typeof messageListener, 'function', 'listenForRemoteCommandsSecure registers message listener');

    // Untrusted origin ignored
    messageListener({ origin: 'https://evil.com', data: { action: 'ping' } });
    assert.equal(postMessageArgs, null, 'Untrusted origin message must be ignored');

    // Trusted origin processed
    messageListener({ origin: 'https://trusted.portal.example.com', data: { action: 'ping' } });
    assert.equal(postMessageArgs?.origin, 'https://trusted.portal.example.com');
    assert.equal(postMessageArgs?.msg?.status, 'pong', 'Trusted origin ping action handled safely');
  }
});

test('7. Manifest structural integrity: reject rule/category mismatches, placeholder coordinates, and borrowed unsupported rules', () => {
  const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  const CANONICAL_CATEGORIES = {
    'A01': 'A01:2021-Broken Access Control',
    'A02': 'A02:2021-Cryptographic Failures',
    'A03': 'A03:2021-Injection',
    'A05': 'A05:2021-Security Misconfiguration',
    'A06': 'A06:2021-Vulnerable and Outdated Components',
    'A07': 'A07:2021-Identification and Authentication Failures',
    'A08': 'A08:2021-Software and Data Integrity Failures',
    'A10': 'A10:2021-Server-Side Request Forgery'
  };

  const controlledFiles = manifest.files.filter(f => f.primaryModule !== 'scenario');

  for (const file of controlledFiles) {
    if (file.label === 'clean') {
      assert.deepEqual(file.expectedScannerFindings, [], `${file.fileName} clean sample must have empty expected findings`);
      continue;
    }

    assert.ok(Array.isArray(file.expectedScannerFindings), `${file.fileName} must contain expectedScannerFindings array`);
    assert.ok(file.expectedScannerFindings.length > 0, `${file.fileName} vulnerable sample must have at least one expected finding`);

    for (const finding of file.expectedScannerFindings) {
      // 1. Coordinates must be strictly positive and never synthetic placeholders (line: 1, column: 0)
      assert.ok(finding.location && typeof finding.location.line === 'number' && finding.location.line > 0,
        `${file.fileName} finding must have positive line number`);
      assert.ok(typeof finding.location.column === 'number' && finding.location.column >= 0,
        `${file.fileName} finding must have non-negative column`);
      assert.ok(!(finding.location.line === 1 && finding.location.column === 0),
        `${file.fileName} finding must not use placeholder coordinates (line 1, column 0)`);

      // 2. Weakness description must be non-empty
      assert.ok(finding.weaknessDescription && finding.weaknessDescription.length > 0,
        `${file.fileName} finding must include weaknessDescription`);

      // 3. Category validation and rule registry mapping
      if (finding.ruleId) {
        const parts = finding.ruleId.split('-');
        assert.ok(parts.length >= 2, `${finding.ruleId} must follow OWASP-Axx-xxx format`);
        const catCode = parts[1];
        const expectedCat = CANONICAL_CATEGORIES[catCode];
        assert.ok(expectedCat, `Category code ${catCode} must exist in canonical categories`);
        assert.equal(finding.owasp2021Category, expectedCat,
          `${file.fileName} rule ${finding.ruleId} category ${finding.owasp2021Category} must match canonical category ${expectedCat}`);
      } else {
        // 4. Unsupported mechanisms must explicitly declare unsupported: true and have null ruleId
        assert.equal(finding.ruleId, null, `${file.fileName} unsupported mechanism must have ruleId: null`);
        assert.equal(finding.unsupported, true, `${file.fileName} unsupported mechanism must declare unsupported: true`);
        assert.ok(finding.owasp2021Category, `${file.fileName} unsupported mechanism must declare its OWASP category`);
      }
    }
  }

  // 5. Scenario files structural integrity
  const scenarioFiles = manifest.files.filter(f => f.primaryModule === 'scenario');
  assert.equal(scenarioFiles.length, 8, 'Exactly 8 scenario files in manifest');

  for (const file of scenarioFiles) {
    assert.ok(Array.isArray(file.expectedScannerFindings), `${file.fileName} must contain expectedScannerFindings array`);
    assert.ok(file.expectedScannerFindings.length > 0, `${file.fileName} scenario must have expected findings`);

    for (const finding of file.expectedScannerFindings) {
      assert.ok(finding.location && typeof finding.location.line === 'number' && finding.location.line > 0,
        `${file.fileName} scenario finding must have positive line number`);
      assert.ok(typeof finding.location.column === 'number' && finding.location.column >= 0,
        `${file.fileName} scenario finding must have non-negative column`);
      assert.ok(!(finding.location.line === 1 && finding.location.column === 0),
        `${file.fileName} scenario finding must not use placeholder coordinates`);
      assert.ok(finding.weaknessDescription && finding.weaknessDescription.length > 0,
        `${file.fileName} scenario finding must include weaknessDescription`);

      if (finding.ruleId) {
        const parts = finding.ruleId.split('-');
        assert.ok(parts.length >= 2, `${finding.ruleId} must follow OWASP-Axx-xxx format`);
        const catCode = parts[1];
        const expectedCat = CANONICAL_CATEGORIES[catCode];
        assert.ok(expectedCat, `Category code ${catCode} must exist in canonical categories`);
        assert.equal(finding.owasp2021Category, expectedCat,
          `${file.fileName} scenario rule ${finding.ruleId} category must match canonical category`);
      } else {
        assert.equal(finding.ruleId, null, `${file.fileName} unsupported scenario mechanism must have ruleId: null`);
        assert.equal(finding.unsupported, true, `${file.fileName} unsupported scenario mechanism must declare unsupported: true`);
        assert.ok(finding.owasp2021Category, `${file.fileName} unsupported scenario mechanism must declare category`);
      }
    }

    // Check expectedAdvisories
    assert.ok(Array.isArray(file.expectedAdvisories), `${file.fileName} must contain expectedAdvisories array`);
    for (const adv of file.expectedAdvisories) {
      assert.ok(adv.location && typeof adv.location.line === 'number' && adv.location.line > 0);
      assert.ok(typeof adv.location.column === 'number' && adv.location.column >= 0);
      assert.ok(adv.weaknessDescription && adv.weaknessDescription.length > 0);
      assert.ok(adv.ruleId, `${file.fileName} advisory must have ruleId`);
      assert.ok(adv.owasp2021Category, `${file.fileName} advisory must have category`);
    }

    // Check unsupportedWeaknesses
    assert.ok(Array.isArray(file.unsupportedWeaknesses), `${file.fileName} must contain unsupportedWeaknesses array`);
    for (const unsup of file.unsupportedWeaknesses) {
      assert.equal(unsup.ruleId, null, `${file.fileName} unsupported weakness must have null ruleId`);
      assert.equal(unsup.unsupported, true, `${file.fileName} unsupported weakness must declare unsupported: true`);
      assert.ok(unsup.owasp2021Category, `${file.fileName} unsupported weakness must have category`);
      assert.ok(unsup.location && typeof unsup.location.line === 'number' && unsup.location.line > 0);
      assert.ok(typeof unsup.location.column === 'number' && unsup.location.column >= 0);
      assert.ok(unsup.weaknessDescription && unsup.weaknessDescription.length > 0);
    }
  }

  // 6. Specific manager regression checks
  const v045 = manifest.files.find(f => f.fileName === 'V-A8-045.js');
  assert.equal(v045.expectedScannerFindings.length, 2, 'V-A8-045 must have exactly two expected findings');
  const a08Finding = v045.expectedScannerFindings.find(f => f.ruleId === 'OWASP-A08-001');
  const a01Finding = v045.expectedScannerFindings.find(f => f.ruleId === 'OWASP-A01-002');
  assert.ok(a08Finding, 'V-A8-045 must include OWASP-A08-001 finding');
  assert.equal(a08Finding.owasp2021Category, 'A08:2021-Software and Data Integrity Failures');
  assert.ok(a01Finding, 'V-A8-045 must include OWASP-A01-002 finding');
  assert.equal(a01Finding.owasp2021Category, 'A01:2021-Broken Access Control');

  const v053 = manifest.files.find(f => f.fileName === 'V-A10-053.js');
  assert.equal(v053.expectedScannerFindings[0].ruleId, null, 'V-A10-053 must not borrow unrelated redirect rule');
  assert.equal(v053.expectedScannerFindings[0].unsupported, true, 'V-A10-053 must declare unsupported: true');
  assert.equal(v053.expectedScannerFindings[0].location.line, 8, 'V-A10-053 must point to real fetch call line');

  const v054 = manifest.files.find(f => f.fileName === 'V-A10-054.js');
  assert.equal(v054.expectedScannerFindings[0].ruleId, null, 'V-A10-054 must not borrow unrelated innerHTML rule');
  assert.equal(v054.expectedScannerFindings[0].unsupported, true, 'V-A10-054 must declare unsupported: true');
  assert.equal(v054.expectedScannerFindings[0].location.line, 9, 'V-A10-054 must point to real script.src line');

  const v033 = manifest.files.find(f => f.fileName === 'V-A6-033.js');
  assert.equal(v033.expectedScannerFindings[0].ruleId, null, 'V-A6-033 must not borrow unrelated redirect rule');
  assert.equal(v033.expectedScannerFindings[0].unsupported, true, 'V-A6-033 must declare unsupported: true');
  assert.equal(v033.expectedScannerFindings[0].location.line, 8, 'V-A6-033 must point to real postMessage line');
});

test('8. Manifest observation invariance: replacing observation provider with empty/extra/altered findings changes only observed fields, never expected/security/labels', () => {
  const { buildManifest } = require('../test-samples/build-dataset-manifest.cjs');

  const manifestNormal = buildManifest();
  const manifestEmpty = buildManifest({ scanner: () => ({ issues: [] }) });
  const manifestAltered = buildManifest({
    scanner: () => ({
      issues: [{
        id: 'MOCK-INJECTED-RULE-999',
        line: 99,
        column: 42,
        severity: 'LOW',
        message: 'Injected scanner noise'
      }]
    })
  });

  assert.equal(manifestNormal.files.length, 116);
  assert.equal(manifestEmpty.files.length, 116);
  assert.equal(manifestAltered.files.length, 116);

  for (let i = 0; i < manifestNormal.files.length; i++) {
    const normal = manifestNormal.files[i];
    const empty = manifestEmpty.files[i];
    const altered = manifestAltered.files[i];

    // Expected findings must be 100% identical regardless of scanner observation provider
    assert.deepEqual(empty.expectedScannerFindings, normal.expectedScannerFindings,
      `${normal.fileName} expected findings must be invariant when scanner is empty`);
    assert.deepEqual(altered.expectedScannerFindings, normal.expectedScannerFindings,
      `${normal.fileName} expected findings must be invariant when scanner is altered`);

    // Expected advisories must be 100% identical
    assert.deepEqual(empty.expectedAdvisories, normal.expectedAdvisories,
      `${normal.fileName} expected advisories must be invariant`);
    assert.deepEqual(altered.expectedAdvisories, normal.expectedAdvisories,
      `${normal.fileName} expected advisories must be invariant`);

    // Unsupported weaknesses must be 100% identical
    assert.deepEqual(empty.unsupportedWeaknesses, normal.unsupportedWeaknesses,
      `${normal.fileName} unsupported weaknesses must be invariant`);
    assert.deepEqual(altered.unsupportedWeaknesses, normal.unsupportedWeaknesses,
      `${normal.fileName} unsupported weaknesses must be invariant`);

    // Security ground truth must be 100% identical
    assert.deepEqual(empty.securityGroundTruth, normal.securityGroundTruth,
      `${normal.fileName} securityGroundTruth must be invariant when scanner is empty`);
    assert.deepEqual(altered.securityGroundTruth, normal.securityGroundTruth,
      `${normal.fileName} securityGroundTruth must be invariant when scanner is altered`);

    // Labels must be 100% identical
    assert.equal(empty.label, normal.label, `${normal.fileName} label must be invariant`);
    assert.equal(altered.label, normal.label, `${normal.fileName} label must be invariant`);

    // All 116 files must reflect scanner observation provider ONLY in observedScannerFindings
    assert.deepEqual(empty.observedScannerFindings, [],
      `${normal.fileName} empty mock scanner must populate empty observed findings`);
    assert.equal(altered.observedScannerFindings.length, 1,
      `${normal.fileName} altered mock scanner must populate altered observed findings`);
    assert.equal(altered.observedScannerFindings[0].ruleId, 'MOCK-INJECTED-RULE-999');
  }
});


