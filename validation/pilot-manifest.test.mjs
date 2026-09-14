import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
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

test('1. Total 116 dataset files preserved in test-samples/samples', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  const files = fs.readdirSync(samplesDir);
  assert.equal(files.length, 116, 'Total files in test-samples/samples must be exactly 116');

  const vFiles = files.filter(f => f.startsWith('V-'));
  const cFiles = files.filter(f => f.startsWith('C-'));
  const sFiles = files.filter(f => !f.startsWith('V-') && !f.startsWith('C-'));

  assert.equal(vFiles.length, 54, 'Exactly 54 vulnerable samples');
  assert.equal(cFiles.length, 54, 'Exactly 54 clean samples');
  assert.equal(sFiles.length, 8, 'Exactly 8 scenario samples');
});

test('2. Baseline hashes file exists and records prior 116 inventory', () => {
  const hashFile = path.join(rootDir, 'documents', 'research-phases', 'checks', '04-baseline-hashes.json');
  assert.ok(fs.existsSync(hashFile), '04-baseline-hashes.json must exist');

  const baseline = JSON.parse(fs.readFileSync(hashFile, 'utf8'));
  assert.equal(baseline.baseCommit, 'ca154776e3896fe4cc6db883b46d9caaf0d23089');
  assert.equal(baseline.totalFiles, 116);
  assert.equal(baseline.counts.vulnerable, 54);
  assert.equal(baseline.counts.clean, 54);
  assert.equal(baseline.counts.scenarios, 8);
  assert.equal(baseline.files.length, 116);
});

test('3. Dataset manifest draft structure and explicit partial coverage', () => {
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

  // Verify each pilot file has full ground truth and reviewer info
  for (const pf of reviewedFiles) {
    assert.ok(pf.sampleId, `${pf.fileName} must have sampleId`);
    assert.ok(pf.pairId, `${pf.fileName} must have pairId`);
    assert.ok(pf.primaryModule, `${pf.fileName} must have primaryModule`);
    assert.ok(pf.intendedBehavior, `${pf.fileName} must have intendedBehavior`);
    assert.ok(pf.securityGroundTruth.rationale, `${pf.fileName} must have security ground truth rationale`);
    assert.ok(Array.isArray(pf.securityGroundTruth.sourceReferences), `${pf.fileName} must have sourceReferences array`);
    assert.ok(pf.securityGroundTruth.sourceReferences.length > 0, `${pf.fileName} must have at least one sourceReference`);
    assert.equal(pf.reviewStatus.aiReviewer, 'Agy (Gemini 3.8 Flash High)');
    assert.equal(pf.reviewStatus.humanReview, 'PENDING');
  }
});

test('4. All 12 pilot sample files parse cleanly without syntax errors', () => {
  const samplesDir = path.join(rootDir, 'test-samples', 'samples');
  for (const fileName of PILOT_FILES) {
    const filePath = path.join(samplesDir, fileName);
    const code = fs.readFileSync(filePath, 'utf8');
    assert.doesNotThrow(() => {
      babelParser.parse(code, {
        sourceType: 'module',
        plugins: ['jsx']
      });
    }, `File ${fileName} must be valid JavaScript`);
  }
});

test('5. Both scanners scan all 12 pilot files and match expected findings', async () => {
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
