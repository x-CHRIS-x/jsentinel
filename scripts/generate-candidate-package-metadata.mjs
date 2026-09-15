import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const sha256 = (filePath) => {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
};

// 1. Dataset files (116)
const manifestPath = path.join(rootDir, 'test-samples', 'dataset-manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

const datasetFilesHashes = {};
const samplesDir = path.join(rootDir, 'test-samples', 'samples');

for (const entry of manifest.files) {
  const filePath = path.join(samplesDir, entry.fileName);
  if (fs.existsSync(filePath)) {
    datasetFilesHashes[entry.fileName] = {
      sampleId: entry.sampleId,
      label: entry.label,
      workloadType: entry.workloadType || 'controlled',
      sha256: sha256(filePath),
      sizeBytes: fs.statSync(filePath).size
    };
  } else {
    throw new Error(`Missing sample file: ${filePath}`);
  }
}

// 2. Scanner source files
const scannerSources = [
  'src/utils/scannerEngine.js',
  'src/utils/babelParser.js',
  'src/utils/findingPolicy.js',
  'src/data/guidanceCatalog.js',
  'src/scanner/rules/accessControl.js',
  'src/scanner/rules/auth.js',
  'src/scanner/rules/deserialization.js',
  'src/scanner/rules/injection.js',
  'src/scanner/rules/knownVulns.js',
  'src/scanner/rules/misconfig.js',
  'src/scanner/rules/sensitiveData.js',
  'src/scanner/rules/ssrf.js',
  'src/scanner/rules/xss.js',
  'vscode-extension/src/scanner/scannerEngine.js',
  'vscode-extension/src/scanner/rules.js',
  'vscode-extension/src/data/guidanceCatalog.js',
  'vscode-extension/src/utils/findingPolicy.js'
];

const scannerSourceHashes = {};
for (const relPath of scannerSources) {
  const absPath = path.join(rootDir, relPath);
  if (fs.existsSync(absPath)) {
    scannerSourceHashes[relPath] = {
      sha256: sha256(absPath),
      sizeBytes: fs.statSync(absPath).size
    };
  } else {
    throw new Error(`Missing scanner source: ${absPath}`);
  }
}

// 3. Active rules inventory (24 active rules)
const activeRules = [
  { ruleId: 'OWASP-A01-001', category: 'A01:2021-Broken Access Control', type: 'vulnerability', description: 'Insecure direct object reference / storage access' },
  { ruleId: 'OWASP-A01-002', category: 'A01:2021-Broken Access Control', type: 'vulnerability', description: 'Missing postMessage origin verification' },
  { ruleId: 'OWASP-A02-001', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Insecure cryptographic algorithm (MD5)' },
  { ruleId: 'OWASP-A02-002', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Insecure cryptographic algorithm (SHA-1)' },
  { ruleId: 'OWASP-A02-003', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Insecure cipher algorithm (DES/RC4)' },
  { ruleId: 'OWASP-A02-004', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Hardcoded cryptographic key or secret' },
  { ruleId: 'OWASP-A02-005', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Cryptographically weak pseudo-random number generator' },
  { ruleId: 'OWASP-A02-006', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Cleartext protocol transmission (HTTP)' },
  { ruleId: 'OWASP-A02-007', category: 'A02:2021-Cryptographic Failures', type: 'vulnerability', description: 'Sensitive token/credential storage in localStorage/sessionStorage' },
  { ruleId: 'OWASP-A03-001', category: 'A03:2021-Injection', type: 'vulnerability', description: 'Dynamic code evaluation via eval()' },
  { ruleId: 'OWASP-A03-002', category: 'A03:2021-Injection', type: 'vulnerability', description: 'DOM-based XSS via innerHTML assignment' },
  { ruleId: 'OWASP-A03-003', category: 'A03:2021-Injection', type: 'vulnerability', description: 'DOM injection via document.write()' },
  { ruleId: 'OWASP-A03-004', category: 'A03:2021-Injection', type: 'vulnerability', description: 'Dynamic code execution via Function() constructor' },
  { ruleId: 'OWASP-A03-005', category: 'A03:2021-Injection', type: 'vulnerability', description: 'Timer-based code execution with string argument' },
  { ruleId: 'OWASP-A03-006', category: 'A03:2021-Injection', type: 'vulnerability', description: 'JavaScript pseudo-protocol injection via location.href' },
  { ruleId: 'OWASP-A03-007', category: 'A03:2021-Injection', type: 'vulnerability', description: 'DOM-based XSS via outerHTML assignment' },
  { ruleId: 'OWASP-A03-008', category: 'A03:2021-Injection', type: 'vulnerability', description: 'React XSS via dangerouslySetInnerHTML' },
  { ruleId: 'OWASP-A05-001', category: 'A05:2021-Security Misconfiguration', type: 'vulnerability', description: 'Console logging of sensitive diagnostic output' },
  { ruleId: 'OWASP-A05-003', category: 'A05:2021-Security Misconfiguration', type: 'vulnerability', description: 'Verbose error leakage / stack trace exposure' },
  { ruleId: 'OWASP-A06-001', category: 'A06:2021-Vulnerable and Outdated Components', type: 'advisory', description: 'Component-review advisory; excluded from vulnerability metrics' },
  { ruleId: 'OWASP-A07-001', category: 'A07:2021-Identification and Authentication Failures', type: 'vulnerability', description: 'Hardcoded user credentials / password constants' },
  { ruleId: 'OWASP-A08-001', category: 'A08:2021-Software and Data Integrity Failures', type: 'vulnerability', description: 'Unsafe deserialization / unvalidated JSON.parse' },
  { ruleId: 'OWASP-A08-002', category: 'A08:2021-Software and Data Integrity Failures', type: 'vulnerability', description: 'External script inclusion without Subresource Integrity (SRI)' },
  { ruleId: 'OWASP-A08-003', category: 'A08:2021-Software and Data Integrity Failures', type: 'vulnerability', description: 'Client-side unvalidated redirection / open navigation target' }
];

// 4. Evaluator modules
const evaluatorModules = [
  'validation/evaluator/adapters.mjs',
  'validation/evaluator/adjudication.mjs',
  'validation/evaluator/evaluator.mjs',
  'validation/evaluator/evaluator.test.mjs',
  'validation/evaluator/index.mjs',
  'validation/evaluator/matching.mjs',
  'validation/evaluator/metrics.mjs',
  'validation/evaluator/runner.mjs',
  'validation/evaluator/schema.mjs'
];

const evaluatorHashes = {};
for (const relPath of evaluatorModules) {
  const absPath = path.join(rootDir, relPath);
  if (fs.existsSync(absPath)) {
    evaluatorHashes[relPath] = {
      sha256: sha256(absPath),
      sizeBytes: fs.statSync(absPath).size
    };
  } else {
    throw new Error(`Missing evaluator module: ${absPath}`);
  }
}

// 5. Manifest hash
const manifestHash = {
  path: 'test-samples/dataset-manifest.json',
  sha256: sha256(manifestPath),
  sizeBytes: fs.statSync(manifestPath).size,
  manifestVersion: manifest.manifestVersion || '1.0.0',
  baseCommit: manifest.baseCommit || '0a76a2f61dea576a0155153a8e0bad6a4d42fdbb'
};

const candidatePackage = {
  packageTitle: 'JSentinel Benchmark and Evaluator Candidate Package',
  status: 'PROPOSED / UNFROZEN',
  groupFreezeStatus: 'PENDING_GROUP_ADOPTION',
  note: 'This package is a proposed research artifact candidate prepared during Phase 05. It does not assert or claim final group or thesis-panel approval, which requires formal group review and freeze adoption.',
  timestamp: new Date().toISOString(),
  environment: {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch
  },
  gitState: {
    evaluatorCommit: '5239da9',
    acceptedEvidenceBaseCommit: '0a76a2f61dea576a0155153a8e0bad6a4d42fdbb',
    branch: 'ao/jsentinel-26/phase05-evaluator'
  },
  datasetSummary: {
    totalFiles: Object.keys(datasetFilesHashes).length,
    controlledFiles: Object.values(datasetFilesHashes).filter(f => f.workloadType === 'controlled').length,
    vulnerableControlled: Object.values(datasetFilesHashes).filter(f => f.workloadType === 'controlled' && f.label === 'vulnerable').length,
    cleanControlled: Object.values(datasetFilesHashes).filter(f => f.workloadType === 'controlled' && f.label === 'clean').length,
    scenarioFiles: Object.values(datasetFilesHashes).filter(f => f.workloadType === 'scenario').length,
    manifest: manifestHash,
    samples: datasetFilesHashes
  },
  activeRulesSummary: {
    totalActiveRules: activeRules.length,
    vulnerabilityRulesCount: activeRules.filter(r => r.type === 'vulnerability').length,
    advisoryRulesCount: activeRules.filter(r => r.type === 'advisory').length,
    rules: activeRules
  },
  scannerSourcesSummary: {
    totalSourceFiles: Object.keys(scannerSourceHashes).length,
    sources: scannerSourceHashes
  },
  evaluatorModulesSummary: {
    totalModules: Object.keys(evaluatorHashes).length,
    modules: evaluatorHashes
  },
  localBenchmarkSummary: {
    executionScope: 'Node development environment only',
    disclaimer: 'Execution timings reflect Node.js AST traversal and do not establish live web-browser DOM or VS Code extension performance on physical AU laboratory computers.',
    totalScanAttempts: 232,
    webAttempts: 116,
    extensionAttempts: 116,
    results: {
      controlledMatrixN: 108,
      truePositives: 45,
      trueNegatives: 53,
      falsePositives: 1,
      falseNegatives: 9,
      accuracy: 0.9074,
      accuracyPercentage: '90.74%',
      precision: 0.9783,
      precisionPercentage: '97.83%',
      recall: 0.8333,
      recallPercentage: '83.33%',
      specificity: 0.9815,
      specificityPercentage: '98.15%',
      falsePositiveRate: 0.0185,
      falsePositiveRatePercentage: '1.85%',
      falseNegativeRate: 0.1667,
      falseNegativeRatePercentage: '16.67%',
      expectedVulnerabilities: 60,
      matchedExpectedRules: 51,
      missedExpectedRules: 6,
      unsupportedExpectedRules: 3,
      expectedRuleRecall: 0.8500,
      expectedRuleRecallPercentage: '85.00%',
      actualVulnerabilityFindings: 52,
      matchedFindings: 51,
      duplicateFindings: 0,
      unmatchedFindings: 1,
      targetMatchFraction: 0.9808,
      targetMatchFractionPercentage: '98.08%',
      adjudicatedPrecision: 'PENDING_MANUAL_GROUND_TRUTH_ADJUDICATION'
    }
  },
  humanAdjudicationProtocol: {
    status: 'SPECIFIED_AND_IMPLEMENTED',
    modulePath: 'validation/evaluator/adjudication.mjs',
    dispositionValues: ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'PENDING'],
    duplicatePolicy: 'EXCLUDE_FROM_PRECISION',
    unmatchedCountRequiringReview: 1,
    unmatchedFindingFile: 'C-A1-001.js',
    unmatchedFindingRule: 'OWASP-A08-001'
  }
};

const outputPath = path.join(rootDir, 'documents', 'research-phases', 'checks', '05-candidate-package-metadata.json');
fs.writeFileSync(outputPath, JSON.stringify(candidatePackage, null, 2), 'utf8');
console.log(`Wrote candidate package metadata to: ${outputPath}`);
