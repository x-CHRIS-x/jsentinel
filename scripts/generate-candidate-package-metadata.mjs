import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const defaultRootDir = path.resolve(__dirname, '..');

/**
 * Computes SHA-256 digest of a file.
 * 
 * @param {string} filePath 
 * @returns {string} Hex digest.
 */
export const sha256 = (filePath) => {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
};

/**
 * Gets git provenance information.
 * 
 * @param {string} rootDir 
 * @returns {{ fullCommit: string, shortCommit: string, isClean: boolean, branch: string }}
 */
export const getGitProvenance = (rootDir) => {
  let fullCommit = 'unknown';
  let shortCommit = 'unknown';
  let isClean = false;
  let branch = 'unknown';

  try {
    fullCommit = execSync('git rev-parse HEAD', { cwd: rootDir, encoding: 'utf8' }).trim();
    shortCommit = execSync('git rev-parse --short HEAD', { cwd: rootDir, encoding: 'utf8' }).trim();
    branch = execSync('git rev-parse --abbrev-ref HEAD', { cwd: rootDir, encoding: 'utf8' }).trim();
    const porcelain = execSync('git status --porcelain', { cwd: rootDir, encoding: 'utf8' }).trim();
    isClean = porcelain.length === 0;
  } catch {
    // git command not available
  }

  return { fullCommit, shortCommit, isClean, branch };
};

/**
 * Validates manifest distribution and extracts file digests.
 * 
 * @param {Object} manifest 
 * @param {string} samplesDir 
 * @returns {{ datasetFilesHashes: Object, counts: Object }}
 */
export const validateAndDigestManifest = (manifest, samplesDir) => {
  const files = manifest.files || [];
  const vulnerableControlled = files.filter(f => f.label === 'vulnerable');
  const cleanControlled = files.filter(f => f.label === 'clean');
  const scenarioFiles = files.filter(f => f.label === 'scenario' || f.workloadType === 'simulated-browser-workload');

  const counts = {
    totalFiles: files.length,
    controlledFiles: vulnerableControlled.length + cleanControlled.length,
    vulnerableControlled: vulnerableControlled.length,
    cleanControlled: cleanControlled.length,
    scenarioFiles: scenarioFiles.length
  };

  // Strict validation: reject any inconsistency from 54V / 54C / 8 scenarios / 116 total
  if (
    counts.totalFiles !== 116 ||
    counts.controlledFiles !== 108 ||
    counts.vulnerableControlled !== 54 ||
    counts.cleanControlled !== 54 ||
    counts.scenarioFiles !== 8
  ) {
    throw new Error(
      `Dataset manifest distribution invalid: expected 54 vulnerable, 54 clean, 8 scenarios (116 total). ` +
      `Found: ${counts.vulnerableControlled} vulnerable, ${counts.cleanControlled} clean, ` +
      `${counts.scenarioFiles} scenarios (total ${counts.totalFiles}).`
    );
  }

  const datasetFilesHashes = {};
  for (const entry of files) {
    const filePath = path.join(samplesDir, entry.fileName);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Sample file not found on disk: ${filePath}`);
    }
    datasetFilesHashes[entry.fileName] = {
      sampleId: entry.sampleId,
      label: entry.label,
      workloadType: entry.workloadType || (entry.label === 'scenario' ? 'simulated-browser-workload' : 'controlled'),
      sha256: sha256(filePath),
      sizeBytes: fs.statSync(filePath).size
    };
  }

  return { datasetFilesHashes, counts };
};

/**
 * Ingests and validates benchmark run reports from disk.
 * 
 * @param {string} runDir - Directory containing web/ and extension/ run folders.
 * @returns {Object} Validated report metrics.
 */
export const ingestRunReports = (runDir) => {
  const webReportPath = path.join(runDir, 'web', 'evaluation_report.json');
  const webMetaPath = path.join(runDir, 'web', 'run_metadata.json');
  const extReportPath = path.join(runDir, 'extension', 'evaluation_report.json');
  const extMetaPath = path.join(runDir, 'extension', 'run_metadata.json');

  if (!fs.existsSync(webReportPath) || !fs.existsSync(webMetaPath)) {
    throw new Error(`Web run artifacts missing in: ${path.join(runDir, 'web')}`);
  }
  if (!fs.existsSync(extReportPath) || !fs.existsSync(extMetaPath)) {
    throw new Error(`Extension run artifacts missing in: ${path.join(runDir, 'extension')}`);
  }

  const webReport = JSON.parse(fs.readFileSync(webReportPath, 'utf8'));
  const webMeta = JSON.parse(fs.readFileSync(webMetaPath, 'utf8'));
  const extReport = JSON.parse(fs.readFileSync(extReportPath, 'utf8'));
  const extMeta = JSON.parse(fs.readFileSync(extMetaPath, 'utf8'));

  // Extract unmatched findings dynamically from reports
  const extractUnmatched = (report) => {
    const unmatchedList = [];
    for (const fileRes of report.fileResults || []) {
      for (const u of fileRes.vulnerabilities?.unmatched || []) {
        unmatchedList.push({
          sampleId: fileRes.sampleId,
          fileName: fileRes.fileName,
          scope: fileRes.label === 'scenario' ? 'scenario' : 'controlled',
          ruleId: u.actualFinding?.ruleId,
          line: u.actualFinding?.location?.line,
          column: u.actualFinding?.location?.column,
          description: u.actualFinding?.description,
          adjudicationStatus: u.adjudicationStatus
        });
      }
    }
    return unmatchedList;
  };

  const webUnmatched = extractUnmatched(webReport);
  const extUnmatched = extractUnmatched(extReport);

  return {
    runDir,
    web: {
      report: webReport,
      metadata: webMeta,
      metrics: {
        completion: webReport.scanCompletion,
        controlledMatrix: webReport.fileConfusionMatrix,
        expectedRule: webReport.expectedRuleMetrics,
        findingPrecision: webReport.findingPrecisionMetrics
      },
      unmatchedFindings: webUnmatched
    },
    extension: {
      report: extReport,
      metadata: extMeta,
      metrics: {
        completion: extReport.scanCompletion,
        controlledMatrix: extReport.fileConfusionMatrix,
        expectedRule: extReport.expectedRuleMetrics,
        findingPrecision: extReport.findingPrecisionMetrics
      },
      unmatchedFindings: extUnmatched
    }
  };
};

/**
 * Builds candidate package metadata dynamically from actual inputs.
 * 
 * @param {Object} [options]
 * @param {string} [options.rootDir]
 * @param {string} [options.runDir]
 * @param {string} [options.manifestPath]
 * @param {string} [options.samplesDir]
 * @returns {Object} Complete candidate package metadata.
 */
export const buildCandidatePackageMetadata = (options = {}) => {
  const rootDir = options.rootDir || defaultRootDir;
  const manifestPath = options.manifestPath || path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const samplesDir = options.samplesDir || path.join(rootDir, 'test-samples', 'samples');

  // Determine run directory: prioritize provided runDir, or search for latest versioned run
  let runDir = options.runDir;
  if (!runDir) {
    const runsBase = path.join(rootDir, 'validation', 'evaluator', 'runs');
    if (fs.existsSync(path.join(runsBase, 'phase05-batch-b-corr1', 'web'))) {
      runDir = path.join(runsBase, 'phase05-batch-b-corr1');
    } else if (fs.existsSync(path.join(runsBase, 'phase05-batch-b', 'web'))) {
      runDir = path.join(runsBase, 'phase05-batch-b');
    } else {
      throw new Error(`No benchmark run directory found in ${runsBase}`);
    }
  }

  // 1. Package.json info
  const pkgPath = path.join(rootDir, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

  // 2. Git provenance
  const gitProv = getGitProvenance(rootDir);

  // 3. Manifest validation and dataset digests
  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Manifest not found: ${manifestPath}`);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const { datasetFilesHashes, counts } = validateAndDigestManifest(manifest, samplesDir);

  const manifestMeta = {
    path: 'test-samples/dataset-manifest.json',
    sha256: sha256(manifestPath),
    sizeBytes: fs.statSync(manifestPath).size,
    manifestVersion: manifest.manifestVersion || '1.0.0',
    baseCommit: manifest.baseCommit || '0a76a2f61dea576a0155153a8e0bad6a4d42fdbb'
  };

  // 4. Scanner sources (17 files)
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

  // 5. Active rules inventory (24 rules)
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

  // 6. Evaluator modules (9 files)
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

  // 7. Ingest run reports dynamically
  const ingestedRuns = ingestRunReports(runDir);

  return {
    packageTitle: 'JSentinel Benchmark and Evaluator Candidate Package',
    status: 'PROPOSED / UNFROZEN',
    groupFreezeStatus: 'PENDING_GROUP_ADOPTION',
    note: 'This package is a proposed research artifact candidate prepared during Phase 05. It does not assert or claim final group or thesis-panel approval, which requires formal group review and freeze adoption.',
    timestamp: new Date().toISOString(),
    packageVersion: pkg.version || '1.1.0',
    gitState: {
      fullCommitHash: gitProv.fullCommit,
      shortCommitHash: gitProv.shortCommit,
      branch: gitProv.branch,
      isWorkingTreeClean: gitProv.isClean,
      acceptedEvidenceBaseCommit: manifestMeta.baseCommit
    },
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      v8Version: process.versions.v8
    },
    datasetSummary: {
      totalFiles: counts.totalFiles,
      controlledFiles: counts.controlledFiles,
      vulnerableControlled: counts.vulnerableControlled,
      cleanControlled: counts.cleanControlled,
      scenarioFiles: counts.scenarioFiles,
      manifest: manifestMeta,
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
    benchmarkRuns: {
      sourceRunDirectory: path.relative(rootDir, runDir).replace(/\\/g, '/'),
      executionScope: 'Node development environment only',
      disclaimer: 'Execution timings reflect Node.js AST traversal and do not establish live web-browser DOM or VS Code extension performance on physical AU laboratory computers.',
      totalScanAttempts: ingestedRuns.web.metadata.summaryCounts.totalFilesAttempted + ingestedRuns.extension.metadata.summaryCounts.totalFilesAttempted,
      web: {
        runId: ingestedRuns.web.metadata.runId,
        totalDurationMs: ingestedRuns.web.metadata.totalDurationMs,
        attempts: ingestedRuns.web.metadata.summaryCounts.totalFilesAttempted,
        metrics: ingestedRuns.web.metrics,
        unmatchedFindings: ingestedRuns.web.unmatchedFindings
      },
      extension: {
        runId: ingestedRuns.extension.metadata.runId,
        totalDurationMs: ingestedRuns.extension.metadata.totalDurationMs,
        attempts: ingestedRuns.extension.metadata.summaryCounts.totalFilesAttempted,
        metrics: ingestedRuns.extension.metrics,
        unmatchedFindings: ingestedRuns.extension.unmatchedFindings
      }
    },
    evaluationPoliciesAndFormulas: {
      completionStateEligibility: 'Completed scans only (status=completed and hasError=false). Partial, failed, or unattempted scans are excluded from the controlled evaluation denominator N.',
      confusionMatrixDenominator: 'N = TP + TN + FP + FN, where N <= 108 (eligible completed controlled scans only).',
      formulas: {
        accuracy: '(TP + TN) / N',
        precision: 'TP / (TP + FP)',
        recall: 'TP / (TP + FN)',
        specificity: 'TN / (TN + FP)',
        falsePositiveRate: 'FP / (FP + TN)',
        falseNegativeRate: 'FN / (FN + TP)',
        expectedRuleRecall: 'matchedExpectedRules / totalExpectedVulnerabilities',
        targetMatchFraction: 'matchedFindings / totalActualFindings',
        adjudicatedPrecision: '(automatedMatched + reviewedUnmatchedTP) / (automatedMatched + reviewedUnmatchedTP + reviewedUnmatchedFP [+ duplicates if COUNT_AS_FP])'
      },
      advisoryPolicy: 'OWASP-A06-001 component-review signals are classified as advisories and excluded from vulnerability detection counts and scoring penalties.',
      coordinateMatchingPolicy: {
        locationTolerance: 0,
        matchColumn: false,
        note: 'Column 0 falsy fallback discrepancy (col || "unknown" in certain rule visitors) documented; line-level coordinates enforced under tolerance 0.'
      }
    },
    reproductionCommands: [
      'node validation/evaluator/runner.mjs --output-dir validation/evaluator/runs/phase05-batch-b-corr1',
      'node --test validation/evaluator/evaluator.test.mjs',
      'node scripts/generate-candidate-package-metadata.mjs --run-dir validation/evaluator/runs/phase05-batch-b-corr1'
    ]
  };
};

// Execute if run from CLI
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let runDir = null;
  let outputPath = path.join(defaultRootDir, 'documents', 'research-phases', 'checks', '05-candidate-package-metadata.json');

  for (let i = 2; i < process.argv.length; i++) {
    if (process.argv[i] === '--run-dir' && i + 1 < process.argv.length) {
      runDir = path.resolve(process.argv[++i]);
    } else if (process.argv[i] === '--output' && i + 1 < process.argv.length) {
      outputPath = path.resolve(process.argv[++i]);
    }
  }

  try {
    const candidatePackage = buildCandidatePackageMetadata({ runDir });
    fs.writeFileSync(outputPath, JSON.stringify(candidatePackage, null, 2), 'utf8');
    console.log(`Generated candidate package metadata at: ${outputPath}`);
  } catch (err) {
    console.error('Failed to generate candidate package metadata:', err.message);
    process.exit(1);
  }
}
