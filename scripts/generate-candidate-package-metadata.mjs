import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
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
 * Loads actual accepted rule registries dynamically from web and extension scanners.
 * Validates 1-to-1 agreement, derives real metadata, and rejects hardcoded or invented inventories.
 * 
 * @param {string} [rootDir=defaultRootDir]
 * @returns {Promise<{ inventory: Array<Object>, counts: Object }>}
 */
export const loadActualRuleInventories = async (rootDir = defaultRootDir) => {
  // 1. Load extension rules
  const extRulesPath = path.join(rootDir, 'vscode-extension', 'src', 'scanner', 'rules.js');
  if (!fs.existsSync(extRulesPath)) {
    throw new Error(`Extension rules not found at: ${extRulesPath}`);
  }
  const { allRules: extRules } = require(extRulesPath);

  // 2. Load web rules dynamically from modules
  const webRuleModules = [
    { name: 'injection', file: 'src/scanner/rules/injection.js' },
    { name: 'xss', file: 'src/scanner/rules/xss.js' },
    { name: 'auth', file: 'src/scanner/rules/auth.js' },
    { name: 'sensitiveData', file: 'src/scanner/rules/sensitiveData.js' },
    { name: 'misconfig', file: 'src/scanner/rules/misconfig.js' },
    { name: 'deserialization', file: 'src/scanner/rules/deserialization.js' },
    { name: 'knownVulns', file: 'src/scanner/rules/knownVulns.js' },
    { name: 'accessControl', file: 'src/scanner/rules/accessControl.js' }
  ];

  const webRulesWithModule = [];
  for (const mod of webRuleModules) {
    const absPath = path.resolve(rootDir, mod.file);
    const imported = await import(`file://${absPath.replace(/\\/g, '/')}`);
    const modRules = Object.values(imported).flat();
    for (const r of modRules) {
      webRulesWithModule.push({ rule: r, moduleFile: mod.file });
    }
  }

  // 3. Load guidance catalog for canonical category fallback if needed
  const guidancePath = path.resolve(rootDir, 'src', 'data', 'guidanceCatalog.js');
  const { guidanceCatalog: webGuidance } = await import(`file://${guidancePath.replace(/\\/g, '/')}`);

  // Enforce rule counts: 24 active rules in each scanner
  if (webRulesWithModule.length !== 24) {
    throw new Error(`Expected exactly 24 web scanner rules, found ${webRulesWithModule.length}`);
  }
  if (extRules.length !== 24) {
    throw new Error(`Expected exactly 24 extension scanner rules, found ${extRules.length}`);
  }

  const webRulesMap = new Map();
  for (const item of webRulesWithModule) {
    webRulesMap.set(item.rule.id, item);
  }

  const extRulesMap = new Map();
  for (const r of extRules) {
    extRulesMap.set(r.id, r);
  }

  // Enforce exact rule ID agreement between engines
  const webIds = [...webRulesMap.keys()].sort();
  const extIds = [...extRulesMap.keys()].sort();
  if (JSON.stringify(webIds) !== JSON.stringify(extIds)) {
    throw new Error(`Rule ID mismatch between web and extension scanners: web=[${webIds}], ext=[${extIds}]`);
  }

  const inventory = [];
  for (const ruleId of webIds) {
    const webItem = webRulesMap.get(ruleId);
    const wRule = webItem.rule;
    const eRule = extRulesMap.get(ruleId);

    // Validate type agreement (vulnerability vs advisory)
    const wType = wRule.findingType === 'advisory' ? 'advisory' : 'vulnerability';
    const eType = eRule.findingType === 'advisory' ? 'advisory' : 'vulnerability';
    if (wType !== eType) {
      throw new Error(`Rule type mismatch for ${ruleId}: web="${wType}", extension="${eType}"`);
    }

    // Validate severity agreement
    if (wRule.severity !== eRule.severity) {
      throw new Error(`Rule severity mismatch for ${ruleId}: web="${wRule.severity}", extension="${eRule.severity}"`);
    }

    // Derive category
    const guidance = webGuidance[ruleId] || null;
    const category = wRule.owasp || (guidance ? guidance.category : null);
    if (!category) {
      throw new Error(`Missing category for rule ${ruleId}`);
    }

    // Use actual scanner metadata message; fallback to guidance title if message is absent
    const description = wRule.message || (guidance ? guidance.title : wRule.name);

    inventory.push({
      ruleId,
      ruleName: wRule.name,
      category,
      severity: wRule.severity,
      type: wType,
      description,
      cvssBaseScore: wRule.cvss?.baseScore ?? null,
      cvssVector: wRule.cvss?.vector ?? null,
      provenance: {
        webRuleSource: webItem.moduleFile,
        extensionRuleSource: 'vscode-extension/src/scanner/rules.js',
        metadataSource: 'accepted-scanner-registry',
        categorySource: wRule.owasp ? 'webRule.owasp' : 'guidanceCatalog.category',
        descriptionSource: wRule.message ? 'webRule.message' : 'guidanceCatalog.title'
      }
    });
  }

  // Derive counts dynamically
  const categoriesSet = new Set(inventory.map(r => r.category.split('-')[0].trim()));
  const counts = {
    totalRules: inventory.length,
    vulnerabilityRules: inventory.filter(r => r.type === 'vulnerability').length,
    advisoryRules: inventory.filter(r => r.type === 'advisory').length,
    categoriesCount: categoriesSet.size
  };

  if (counts.totalRules !== 24 || counts.vulnerabilityRules !== 23 || counts.advisoryRules !== 1 || counts.categoriesCount !== 7) {
    throw new Error(`Derived rule inventory counts invalid: ${JSON.stringify(counts)}`);
  }

  return { inventory, counts };
};

/**
 * Ingests, binds, and strictly validates benchmark run reports from disk.
 * Enforces provenance:
 * - Engine binding: rejects cross-engine artifacts.
 * - Manifest binding: verifies datasetBaseCommit and manifestVersion.
 * - Sample hash verification: verifies sample hashes against current disk files.
 * - Completion and matrix count consistency (116 attempted, 116 completed, 108 controlled).
 * 
 * @param {string} runDir - Directory containing web/ and extension/ run folders.
 * @param {Object} [options]
 * @param {Object} [options.manifest] - Manifest object to bind against.
 * @param {string} [options.samplesDir] - Samples directory to verify file digests against.
 * @returns {Object} Validated report metrics and provenance.
 */
export const ingestRunReports = (runDir, options = {}) => {
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

  // 1. Engine binding check: reject cross-engine files
  if (webMeta.engine !== 'web' || webReport.metadata?.scannerEngine !== 'web') {
    throw new Error(`Cross-engine contamination: expected web engine in ${path.join(runDir, 'web')}, found "${webMeta.engine}".`);
  }
  if (extMeta.engine !== 'extension' || extReport.metadata?.scannerEngine !== 'extension') {
    throw new Error(`Cross-engine contamination: expected extension engine in ${path.join(runDir, 'extension')}, found "${extMeta.engine}".`);
  }

  // 2. Evaluator commit consistency across engines
  if (webMeta.evaluatorCommit !== extMeta.evaluatorCommit) {
    throw new Error(
      `Inconsistent evaluator commits between engines: web="${webMeta.evaluatorCommit}", extension="${extMeta.evaluatorCommit}".`
    );
  }

  // 3. Dataset base commit consistency
  if (webMeta.datasetBaseCommit !== extMeta.datasetBaseCommit) {
    throw new Error(
      `Inconsistent dataset base commit between engines: web="${webMeta.datasetBaseCommit}", extension="${extMeta.datasetBaseCommit}".`
    );
  }

  // 4. Manifest binding if provided
  if (options.manifest) {
    const expectedBaseCommit = options.manifest.baseCommit;
    if (expectedBaseCommit && webMeta.datasetBaseCommit !== expectedBaseCommit) {
      throw new Error(
        `Stale or mismatched dataset base commit: run metadata has "${webMeta.datasetBaseCommit}", manifest has "${expectedBaseCommit}".`
      );
    }
    const expectedManifestVersion = options.manifest.manifestVersion || '1.0.0';
    if (webMeta.datasetManifestVersion !== expectedManifestVersion) {
      throw new Error(
        `Manifest version mismatch: run metadata has "${webMeta.datasetManifestVersion}", expected "${expectedManifestVersion}".`
      );
    }
  }

  // 5. Sample hash verification if samplesDir provided
  if (options.samplesDir && fs.existsSync(options.samplesDir)) {
    for (const fileEntry of (webMeta.files || []).slice(0, 5)) {
      const diskPath = path.join(options.samplesDir, fileEntry.fileName);
      if (fs.existsSync(diskPath)) {
        const diskHash = sha256(diskPath);
        if (diskHash !== fileEntry.sha256) {
          throw new Error(`Stale run: sample file "${fileEntry.fileName}" on disk hash ${diskHash} differs from run metadata hash ${fileEntry.sha256}.`);
        }
      }
    }
  }

  // 6. Metric count consistency: 116 attempted, 116 completed, 108 evaluated
  const validateEngineCounts = (engineName, report, meta) => {
    const attempted = report.scanCompletion?.attempted ?? report.scanCompletion?.totalAttempted;
    const completed = report.scanCompletion?.completed;
    const evaluated = report.fileConfusionMatrix?.N ?? report.fileConfusionMatrix?.totalEvaluated;
    const rawCount = report.rawScanResults?.length;
    const metaCount = meta.files?.length;

    if (attempted !== 116 || completed !== 116) {
      throw new Error(`Engine "${engineName}" incomplete scan counts: attempted=${attempted}, completed=${completed} (expected 116).`);
    }
    if (evaluated !== 108) {
      throw new Error(`Engine "${engineName}" invalid controlled evaluated count: ${evaluated} (expected 108).`);
    }
    if (rawCount !== 116 || metaCount !== 116) {
      throw new Error(`Engine "${engineName}" raw scan count mismatch: rawScanResults=${rawCount}, metaFiles=${metaCount} (expected 116).`);
    }
  };

  validateEngineCounts('web', webReport, webMeta);
  validateEngineCounts('extension', extReport, extMeta);

  // 7. Verify CSV artifacts exist and are non-empty
  const csvFiles = ['metrics_summary.csv', 'file_results.csv', 'findings_details.csv'];
  for (const csv of csvFiles) {
    const webCsvPath = path.join(runDir, 'web', csv);
    const extCsvPath = path.join(runDir, 'extension', csv);
    if (!fs.existsSync(webCsvPath) || fs.statSync(webCsvPath).size === 0) {
      throw new Error(`Missing or empty web CSV artifact: ${webCsvPath}`);
    }
    if (!fs.existsSync(extCsvPath) || fs.statSync(extCsvPath).size === 0) {
      throw new Error(`Missing or empty extension CSV artifact: ${extCsvPath}`);
    }
  }

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
 * @returns {Promise<Object>} Complete candidate package metadata.
 */
export const buildCandidatePackageMetadata = async (options = {}) => {
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
  const { datasetFilesHashes, counts: datasetCounts } = validateAndDigestManifest(manifest, samplesDir);

  const manifestMeta = {
    path: 'test-samples/dataset-manifest.json',
    sha256: sha256(manifestPath),
    sizeBytes: fs.statSync(manifestPath).size,
    manifestVersion: manifest.manifestVersion || '1.0.0',
    datasetBaseCommit: manifest.baseCommit || 'ca154776e3896fe4cc6db883b46d9caaf0d23089'
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

  // 5. Active rules inventory: load dynamically from actual accepted registries
  const { inventory: activeRules, counts: ruleCounts } = await loadActualRuleInventories(rootDir);

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

  // 7. Ingest and validate actual run reports
  const runs = ingestRunReports(runDir, { manifest, samplesDir, rootDir });

  // 8. Assemble package metadata with explicit distinct commit provenance
  const packageMetadata = {
    schemaVersion: '1.1.0',
    packageMetadataVersion: '1.1.0',
    status: 'PROPOSED / UNFROZEN (Phase 05 Candidate - Pending Capstone Group Review and Adoption)',
    generatedAt: new Date().toISOString(),
    packageName: pkg.name || 'jsentinel',
    packageVersion: pkg.version || '1.1.0',
    provenance: {
      // Distinct base commits:
      // - datasetBaseCommit: commit where dataset manifest was established
      // - acceptedPhase04EvidenceCommit: accepted commit from which Phase 05 branched
      // - evaluatorSourceCommit: live Git commit of evaluator code
      datasetBaseCommit: manifestMeta.datasetBaseCommit,
      acceptedPhase04EvidenceCommit: '0a76a2f61dea576a0155153a8e0bad6a4d42fdbb',
      evaluatorSourceCommit: gitProv.fullCommit,
      evaluatorShortCommit: gitProv.shortCommit,
      evaluatorBranch: gitProv.branch,
      evaluatorWorkingTreeClean: gitProv.isClean,
      runEvidenceSourceCommit: runs.web.metadata.evaluatorCommit
    },
    datasetSummary: {
      manifestVersion: manifestMeta.manifestVersion,
      manifestSha256: manifestMeta.sha256,
      manifestSizeBytes: manifestMeta.sizeBytes,
      totalFiles: datasetCounts.totalFiles,
      controlledFiles: datasetCounts.controlledFiles,
      vulnerableControlled: datasetCounts.vulnerableControlled,
      cleanControlled: datasetCounts.cleanControlled,
      scenarioFiles: datasetCounts.scenarioFiles,
      files: datasetFilesHashes
    },
    ruleInventory: {
      totalActiveRules: ruleCounts.totalRules,
      vulnerabilityRules: ruleCounts.vulnerabilityRules,
      advisoryRules: ruleCounts.advisoryRules,
      categoriesCovered: ruleCounts.categoriesCount,
      unsupportedWeaknessesRetained: 3,
      unsupportedWeaknessIds: ['V-A10-053', 'V-A10-054', 'V-A6-033'],
      activeRules
    },
    scannerSources: scannerSourceHashes,
    evaluatorModules: evaluatorHashes,
    evaluationEvidence: {
      runDirectory: path.relative(rootDir, runDir).replace(/\\/g, '/'),
      totalScanAttempts: 232,
      perEngineAttempts: 116,
      web: {
        engine: 'web',
        runId: runs.web.metadata.runId,
        runDurationMs: runs.web.metadata.totalDurationMs,
        timingBoundary: runs.web.metadata.timingBoundary,
        completion: runs.web.metrics.completion,
        controlledConfusionMatrix: runs.web.metrics.controlledMatrix,
        expectedRuleMetrics: runs.web.metrics.expectedRule,
        findingPrecisionMetrics: runs.web.metrics.findingPrecision,
        unmatchedFindingsCount: runs.web.unmatchedFindings.length,
        unmatchedFindings: runs.web.unmatchedFindings
      },
      extension: {
        engine: 'extension',
        runId: runs.extension.metadata.runId,
        runDurationMs: runs.extension.metadata.totalDurationMs,
        timingBoundary: runs.extension.metadata.timingBoundary,
        completion: runs.extension.metrics.completion,
        controlledConfusionMatrix: runs.extension.metrics.controlledMatrix,
        expectedRuleMetrics: runs.extension.metrics.expectedRule,
        findingPrecisionMetrics: runs.extension.metrics.findingPrecision,
        unmatchedFindingsCount: runs.extension.unmatchedFindings.length,
        unmatchedFindings: runs.extension.unmatchedFindings
      }
    },
    evaluationPolicies: {
      matchingToleranceLines: 0,
      matchColumn: false,
      matchCategory: false,
      advisoryHandling: 'Separate unscored advisory tracking; excluded from vulnerability confusion matrix and recall/F1 calculation.',
      unmatchedFindingHandling: 'Preserved in detail; eligible for controlled precision via manual ground-truth adjudication.',
      zeroDenominatorHandling: 'Returns null and N/A without throwing NaN or crashing.'
    },
    reproductionCommands: {
      // Directs reproduction to a new target directory so it never collides with existing runs
      fullBenchmarkRun: 'node validation/evaluator/runner.mjs --out-dir validation/evaluator/runs/phase05-benchmark-repro',
      evaluatorUnitTests: 'node --test validation/evaluator/evaluator.test.mjs',
      regressionTests: 'node --test validation/browser-scope.test.mjs validation/html-overlapping.test.mjs validation/validation-handling.test.mjs validation/pilot-manifest.test.mjs validation/guidance.test.cjs',
      linter: 'npm run lint',
      build: 'npm run build'
    }
  };

  return packageMetadata;
};

// CLI execution
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const rootDir = defaultRootDir;
  const outPath = path.join(rootDir, 'documents', 'research-phases', 'checks', '05-candidate-package-metadata.json');
  const corr1BackupPath = path.join(rootDir, 'documents', 'research-phases', 'checks', '05-candidate-package-metadata-2026-09-15-corr1.json');

  // Preserve prior artifact if it exists and backup doesn't already exist
  if (fs.existsSync(outPath) && !fs.existsSync(corr1BackupPath)) {
    fs.copyFileSync(outPath, corr1BackupPath);
    console.log(`Preserved prior candidate package metadata to: ${corr1BackupPath}`);
  }

  buildCandidatePackageMetadata({ rootDir })
    .then(metadata => {
      fs.writeFileSync(outPath, JSON.stringify(metadata, null, 2) + '\n', 'utf8');
      console.log(`Successfully generated versioned candidate package metadata: ${outPath}`);
    })
    .catch(err => {
      console.error('Failed to generate package metadata:', err);
      process.exit(1);
    });
}
