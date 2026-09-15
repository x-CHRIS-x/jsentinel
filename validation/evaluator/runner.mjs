/**
 * JSentinel Reproducible Local Benchmark Runner (Phase 05 Batch B & C)
 * 
 * Executes both actual scanner engines (Web and Extension) against the accepted
 * 116-file benchmark dataset (108 controlled files + 8 scenarios).
 * 
 * Strict research guarantees:
 * - Reads from accepted manifest test-samples/dataset-manifest.json without modification.
 * - Does not modify dataset files, scanner engines, or detection rules.
 * - Refuses to overwrite existing populated run directories; requires a new versioned path or runId.
 * - Records full raw outputs, normalized results, JSON/CSV summaries, and raw errors.
 * - Records exact full commit SHA, working tree cleanliness, and dependency versions.
 * - Records timing boundary explicitly labeled "Node development only".
 * - Supports CLI arguments for reproduction and pipeline integration.
 * - Evaluates 232 total scan attempts (116 per engine: 108 controlled, 8 scenarios).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { execSync } from 'node:child_process';

import { JSentinelEvaluator, EVALUATOR_VERSION } from './evaluator.mjs';
import { scanWithWebAdapter, scanWithExtensionAdapter, loadWebScanner, loadExtensionScanner } from './adapters.mjs';
import { SCHEMA_VERSION } from './schema.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..', '..');

/**
 * Computes SHA-256 digest of a string or buffer.
 * 
 * @param {string|Buffer} content 
 * @returns {string} Hex hash.
 */
export const sha256 = (content) => {
  return crypto.createHash('sha256').update(content).digest('hex');
};

/**
 * Gets git provenance information.
 * 
 * @returns {{ fullCommit: string, shortCommit: string, isClean: boolean, branch: string }}
 */
export const getGitProvenance = () => {
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
 * Reads dependency versions from package.json.
 * 
 * @returns {Object} Dependency inventory.
 */
export const getDependencyVersions = () => {
  try {
    const pkgPath = path.join(rootDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      return {
        packageVersion: pkg.version || 'unknown',
        dependencies: pkg.dependencies || {},
        devDependencies: pkg.devDependencies || {}
      };
    }
  } catch {
    // ignore
  }
  return { packageVersion: 'unknown', dependencies: {}, devDependencies: {} };
};

/**
 * Executes a full benchmark run for a specific engine over all 116 manifest files.
 * 
 * @param {Object} params
 * @param {string} params.engineType - 'web' | 'extension'
 * @param {Object} params.manifest - Loaded dataset manifest object.
 * @param {string} params.samplesDir - Path to test-samples/samples directory.
 * @param {string} params.outputDir - Output directory for run artifacts.
 * @param {Object} [params.provenance] - Git and environment provenance.
 * @returns {Promise<Object>} Run summary.
 */
export const runEngineBenchmark = async ({
  engineType,
  manifest,
  samplesDir,
  outputDir,
  provenance = null,
  runId: customRunId = null,
  manifestSha256 = null
}) => {
  // Refuse to overwrite if directory exists and contains files
  if (fs.existsSync(outputDir)) {
    const existingFiles = fs.readdirSync(outputDir);
    if (existingFiles.length > 0) {
      throw new Error(
        `Output directory "${outputDir}" already exists and is populated (${existingFiles.length} files). ` +
        `Refusing to overwrite existing evidence. Specify a new directory or runId.`
      );
    }
  } else {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const gitProv = provenance || getGitProvenance();
  const depVersions = getDependencyVersions();

  const startTime = new Date().toISOString();
  const startPerf = performance.now();

  const scanResultsMap = new Map();
  const fileTimingAndHashes = [];

  // Pre-load scanner engines
  if (engineType === 'web') {
    await loadWebScanner();
  } else {
    loadExtensionScanner();
  }

  const manifestFiles = manifest.files || [];

  for (const fileEntry of manifestFiles) {
    const fileName = fileEntry.fileName;
    const filePath = path.join(samplesDir, fileName);

    let code = '';
    let fileHash = 'missing';

    if (fs.existsSync(filePath)) {
      code = fs.readFileSync(filePath, 'utf8');
      fileHash = sha256(code);
    } else {
      console.warn(`[${engineType}] File not found on disk: ${filePath}`);
    }

    const scanStart = performance.now();
    let scanResult = null;

    if (engineType === 'web') {
      scanResult = await scanWithWebAdapter(code, fileName);
    } else {
      scanResult = scanWithExtensionAdapter(code, fileName);
    }

    const scanDurationMs = performance.now() - scanStart;

    scanResultsMap.set(fileName, scanResult);
    fileTimingAndHashes.push({
      sampleId: fileEntry.sampleId,
      fileName,
      sha256: fileHash,
      label: fileEntry.label,
      workloadType: fileEntry.workloadType || 'controlled',
      scanStatus: scanResult.status,
      findingsCount: scanResult.findings.length,
      hasError: scanResult.hasError,
      durationMs: Number(scanDurationMs.toFixed(3))
    });
  }

  const endPerf = performance.now();
  const endTime = new Date().toISOString();
  const totalDurationMs = Number((endPerf - startPerf).toFixed(3));

  const runId = customRunId || `run-${engineType}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

  // Run suite evaluation
  const evaluator = new JSentinelEvaluator({
    scannerEngine: engineType,
    runId
  });

  const evaluationResult = evaluator.evaluateSuite({
    manifestFiles,
    scanResultsMap,
    datasetManifestVersion: manifest.manifestVersion || '1.0.0',
    runId
  });

  // Generate exports
  const jsonReport = evaluator.exportJSON(evaluationResult);
  const { metricsSummaryCsv, fileResultsCsv, findingsDetailsCsv } = evaluator.exportCSV(evaluationResult);

  // Run metadata and provenance
  const runMetadata = {
    runId,
    engine: engineType,
    evaluatorVersion: EVALUATOR_VERSION,
    evaluatorCommit: gitProv.fullCommit,
    evaluatorShortCommit: gitProv.shortCommit,
    isWorkingTreeClean: gitProv.isClean,
    branch: gitProv.branch,
    schemaVersion: SCHEMA_VERSION,
    packageVersion: depVersions.packageVersion,
    datasetManifestVersion: manifest.manifestVersion || '1.0.0',
    datasetBaseCommit: manifest.baseCommit || 'unknown',
    manifestSha256: manifestSha256 || null,
    startTime,
    endTime,
    totalDurationMs,
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      v8Version: process.versions.v8
    },
    dependencies: depVersions.dependencies,
    devDependencies: depVersions.devDependencies,
    timingBoundary: {
      scope: 'Node development environment only',
      disclaimer: 'Execution timings reflect Node.js AST traversal and do not establish live web-browser DOM or VS Code extension performance on physical AU laboratory computers.'
    },
    summaryCounts: {
      totalFilesAttempted: fileTimingAndHashes.length,
      controlledFilesCount: fileTimingAndHashes.filter(f => f.label !== 'scenario').length,
      scenarioFilesCount: fileTimingAndHashes.filter(f => f.label === 'scenario').length,
      completedScans: evaluationResult.scanCompletion.completed,
      partialScans: evaluationResult.scanCompletion.partial,
      failedScans: evaluationResult.scanCompletion.failed,
      unattemptedScans: evaluationResult.scanCompletion.unattempted
    },
    files: fileTimingAndHashes
  };

  // Write outputs to run directory
  fs.writeFileSync(path.join(outputDir, 'evaluation_report.json'), jsonReport, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'metrics_summary.csv'), metricsSummaryCsv, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'file_results.csv'), fileResultsCsv, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'findings_details.csv'), findingsDetailsCsv, 'utf8');
  fs.writeFileSync(path.join(outputDir, 'run_metadata.json'), JSON.stringify(runMetadata, null, 2), 'utf8');

  return {
    engine: engineType,
    outputDir,
    totalAttempts: fileTimingAndHashes.length,
    controlledCount: runMetadata.summaryCounts.controlledFilesCount,
    scenarioCount: runMetadata.summaryCounts.scenarioFilesCount,
    evaluationResult,
    runMetadata
  };
};

/**
 * Runs both Web and Extension benchmarks over the dataset manifest.
 * 
 * @param {Object} [options]
 * @param {string} [options.manifestPath]
 * @param {string} [options.samplesDir]
 * @param {string} [options.baseOutputDir]
 * @param {string} [options.runId]
 * @param {Object} [options.provenance]
 * @returns {Promise<{ web: Object, extension: Object }>}
 */
export const runBothEngineBenchmarks = async (options = {}) => {
  const manifestPath = options.manifestPath || path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const samplesDir = options.samplesDir || path.join(rootDir, 'test-samples', 'samples');
  
  // Default to a distinct versioned run directory to prevent overwriting prior evidence
  const runId = options.runId || 'phase05-batch-b-corr2';
  const baseOutputDir = options.baseOutputDir || path.join(rootDir, 'validation', 'evaluator', 'runs', runId);
  const gitProv = options.provenance || getGitProvenance();

  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Manifest not found at path: ${manifestPath}`);
  }

  const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
  const manifestSha256 = sha256(manifestRaw);
  const manifest = JSON.parse(manifestRaw);

  const webOutputDir = path.join(baseOutputDir, 'web');
  const extOutputDir = path.join(baseOutputDir, 'extension');

  console.log(`Starting Phase 05 benchmark run [${runId}] over 116 files...`);
  console.log(`Base output directory: ${baseOutputDir}`);

  console.log(`Executing Web Scanner Engine...`);
  const webResult = await runEngineBenchmark({
    engineType: 'web',
    manifest,
    manifestSha256,
    samplesDir,
    outputDir: webOutputDir,
    provenance: gitProv
  });
  console.log(`Web Scanner Engine completed in ${webResult.runMetadata.totalDurationMs}ms.`);

  console.log(`Executing Extension Scanner Engine...`);
  const extResult = await runEngineBenchmark({
    engineType: 'extension',
    manifest,
    manifestSha256,
    samplesDir,
    outputDir: extOutputDir,
    provenance: gitProv
  });
  console.log(`Extension Scanner Engine completed in ${extResult.runMetadata.totalDurationMs}ms.`);

  return {
    runId,
    baseOutputDir,
    web: webResult,
    extension: extResult
  };
};

/**
 * Parses CLI arguments.
 * 
 * @param {string[]} args 
 * @returns {Object} Parsed options.
 */
export const parseCliArgs = (args) => {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--output-dir' || arg === '--out-dir') && i + 1 < args.length) {
      options.baseOutputDir = path.resolve(args[++i]);
    } else if (arg === '--run-id' && i + 1 < args.length) {
      options.runId = args[++i];
    } else if (arg === '--manifest' && i + 1 < args.length) {
      options.manifestPath = path.resolve(args[++i]);
    } else if (arg === '--samples-dir' && i + 1 < args.length) {
      options.samplesDir = path.resolve(args[++i]);
    }
  }
  return options;
};

// Execute if run directly from CLI
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const cliOptions = parseCliArgs(process.argv.slice(2));
  runBothEngineBenchmarks(cliOptions)
    .then(({ runId, baseOutputDir, web, extension }) => {
      console.log(`--- Benchmark Run [${runId}] Complete ---`);
      console.log(`Outputs: ${baseOutputDir}`);
      console.log(`Web: ${web.totalAttempts} attempts (${web.controlledCount} controlled, ${web.scenarioCount} scenarios)`);
      console.log(`Extension: ${extension.totalAttempts} attempts (${extension.controlledCount} controlled, ${extension.scenarioCount} scenarios)`);
      console.log(`Total scan attempts: ${web.totalAttempts + extension.totalAttempts}`);
    })
    .catch(err => {
      console.error('Benchmark execution error:', err.message);
      process.exit(1);
    });
}
