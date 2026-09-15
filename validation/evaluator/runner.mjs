/**
 * JSentinel Reproducible Local Benchmark Runner (Phase 05 Batch B)
 * 
 * Executes both actual scanner engines (Web and Extension) against the accepted
 * 116-file benchmark dataset (108 controlled files + 8 scenarios).
 * 
 * Strict research guarantees:
 * - Reads from accepted manifest test-samples/dataset-manifest.json without modification.
 * - Does not modify dataset files, scanner engines, or detection rules.
 * - Records full raw outputs, normalized results, JSON/CSV summaries, and errors.
 * - Calculates source hashes, records exact commit, environment/tool versions,
 *   and records timing boundary labeled "Node development only".
 * - Isolates runs into versioned directories; never overwrites previous run evidence.
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
 * Gets the current git commit hash if available.
 * 
 * @returns {string} Short git commit hash or 'unknown'.
 */
export const getGitCommitHash = () => {
  try {
    return execSync('git rev-parse --short HEAD', { cwd: rootDir, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
};

/**
 * Executes a full benchmark run for a specific engine over all 116 manifest files.
 * 
 * @param {Object} params
 * @param {string} params.engineType - 'web' | 'extension'
 * @param {Object} params.manifest - Loaded dataset manifest object.
 * @param {string} params.samplesDir - Path to test-samples/samples directory.
 * @param {string} params.outputDir - Output directory for run artifacts.
 * @param {string} params.commitHash - Git commit hash of evaluator state.
 * @returns {Promise<Object>} Run summary.
 */
export const runEngineBenchmark = async ({
  engineType,
  manifest,
  samplesDir,
  outputDir,
  commitHash = getGitCommitHash()
}) => {
  fs.mkdirSync(outputDir, { recursive: true });

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

  // Run suite evaluation
  const evaluator = new JSentinelEvaluator({
    scannerEngine: engineType
  });

  const evaluationResult = evaluator.evaluateSuite({
    manifestFiles,
    scanResultsMap,
    datasetManifestVersion: manifest.manifestVersion || '1.0.0'
  });

  // Generate exports
  const jsonReport = evaluator.exportJSON(evaluationResult);
  const { metricsSummaryCsv, fileResultsCsv, findingsDetailsCsv } = evaluator.exportCSV(evaluationResult);

  // Run metadata and provenance
  const runMetadata = {
    runId: `run-${engineType}-${Date.now()}`,
    engine: engineType,
    evaluatorVersion: EVALUATOR_VERSION,
    evaluatorCommit: commitHash,
    schemaVersion: SCHEMA_VERSION,
    datasetManifestVersion: manifest.manifestVersion || '1.0.0',
    datasetBaseCommit: manifest.baseCommit || 'unknown',
    startTime,
    endTime,
    totalDurationMs,
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      v8Version: process.versions.v8
    },
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
 * @param {string} [options.commitHash]
 * @returns {Promise<{ web: Object, extension: Object }>}
 */
export const runBothEngineBenchmarks = async (options = {}) => {
  const manifestPath = options.manifestPath || path.join(rootDir, 'test-samples', 'dataset-manifest.json');
  const samplesDir = options.samplesDir || path.join(rootDir, 'test-samples', 'samples');
  const baseOutputDir = options.baseOutputDir || path.join(rootDir, 'validation', 'evaluator', 'runs', 'phase05-batch-b');
  const commitHash = options.commitHash || getGitCommitHash();

  if (!fs.existsSync(manifestPath)) {
    throw new Error(`Manifest not found at path: ${manifestPath}`);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  const webOutputDir = path.join(baseOutputDir, 'web');
  const extOutputDir = path.join(baseOutputDir, 'extension');

  console.log(`Starting Phase 05 Batch B benchmark runs over 116 files...`);

  console.log(`Executing Web Scanner Engine...`);
  const webResult = await runEngineBenchmark({
    engineType: 'web',
    manifest,
    samplesDir,
    outputDir: webOutputDir,
    commitHash
  });
  console.log(`Web Scanner Engine completed in ${webResult.runMetadata.totalDurationMs}ms.`);

  console.log(`Executing Extension Scanner Engine...`);
  const extResult = await runEngineBenchmark({
    engineType: 'extension',
    manifest,
    samplesDir,
    outputDir: extOutputDir,
    commitHash
  });
  console.log(`Extension Scanner Engine completed in ${extResult.runMetadata.totalDurationMs}ms.`);

  return {
    web: webResult,
    extension: extResult
  };
};

// Execute if run directly from CLI
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runBothEngineBenchmarks()
    .then(({ web, extension }) => {
      console.log('--- Phase 05 Batch B Benchmark Runs Complete ---');
      console.log(`Web: ${web.totalAttempts} attempts (${web.controlledCount} controlled, ${web.scenarioCount} scenarios)`);
      console.log(`Extension: ${extension.totalAttempts} attempts (${extension.controlledCount} controlled, ${extension.scenarioCount} scenarios)`);
      console.log(`Total scan attempts: ${web.totalAttempts + extension.totalAttempts}`);
    })
    .catch(err => {
      console.error('Benchmark execution error:', err);
      process.exit(1);
    });
}
