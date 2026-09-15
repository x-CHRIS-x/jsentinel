/**
 * JSentinel Research Evaluator Engine (Phase 05 Batch A)
 * 
 * Central evaluator coordinating adapters, one-to-one matching, metadata checks,
 * metrics calculation, schema validation, and CSV/JSON reporting.
 */

import { SCHEMA_VERSION, validateEvaluationResult } from './schema.mjs';
import {
  scanWithWebAdapter,
  scanWithExtensionAdapter,
  adaptSuppliedOutput
} from './adapters.mjs';
import { matchSampleFindings, DEFAULT_MATCHING_POLICY } from './matching.mjs';
import { calculateEvaluationMetrics } from './metrics.mjs';

export const EVALUATOR_VERSION = '1.0.0-phase05-batch-a';

export class JSentinelEvaluator {
  /**
   * @param {Object} [options]
   * @param {Object} [options.matchingPolicy]
   * @param {string} [options.scannerEngine='supplied'] - 'web' | 'extension' | 'supplied'
   */
  constructor(options = {}) {
    this.matchingPolicy = { ...DEFAULT_MATCHING_POLICY, ...options.matchingPolicy };
    this.scannerEngine = options.scannerEngine || 'supplied';
    this.version = EVALUATOR_VERSION;
  }

  /**
   * Evaluates an individual sample manifest against an actual scan result.
   * 
   * @param {Object} sampleManifest - Ground truth entry from dataset manifest.
   * @param {Object} scanResult - Normalized result from scanner adapter.
   * @returns {Object} Sample match output.
   */
  evaluateSample(sampleManifest, scanResult) {
    return matchSampleFindings({
      sampleManifest,
      scanResult,
      options: this.matchingPolicy
    });
  }

  /**
   * Evaluates a collection of samples against their corresponding scan results.
   * 
   * @param {Object} params
   * @param {Array<Object>} params.manifestFiles - Array of manifest file entries.
   * @param {Map<string, Object>|Object} params.scanResultsMap - Map of fileName -> normalized scan result.
   * @param {string} [params.datasetManifestVersion='1.0.0']
   * @returns {Object} Complete evaluation report conforming to schema.
   */
  evaluateSuite({ manifestFiles = [], scanResultsMap = {}, datasetManifestVersion = '1.0.0' }) {
    const resultsMap = scanResultsMap instanceof Map
      ? scanResultsMap
      : new Map(Object.entries(scanResultsMap));

    const sampleMatches = [];
    const rawResultsList = [];
    const scenarioObservations = [];

    for (const fileManifest of manifestFiles) {
      const fileName = fileManifest.fileName;
      let scanResult = resultsMap.get(fileName);

      if (!scanResult) {
        // Unscanned file recorded as failed/unattempted
        scanResult = {
          engine: this.scannerEngine,
          fileName,
          status: 'failed',
          attempted: true,
          completed: false,
          isPartial: false,
          isFailed: true,
          hasError: true,
          error: `No scan output provided for file: ${fileName}`,
          findings: [],
          rawOutput: null
        };
      }

      rawResultsList.push(scanResult);
      const match = this.evaluateSample(fileManifest, scanResult);
      sampleMatches.push(match);

      if (fileManifest.label === 'scenario') {
        scenarioObservations.push({
          scenarioId: fileManifest.sampleId || fileManifest.scenarioId || fileName,
          fileName,
          scanStatus: scanResult.status,
          hasError: Boolean(scanResult.hasError),
          vulnerabilities: {
            expectedCount: match.vulnerabilities.expectedCount,
            actualCount: match.vulnerabilities.actualCount,
            matchedCount: match.vulnerabilities.matchedCount,
            missedCount: match.vulnerabilities.missedCount,
            duplicateCount: match.vulnerabilities.duplicateCount,
            unmatchedCount: match.vulnerabilities.unmatchedCount,
            matchedDetails: match.vulnerabilities.matched.map(m => ({
              ruleId: m.expected.ruleId,
              expectedLine: m.expected.location?.line,
              actualLine: m.actualFinding?.location?.line
            }))
          },
          advisories: {
            expectedCount: match.advisories.expectedCount,
            actualCount: match.advisories.actualCount,
            matchedCount: match.advisories.matchedCount
          }
        });
      }
    }

    const calculated = calculateEvaluationMetrics(sampleMatches, rawResultsList);

    const evaluationResult = {
      schemaVersion: SCHEMA_VERSION,
      metadata: {
        evaluatorVersion: this.version,
        timestamp: new Date().toISOString(),
        scannerEngine: this.scannerEngine,
        datasetManifestVersion,
        matchingPolicy: this.matchingPolicy
      },
      scanCompletion: calculated.scanCompletion,
      fileConfusionMatrix: calculated.fileConfusionMatrix,
      expectedRuleMetrics: calculated.expectedRuleMetrics,
      findingPrecisionMetrics: calculated.findingPrecisionMetrics,
      advisoryMetrics: calculated.advisoryMetrics,
      metadataChecksSummary: calculated.metadataChecksSummary,
      scenarioObservations,
      fileResults: sampleMatches
    };

    const validation = validateEvaluationResult(evaluationResult);
    if (!validation.valid) {
      throw new Error(`Evaluator produced invalid schema result:\n${validation.errors.join('\n')}`);
    }

    return evaluationResult;
  }

  /**
   * Serializes an evaluation result to formatted JSON.
   * 
   * @param {Object} evaluationResult 
   * @returns {string}
   */
  exportJSON(evaluationResult) {
    return JSON.stringify(evaluationResult, null, 2);
  }

  /**
   * Generates CSV representations of the evaluation results.
   * 
   * @param {Object} evaluationResult 
   * @returns {{ metricsSummaryCsv: string, fileResultsCsv: string, findingsDetailsCsv: string }}
   */
  exportCSV(evaluationResult) {
    // 1. Metrics Summary CSV
    const cm = evaluationResult.fileConfusionMatrix;
    const exp = evaluationResult.expectedRuleMetrics;
    const prec = evaluationResult.findingPrecisionMetrics;
    const sc = evaluationResult.scanCompletion;
    const adv = evaluationResult.advisoryMetrics;

    const summaryRows = [
      ['Metric', 'Category', 'Value', 'Percentage', 'Formula', 'Notes'],
      ['Attempted Scans', 'Completion', sc.attempted, 'N/A', 'Total files attempted', ''],
      ['Completed Scans', 'Completion', sc.completed, 'N/A', 'Scans with status=completed and hasError=false', 'Eligible for matrix'],
      ['Partial Scans', 'Completion', sc.partial, 'N/A', 'Scans with rule execution errors', 'Excluded from matrix'],
      ['Failed Scans', 'Completion', sc.failed, 'N/A', 'Scans with fatal error or parse failure', 'Excluded from matrix'],
      ['Excluded Scans', 'Completion', sc.excluded, 'N/A', 'Simulated scenarios segregated', 'Reported separately'],
      ['True Positives (TP)', 'Controlled Matrix', cm.TP, 'N/A', 'Vulnerable file with >=1 vuln alert', ''],
      ['True Negatives (TN)', 'Controlled Matrix', cm.TN, 'N/A', 'Clean file with 0 vuln alerts', 'Advisory A06 excluded'],
      ['False Positives (FP)', 'Controlled Matrix', cm.FP, 'N/A', 'Clean file with >=1 vuln alert', ''],
      ['False Negatives (FN)', 'Controlled Matrix', cm.FN, 'N/A', 'Vulnerable file with 0 vuln alerts', ''],
      ['Completed Sample Size (N)', 'Controlled Matrix', cm.N, 'N/A', 'TP + TN + FP + FN', 'Completed controlled scans only'],
      ['Accuracy', 'Controlled Matrix', cm.accuracy !== null ? cm.accuracy.toFixed(4) : 'N/A', cm.percentages.accuracy, '(TP + TN) / N', 'Zero denominator N/A'],
      ['Precision', 'Controlled Matrix', cm.precision !== null ? cm.precision.toFixed(4) : 'N/A', cm.percentages.precision, 'TP / (TP + FP)', 'Zero denominator N/A'],
      ['Recall (TPR)', 'Controlled Matrix', cm.recall !== null ? cm.recall.toFixed(4) : 'N/A', cm.percentages.recall, 'TP / (TP + FN)', 'Zero denominator N/A'],
      ['Specificity (TNR)', 'Controlled Matrix', cm.specificity !== null ? cm.specificity.toFixed(4) : 'N/A', cm.percentages.specificity, 'TN / (TN + FP)', 'Zero denominator N/A'],
      ['False Positive Rate (FPR)', 'Controlled Matrix', cm.falsePositiveRate !== null ? cm.falsePositiveRate.toFixed(4) : 'N/A', cm.percentages.falsePositiveRate, 'FP / (FP + TN)', 'Zero denominator N/A'],
      ['False Negative Rate (FNR)', 'Controlled Matrix', cm.falseNegativeRate !== null ? cm.falseNegativeRate.toFixed(4) : 'N/A', cm.percentages.falseNegativeRate, 'FN / (FN + TP)', 'Zero denominator N/A'],
      ['Expected Vulnerabilities', 'Expected-Rule', exp.totalExpected, 'N/A', 'Total target expectations in completed scans', ''],
      ['Matched Expected Rules', 'Expected-Rule', exp.matchedExpected, 'N/A', 'One-to-one rule and location match', ''],
      ['Missed Expected Rules', 'Expected-Rule', exp.missedExpected, 'N/A', 'Targets without valid matching finding', ''],
      ['Expected-Rule Recall', 'Expected-Rule', exp.expectedRuleRecall !== null ? exp.expectedRuleRecall.toFixed(4) : 'N/A', exp.expectedRuleRecallPercentage, 'matchedExpected / totalExpected', 'Zero denominator N/A'],
      ['Actual Vuln Findings', 'Finding-Precision', prec.totalActualFindings, 'N/A', 'Total in-scope alerts from completed scans', ''],
      ['Matched Findings', 'Finding-Precision', prec.matchedFindings, 'N/A', 'Findings matched to ground-truth targets', ''],
      ['Duplicate Findings', 'Finding-Precision', prec.duplicateFindings, 'N/A', 'Duplicates of target; cannot inflate match', ''],
      ['Unmatched Findings', 'Finding-Precision', prec.unmatchedFindings, 'N/A', 'Unmatched alerts', 'PENDING manual ground-truth adjudication'],
      ['Provisional Precision', 'Finding-Precision', prec.provisionalPrecision !== null ? prec.provisionalPrecision.toFixed(4) : 'N/A', prec.provisionalPrecisionPercentage, 'matched / totalActual', 'Subject to manual adjudication'],
      ['Expected Advisories (A06)', 'Advisory A06', adv.totalExpectedAdvisories, 'N/A', 'Informational component reviews', 'Excluded from vulnerability metrics'],
      ['Detected Advisories (A06)', 'Advisory A06', adv.detectedAdvisories, 'N/A', 'A06 findings captured', 'Excluded from vulnerability metrics'],
      ['Matched Advisories (A06)', 'Advisory A06', adv.matchedAdvisories, 'N/A', 'A06 findings matched', 'Excluded from vulnerability metrics']
    ];

    const metricsSummaryCsv = summaryRows
      .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    // 2. File Results CSV
    const fileRows = [
      ['Sample ID', 'File Name', 'Ground Truth Label', 'Scan Status', 'Has Error', 'Actual Vulns Count', 'Actual Advisories Count', 'Is Positive', 'Matrix Classification']
    ];

    for (const f of evaluationResult.fileResults) {
      if (f.label === 'scenario') continue;
      const isPositive = f.vulnerabilities.actualCount > 0;
      let classification = 'EXCLUDED_INCOMPLETE';
      if (f.scanStatus === 'completed' && !f.hasScanError) {
        if (f.label === 'vulnerable') {
          classification = isPositive ? 'TP' : 'FN';
        } else if (f.label === 'clean') {
          classification = isPositive ? 'FP' : 'TN';
        }
      }

      fileRows.push([
        f.sampleId,
        f.fileName,
        f.label,
        f.scanStatus,
        f.hasScanError ? 'YES' : 'NO',
        f.vulnerabilities.actualCount,
        f.advisories.actualCount,
        isPositive ? 'YES' : 'NO',
        classification
      ]);
    }

    const fileResultsCsv = fileRows
      .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    // 3. Finding Details CSV
    const detailRows = [
      ['Sample ID', 'File Name', 'Expected Rule', 'Expected Line', 'Expected Category', 'Expected Severity', 'Actual Rule', 'Actual Line', 'Actual Severity', 'Match Status', 'Category Match', 'Severity Match', 'Location Match', 'Adjudication Status']
    ];

    for (const f of evaluationResult.fileResults) {
      for (const m of f.vulnerabilities.matched) {
        detailRows.push([
          f.sampleId,
          f.fileName,
          m.expected.ruleId,
          m.expected.location?.line ?? 'N/A',
          m.expected.owasp2021Category ?? 'N/A',
          m.expected.severity ?? 'N/A',
          m.actualFinding.ruleId,
          m.actualFinding.location?.line ?? 'N/A',
          m.actualFinding.severity ?? 'N/A',
          'MATCHED',
          m.metadataChecks.categoryMatch ? 'MATCH' : 'MISMATCH',
          m.metadataChecks.severityMatch ? 'MATCH' : 'MISMATCH',
          m.metadataChecks.locationMatch ? 'MATCH' : 'MISMATCH',
          'MATCHED_TARGET'
        ]);
      }

      for (const m of f.vulnerabilities.missed) {
        detailRows.push([
          f.sampleId,
          f.fileName,
          m.expected.ruleId,
          m.expected.location?.line ?? 'N/A',
          m.expected.owasp2021Category ?? 'N/A',
          m.expected.severity ?? 'N/A',
          'NONE',
          'NONE',
          'NONE',
          'MISSED',
          'N/A',
          'N/A',
          'N/A',
          'MISSED_TARGET'
        ]);
      }

      for (const d of f.vulnerabilities.duplicates) {
        detailRows.push([
          f.sampleId,
          f.fileName,
          'DUPLICATE_OF_TARGET',
          'N/A',
          'N/A',
          'N/A',
          d.actualFinding.ruleId,
          d.actualFinding.location?.line ?? 'N/A',
          d.actualFinding.severity ?? 'N/A',
          'DUPLICATE',
          'N/A',
          'N/A',
          'N/A',
          'DUPLICATE_OF_TARGET'
        ]);
      }

      for (const u of f.vulnerabilities.unmatched) {
        detailRows.push([
          f.sampleId,
          f.fileName,
          'NONE_EXPECTED',
          'N/A',
          'N/A',
          'N/A',
          u.actualFinding.ruleId,
          u.actualFinding.location?.line ?? 'N/A',
          u.actualFinding.severity ?? 'N/A',
          'UNMATCHED',
          'N/A',
          'N/A',
          'N/A',
          'PENDING_MANUAL_ADJUDICATION'
        ]);
      }
    }

    const findingsDetailsCsv = detailRows
      .map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    return {
      metricsSummaryCsv,
      fileResultsCsv,
      findingsDetailsCsv
    };
  }
}
