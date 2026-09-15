/**
 * JSentinel Research Evaluator - Public API Entry Point
 * 
 * Exports the JSentinelEvaluator class, scanner adapters, matching engine,
 * metrics calculator, and schema validator.
 */

export { JSentinelEvaluator, EVALUATOR_VERSION } from './evaluator.mjs';
export {
  scanWithWebAdapter,
  scanWithExtensionAdapter,
  adaptSuppliedOutput,
  loadWebScanner,
  loadExtensionScanner,
  normalizeFinding,
  normalizeScanResult,
  mapRuleIdToCategory,
  OWASP_2021_CATEGORIES
} from './adapters.mjs';
export {
  matchSampleFindings,
  DEFAULT_MATCHING_POLICY,
  isAdvisoryRule,
  extractCategoryCode
} from './matching.mjs';
export {
  calculateEvaluationMetrics,
  safeRatio
} from './metrics.mjs';
export {
  SCHEMA_VERSION,
  RESULT_SCHEMA_DEFINITION,
  validateEvaluationResult
} from './schema.mjs';
