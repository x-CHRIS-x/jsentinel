/**
 * JSentinel Scanner Adapters
 * 
 * Provides unified adapters for the actual web scanner engine, the actual VS Code
 * extension engine, and pre-recorded supplied outputs.
 * 
 * Normalizes findings into a consistent structure retaining:
 * - rule ID
 * - category (mapped to OWASP Top 10 2021 and raw category preserved)
 * - location ({ line, column }) with strict coordinate parsing
 * - guidance ID (never invented from rule ID)
 * - severity (never invented as fallback)
 * - description / message
 * - parse and rule-execution errors
 * - completion status (unattempted, attempted, completed, partial, failed)
 * 
 * Strict safety rules:
 * - Empty findings on error scans must NEVER be inferred as completed success or clean negatives.
 * - Contradictory or missing completion evidence fails closed.
 * - Objects without valid file content are rejected as malformed descriptors.
 */

import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..', '..');

const require = createRequire(import.meta.url);

// Category mapping for OWASP 2021 codes
export const OWASP_2021_CATEGORIES = {
  A01: 'A01:2021-Broken Access Control',
  A02: 'A02:2021-Cryptographic Failures',
  A03: 'A03:2021-Injection',
  A05: 'A05:2021-Security Misconfiguration',
  A06: 'A06:2021-Vulnerable and Outdated Components',
  A07: 'A07:2021-Identification and Authentication Failures',
  A08: 'A08:2021-Software and Data Integrity Failures',
  A10: 'A10:2021-Server-Side Request Forgery (SSRF) (historical)'
};

/**
 * Maps a rule ID (e.g. 'OWASP-A03-001') to standard OWASP 2021 category name.
 * 
 * @param {string} ruleId 
 * @returns {string|null}
 */
export const mapRuleIdToCategory = (ruleId) => {
  if (!ruleId || typeof ruleId !== 'string') {
    return null;
  }
  const match = ruleId.match(/OWASP-(A\d{2})-/);
  if (match && OWASP_2021_CATEGORIES[match[1]]) {
    return OWASP_2021_CATEGORIES[match[1]];
  }
  return null;
};

/**
 * Normalizes an individual raw issue into the standard evaluator finding shape.
 * Preserves missing metadata explicitly as null without inventing fake fallbacks.
 * 
 * @param {Object} issue - Raw issue object from scanner.
 * @returns {Object|null} Normalized finding.
 */
export const normalizeFinding = (issue) => {
  if (!issue || typeof issue !== 'object') {
    return null;
  }

  const ruleId = issue.id || issue.ruleId || null;
  const isA06 = (ruleId && ruleId.startsWith('OWASP-A06-')) || issue.findingType === 'advisory';

  const rawLine = issue.line !== undefined ? issue.line : issue.location?.line;
  const rawCol = issue.column !== undefined ? issue.column : issue.location?.column;

  let parsedLine = null;
  if (typeof rawLine === 'number' && Number.isFinite(rawLine) && rawLine > 0) {
    parsedLine = rawLine;
  } else if (typeof rawLine === 'string' && /^\d+$/.test(rawLine.trim())) {
    const num = parseInt(rawLine.trim(), 10);
    if (num > 0) parsedLine = num;
  }

  let parsedCol = null;
  if (typeof rawCol === 'number' && Number.isFinite(rawCol) && rawCol >= 0) {
    parsedCol = rawCol;
  } else if (typeof rawCol === 'string' && /^\d+$/.test(rawCol.trim())) {
    parsedCol = parseInt(rawCol.trim(), 10);
  }

  // Preserve raw metadata without inventing defaults
  const rawCategory = issue.owasp2021Category || issue.category || null;
  const mappedCategory = rawCategory || (ruleId ? mapRuleIdToCategory(ruleId) : null);
  const severity = issue.severity ? String(issue.severity).toUpperCase() : (isA06 ? 'INFORMATIONAL' : null);
  const guidanceId = issue.guidanceId ? String(issue.guidanceId) : null;
  const description = issue.message || issue.description || issue.weaknessDescription || null;

  return {
    id: ruleId,
    ruleId,
    category: mappedCategory,
    rawCategory,
    severity,
    findingType: isA06 ? 'advisory' : (issue.findingType || 'vulnerability'),
    location: {
      line: parsedLine,
      column: parsedCol
    },
    guidanceId,
    description,
    sourceLine: issue.sourceLine || null,
    confidence: issue.confidence || null,
    rawFinding: issue
  };
};

/**
 * Normalizes a scanner engine result into a standardized RawScanResult.
 * Fails closed on missing or contradictory completion evidence.
 * 
 * @param {Object} params
 * @param {string} params.engine - 'web' | 'extension' | 'supplied'
 * @param {string} params.fileName - Target file name or path
 * @param {Object} params.rawResult - Direct output from scanner engine
 * @param {Error|null} [params.thrownError] - Any unhandled error caught during execution
 * @returns {Object} Normalized scan result.
 */
export const normalizeScanResult = ({ engine, fileName, rawResult, thrownError = null }) => {
  if (thrownError) {
    return {
      engine,
      fileName,
      scannerVersion: 'unknown',
      status: 'failed',
      attempted: true,
      completed: false,
      isPartial: false,
      isFailed: true,
      isUnattempted: false,
      hasError: true,
      error: thrownError.message || String(thrownError),
      parseError: null,
      ruleErrors: [],
      findings: [],
      rawOutput: null
    };
  }

  // Fail closed if rawResult is missing or not a non-null object
  if (!rawResult || typeof rawResult !== 'object') {
    return {
      engine,
      fileName,
      scannerVersion: 'unknown',
      status: 'failed',
      attempted: true,
      completed: false,
      isPartial: false,
      isFailed: true,
      isUnattempted: false,
      hasError: true,
      error: 'Empty or invalid scanner engine response received.',
      parseError: null,
      ruleErrors: [],
      findings: [],
      rawOutput: rawResult
    };
  }

  // Fail closed if issues is missing or not an array
  if (!Array.isArray(rawResult.issues)) {
    return {
      engine,
      fileName: rawResult.fileName || fileName,
      scannerVersion: rawResult.scannerVersion || 'unknown',
      status: 'failed',
      attempted: true,
      completed: false,
      isPartial: false,
      isFailed: true,
      isUnattempted: false,
      hasError: true,
      error: rawResult.error || 'Malformed scanner response: issues array missing or invalid.',
      parseError: rawResult.parseError || null,
      ruleErrors: Array.isArray(rawResult.ruleErrors) ? rawResult.ruleErrors : [],
      findings: [],
      rawOutput: rawResult
    };
  }

  // Preserve all errors
  const ruleErrors = Array.isArray(rawResult.ruleErrors) ? rawResult.ruleErrors : [];
  const rawError = rawResult.error || null;
  const parseError = rawResult.parseError || (rawError && rawError.toLowerCase().includes('parse') ? rawError : null);

  // Status resolution honoring engine contracts and explicit flags
  let status = 'failed';

  if (rawResult.status === 'unattempted') {
    status = 'unattempted';
  } else if (
    rawResult.status === 'failed' ||
    rawResult.success === false ||
    parseError
  ) {
    status = 'failed';
  } else if (rawResult.status === 'partial') {
    status = 'partial';
  } else if (rawResult.completed === false) {
    status = (rawResult.hasError || ruleErrors.length > 0) ? 'partial' : 'failed';
  } else if (rawResult.status === 'completed' || rawResult.success === true) {
    if (rawError || rawResult.hasError || ruleErrors.length > 0) {
      status = 'partial';
    } else {
      status = 'completed';
    }
  } else {
    // Unrecognized status string (e.g. 'unknown', 'weird') or missing explicit contract
    status = 'failed';
  }

  const normalizedFindings = rawResult.issues.map(normalizeFinding).filter(Boolean);

  const attempted = status !== 'unattempted';
  const completed = status === 'completed';
  const isPartial = status === 'partial';
  const isFailed = status === 'failed';
  const isUnattempted = status === 'unattempted';

  return {
    engine,
    fileName: rawResult.fileName || fileName,
    scannerVersion: rawResult.scannerVersion || 'unknown',
    status,
    attempted,
    completed,
    isPartial,
    isFailed,
    isUnattempted,
    hasError: Boolean(rawResult.hasError || rawError || parseError || ruleErrors.length > 0 || isFailed || isPartial),
    error: rawError,
    parseError,
    ruleErrors,
    findings: normalizedFindings,
    rawOutput: rawResult
  };
};

/**
 * Cache for lazy-loaded scanner engines and rules.
 */
let loadedWebEngine = null;
let loadedExtEngine = null;

/**
 * Loads the web scanner engine and its 8 modules (24 rules).
 */
export const loadWebScanner = async () => {
  if (loadedWebEngine) {
    return loadedWebEngine;
  }

  const { scanFile } = await import('../../src/utils/scannerEngine.js');
  const moduleNames = [
    'injection', 'xss', 'auth', 'sensitiveData', 'misconfig',
    'deserialization', 'knownVulns', 'accessControl'
  ];

  const ruleModules = await Promise.all(
    moduleNames.map(name => import(`../../src/scanner/rules/${name}.js`))
  );
  const rules = ruleModules.flatMap(m => Object.values(m).flat());

  loadedWebEngine = { scanFile, rules };
  return loadedWebEngine;
};

/**
 * Loads the VS Code extension scanner engine and its rules.
 */
export const loadExtensionScanner = () => {
  if (loadedExtEngine) {
    return loadedExtEngine;
  }

  const { scanCode } = require('../../vscode-extension/src/scanner/scannerEngine.js');
  const { allRules } = require('../../vscode-extension/src/scanner/rules.js');

  loadedExtEngine = { scanCode, rules: allRules };
  return loadedExtEngine;
};

/**
 * Adapter to execute the actual web scanner on code or a file-like object.
 * Rejects malformed input descriptors without valid file content.
 * 
 * @param {string|{name: string, content?: string, code?: string, text?: Function}} fileInput
 * @param {string} [fileName='sample.js'] - File name.
 * @param {Object} [customEngine] - Optional mocked/injected engine for tests.
 * @returns {Promise<Object>} Normalized scan result.
 */
export const scanWithWebAdapter = async (fileInput, fileName = 'sample.js', customEngine = null) => {
  let resolvedName = fileName;
  try {
    if (fileInput === null || fileInput === undefined) {
      throw new Error('Malformed input descriptor: fileInput is null or undefined.');
    }

    let code = null;

    if (typeof fileInput === 'object') {
      resolvedName = fileInput.name || fileName;
      if (typeof fileInput.text === 'function') {
        code = await fileInput.text();
      } else if (typeof fileInput.content === 'string') {
        code = fileInput.content;
      } else if (typeof fileInput.code === 'string') {
        code = fileInput.code;
      } else {
        throw new Error('Malformed file input descriptor: missing valid text() function, content string, or code string.');
      }
    } else if (typeof fileInput === 'string') {
      code = fileInput;
    } else {
      throw new Error('Invalid file input type: must be a string or descriptor object with code/content/text.');
    }

    if (typeof code !== 'string') {
      throw new Error('Resolved file code is not a string.');
    }

    const engine = customEngine || (await loadWebScanner());
    const fileLike = {
      name: resolvedName,
      text: async () => code
    };

    const rawResult = await engine.scanFile(fileLike, engine.rules);
    return normalizeScanResult({
      engine: 'web',
      fileName: resolvedName,
      rawResult
    });
  } catch (err) {
    return normalizeScanResult({
      engine: 'web',
      fileName: resolvedName,
      rawResult: null,
      thrownError: err
    });
  }
};

/**
 * Adapter to execute the actual VS Code extension scanner on code.
 * Rejects malformed input descriptors without valid file content.
 * 
 * @param {string|{name: string, content?: string, code?: string, text?: Function}} fileInput
 * @param {string} [fileName='sample.js'] - File name.
 * @param {Object} [customEngine] - Optional mocked/injected engine for tests.
 * @returns {Object} Normalized scan result.
 */
export const scanWithExtensionAdapter = (fileInput, fileName = 'sample.js', customEngine = null) => {
  let resolvedName = fileName;
  try {
    if (fileInput === null || fileInput === undefined) {
      throw new Error('Malformed input descriptor: fileInput is null or undefined.');
    }

    let code = null;

    if (typeof fileInput === 'object') {
      resolvedName = fileInput.name || fileName;
      if (typeof fileInput.content === 'string') {
        code = fileInput.content;
      } else if (typeof fileInput.code === 'string') {
        code = fileInput.code;
      } else if (typeof fileInput.text === 'function') {
        // Synchronous wrapper if text() returned immediate string
        const textRes = fileInput.text();
        if (typeof textRes === 'string') {
          code = textRes;
        } else {
          throw new Error('Asynchronous text() function not supported in synchronous extension scanner adapter.');
        }
      } else {
        throw new Error('Malformed file input descriptor: missing valid content or code string.');
      }
    } else if (typeof fileInput === 'string') {
      code = fileInput;
    } else {
      throw new Error('Invalid file input type: must be a string or descriptor object with code/content.');
    }

    if (typeof code !== 'string') {
      throw new Error('Resolved file code is not a string.');
    }

    const engine = customEngine || loadExtensionScanner();
    const rawResult = engine.scanCode(code, resolvedName, engine.rules);

    return normalizeScanResult({
      engine: 'extension',
      fileName: resolvedName,
      rawResult
    });
  } catch (err) {
    return normalizeScanResult({
      engine: 'extension',
      fileName: resolvedName,
      rawResult: null,
      thrownError: err
    });
  }
};

/**
 * Adapter for pre-recorded or supplied scan results.
 * 
 * @param {Object} suppliedOutput - Recorded scanner output JSON object.
 * @param {string} [fileName='unknown'] - File name fallback.
 * @returns {Object} Normalized scan result.
 */
export const adaptSuppliedOutput = (suppliedOutput, fileName = 'unknown') => {
  try {
    return normalizeScanResult({
      engine: 'supplied',
      fileName: suppliedOutput?.fileName || fileName,
      rawResult: suppliedOutput
    });
  } catch (err) {
    return normalizeScanResult({
      engine: 'supplied',
      fileName,
      rawResult: null,
      thrownError: err
    });
  }
};
