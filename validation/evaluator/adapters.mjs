/**
 * JSentinel Scanner Adapters
 * 
 * Provides unified adapters for the actual web scanner engine, the actual VS Code
 * extension engine, and pre-recorded supplied outputs.
 * 
 * Normalizes findings into a consistent structure retaining:
 * - rule ID
 * - category (mapped to OWASP Top 10 2021)
 * - location ({ line, column })
 * - guidance ID
 * - severity
 * - description / message
 * - parse and rule-execution errors
 * - completion status (attempted, completed, partial, failed)
 * 
 * Strict safety rule: Empty findings on error scans must NEVER be inferred as
 * completed success or clean negatives.
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
 * @returns {string}
 */
export const mapRuleIdToCategory = (ruleId) => {
  if (!ruleId || typeof ruleId !== 'string') {
    return 'Unknown';
  }
  const match = ruleId.match(/OWASP-(A\d{2})-/);
  if (match && OWASP_2021_CATEGORIES[match[1]]) {
    return OWASP_2021_CATEGORIES[match[1]];
  }
  return 'Uncategorized';
};

/**
 * Normalizes an individual raw issue into the standard evaluator finding shape.
 * 
 * @param {Object} issue - Raw issue object from scanner.
 * @returns {Object} Normalized finding.
 */
export const normalizeFinding = (issue) => {
  if (!issue || typeof issue !== 'object') {
    return null;
  }

  const ruleId = issue.id || issue.ruleId || 'UNKNOWN_RULE';
  const category = issue.owasp2021Category || issue.category || mapRuleIdToCategory(ruleId);
  const isA06 = ruleId.startsWith('OWASP-A06-') || issue.findingType === 'advisory';

  const rawLine = issue.line !== undefined ? issue.line : (issue.location?.line);
  const rawCol = issue.column !== undefined ? issue.column : (issue.location?.column);

  const lineNum = typeof rawLine === 'number' ? rawLine : parseInt(rawLine, 10);
  const colNum = typeof rawCol === 'number' ? rawCol : parseInt(rawCol, 10);

  return {
    id: ruleId,
    ruleId,
    category,
    severity: (issue.severity || (isA06 ? 'INFORMATIONAL' : 'MEDIUM')).toUpperCase(),
    findingType: isA06 ? 'advisory' : (issue.findingType || 'vulnerability'),
    location: {
      line: Number.isNaN(lineNum) ? 0 : lineNum,
      column: Number.isNaN(colNum) ? null : colNum
    },
    guidanceId: issue.guidanceId || ruleId,
    description: issue.message || issue.description || issue.weaknessDescription || '',
    sourceLine: issue.sourceLine || '',
    confidence: issue.confidence || null,
    rawFinding: issue
  };
};

/**
 * Normalizes a scanner engine result into a standardized RawScanResult.
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
      status: 'failed',
      attempted: true,
      completed: false,
      isPartial: false,
      isFailed: true,
      hasError: true,
      error: thrownError.message || String(thrownError),
      parseError: null,
      findings: [],
      rawOutput: null
    };
  }

  if (!rawResult || typeof rawResult !== 'object') {
    return {
      engine,
      fileName,
      status: 'failed',
      attempted: true,
      completed: false,
      isPartial: false,
      isFailed: true,
      hasError: true,
      error: 'Empty or invalid scanner engine response received.',
      parseError: null,
      findings: [],
      rawOutput: rawResult
    };
  }

  const rawIssues = Array.isArray(rawResult.issues) ? rawResult.issues : [];
  const normalizedFindings = rawIssues.map(normalizeFinding).filter(Boolean);

  let status = 'completed';
  if (rawResult.success === false || rawResult.error) {
    status = 'failed';
  } else if (rawResult.hasError) {
    status = 'partial';
  }

  return {
    engine,
    fileName: rawResult.fileName || fileName,
    scannerVersion: rawResult.scannerVersion || 'unknown',
    status,
    attempted: true,
    completed: status === 'completed',
    isPartial: status === 'partial',
    isFailed: status === 'failed',
    hasError: Boolean(rawResult.hasError || rawResult.error || status === 'failed'),
    error: rawResult.error || null,
    parseError: rawResult.error && rawResult.error.toLowerCase().includes('parse') ? rawResult.error : null,
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
 * 
 * @param {string|{name: string, content: string}} fileInput - File content or descriptor.
 * @param {string} [fileName='sample.js'] - File name.
 * @param {Object} [customEngine] - Optional mocked/injected engine for tests.
 * @returns {Promise<Object>} Normalized scan result.
 */
export const scanWithWebAdapter = async (fileInput, fileName = 'sample.js', customEngine = null) => {
  try {
    let name = fileName;
    let code = '';

    if (fileInput && typeof fileInput === 'object') {
      name = fileInput.name || fileName;
      if (typeof fileInput.text === 'function') {
        code = await fileInput.text();
      } else if (typeof fileInput.content === 'string') {
        code = fileInput.content;
      }
    } else if (typeof fileInput === 'string') {
      code = fileInput;
    } else {
      throw new Error('Invalid file input provided to web scanner adapter.');
    }

    const engine = customEngine || (await loadWebScanner());
    const fileLike = {
      name,
      text: async () => code
    };

    const rawResult = await engine.scanFile(fileLike, engine.rules);
    return normalizeScanResult({
      engine: 'web',
      fileName: name,
      rawResult
    });
  } catch (err) {
    return normalizeScanResult({
      engine: 'web',
      fileName: typeof fileInput === 'object' ? (fileInput?.name || fileName) : fileName,
      rawResult: null,
      thrownError: err
    });
  }
};

/**
 * Adapter to execute the actual VS Code extension scanner on code.
 * 
 * @param {string|{name: string, content: string}} fileInput - File content or descriptor.
 * @param {string} [fileName='sample.js'] - File name.
 * @param {Object} [customEngine] - Optional mocked/injected engine for tests.
 * @returns {Object} Normalized scan result.
 */
export const scanWithExtensionAdapter = (fileInput, fileName = 'sample.js', customEngine = null) => {
  try {
    let name = fileName;
    let code = '';

    if (fileInput && typeof fileInput === 'object') {
      name = fileInput.name || fileName;
      if (typeof fileInput.content === 'string') {
        code = fileInput.content;
      } else if (typeof fileInput.code === 'string') {
        code = fileInput.code;
      }
    } else if (typeof fileInput === 'string') {
      code = fileInput;
    } else {
      throw new Error('Invalid file input provided to extension scanner adapter.');
    }

    const engine = customEngine || loadExtensionScanner();
    const rawResult = engine.scanCode(code, name, engine.rules);

    return normalizeScanResult({
      engine: 'extension',
      fileName: name,
      rawResult
    });
  } catch (err) {
    return normalizeScanResult({
      engine: 'extension',
      fileName: typeof fileInput === 'object' ? (fileInput?.name || fileName) : fileName,
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
