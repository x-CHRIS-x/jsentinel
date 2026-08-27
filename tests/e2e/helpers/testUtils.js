/* global process */
/**
 * JSentinel E2E Test Suite - Shared Utilities & Runner Harness
 * 
 * Provides zero-dependency assertion helpers, AST scanner execution,
 * dynamic catalog loader, and result formatting.
 */

import * as Babel from '@babel/standalone';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const PROJECT_ROOT = path.resolve(__dirname, '../../..');

// Import all scanner rules
import { accessControlRules } from '../../../src/scanner/rules/accessControl.js';
import { authRules } from '../../../src/scanner/rules/auth.js';
import { deserializationRules } from '../../../src/scanner/rules/deserialization.js';
import { injectionRules } from '../../../src/scanner/rules/injection.js';
import { knownVulnsRules } from '../../../src/scanner/rules/knownVulns.js';
import { misconfigRules } from '../../../src/scanner/rules/misconfig.js';
import { sensitiveDataRules } from '../../../src/scanner/rules/sensitiveData.js';
import { ssrfRules } from '../../../src/scanner/rules/ssrf.js';
import { xssRules } from '../../../src/scanner/rules/xss.js';

export const ALL_SCANNER_RULES = [
  ...accessControlRules,
  ...authRules,
  ...deserializationRules,
  ...injectionRules,
  ...knownVulnsRules,
  ...misconfigRules,
  ...sensitiveDataRules,
  ...ssrfRules,
  ...xssRules
];

/**
 * Executes static security scanning on a string of source code using Babel AST transform.
 * 
 * @param {string} code - Source code string
 * @param {string} [fileName='test.js'] - File name for preset determination
 * @param {Array} [rules=ALL_SCANNER_RULES] - Rules to evaluate
 * @returns {Array<Object>} - Detected scan issues with attached sourceLine
 */
export function scanSourceCode(code, fileName = 'test.js', rules = ALL_SCANNER_RULES) {
  const issues = [];
  const lines = code.split('\n');
  const isTypeScript = fileName.endsWith('.ts') || fileName.endsWith('.tsx');

  for (const rule of rules) {
    try {
      Babel.transform(code, {
        filename: fileName,
        ast: false,
        code: false,
        highlightCode: false,
        parserOpts: {
          errorRecovery: true
        },
        presets: [
          isTypeScript ? 'typescript' : null,
          ['react', { runtime: 'automatic' }]
        ].filter(Boolean),
        plugins: [
          () => ({
            visitor: rule.visitor(issues)
          })
        ]
      });
    } catch {
      // In error recovery mode, partial errors do not abort the full scan
    }
  }

  // Attach sourceLine and ensure guidanceId fallback if not explicitly attached by rule visitor
  return issues.map(issue => {
    let sourceLine = issue.sourceLine;
    if (!sourceLine && typeof issue.line === 'number' && issue.line >= 1 && issue.line <= lines.length) {
      sourceLine = lines[issue.line - 1].trim();
    }
    return {
      ...issue,
      sourceLine: sourceLine || '',
      guidanceId: issue.guidanceId || issue.id
    };
  });
}

/**
 * Loads the Web Guidance Catalog module dynamically.
 * @returns {Promise<Object>}
 */
export async function loadWebGuidanceCatalog() {
  const catalogPath = path.join(PROJECT_ROOT, 'src/data/guidanceCatalog.js');
  if (!fs.existsSync(catalogPath)) {
    throw new Error(`Web guidance catalog not found at ${catalogPath}`);
  }
  const fileUrl = new URL(`file://${catalogPath.replace(/\\/g, '/')}`).href;
  return await import(fileUrl);
}

/**
 * Loads the VS Code Extension Guidance Catalog module dynamically.
 * @returns {Promise<Object>}
 */
export async function loadExtensionGuidanceCatalog() {
  const catalogPath = path.join(PROJECT_ROOT, 'vscode-extension/src/data/guidanceCatalog.js');
  if (!fs.existsSync(catalogPath)) {
    throw new Error(`Extension guidance catalog not found at ${catalogPath}`);
  }
  const fileUrl = new URL(`file://${catalogPath.replace(/\\/g, '/')}`).href;
  return await import(fileUrl);
}

/**
 * Test assertion and execution runner
 */
export class TestRunner {
  constructor(suiteName) {
    this.suiteName = suiteName;
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
    this.errors = [];
    this.startTime = 0;
  }

  test(name, fn) {
    this.tests.push({ name, fn });
  }

  async run() {
    this.startTime = Date.now();
    console.log(`\n\x1b[1m\x1b[36m=== Running ${this.suiteName} ===\x1b[0m`);

    for (const t of this.tests) {
      try {
        await t.fn();
        this.passed++;
        console.log(`  \x1b[32m✓\x1b[0m ${t.name}`);
      } catch (err) {
        this.failed++;
        this.errors.push({ name: t.name, error: err });
        console.log(`  \x1b[31m✗\x1b[0m ${t.name}`);
        console.log(`    \x1b[31mError: ${err.message}\x1b[0m`);
        if (err.stack && process.env.DEBUG_TESTS) {
          console.log(`    ${err.stack.split('\n').slice(1, 4).join('\n    ')}`);
        }
      }
    }

    const duration = ((Date.now() - this.startTime) / 1000).toFixed(2);
    console.log(`\n  \x1b[1mResults: ${this.passed} passed, ${this.failed} failed (${duration}s)\x1b[0m\n`);

    return {
      suiteName: this.suiteName,
      total: this.tests.length,
      passed: this.passed,
      failed: this.failed,
      duration: parseFloat(duration),
      errors: this.errors
    };
  }
}

// Minimal assertion helpers
export function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

export function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message ? message + ' - ' : ''}Expected: ${JSON.stringify(expected)}, Actual: ${JSON.stringify(actual)}`);
  }
}

export function assertNotEqual(actual, expected, message) {
  if (actual === expected) {
    throw new Error(`${message ? message + ' - ' : ''}Expected not to equal: ${JSON.stringify(expected)}`);
  }
}

export function assertTrue(value, message) {
  if (value !== true) {
    throw new Error(`${message ? message + ' - ' : ''}Expected true, received: ${JSON.stringify(value)}`);
  }
}

export function assertFalse(value, message) {
  if (value !== false) {
    throw new Error(`${message ? message + ' - ' : ''}Expected false, received: ${JSON.stringify(value)}`);
  }
}

export function assertIncludes(container, item, message) {
  if (typeof container === 'string' && !container.includes(item)) {
    throw new Error(`${message ? message + ' - ' : ''}String does not contain "${item}": "${container.substring(0, 100)}..."`);
  } else if (Array.isArray(container) && !container.includes(item)) {
    throw new Error(`${message ? message + ' - ' : ''}Array does not contain item: ${JSON.stringify(item)}`);
  }
}

export function assertDeepEqual(actual, expected, message) {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);
  if (a !== b) {
    throw new Error(`${message ? message + ' - ' : ''}Deep equality mismatch.\nExpected: ${b}\nActual:   ${a}`);
  }
}
