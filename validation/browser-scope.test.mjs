import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync, readdirSync } from 'node:fs';
import vm from 'node:vm';
import { scanFile } from '../src/utils/scannerEngine.js';
import * as policy from '../src/utils/findingPolicy.js';
import { formatJSONReport } from '../src/utils/jsonExporter.js';

const require = createRequire(import.meta.url);
const extensionPolicy = require('../vscode-extension/src/utils/findingPolicy.js');
const { scanCode } = require('../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../vscode-extension/src/scanner/rules.js');
const modules = ['injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization', 'knownVulns', 'accessControl'];
const rules = (await Promise.all(modules.map(name => import(`../src/scanner/rules/${name}.js`)))).flatMap(mod => Object.values(mod).flat());
const scanBoth = async (code, name = 'example.js') => [
  await scanFile({ name, text: async () => code }, rules), scanCode(code, name, allRules)
];

test('active registrations agree: 24 IDs, 7 categories, one advisory check', () => {
  assert.equal(rules.length, 24);
  assert.deepEqual(rules.map(r => r.id).sort(), allRules.map(r => r.id).sort());
  assert.equal(new Set(rules.map(r => r.id.split('-')[1])).size, 7);
  assert.equal(rules.filter(policy.isAdvisory).length, 1);
  for (const id of ['OWASP-A10-001', 'OWASP-A05-002', 'OWASP-A05-004']) assert.ok(!rules.some(r => r.id === id));
});

test('ordinary requests and server-header snippets do not emit retired findings', async () => {
  for (const code of ['fetch(target);', 'axios.get(target);', 'res.setHeader("Access-Control-Allow-Origin", "*");']) {
    for (const result of await scanBoth(code)) {
      assert.equal(result.hasError, false);
      assert.deepEqual(result.issues, []);
    }
  }
});

test('imports and requires produce visible, unscored advisories in both engines and JSON', async () => {
  for (const code of ['import axios from "axios"; axios.get(target);', 'const axios = require("axios"); axios.get("/api/profile");', 'import express from "express"; const app = express();']) {
    for (const result of await scanBoth(code)) {
      assert.equal(result.hasError, false);
      assert.equal(result.scannerVersion, policy.SCANNER_VERSION);
      assert.equal(result.issues.length, 1);
      const issue = result.issues[0];
      assert.equal(issue.guidanceId, 'OWASP-A06-001:component-review');
      assert.equal(issue.severity, 'INFORMATIONAL');
      assert.equal(issue.findingType, 'advisory');
      assert.equal(issue.cvssBaseScore, null);
      for (const implementation of [policy, extensionPolicy]) {
        const stats = implementation.calculateStats([result]);
        assert.equal(stats.totalIssues, 0);
        assert.equal(stats.activeIssuesCount, 0);
        assert.equal(stats.advisoryCount, 1);
        assert.equal(stats.securityScore, 100);
      }
      const report = formatJSONReport([result], { totalIssues: 99 });
      assert.equal(report.summary.totalIssues, 0);
      assert.equal(report.summary.advisoryCount, 1);
      assert.equal(report.files[0].score, 100);
      assert.equal(report.issues[0].eligibleForVulnerabilityMetrics, false);
      assert.equal(report.owaspProfile.find(cat => cat.category === 'A06').advisoryCount, 1);
      assert.equal(report.owaspProfile.some(cat => cat.category === 'A10'), false);
    }
  }
});

test('legacy A06 scoring and historical A10 remain intact without relabeling input', () => {
  const results = [{ fileName: 'legacy.js', issues: [
    { id: 'OWASP-A06-001', guidanceId: 'OWASP-A06-001:component-review', severity: 'MEDIUM', line: 1, column: 0 },
    { id: 'OWASP-A10-001', severity: 'HIGH', line: 2, column: 0 }
  ] }];
  const before = structuredClone(results);
  for (const implementation of [policy, extensionPolicy]) {
    assert.equal(implementation.calculateStats(results).securityScore, 85);
    assert.equal(implementation.getOwaspCategories(results).find(c => c.name.startsWith('A10')).count, 1);
  }
  const report = formatJSONReport(results);
  assert.equal(report.summary.totalIssues, 2);
  assert.equal(report.summary.advisoryCount, 0);
  assert.deepEqual(report.meta.scannerVersions, ['Legacy / version not recorded']);
  assert.equal(report.owaspProfile.find(cat => cat.category === 'A10').count, 1);
  assert.deepEqual(results, before);
});

test('mixed findings and exemptions keep vulnerability and advisory counts separate', async () => {
  const [result] = await scanBoth('import axios from "axios";\neval(userInput);');
  const advisory = result.issues.find(policy.isAdvisory);
  const vulnerability = result.issues.find(i => i.id === 'OWASP-A03-001');
  assert.ok(advisory && vulnerability);
  const key = issue => `${result.fileName}:${issue.id}:${issue.line}:${issue.column}`;
  for (const implementation of [policy, extensionPolicy]) {
    assert.equal(implementation.calculateStats([result]).securityScore, 80);
    assert.equal(implementation.calculateStats([result], [key(advisory)]).securityScore, 80);
    const exempted = implementation.calculateStats([result], [key(vulnerability)]);
    assert.equal(exempted.securityScore, 100);
    assert.equal(exempted.activeAdvisoryCount, 1);
    assert.equal(exempted.activeIssuesCount, 0);
  }
});

test('sensitive HTTP and eval checks still run', async () => {
  for (const [code, id] of [['fetch("http://api.example.com/login");', 'OWASP-A02-004'], ['eval(userInput);', 'OWASP-A03-001']]) {
    for (const result of await scanBoth(code)) {
      assert.equal(result.hasError, false);
      assert.ok(result.issues.some(issue => issue.id === id));
    }
  }
});

test('all 116 existing samples parse and both engines agree on finding locations and classification', async () => {
  const dir = new URL('../test-samples/samples/', import.meta.url);
  const files = readdirSync(dir).filter(name => /\.(js|jsx|ts|tsx)$/.test(name));
  assert.equal(files.length, 116);
  for (const name of files) {
    const results = await scanBoth(readFileSync(new URL(name, dir), 'utf8'), name);
    const normalized = results.map(result => {
      assert.equal(result.hasError, false, name);
      return result.issues.map(i => [i.id, i.line, i.column, i.severity, i.findingType || 'vulnerability-pattern'].join(':')).sort();
    });
    assert.deepEqual(normalized[0], normalized[1], name);
  }
});

test('web and packaged extension share identical policy logic', () => {
  const web = readFileSync(new URL('../src/utils/findingPolicy.js', import.meta.url), 'utf8').split('\nexport {')[0];
  const extension = readFileSync(new URL('../vscode-extension/src/utils/findingPolicy.js', import.meta.url), 'utf8').split('\nmodule.exports =')[0];
  assert.equal(web, extension);
});

// Exercise actual consumers with only host boundaries replaced, not a reimplementation.
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
function initializer(file, name) {
  const source = readFileSync(new URL(file, import.meta.url), 'utf8');
  let expression;
  traverse(parser.parse(source, { sourceType: 'unambiguous', plugins: ['jsx'] }), {
    VariableDeclarator(path) {
      if (path.node.id.name === name) expression = source.slice(path.node.init.start, path.node.init.end);
    }
  });
  assert.ok(expression, name);
  return expression;
}

test('actual app history, category memo and extension stats consume the advisory policy', async () => {
  const [result] = await scanBoth('import axios from "axios";');
  const createHistory = vm.runInNewContext(`(${initializer('../src/App.jsx', 'createScanHistoryRecord')})`, {
    ...policy, getCurrentTimestamp: () => 'test time'
  });
  const record = createHistory('test', [result]);
  assert.equal(record.stats.totalIssues, 0);
  assert.equal(record.stats.activeAdvisoryCount, 1);
  assert.equal(record.results[0].scannerVersion, policy.SCANNER_VERSION);
  const extStats = vm.runInNewContext(`(${initializer('../vscode-extension/src/extension.js', 'calculateStats')})(scannedFiles, [])`, {
    summarizeFindings: extensionPolicy.calculateStats, scannedFiles: { test: result }
  });
  assert.equal(extStats.totalIssues, 0);
  assert.equal(extStats.advisoryCount, 1);
  const categories = vm.runInNewContext(initializer('../src/App.jsx', 'owaspCategories'), {
    ...policy, results: [{ fileName: 'old.js', issues: [{ id: 'OWASP-A10-001', severity: 'HIGH' }] }],
    fpFlags: [], useMemo: fn => fn()
  });
  assert.equal(categories.find(cat => cat.name.startsWith('A10')).count, 1);
});

test('both PDF generators execute and separate advisories in their actual tables', async () => {
  const [result] = await scanBoth('import axios from "axios";');
  const { jsPDF } = require('jspdf');
  const realAutoTable = require('jspdf-autotable').autoTable;
  const guidance = require('../vscode-extension/src/data/guidanceCatalog.js');
  for (const file of ['../src/utils/pdfGenerator.js', '../vscode-extension/src/utils/pdfGenerator.js']) {
    const tables = [];
    let saved = false;
    class TestPDF extends jsPDF {
      constructor() { super(); this.save = () => { saved = true; }; }
    }
    const autoTable = (doc, options) => { tables.push(options); realAutoTable(doc, options); };
    const source = readFileSync(new URL(file, import.meta.url), 'utf8');
    const context = { ...policy, ...guidance, jsPDF: TestPDF, autoTable, Buffer, module: { exports: {} } };
    if (file.startsWith('../src/')) {
      const runnable = source.replace(/^import .*;\r?\n/gm, '').replace('export const generatePDFReport', 'const generatePDFReport');
      vm.runInNewContext(runnable + '\ngeneratePDFReport(results, {});', { ...context, results: [result] });
      assert.equal(saved, true);
    } else {
      const runnable = source.replace(/^const .* = require\(.*;\r?\n/gm, '');
      vm.runInNewContext(runnable, context);
      const buffer = context.module.exports.generatePDFBuffer({ scannedFiles: [result] });
      assert.equal(buffer.subarray(0, 5).toString(), '%PDF-');
    }
    const matrix = tables.find(table => table.head[0][0] === 'Resource File');
    assert.equal(matrix.body[0][2], 0, file + ' raw vulnerability count');
    assert.equal(matrix.body[0][3], 0, file + ' active vulnerability count');
    assert.equal(matrix.body[0][4], '100.0%');
    assert.ok(tables.some(table => table.body.some(row => row[0] === 'Component-review Advisories (not scored)' && row[1] === '1 informational findings')));
    const category = tables.find(table => table.head[0][0] === 'OWASP Core Category Profile Description');
    assert.equal(category.body.length, 7);
    assert.ok(category.body.some(row => row[0].startsWith('A06') && row[1] === '0 active findings; 1 advisories'));
  }
});

test('VS Code advisories use information diagnostics and retain severity filtering', async () => {
  const [result] = await scanBoth('import axios from "axios";');
  const vscode = {
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
    Position: class {}, Range: class {}, Uri: { parse: value => value },
    Diagnostic: class { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } }
  };
  const context = { require: () => vscode, module: { exports: {} } };
  vm.runInNewContext(readFileSync(new URL('../vscode-extension/src/diagnosticsProvider.js', import.meta.url), 'utf8'), context);
  const document = { fileName: result.fileName, lineCount: 1, lineAt: () => ({ text: 'import axios from "axios";' }) };
  const { createDiagnostics } = context.module.exports;
  assert.equal(createDiagnostics(document, result.issues)[0].severity, 2);
  assert.equal(createDiagnostics(document, result.issues, 'MEDIUM').length, 0);
});
