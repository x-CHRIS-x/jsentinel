import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';

import {
  scanFile,
  deduplicateOverlappingHtmlIssues as webDeduplicate
} from '../../../src/utils/scannerEngine.js';
import * as webPolicy from '../../../src/utils/findingPolicy.js';
import { formatJSONReport } from '../../../src/utils/jsonExporter.js';

const require = createRequire(import.meta.url);
const { scanCode, deduplicateOverlappingHtmlIssues: extensionDeduplicate } =
  require('../../../vscode-extension/src/scanner/scannerEngine.js');
const { allRules } = require('../../../vscode-extension/src/scanner/rules.js');
const extensionPolicy = require('../../../vscode-extension/src/utils/findingPolicy.js');
const { generatePDFBuffer } = require('../../../vscode-extension/src/utils/pdfGenerator.js');

const moduleNames = [
  'injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization',
  'knownVulns', 'accessControl'
];
const webRules = (await Promise.all(moduleNames.map(name =>
  import(`../../../src/scanner/rules/${name}.js`)
))).flatMap(module => Object.values(module).flat());

const scanBoth = async (code, fileName) => ({
  web: await scanFile({ name: fileName, text: async () => code }, webRules),
  extension: scanCode(code, fileName, allRules)
});
const normalized = result => result.issues.map(issue => ({
  id: issue.id,
  type: issue.findingType || 'vulnerability-pattern',
  severity: issue.severity,
  line: issue.line,
  column: issue.column,
  sourceLine: issue.sourceLine
}));

const cases = {
  template: 'target.innerHTML = `<p>${input}</p>`;',
  functionResult: 'target.innerHTML = render(input);',
  generic: 'target.innerHTML = input;',
  twoSameLine: 'a.innerHTML = `<p>${x}</p>`; b.innerHTML = render(y);',
  unrelatedSameLine: 'eval(input); target.innerHTML = `<p>${input}</p>`;',
  advisoryOnly: 'import axios from "axios"; axios.get("/api/data");',
  mixed: 'import axios from "axios";\ntarget.innerHTML = `<p>${input}</p>`;'
};

const observed = {};
for (const [name, code] of Object.entries(cases)) {
  const results = await scanBoth(code, `${name}.js`);
  assert.equal(results.web.hasError, false, `${name}: web scan error`);
  assert.equal(results.extension.hasError, false, `${name}: extension scan error`);
  const webHtml = normalized(results.web).filter(issue => ['OWASP-A03-004', 'OWASP-A03-005', 'OWASP-A03-006'].includes(issue.id));
  const extensionHtml = normalized(results.extension).filter(issue => ['OWASP-A03-004', 'OWASP-A03-005', 'OWASP-A03-006'].includes(issue.id));
  assert.deepEqual(webHtml, extensionHtml, `${name}: targeted HTML engine mismatch`);
  observed[name] = {
    webIssues: normalized(results.web),
    extensionIssues: normalized(results.extension),
    webStats: webPolicy.calculateStats([results.web]),
    extensionStats: extensionPolicy.calculateStats([results.extension])
  };
}

assert.deepEqual(observed.template.webIssues.map(issue => issue.id), ['OWASP-A03-004']);
assert.deepEqual(observed.functionResult.webIssues.map(issue => issue.id), ['OWASP-A03-005']);
assert.deepEqual(observed.generic.webIssues.map(issue => issue.id), ['OWASP-A03-006']);
assert.deepEqual(observed.twoSameLine.webIssues.map(issue => issue.id), ['OWASP-A03-004', 'OWASP-A03-005']);
assert.notEqual(observed.twoSameLine.webIssues[0].column, observed.twoSameLine.webIssues[1].column);
assert.deepEqual(observed.unrelatedSameLine.webIssues.map(issue => issue.id).sort(), ['OWASP-A03-001', 'OWASP-A03-004']);
assert.equal(observed.template.webStats.securityScore, 90);
assert.equal(observed.twoSameLine.webStats.securityScore, 80);
assert.equal(observed.advisoryOnly.webStats.totalIssues, 0);
assert.equal(observed.advisoryOnly.webStats.advisoryCount, 1);
assert.equal(observed.advisoryOnly.webStats.securityScore, 100);
assert.equal(observed.mixed.webStats.totalIssues, 1);
assert.equal(observed.mixed.webStats.advisoryCount, 1);
assert.equal(observed.mixed.webStats.securityScore, 90);

const templateScans = await scanBoth(cases.template, 'template.js');
for (const [engine, result] of Object.entries(templateScans)) {
  const key = `${result.fileName}:${result.issues[0].id}:${result.issues[0].line}:${result.issues[0].column}`;
  const policy = engine === 'web' ? webPolicy : extensionPolicy;
  assert.equal(policy.calculateStats([result], [key]).activeIssuesCount, 0);
  assert.equal(policy.calculateStats([result], [key]).securityScore, 100);
}

const combinedResults = [
  (await scanBoth(cases.template, 'template.js')).web,
  (await scanBoth(cases.advisoryOnly, 'advisory.js')).web
];
const jsonReport = formatJSONReport(combinedResults, { securityScore: -1 }, [], []);
assert.equal(jsonReport.summary.totalIssues, 1);
assert.equal(jsonReport.summary.advisoryCount, 1);
assert.equal(jsonReport.summary.securityScore, 90);
assert.deepEqual(jsonReport.issues.map(issue => issue.id), ['OWASP-A03-004', 'OWASP-A06-001']);

const extensionResults = [
  (await scanBoth(cases.template, 'template.js')).extension,
  (await scanBoth(cases.advisoryOnly, 'advisory.js')).extension
];
const scannedFiles = Object.fromEntries(extensionResults.map(result => [result.fileName, result]));
const pdfBuffer = generatePDFBuffer({ scannedFiles, projectName: 'Phase03 independent probe' });
assert.equal(pdfBuffer.subarray(0, 5).toString(), '%PDF-');
assert.ok(pdfBuffer.length > 10000);
const pdfPath = join(tmpdir(), `jsentinel-phase03-independent-${process.pid}.pdf`);
writeFileSync(pdfPath, pdfBuffer);

const synthetic = [
  { id: 'OWASP-A03-004', line: 7, column: 2, assignment: 'first' },
  { id: 'OWASP-A03-005', line: 7, column: 2, assignment: 'second' },
  { id: 'OWASP-A02-001', line: 7, column: 2, assignment: 'unrelated' }
];
const duplicateSameId = [
  { id: 'OWASP-A03-006', line: 9, column: 4, marker: 'first' },
  { id: 'OWASP-A03-006', line: 9, column: 4, marker: 'second' }
];
const differentColumns = [
  { id: 'OWASP-A03-006', line: 9, column: 4, marker: 'first' },
  { id: 'OWASP-A03-006', line: 9, column: 20, marker: 'second' }
];

const syntheticObservations = {};
for (const [engine, deduplicate] of Object.entries({ web: webDeduplicate, extension: extensionDeduplicate })) {
  syntheticObservations[engine] = {
    identicalCoordinateDifferentAssignments: deduplicate(synthetic).map(issue => `${issue.id}:${issue.assignment}`),
    duplicateSameIdSameCoordinate: deduplicate(duplicateSameId).map(issue => `${issue.id}:${issue.marker}`),
    sameIdDifferentColumns: deduplicate(differentColumns).map(issue => `${issue.id}:${issue.marker}`)
  };
  assert.deepEqual(syntheticObservations[engine].identicalCoordinateDifferentAssignments,
    ['OWASP-A03-004:first', 'OWASP-A02-001:unrelated']);
  assert.deepEqual(syntheticObservations[engine].duplicateSameIdSameCoordinate,
    ['OWASP-A03-006:first']);
  assert.equal(syntheticObservations[engine].sameIdDifferentColumns.length, 2);
}

console.log(JSON.stringify({
  candidate: 'caa5e6c22f1fb22683c1932746cb7b6ff772a8dd',
  actualScannerObservations: observed,
  jsonSummary: jsonReport.summary,
  pdf: { path: pdfPath, bytes: pdfBuffer.length },
  syntheticObservations
}, null, 2));
