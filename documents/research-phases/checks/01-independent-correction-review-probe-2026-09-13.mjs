/**
 * Independent Phase 01 correction-review probe.
 *
 * Run from the repository root after `npm.cmd ci`:
 *   node documents/research-phases/checks/01-independent-correction-review-probe-2026-09-13.mjs
 *
 * Render the generated PDFs from the repository root with the renderer used in
 * the review (PyMuPDF 1.27.2.3):
 *   python -c "import fitz, pathlib; src=pathlib.Path('tmp/phase01-correction-review/output'); out=pathlib.Path('tmp/phase01-correction-review/rendered'); out.mkdir(parents=True, exist_ok=True); [page.get_pixmap(matrix=fitz.Matrix(1.5,1.5), alpha=False).save(out/(pdf.stem+'-page-'+str(i+1)+'.png')) for pdf in src.glob('*.pdf') for i,page in enumerate(fitz.open(pdf))]; print('\\n'.join(str(p) for p in out.glob('*.png')))"
 *
 * This development probe scans source strings; it does not execute them and is
 * not a formal research-accuracy or AU-lab test.
 */
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { scanFile } from '../../../src/utils/scannerEngine.js';
import { formatJSONReport } from '../../../src/utils/jsonExporter.js';
import * as policy from '../../../src/utils/findingPolicy.js';

const require = createRequire(import.meta.url);
const modules = ['injection', 'xss', 'auth', 'sensitiveData', 'misconfig', 'deserialization', 'knownVulns', 'accessControl'];
const webRules = (await Promise.all(modules.map(name => import(`../../../src/scanner/rules/${name}.js`))))
  .flatMap(mod => Object.values(mod).flat());
const { jsPDF } = require('../../../node_modules/jspdf');
const realAutoTable = require('../../../node_modules/jspdf-autotable').autoTable;
const guidance = require('../../../vscode-extension/src/data/guidanceCatalog.js');
const outputDir = new URL('../../../tmp/phase01-correction-review/output/', import.meta.url);
mkdirSync(outputDir, { recursive: true });

const scan = async (name, source) => scanFile({ name, text: async () => source }, webRules);
const advisory = await scan('advisory.js', 'import axios from "axios";');
const mixed = await scan('mixed.js', 'import axios from "axios"; eval(userInput);');

const stale = formatJSONReport(
  [advisory],
  { totalIssues: 999, activeIssues: 999, securityScore: 0 },
  [{ category: 'A06', count: 999 }],
  []
);
assert.equal(stale.summary.totalIssues, 0);
assert.equal(stale.summary.activeIssuesCount, 0);
assert.equal(stale.summary.advisoryCount, 1);
assert.equal(stale.summary.securityScore, 100);
assert.equal(stale.owaspProfile.find(row => row.category === 'A06')?.count, 0);
assert.equal(stale.issues[0].eligibleForVulnerabilityMetrics, false);

const legacy = structuredClone(advisory);
delete legacy.issues[0].findingType;
legacy.issues[0].severity = 'MEDIUM';
legacy.issues[0].cvssScore = 5;
const legacyJSON = formatJSONReport([legacy], {}, [], []);
assert.equal(legacyJSON.summary.totalIssues, 1);
assert.equal(legacyJSON.summary.activeIssuesCount, 1);
assert.equal(legacyJSON.summary.advisoryCount, 0);
assert.equal(legacyJSON.summary.securityScore, 95);

const webSource = readFileSync(new URL('../../../src/utils/pdfGenerator.js', import.meta.url), 'utf8');
const webRunnable = webSource
  .replace(/^import .*;\r?\n/gm, '')
  .replace('export const generatePDFReport', 'const generatePDFReport')
  .replace(/doc\.save\(`JSENTINEL-SECURITY-AUDIT-REPORT-\$\{docDate\}\.pdf`\);/, 'capturePDF(doc);');
const webContext = {
  ...policy, ...guidance, Buffer,
  jsPDF,
  autoTable: realAutoTable,
  capturePDF: doc => writeFileSync(new URL('web-mixed.pdf', outputDir), Buffer.from(doc.output('arraybuffer'))),
  module: { exports: {} },
  results: [mixed]
};
vm.runInNewContext(webRunnable + '\ngeneratePDFReport(results, {});', webContext);

const extSource = readFileSync(new URL('../../../vscode-extension/src/utils/pdfGenerator.js', import.meta.url), 'utf8');
const extRunnable = extSource.replace(/^const .* = require\(.*;\r?\n/gm, '');
const extContext = { ...policy, ...guidance, jsPDF, autoTable: realAutoTable, Buffer, module: { exports: {} } };
vm.runInNewContext(extRunnable, extContext);
const extBuffer = extContext.module.exports.generatePDFBuffer({ scannedFiles: [mixed] });
writeFileSync(new URL('extension-mixed.pdf', outputDir), extBuffer);

console.log(JSON.stringify({
  advisory: stale.summary,
  legacy: legacyJSON.summary,
  mixedTypes: mixed.issues.map(issue => [issue.id, issue.findingType, issue.severity]),
  outputs: ['web-mixed.pdf', 'extension-mixed.pdf']
}, null, 2));
