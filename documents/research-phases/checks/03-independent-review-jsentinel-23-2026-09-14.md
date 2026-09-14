# Phase 03 Independent Review — jsentinel-23

Date: September 14, 2026 (Asia/Manila)
Reviewer: AO worker session `jsentinel-23`, separate from implementer `jsentinel-22`
Verdict: **PASS, scoped to Phase 03 candidate `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd`**
Manager acceptance: **PENDING**

## Identity and routing verification

- Harness: AO-managed implementation worker. Locally observed `AO_SESSION_ID=jsentinel-23`, `AO_PROJECT_ID=jsentinel`, AO app version `0.12.10`, and the session worktree.
- Requested model route: GPT-5.6 Sol. The active harness configuration identifies this worker as GPT-5.6 Sol; no contradictory local evidence was found.
- Requested reasoning effort: MEDIUM. The worktree and AO environment expose no machine-readable reasoning-effort field, so MEDIUM could not be independently verified from inside the worker. This is an explicit verification limit, not evidence of a routing mismatch.
- No subagents or substitute model routes were used.

## Exact scope and references

- Evidence branch start: `1e1ade40ea707b1b208273ecb378d1b1ee51e21d`.
- Accepted Phase 02 comparison base: `4a22c67953f52cb9356f5de5dbd6cacf79329f40`.
- Phase 03 candidate: `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd`.
- Verified candidate parent: `caa5e6c^` resolves exactly to `4a22c67953f52cb9356f5de5dbd6cacf79329f40`.
- Integrity rules read from `git show e7a670e:AGENTS.md`.
- Guides and evidence read: root and phase README material; `03-findings-and-scoring.md`; all `03-changes.md`, `03-checklist.md`, and `03-issues.md`; Phase 02 acceptance and independent-review evidence; advisory and historical-record constraints.
- Entire actual base-to-candidate diff inspected: five files, 455 insertions and 10 deletions. All production changes and the complete 323-line candidate regression test were reviewed. No UI-only masking, report-only masking, dataset work, evaluator changes, methodology changes, chapter changes, Phase 04 work, or generalized scanner rewrite is present.

## Independent runtime evidence

The durable probe is `03-independent-review-probe-2026-09-14.mjs`. It loads both actual scanners and their real rule registries, exercises downstream policy and JSON export, generates a real extension PDF buffer, and exposes synthetic identity-boundary behavior.

| Criterion | Result | Independent evidence |
| --- | --- | --- |
| A03 applicability priority | PASS | Dynamic template produced only A03-004; function result only A03-005; generic assignment only A03-006 in both scanners. |
| One finding and one deduction | PASS | Each single HIGH survivor produced one vulnerability and score 90 in both policy implementations. |
| Two assignments, including same line | PASS | `a.innerHTML = template; b.innerHTML = render(y);` produced A03-004 at column 0 and A03-005 at column 29, score 80, in both scanners. Two generic same-line assignments are also covered by the candidate regression suite. |
| Duplicate same-ID behavior | PASS within production contract | Synthetic same-ID records at one coordinate collapse to one; same ID at different columns survives twice. Actual rule traversal emits A03-006 once per assignment node, so the former represents duplicate emission for one source position, not two valid source assignments. |
| Unrelated vulnerability retained | PASS | Actual `eval(input)` plus template assignment retained A03-001 and A03-004 in both engines. Synthetic unrelated A02 at the exact HTML coordinate also survives. |
| False-positive filtering | PASS | The surviving finding's exact file/ID/line/column key removes the active count and restores score 100 in both policies. JSON marks and recomputes exemptions in the candidate suite. |
| A06 advisory-only | PASS | Both scanners emitted one INFORMATIONAL advisory, zero vulnerabilities, and score 100. |
| Mixed vulnerability and advisory | PASS | Both scanners emitted one A03-004 vulnerability plus one A06-001 advisory; only the vulnerability counted and score was 90. |
| JSON behavior | PASS | Real `formatJSONReport` ignored a deliberately stale caller score, returned one vulnerability, one advisory, score 90, and both issue records. |
| PDF behavior | PASS for extension runtime; web PDF covered by automated guidance test only | Real `generatePDFBuffer` produced a 37,472-byte, four-page PDF. Independent `pypdf` text extraction found score 90.0%, one active vulnerability, one advisory, A03-004, A06-001, and the advisory/no-deduction explanation. |
| New history vs saved historical records | PASS by code-path inspection and focused regression | New records call `calculateStats(updated, fpFlags)` on deduplicated scanner output. Saved history is parsed and retained as stored; loading assigns `historyItem.results` directly without rescanning or recalculating its saved `historyItem.stats`. Candidate Regression J preserves a legacy two-finding/score-80 record while a new equivalent scan produces one/90. |
| Both scanners and downstream agreement | PASS within Phase 03 scope | Target HTML IDs, locations, counts, score, advisory policy, and export behavior agree. |

## Assignment identity challenge

The helper uses a per-file `line:column` map and does not carry an AST node identifier. A synthetic list describing two allegedly different assignments with the same line and column loses the lower-priority record in both helpers. This is observable and is recorded by the probe.

This is **not a Phase 03 blocker** for actual scanner output. Both scanners obtain the coordinates from Babel `AssignmentExpression.loc.start`; within one parsed source file, two distinct AST nodes cannot begin at the same source offset. The three scoped rules all fire on the assignment node itself, and the updated web rules use numeric line/column fallbacks. Therefore, for production emissions, a shared file-local line and column is a justified identity for the same assignment, while two valid assignments necessarily differ in column or line. The helper is invoked separately per file, so cross-file collisions are impossible. The synthetic “different assignment, identical coordinate” object cannot be produced by either actual parser traversal under this rule contract.

The limitation is that the exported helper is not robust for arbitrary caller-created records or future scoped rules that omit/truncate coordinates. If its input contract expands, assignment identity should be made explicit (for example, a stable source range) or invalid coordinates should not be deduplicated. This is informational and does not invalidate the current production path.

## Findings

### Informational: synthetic identical-coordinate records are location-deduplicated

- Reproduction: pass A03-004 and A03-005 objects with identical `line` and `column` but distinct synthetic assignment markers to either exported helper.
- Observed: A03-004 survives and A03-005 is removed.
- Severity: Informational / future robustness.
- Assessment: Not producible as two distinct assignments by the actual Babel-backed scanners; location is unique source-node identity in the scoped production contract.

### Informational inherited issue: unrelated A03-001 column-zero parity

- Reproduction: scan `eval(input); target.innerHTML = template` on line 1.
- Observed: both findings survive and totals/scores agree, but the web A03-001 reports column `'unknown'` while the extension reports column `0`.
- Base evidence: the accepted base already uses `|| 'unknown'` for web A03-001 and `|| 0` for extension A03-001. Candidate does not change that rule.
- Severity: Low/informational, outside the targeted overlapping-HTML changes. No general rewrite was made.

### Dependency audit observation

- Root `npm ci` reported 11 existing dependency audit advisories (1 low, 4 moderate, 6 high). Extension install reported zero. No dependency manifests changed in Phase 03, and audit remediation was outside scope.

## Commands and observed exits

| Command | Exit | Result |
| --- | ---: | --- |
| `git switch -c ao/jsentinel-23/phase03-independent-review 1e1ade40...` | 0 | Clean independent evidence branch created from required evidence commit. |
| `npm ci` | 0 | 192 lockfile-pinned packages installed; audit observation above. |
| `npm --prefix vscode-extension ci` | 0 | 45 lockfile-pinned packages installed; zero audit advisories. |
| Initial probe before install | 1 | Expected environment failure: missing `@babel/standalone`; no scanner assertions executed. Disclosed, then dependencies installed. |
| `node documents/research-phases/checks/03-independent-review-probe-2026-09-14.mjs` | 0 | Actual dual-scanner, stats, JSON, PDF, FP, advisory, mixed, and synthetic probes passed. |
| `python -c ... PdfReader(...) ...` | 0 | Real PDF: 4 pages, 6,707 extracted characters; required score/count/rule/advisory text observed. |
| `node --test validation/validation-handling.test.mjs validation/browser-scope.test.mjs validation/guidance.test.cjs validation/html-overlapping.test.mjs` | 0 | 40 passed, 0 failed, 0 skipped/todo; 7.82 seconds. Includes 116-sample dual-engine parity and relevant browser/guidance/PDF checks. |
| `npm run lint` | 0 | Root ESLint clean. |
| `npm --prefix vscode-extension run lint` | 0 | Extension ESLint clean. |
| `npm run build` | 0 | Vite production build succeeded, 233 modules; existing large-chunk warning only. |
| `node --check` on all four changed production JS files, candidate regression test, and independent probe | 0 | Syntax checks clean. |
| `git diff --check 4a22c67..caa5e6c` | 0 | Candidate diff has no whitespace errors. |

## Limits and untested paths

- Manual web UI cards and browser-download interaction: **NOT RUN**.
- Live VS Code diagnostics/sidebar interaction: **NOT RUN**.
- Manual PDF visual/layout inspection: **NOT RUN**. PDF structure and extracted text were checked; no claim is made about visual fidelity.
- Real web `doc.save()` browser download: **NOT RUN**. Web PDF logic was exercised by the existing automated browser/guidance test; the real binary/content check used the extension generator.
- No formal research accuracy, AU laboratory, dataset, evaluator, methodology, chapter, or advisory-guide validation was performed or claimed.

## Scoped verdict

**PASS** for candidate `caa5e6c22f1fb22683c1932746cb7b6ff772a8dd` against Phase 03. The location key is justified identity for the actual per-file Babel assignment-node emissions, and all required production behaviors passed independent tests. The arbitrary synthetic-input limitation and inherited unrelated coordinate discrepancy are disclosed above. Manager acceptance remains pending; this review does not authorize merge or Phase 04.
