# JSentinel phased work plan

Prepared September 10, 2026. Planning branch: `plan/research-phases`.

This folder replaces the earlier single implementation plan. Creating these guides does not start the scanner changes, regenerate the dataset, or revise the chapters. Each phase is a separate piece of work with its own stopping point.

## Start here

Review Phase 00 together to confirm the schedule and remaining responsibilities. Chris handles the system and technical testing; the assigned ISO classmate handles Phase 06 and the specified ISO portions of Phase 08. Start one technical phase at a time and review its result before choosing the next phase.

| Phase | Deliverable | Depends on | Status |
| --- | --- | --- | --- |
| [00: Team and timeline](00-team-and-timeline.md) | Agreed workload, owners, and lab arrangements | None | Not started |
| [01: Browser scope and rule categories](01-browser-scope-and-categories.md) | Browser-only active checks in both scanners | 00 | Not started |
| [02: Validation handling](02-validation-handling.md) | Invalid checks cannot hide browser redirect findings | 01 | Not started |
| [03: Duplicate findings and scoring](03-findings-and-scoring.md) | One finding and one deduction for overlapping HTML checks | 02 | Not started |
| [04: Dataset and manifest](04-dataset-and-manifest.md) | Reviewed 54 vulnerable, 54 corrected, and 8 scenario files | 03; preparation can start after 01 | Not started |
| [05: Evaluator and freeze](05-evaluator-and-freeze.md) | Checked evaluator, agreed Chapter III method, and frozen test package | 04; evaluator prototype can use its pilot | Not started |
| [06: Survey tables and document setup](06-survey-and-document-setup.md) | ISO results in shared Google Sheets and Google Docs | Assignment recorded; access to shared inputs | Not started |
| [07: AU lab testing](07-au-lab-testing.md) | Recorded results from actual lab PCs | 05 for measured runs; logistics can start after 00 | Not started |
| [08: Advisory guide and chapters](08-advisory-and-chapters.md) | Corrected guide and evidence-based Chapters I to V | 05, 06, and 07 for final results | Not started |

The technical sequence is 01 through 05, followed by measured lab runs in 07. Another groupmate can work on 06 while that sequence is underway. Phase 08 has separate batches for the advisory guide, targeted early-chapter corrections, Chapter IV, and Chapter V.

## Assigned work and shared documents

| Person | Responsibility |
| --- | --- |
| Chris | Phases 01 through 05 and technical preparation for 07; provide the technical method and results for the paper. |
| Assigned ISO classmate | Phase 06; Phase 08 Batch C's Project Evaluation Results and ISO interpretation; Phase 08 Batch D's Feedback tables and explanation. |
| Whole group | Phase 00 scheduling, Phase 07 lab arrangements and assistance, and final review. Assign the remaining Phase 08 sections separately. |

The ISO classmate's assignment has not expanded to scanner tests, Chapter III technical methods, the advisory guide, or the entire conclusion. Phase 06 can proceed while the technical work continues. Assignment does not mean the work is completed.

Use shared Google Sheets for ISO calculations and a shared Google Doc for chapter prose and tables. Keep untouched professor Word templates as formatting references and inspect final DOCX/PDF exports against them. Enter the restricted Drive, Sheet, and Doc links in the group's shared handoff when available; no links have been supplied here. These Markdown files remain task guides. The supplied `Final-Grp13-IT225-Chapters123-Aug25-2026.md` is a reference snapshot, not the live paper.

## Decisions carried forward

- Analyze browser-side source through both the web app and VS Code extension. Server-side scanning is outside the agreed scope.
- Keep the four identified problems in scope: false SSRF classifications, unreliable validation suppression, duplicate HTML findings and deductions, and incorrect A06 classifications.
- Keep 116 files: 108 controlled samples plus 8 simulated browser application scenarios. File count alone does not establish test quality.
- Allocate the 54 V/C pairs to defensible browser vulnerability cases. Check advisory-only behavior separately in regressions or the existing scenarios; do not force every active check into a vulnerable/clean pair.
- Treat accuracy measurement as a research procedure. No new accuracy dashboard or testing feature is required in the product.
- Use the professor's supplied Word templates. Preserve the user's existing Chapter III edits and make only the remaining evidence-based corrections.
- Keep survey perceptions, local development checks, and AU lab results separate. There is no target accuracy percentage to manufacture.

The expected scope after Phase 01 is 24 active base checks, including an A06 component-review check, across 7 OWASP Top 10:2021 categories and 8 modules. Confirm the actual registry before using those counts in the paper. Distinguish vulnerability-pattern checks from advisory checks. Planned A06 review signals are informational: exclude them from vulnerability totals, project-score deductions, and vulnerability accuracy metrics. Check count is not a claim of complete category coverage.

The four fixes are the starting corrections, not proof that all remaining rules are correct. Phase 04 reviews sample labels against actual browser behavior. Phase 05 verifies category, severity, location, and description as promised in Chapter III, and settles the written method before Phase 07. None of these checks requires a larger dataset or a new analysis engine.

## Working in small batches

A focused work block means roughly two hours of available work, not a delivery promise. The estimates in Phase 00 are discussion starters for the group. Each numbered batch in a phase can be completed and reviewed separately.

To resume, use a request such as: "Do Phase 02 from documents/research-phases/02-validation-handling.md and stop after its checks." For a larger phase, specify a batch. Completing one phase does not authorize running the rest automatically.

At each stop, record what changed, what was checked, unresolved issues, and the next dependency. Keep code and evidence versioned together when formal testing begins. The phase guides are tracked. Most research inputs outside this folder remain ignored and require access to the group's shared copies. A reference file placed here is not automatically committed or uploaded. Keep respondent data in the restricted group folder.

These guides are working notes. Transfer only reviewed chapter content into the paper. Remove chat references, comment markers, prompts, and work checklists from chapter drafts.
