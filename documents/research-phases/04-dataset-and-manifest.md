# Phase 04: Improve the 116-file dataset

Status: Not started. Finalization depends on Phase 03; planning can begin after Phase 01. Suggested size: 3 to 5 focused blocks.

Keep 54 vulnerable samples, 54 corresponding corrected samples, and 8 simulated browser application scenarios. Review a small pilot before regenerating the full folder.

## Batch A: Six pairs and a manifest draft

Start with pairs covering browser redirects, exposed API keys, template HTML, function-result HTML, general HTML, and object merging. Vary actual code structure, input origin, or validation behavior. Changing comments or variable labels alone does not create meaningful additional coverage.

For each file, record a stable sample ID, pair or scenario ID, primary module, intended behavior, and the reason for each label. For each expected finding, record its rule ID, expected OWASP category, expected severity with its scenario assumptions, and location. Include a brief description of the weakness so a reviewer can check whether the actual message describes it correctly; exact message-string matching is unnecessary. Record source references, reviewer, and whether the case was used during development. Use only synthetic credentials.

Separate vulnerability labels from expected scanner behavior. A filename or an existing scanner alert cannot establish ground truth. For an import or parsing operation, include the context that makes it unsafe. Record review-only expectations separately when the code does not establish a vulnerability.

## Batch B: Expand the controlled samples

Allocate 54 distinct V/C pairs across browser cases with defensible vulnerability labels, including the six pilot pairs. Use the Phase 01 inventory to review coverage, but do not require two pairs for every active check. Reassign the former A06 advisory pairs to meaningful variations of supported browser weaknesses. Test A06 review behavior through development regressions outside the counted dataset or through the existing eight scenarios. Neither route changes the 116-file total.

Replace server-only samples with browser cases. Review clean counterparts for the intended weakness and unintended weaknesses. If a label remains ambiguous, resolve it before freezing the benchmark. Do not label a benign operation vulnerable simply to guarantee coverage or a passing score.

The four planned fixes are not an exhaustive rule-validity audit. During this existing label review, check whether each claimed correction actually works in a browser. Include the known cookie case: adding `HttpOnly` to a `document.cookie` assignment does not create an HttpOnly cookie, even though the current rule can stop warning when that string also contains `Secure`. [MDN documents the browser limitation](https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie). Keep labels based on actual behavior. Correct the rule in a bounded follow-up before freezing, or retain the defensible case and report a remaining miss honestly. Do not rename a missed vulnerable case as clean or silently remove it to improve the result.

Update `test-samples/generate-samples.cjs` and `test-samples/samples/` together. Preserve a versioned copy or hashes of the prior dataset before replacement. The manifest must identify OWASP 2021 mappings without relying on the old filename prefixes.

## Batch C: Eight browser scenarios and the table inventory

Keep eight scenarios, adapting server-oriented examples into browser modules where necessary. Record multiple expected findings individually. Describe them as simulated workloads, not independently collected production applications. Keep them outside the controlled-sample confusion matrix.

Produce the paper's module counts from the manifest. Keep the existing table columns, a controlled subtotal of 108, a separate scenario row of 8 with dashes in the V/C columns, and a grand total of 116. Count each file once under its primary module or scenario group.

An active advisory module can have zero controlled vulnerability pairs. Show that honestly in the inventory and explain where its advisory behavior was checked. The table describes dataset distribution, not a promise of equal samples or confirmed-vulnerability coverage for every active check.

## Checks and stopping point

- [ ] Exactly 54 V files, 54 C files, and 8 scenario files exist.
- [ ] The generator reproduces the manifest and meaningful code variations.
- [ ] Every controlled pair has reviewed labels, expected categories, severities, locations, and a description-review note.
- [ ] Uncertain advisory signals are not mislabeled as confirmed vulnerabilities.
- [ ] Claimed clean corrections, including cookie behavior, are justified independently of scanner output; remaining rule limitations are recorded.
- [ ] A groupmate reviews the labels where practical, with unresolved cases recorded honestly.
- [ ] Module-row totals reconcile with the subtotals and 116-file total.

Deliver the reviewed dataset, manifest, and table inventory. Stop before reporting accuracy or conducting formal lab runs.
