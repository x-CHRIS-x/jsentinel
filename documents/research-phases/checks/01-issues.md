# Phase 01 — Issues and Carry-Forwards

## Known limitations

### 1. A06 advisory-only scoring not yet separated (carry-forward to Phase 03)

**What:** Phase 01 removes the incorrect `express-headers` and `dynamic-request-target` branches from `OWASP-A06-001`. The surviving `component-review` branch still emits `severity: "MEDIUM"`, which the current scoring logic in `App.jsx` treats the same as any other MEDIUM finding — 5-point penalty per occurrence.

**Phase 01 plan note:** The README and Phase 01 doc both state that advisory-only A06 signals should "remain visible for review but do not inflate vulnerability totals, deduct project-score points, or enter vulnerability accuracy calculations." Phase 01 removes the wrong branches. Phase 03 is the correct place to implement the scoring/counting separation.

**What the independent verifier should check:** Confirm that the `component-review` finding still appears in the findings list after scanning a file with a risky library import. Confirm Phase 03 is scoped to fix the scoring and totals separation.

---

### 2. Guidance catalog wording for retired rule IDs

**What:** `OWASP-A05-002`, `OWASP-A05-004`, `OWASP-A10-001`, `OWASP-A06-001:express-headers`, and `OWASP-A06-001:dynamic-request-target` still have guidance entries in both `src/data/guidanceCatalog.js` and `vscode-extension/src/data/guidanceCatalog.js`. Their wording was not updated to say "this check is retired."

**Impact:** Low. These entries are only resolved when a finding references the ID. Since the rules no longer emit these IDs, the entries are effectively dead for new scans. Historical results that saved these IDs will still show the old guidance — which is acceptable per the README decision to keep historical results identifiable under their original version.

**Verifier note:** If the paper needs to document the exact wording change, the guidance catalog entries for retired IDs may warrant a minor update in a future pass.

---

### 3. `isValidated` helper remains in `accessControl.js` and `ssrf.js`

**What:** The `isValidated` helper function that checked for validation patterns around variables is still present in `src/scanner/rules/accessControl.js`. It was removed from `knownVulns.js` as part of the SSRF tracking cleanup. The `ssrf.js` file itself is now just an empty array export, so the function is fully gone from that file.

**Impact:** None for correctness — the helper in `accessControl.js` is still actively used by the A01-001 open-redirect rule. This is correct behavior.

---

### 4. Chunk size build warning (pre-existing)

**What:** The `npm run build` output includes: `Some chunks are larger than 500 kB after minification` for `index-*.js` (3,762 kB before gzip). This warning existed before Phase 01.

**Impact:** None for Phase 01. Not caused by these changes. Babel parser is the main contributor to bundle size. This is a known project characteristic documented in the GEMINI.md limitations.

---

## Dependencies for the next phase

### Phase 02 (Validation handling)
- Phase 02 can now proceed. The SSRF rule is no longer in scope, so validation refactoring does not need to account for the `isValidated` helper's usage in the retired SSRF/axios tracking branches.
- The `isValidated` helper in `accessControl.js` remains for the open-redirect rule — Phase 02 may need to review or extend this for its validation handling work.

### Phase 03 (Duplicate findings and scoring)
- Must implement the advisory-only scoring separation for `OWASP-A06-001` component-review signals. Phase 01 left this unresolved per explicit plan.

---

## Items requiring human judgment

- **Rule count for the paper:** Confirm with Chris that the active rule count change from 27 to 24 (retiring A05-002, A05-004, A10-001, and the two A06 sub-branches) is documented correctly in Chapter III. The GEMINI.md still lists 27 rules. This needs to be updated in the paper draft.
- **A06 advisory classification for accuracy metrics:** Decide exactly how the component-review advisory findings will be treated in Phase 04 dataset labeling and Phase 05 accuracy measurement. Phase 01 does not resolve this — only removes the incorrectly-classified branches.
