# Phase 07: Collect AU laboratory results

Status: Not started. Logistics can begin after Phase 00; measured runs require Phase 05.

This phase is conducted by the group on actual AU lab PCs. Time depends on lab access and the agreed PC count. Preparation and a setup pilot are separate from the formal runs.

## Batch A: Prepare the record sheet and setup pilot

Confirm the participating PCs and schedule. Use the scanner builds, dataset, manifest, evaluator, and written Chapter III method frozen in Phase 05. Chris leads technical testing with group assistance; the ISO classmate's survey assignment does not automatically include operating lab tests. Record PC identifier, CPU, RAM, OS, browser and VS Code versions, build identifiers, dataset hash, date, and operator.

Use the timing boundary agreed in Phase 05, such as file input ready to completed scan results. Distinguish per-file scan time from total project time and from manual upload time. If setup requires a method change, update and date it before formal runs. If the paper retains its target of under two seconds for a typical file of 500 lines or fewer, record line counts and measure the relevant files explicitly.

Run a setup pilot to verify loading, export collection, and screenshots. Correct setup problems before collecting formal evidence. Record memory measurements only with a defined tool and method; otherwise leave that claim unsupported and flag the required wording correction.

## Batch B: Run both actual interfaces

On each participating PC, run the web application in the recorded browser and the extension in actual VS Code. Use all 108 controlled files and the 8 scenarios, keeping their result groups separate. One warm-up and three measured runs per interface is the proposed starting protocol, not an additional professor requirement. Agree on feasible repetitions and the PC count in Phase 05 before measurement; record the chosen protocol consistently.

Under the recorded definition of one controlled test case as one file with expected and actual results, the 108 controlled cases exceed the recorded minimum of 100 tests per PC. Timing repetitions are repeated observations of the same files, not additional independent accuracy cases. Report measured-run mean and range with the number of repetitions. Preserve disagreements or intermittent errors rather than selecting the best run.

Retain raw exports, evaluator output, environment records, and screenshots. A screenshot should support a recorded run, not replace the underlying counts. Keep technical lab evidence distinct from the earlier demonstration-based survey.

## Batch C: Review results before chapter writing

Confirm counts against the frozen manifest. Report scan completion, file-level metrics, expected-rule results, category/severity/location/description checks, scenario observations, and timings with their denominators. Keep advisory observations separate. Describe static findings without calling every alert a confirmed vulnerability.

If a defect requires a fix, retain the original result, identify a new build or dataset version, and repeat the affected formal protocol. Do not silently alter labels to improve accuracy. If testing cannot be completed, record the limitation and follow the professor's direction on unfulfilled promises.

## Done and stop

- [ ] The agreed PCs and both interfaces have complete, identifiable run records.
- [ ] Raw results, calculations, and screenshots can be traced to the same versions.
- [ ] Repetitions, scan errors, and exclusions are disclosed.
- [ ] A groupmate has checked the reported totals against the evidence.

Deliver the lab evidence package and measured-results tables. Stop before converting them into final conclusions.
