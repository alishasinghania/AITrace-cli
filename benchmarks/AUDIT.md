# Phase 7 benchmark audit

Inspected `benchmarks/harness.py` (pre-fix), all `# gt:` fixtures, `tests/test_detection_benchmark.py`, and `benchmarks/README.md`. Detection analyzers were not changed.

## Verified correct behavior (pre-fix)

- Expected positives with no analyzer hit were scored as FN (`confirmed_taint`, `pattern`, `sql_interpolation`, `rce_execution`, `coverage`).
- `absent` annotations scored an unexpected named rule as FP and a miss as TN.
- `ClassScore.precision` / `recall` already returned `None` when the denominator was zero; JSON stored `null`.
- Duplicate analyzer rows with the same `(rule, basename, line)` were collapsed by a `set` before matching, so they did not inflate TP **when basenames were unique**.
- Coverage annotations required coverage metadata, not a `FLOW-*` finding.
- `structural` required the absence of confirmed `FLOW-*` at the sink.
- `dataflow_role` required a DataFlow role and the absence of `FLOW-HTTP`.
- The harness is not imported by the scan engine.

## Confirmed harness defects (pre-fix)

1. **Basename identity.** Matching used `(rule, file basename, line)`. Two files named `app.py` at the same line in one case could steal each other’s matches.
2. **Datasets mixed.** `run_all()` iterated every child of `cases/`, so `held_out/` was folded into the same `by_class` totals that tests asserted as precision/recall `1.0`.
3. **Held-out labeling.** `held_out/` was synthetic and already inspected in Phase 6. It was not an independent third-party application.
4. **Double-counted FPs.** A `structural` or `absent` hit on a `FLOW-*` finding did not mark that identity claimed, so the unannotated-FLOW loop could add a second FP for the same row.
5. **No explicit missing-line handling.** A finding with `line is None` silently failed `has_rule(..., annotated_line)` (FN) without saying the sink line was missing.
6. **Rule aliases undocumented as evidence-strength.** `rce_execution` accepted `FLOW-RCE` or PAT-025/004/002; `sql_interpolation` accepted `FLOW-SQL` or `PAT-003`. That is class-level matching, not “pattern ≡ confirmed taint”, but the report did not say so.
7. **README vs code.** README said the harness copies cases to a temp tree; it scanned the case directory in place. README said precision/recall were reported only for `confirmed_taint`; JSON reported every class.
8. **No harness-integrity tests.** Tests only asserted perfect scores on live analyzer output, so a scorer that always emits TP would still pass if the fixtures happened to be fully detected.
9. **Duplicate annotations.** Two identical `# gt:` markers on one line would both TP against one finding.
10. **Combined headline.** A single `by_class` object invited reading development fixtures as overall accuracy.

## Suspected / residual issues (not fully closed)

- Unexpected **pattern** findings are FP only when an `absent` annotation names that rule. Unannotated `PAT-*` rows are not auto-FP. That is documented policy, not a silent bug.
- `source_line` is recorded as a lineage note when missing; it is not part of the match identity (GT markers sit on **sink** lines).
- Analyzer paths that cannot be relativized to the case root fall back to basename; that last-resort fallback can still collide if the engine emits only a basename.
- `locked_eval/held_out` remains a synthetic clone of Phase 6 fixtures. Locked ≠ independent.

## Untested before Phase 7

- Same-basename collision.
- Injected scoring regressions (remove a TP / add an FP).
- Controlled duplicate findings.
- Missing sink line on an otherwise matching rule.
- Empty evidence class (undefined precision/recall display).
