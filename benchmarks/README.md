# AITrace detection benchmark

Synthetic fixtures with annotated ground truth. This directory is **evaluation
infrastructure**, not part of the analyzer.

`benchmarks/` is ignored when scanning the AITrace repository itself.

## Datasets

| Dataset | Path | What it is |
|---|---|---|
| Development | `cases/development/` | Fixtures used while implementing and debugging taint/FLOW behavior. |
| Locked evaluation | `cases/locked_eval/` | Isolated from the development tree. **Not** a third-party app: these files were authored in Phase 6 as `held_out/`. |

Do not merge the two scores. Do not treat either score as production accuracy.

A genuinely independent application is **not** in this repository. Protocol:
`INDEPENDENT_EVALUATION.md`.

## Reproduce

From a clean checkout of this repository:

```bash
PYTHONPATH=. python3 benchmarks/harness.py
PYTHONPATH=src pytest tests/test_detection_benchmark.py tests/test_benchmark_integrity.py -v --tb=short
```

The harness writes `benchmarks/last_report.json` (gitignored) and prints
**separate** `development` and `locked_eval` blocks. Each block includes
`independent: false` today.

## Matching policy

Identity of a finding is:

`(rule, POSIX path relative to the case directory, sink line)`

Basename-only matching is **not** used. Two `app.py` files in different
subdirectories cannot share a true positive.

Ground-truth markers live on **sink** lines:

```
# gt:RULE:class
# gt:http:dataflow_role|role=body
```

| Ground-truth class | Counts as |
|---|---|
| `confirmed_taint` | Exact `FLOW-*` rule at that case-relative path and sink line |
| `sql_interpolation` | `FLOW-SQL` **or** `PAT-003` (both at once is a dedup FN). Alias class; not confirmed taint |
| `rce_execution` | `FLOW-RCE` or `PAT-025` / `PAT-004` / `PAT-002`. Alias class; not confirmed taint |
| `pattern` | Named `PAT-*` at that path and line. Does **not** count as confirmed taint |
| `absent` | TN if the named rule is missing; FP if it is present |
| `dataflow_role` | DataFlow with that `sink_arg_role` and **no** `FLOW-HTTP` |
| `coverage` | Coverage metadata records the limitation. Not a finding |
| `structural` | TN if no `FLOW-*` at the sink; FP if confirmed taint is emitted. BFS reachability is ignored |

Architecture nodes, BFS paths, inventory, HTML/JSON duplicates, and coverage
samples are **not** confirmed detections.

### Aliases and evidence strength

`sql_interpolation` and `rce_execution` accept more than one rule so a single
annotated issue can be credited whether the engine promoted a FLOW finding or
left a covering pattern. That is **not** a claim that pattern evidence equals
value-taint evidence. `confirmed_taint` still requires the named `FLOW-*` rule.

### Missing lines

- A finding with no positive sink `line` cannot match an annotated line (FN,
  detail states the line is missing).
- An unannotated `FLOW-*` finding with a missing sink line is an FP.
- Missing `source_line` is a lineage note only; identity uses the sink.

### Duplicates

Analyzer rows with the same identity count once. One finding identity can
satisfy at most one annotation. Duplicate `# gt:` markers on the same line
yield FN for the extras.

### Unexpected findings

- Extra `FLOW-*` rows that no annotation claimed are `confirmed_taint` FPs.
- Extra `PAT-*` rows are FP only when an `absent` annotation names that rule.

## Metrics

Computed **within one evidence class** and **within one dataset**.

| Metric | Formula | Undefined when |
|---|---|---|
| Precision | `tp / (tp + fp)` | `tp + fp == 0` |
| Recall | `tp / (tp + fn)` | `tp + fn == 0` |
| TN | `absent` / `structural` negatives that stayed negative | not used in precision/recall |

Undefined metrics are serialized as JSON `null` and printed as `undefined`.
They are not displayed as `1.0`.

There is no combined development+locked precision/recall.

## Compatibility

Older reports used `(rule, basename, line)`. Re-run the harness after this
change; basename identities are not comparable to case-relative paths.

## Threats to validity

- Development fixtures were written to exercise known analyzer behavior.
- `locked_eval/held_out` is synthetic and was inspected during Phase 6.
- No independent third-party ground truth is scored here.
- Interprocedural coverage is incomplete; unresolved calls are coverage, not FN
  unless annotated as expected confirmed taint.
- Pattern aliases can credit a PAT hit on an `rce_execution` / `sql_interpolation`
  line without a FLOW finding.
- Last-resort basename fallback remains if the analyzer emits a path outside the
  case root.
