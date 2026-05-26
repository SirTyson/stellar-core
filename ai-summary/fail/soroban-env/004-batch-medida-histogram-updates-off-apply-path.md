# H004: Batch Per-Tx Medida Histogram Updates Out of Apply Workers

**Date**: 2026-05-25
**Subsystem**: soroban-env (apply path glue / SorobanMetrics)
**Severity**: Low
**Impact**: Apply-time reduction via eliminated CKMS sample-insert work on apply workers
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`HostFunctionMetrics::~HostFunctionMetrics()` in
`src/transactions/InvokeHostFunctionOpFrame.cpp:175-230` is invoked
once per InvokeHostFunctionOp on the worker thread that just finished
applying the tx. It issues five `medida::Histogram::Update()` calls
(`mHostFnOpInvokeTimeNsecs`, `*ExclVm`, `*FsecsCpuInsnRatio`,
`*ExclVm`, `mHostFnOpDeclaredInsnsUsageRatio`) plus a `Mark` cascade.
Each `Update` performs a CKMS streaming-quantile sample insert that
takes ~7 µs (as measured by the Tracy `Update` zone). Expected
behavior is that these telemetry updates happen off the synchronous
apply path — e.g., batched per cluster and merged once at end of
`closeLedger` via a single Update call per histogram per worker — so
that workers do not spend µs-scale CPU on telemetry sample insertion
per tx.

## Mechanism

The Tracy `Update` zone shows ~21 066 calls totalling 152 ms of CPU
across the 71-ledger benchmark, i.e. ~2.14 ms / ledger of pure CPU
spent on histogram sample insertion. Per-worker, that is
~0.27 ms / ledger / worker once divided across 8 apply workers,
because the soroswap apply path is dominated by independent
per-cluster work and the histograms are updated from each worker
thread directly. Hoisting these updates to a per-worker buffer
(struct of arrays) drained once per ledger close would remove
the µs-scale per-tx work from the critical path.

## Trigger

Run the soroswap apply-load benchmark. In the Tracy profile, locate
the `Update` zone backed by `libmedida/src/medida/histogram.cc:115`
and confirm the source frames lead to
`HostFunctionMetrics::~HostFunctionMetrics()`. Measure
self-time per occurrence (~7 µs) and call count per ledger (~297).

## Target Code

- `src/transactions/InvokeHostFunctionOpFrame.cpp:175-230` — destructor with the 5 Update calls.
- `src/main/SorobanMetrics.h` — histogram definitions.
- `lib/libmedida/src/medida/histogram.cc:115` — Update implementation (CKMS sample insert).

## Evidence

- Tracy zone `Update` at `histogram.cc:115`: 21 066 events,
  ~152 ms total CPU, ~7 µs mean self-time per call.
- 5 Update calls per InvokeHostFunctionOp tx × ~8 k swap txs = ~40 k
  expected updates; the lower observed count (~21 k) suggests metrics
  paths are partially short-circuited (e.g., `mDisableMetrics` true
  in some paths or some Updates conditional), but the bulk is from
  this destructor.
- All five Updates are independent per-tx events; batched merge to
  a single per-worker insertion at ledger close is conceptually
  straightforward.

## Anti-Evidence

- 152 ms CPU / (8 workers × 71 ledgers) = ~0.27 ms / worker / ledger
  ≈ **0.13 % of the 207 ms soroswap wall** on the critical path,
  assuming perfect worker overlap with apply.
- Even under the pessimistic assumption that all 152 ms serializes
  on a shared histogram mutex (which CKMS does take), the wall
  contribution is 152 / 71 / 207 ≈ **1.03 %**, still below the
  Medium 3 % floor and well within benchmark noise.
- Batching adds complexity for a sub-Low gain; not worth the
  surface area.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not present in fail/summary.md; no prior
investigation targeted medida histogram Update contention or
per-tx-destructor telemetry overhead.

### Why It Failed

Below objective severity threshold. The total Tracy `Update`
self-time across the benchmark is 152 ms; divided across the 71
ledgers and 8 apply workers, the best-case wall-time contribution
is ~0.13 %, and the worst-case (full mutex serialization) is
~1.03 %. Both fall in the Low (1–3 %) or sub-Low band, while the
objective accepts only Medium (3–10 %) and High (>10 %) hypotheses
at the hypothesis stage.

### Lesson Learned

Medida histogram telemetry on apply workers is in the noise floor
even under pessimistic contention assumptions; future investigators
can skip this entire family of "move metrics off the apply path"
optimizations. The general per-tx-overhead band for soroswap is
sub-1 % per call class — bottlenecks at the Medium threshold must
involve either (a) zones with > 20 ms / ledger of synchronous
self-time, or (b) restructuring of a dominant phase rather than
trimming per-tx fixed costs.
