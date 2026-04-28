# Failed Investigations: Bucket Subsystem

Condensed failure summaries for investigations targeting the bucket subsystem. Last updated 2026-04-28.

## Summary Table

| File | Hypothesis | Why Failed | Stage | Key Lesson |
|------|-----------|------------|-------|------------|
| 001.md | Remove per-lookup heap allocation from in-memory bucket index queries | Below Medium threshold — `scan` zone is only ~2.83% of apply time; even a perfect fix cannot reach the required 3% floor | reviewer | In-memory bucket index lookups are not a significant apply-path hotspot; heap allocations per probe are too small to matter at scale |
| 002.md | Build bucket index metadata during output writes to shorten merge futures | PoC targeted the wrong code path — `createIndex` runs on the background Merge task thread, not the apply thread; shifting it earlier saves no apply-side wall time | PoC | Only work on the apply thread's critical path can reduce apply time; background-thread optimizations have no effect on apply latency unless they unblock a synchronous apply-thread wait |

## Meta-Patterns

1. **Background Work ≠ Critical-Path Savings**: Optimizations that move or reduce work on background threads (merge task, bucket compile, GC) cannot improve top-line apply time unless those threads are a blocking dependency of the apply thread. Always confirm an apply-thread wait on the target before attributing apply latency to background tasks.

2. **Threshold Realism Before Hypothesis Formation**: Quantify the fraction of apply time attributable to the target zone before writing a hypothesis. The Medium severity floor (3–10%) must be reachable by the proposed change alone; if the zone is <3% even in a perfect scenario, reject the hypothesis at formation time.
