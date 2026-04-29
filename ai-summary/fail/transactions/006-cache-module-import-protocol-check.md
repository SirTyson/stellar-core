# H006: Cache ParsedModule Host-Import Protocol Checks

**Date**: 2026-04-29
**Subsystem**: transactions, soroban-env
**Severity**: Low
**Impact**: below objective severity threshold (Low not accepted at hypothesis stage)
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

When a cached Soroban `ParsedModule` is instantiated repeatedly for the same ledger protocol, Core should still reject contracts that import host functions unavailable in that protocol and should return the same VM errors for unsupported imports. Since the parsed module and ledger protocol are unchanged across many soroswap invocations, the compatibility result could in principle be cached on the parsed module or module cache.

## Mechanism

`Host::instantiate_vm` retrieves a cached `ParsedModule` from `ModuleCache`, then `Vm::from_parsed_module_and_wasmi_linker` calls `Vm::instantiate_wasmi`, which calls `ParsedModule::check_contract_imports_match_host_protocol` before every wasmi instantiation. That check scans imported symbols against `HOST_FUNCTIONS` even when the same module has already passed the same protocol check earlier in the ledger. Caching the pass/fail result would remove repeated import-symbol scans without changing VM instantiation or execution semantics.

## Trigger

Run the current soroswap apply-load Tracy benchmark and inspect `ParsedModule::check_contract_imports_match_host_protocol` under `applyLedger`. The issue triggers on repeated soroswap contract calls that hit the inter-ledger module cache and instantiate the same parsed modules many times.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:787-801` — cached module hit still calls `Vm::from_parsed_module_and_wasmi_linker`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:154-187` — `instantiate_wasmi` charges instantiation and calls the import/protocol check before linker instantiation.
- `src/rust/soroban/p26/soroban-env-host/src/vm/parsed_module.rs:403-449` — `check_contract_imports_match_host_protocol` scans module imports against every host-function descriptor.
- `src/rust/soroban/p26/soroban-env-host/src/vm/module_cache.rs:189-195` — module cache returns the same `Arc<ParsedModule>` for repeated invocations of the same wasm hash.

## Evidence

The code path is real and in the measured apply subtree. The current soroswap trace shows `ParsedModule::check_contract_imports_match_host_protocol` with 116.161 ms of apply-window overlap across 10,059 events, sourced at `soroban-env-host/src/vm/parsed_module.rs:423`; `Vm::instantiate_wasmi - instantiate` also appears under `applyLedger`, confirming the check runs during cached-module VM construction, not only during setup.

## Anti-Evidence

The measured cost is too small for this objective. The entire import-check overlap is only 116.161 ms across 69 `applyLedger` windows, with an 8.210 ms hottest-thread overlap, so even deleting the check entirely would not plausibly save the required 3-10% median soroswap apply time. This is also adjacent to the already rejected wasmi-instance caching family: the import check can be cached, but the dominant instantiation cost still remains.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-04-29
**Failed At**: hypothesis
**Novelty**: PASS — module-import protocol result caching was not previously recorded in the transactions failure summary

### Why It Failed

The mechanism is correct but below the objective severity threshold. The import compatibility scan is a repeated apply-path check, but its full measured overlap is a small fraction of `applyLedger`, and a correct cache could recover only part of that already-small cost after lookup and invalidation overhead.

### Lesson Learned

Cached-module instantiation still contains small repeated checks beyond wasmi instantiation itself, but each candidate must be bounded against apply-window overlap. For the current soroswap baseline, `ParsedModule` import-protocol checks are Low-tier and should not be promoted unless a future trace shows substantially higher per-ledger overlap.
