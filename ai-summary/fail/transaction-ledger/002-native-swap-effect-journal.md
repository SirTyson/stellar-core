# H002: Native Soroswap Swap Effect Journal

**Date**: 2026-05-25
**Subsystem**: transaction-ledger / native Soroswap apply path
**Severity**: High
**Impact**: dominant-phase redesign of native soroswap swap apply, targeting >10% of the remaining native-swap worker envelope if the typed journal replaces nested SAC child frames and redundant effect extraction
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the protocol-gated native Soroswap pool `swap` fast path, the host should
produce the same observable result as the current nested-contract emulation:
identical auth preimages, SAC transfer events, pool swap event, balance and
reserve ledger writes, rent/resource accounting, and deterministic success
hash inputs. It should not have to route the known pair swap through generic
`call_n_internal` SAC child frames and then rediscover the resulting ledger
effects through generic storage diff extraction.

## Mechanism

`call_native_soroswap_pool_swap` already recognizes the exact pair-swap shape
and executes the pool invariant natively, but it still invokes SAC transfers via
`soroswap_pool_invoke_sac_transfer -> call_n_internal` and then calls the
specialized balance reader to re-read pair balances before updating reserves
(`src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1252,
1465-1501`). This preserves behavior but leaves the hot path split across
generic frame push/pop, SAC dispatch, auth/event construction, storage diffing,
and C++ `recordStorageChanges`. A native swap effect journal would execute the
recognized swap as one typed operation: synthesize the SAC-equivalent auth/event
records in canonical order, mutate the two affected SAC balance entries and the
pair reserve fields in typed journal slots, and emit typed ledger effects to the
existing C++ result path without another generic child-call and storage-diff
round trip.

## Trigger

Run the current soroswap apply-load benchmark after the native pair-swap fast
path matches a pool `swap` call. The triggering condition is any matched call at
`match_native_soroswap_pool_swap` with one non-zero output amount, which causes
one nested SAC transfer, two pair-balance reads, and one reserve update for the
common swap shape.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` —
  native pool-swap matcher and shape guard.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` —
  native pool-swap implementation that still delegates output transfers and
  balance reads to generic SAC helpers.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` —
  nested SAC transfer and balance helper calls that the typed journal would
  replace for the matched pair-swap case.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-730` — C++ storage-change
  extraction/validation currently consumes generic encoded ledger-entry output.

## Evidence

The current diagnostic trace shows the matched native-swap path is under
`applyLedger`: `SAC transfer` contributes 2.910s contained time over 17,333
events, `call` contributes 5.428s contained time over 26,079 events, and the
whole `invoke_host_function` subtree contributes 23.906s contained worker time
over 8,705 calls. Source inspection shows the native pool swap has enough typed
knowledge to identify token addresses, reserves, output amount, and pair
contract address before it calls the generic SAC transfer/balance helpers. A
single typed journal that handles the matched swap end-to-end can remove a
larger envelope than prior narrow SAC micro-optimizations because it eliminates
the child-frame dispatch boundary, the immediate pair-balance re-read, and the
generic storage-diff rediscovery for the same known entries.

## Anti-Evidence

This is only viable as a protocol-gated redesign: direct balance mutation or
event construction changes protocol-visible metering unless the new path either
reproduces the old charges exactly or intentionally gates the budget change.
Prior narrow SAC-transfer shortcuts failed because SAC auth frames and events
are consensus-visible; this hypothesis must therefore include synthetic
SAC-equivalent auth/event records and verify byte-for-byte success-hash
preimages for matched swaps. If the remaining removable subset after preserving
auth, events, TTL extension, rent accounting, and budget charges is limited to
frame scaffolding only, the impact will fall below Medium.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — related to, but distinct from, `ai-summary/success/transaction-ledger/001-typed-sac-balance-storage-fast-path.md`; no prior fail/success record covers a native pool-swap effect journal
**Failed At**: reviewer

### Trace Summary

The native Soroswap fast path is reached from `call_contract_fn` when the pool wasm hash, function name, argument shape, and instance-storage layout match; it then runs `call_native_soroswap_pool_swap` inside a normal `Frame::NativeContract`. The current implementation already avoids generic SAC `balance` child calls for the pair owner by reading contract balances through typed SAC balance helpers, but it still must read those balances after the router's earlier input transfer to compute `amount_*_in`. After the host invocation completes, all storage effects from the entire router invocation flow through `Host::try_finish`, `get_ledger_changes`, `extract_ledger_effects`, and C++ `recordStorageChanges`; this is not a pool-swap-local boundary that a typed swap journal can bypass without replacing the Rust/C++ invocation output contract and the C++ footprint/rent/resource validation path.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:782-835` — `call_contract_fn` dispatches recognized Soroswap wasm calls to `Frame::NativeContract` and otherwise falls back to VM or SAC dispatch.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1127-1176` — `match_native_soroswap_pool_swap` is a narrow next-protocol-gated matcher for `swap(amount_0_out, amount_1_out, to)` and validates only the pool instance layout.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1178-1375` — `call_native_soroswap_pool_swap` performs TTL extension, reserve/output checks, one or two output SAC transfers, direct pair-balance reads, invariant checks, reserve update, and pool swap event emission.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1465-1501` — output transfers still call `call_n_internal`, while pair balance reads first try `soroswap_pool_read_sac_contract_balance` before falling back to a child SAC `balance` call.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:150-199` — the pair balance read path is already the typed SAC balance-storage path: it builds the SAC balance ledger key directly, decodes `BalanceValue` directly, extends TTL, and returns `0` for missing contract balances.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` includes nonnegative checks, `from.require_auth`, instance/code TTL extension, spend/receive balance mutation, and canonical transfer event emission.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:453-581` — enforcing host invocation always finishes by extracting ledger changes and encoded contract events from the full host storage/events state on success.
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:224-356` — `get_ledger_changes` walks the full storage footprint, computes old/new entry sizes and TTL deltas, and serializes read-write new values as encoded `LedgerEntry` values.
- `src/rust/src/soroban_proto_any.rs:261-301,478-506` — `extract_ledger_effects` converts ledger changes into `RustBuf` encoded ledger entries and returns those through `InvokeHostFunctionOutput::modified_ledger_entries`.
- `src/rust/src/bridge.rs:30-55` — the CXX bridge output ABI exposes only raw encoded result value, contract events, modified ledger entries, and rent fee; there is no typed ledger-effect channel.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584` — C++ calls the Rust host through `rust_bridge::invoke_host_function` and receives the encoded output.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:640-766` — `recordStorageChanges` must deserialize each returned ledger entry, validate contract-entry limits, meter write resources, match RW footprint coverage, apply upserts/deletes, and enforce created-entry/TTL invariants.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:982-1017,1358-1377` — sequential and parallel Soroban apply both use the same helper sequence: add footprint, invoke Rust host, record storage changes, collect events, consume refundable resources, and finalize the success hash.

### Why It Failed

The proposed optimization overstates the removable work. The pool swap is only one nested call inside a larger router host invocation, and current host output is still a whole-invocation storage diff exported as encoded ledger entries; C++ must deserialize and validate those entries to enforce footprint coverage, resource limits, creation rules, TTL pairing, and rent/resource accounting before committing them to the ledger state. A local native swap journal therefore cannot "emit typed ledger effects to the existing C++ result path without another generic child-call and storage-diff round trip" unless it redesigns the Rust/C++ Soroban output ABI and duplicates the same C++ validation semantics, which is outside the stated pool-swap-local mechanism.

The remaining localized work also does not clear the objective's Medium threshold. Pair balance reads are not generic SAC child calls in the common contract-owner case anymore; they already use the typed SAC balance storage helper from the prior confirmed optimization, and at least one current balance read remains semantically required because the swap computes input amount from balances after the router's earlier input transfer. Replacing the output SAC `transfer` child call would have to reproduce `require_auth`, TTL extension, typed balance read/write semantics, authorization/clawback checks, transfer event bytes, diagnostic/budget behavior, and success-hash inputs; after preserving those consensus-visible effects, the safely removable subset is mostly frame dispatch/scaffolding and a small number of encoded-entry round trips, below the Medium/High apply-time target required by the optimize-soroswap objective.

### Lesson Learned

Do not count broad Tracy `call`, `SAC transfer`, or storage-output totals as removable unless the trace shows a specific boundary that can be eliminated without preserving the same auth, event, TTL, rent, budget, success-hash, and C++ ledger-application semantics. For native Soroswap follow-ups, account for already-landed typed SAC balance helpers and distinguish pool-swap-local work from whole-host-invocation storage extraction.
