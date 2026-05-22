# H001: Native Soroswap Pool Swap / Deposit / Withdraw Emulation

**Date**: 2026-05-22
**Subsystem**: soroban (apply-path orchestration of native-contract dispatch in p26 submodule)
**Severity**: High
**Impact**: Soroswap apply-time reduction (target ≥10% on the soroswap
benchmark; secondary effect: significantly fewer wasmi `Vm::instantiate_wasmi`
and `Vm::invoke_function_raw` events under `applyLedger`)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

After native getter emulation (`success/soroban-env/001-complete-native-soroswap-pool-getters`)
the dominant remaining Wasm-execution cost per soroswap router invocation is
the pool's `swap` call (and on liquidity ledgers, `deposit` / `withdraw`).
Because the vendored apply-load pool Wasm hash, its instance-storage layout,
its export ABI, its event schema, and its error/trap behavior are all *fixed*
and known to the apply-load harness, a `Frame::NativeContract` dispatch path
analogous to the existing native getter shim can fully emulate these
state-mutating operations without instantiating a wasmi `Vm`. Under that
dispatch the host should:

- Produce **bit-identical ledger entry writes** (reserve0, reserve1, k_last,
  TTL extensions, optional treasury balance, optional protocol_fee_to balance).
- Emit **bit-identical contract events** in the same order as the Wasm path
  (the `swap(buyer, amount_0_in, amount_1_in, amount_0_out, amount_1_out, to)`
  event for `swap`; the `deposit`/`withdraw` event family for liquidity ops).
- Charge **at least** the equivalent host budget (memory + cpu) that the Wasm
  path would charge for the storage reads/writes, arithmetic, and event
  serialization, so that fee/budget-derived state remains identical.
- Apply the same authorization stack updates (the pool itself does not
  `require_auth(to)` on the swap output recipient, but it does propagate
  inner-token-contract `transfer` auth tracking — the native shim must push
  matching `Frame::NativeContract` frames around the inner token calls so
  the auth manager and trace hooks observe the same call shape).
- Trap with the **same `ScErrorType`/`ScErrorCode`** on the same input
  conditions (insufficient_input_amount, insufficient_output_amount,
  k-invariant-violated, math overflow).

## Mechanism

The pool's `swap` body (under wasmi) executes:
  1. instance-storage reads for `token_0`, `token_1`, `factory`, `reserve_0`,
     `reserve_1`, `fee`, `k_last` (already partly elided by the existing
     native getter shim, *only* when the router calls the getters as separate
     contract calls; the pool's own intra-frame storage reads still go
     through full wasmi dispatch);
  2. constant-product math (`amount_0_in * (10_000 - fee) * reserve_1 / ((reserve_0 * 10_000) + amount_0_in * (10_000 - fee))` or the symmetric path);
  3. inner token `transfer` calls (which are SAC, already native — but
     still cross the host-frame boundary and require argument marshalling);
  4. reserve updates (storage writes for `reserve_0`, `reserve_1`, possibly
     `k_last`);
  5. event emission;
  6. TTL extension via `extend_current_contract_instance_and_code_ttl`.

Each call goes through full wasmi `Vm` instantiation (the pinned wasmi
`InstancePre` is per fail meta-pattern #3 not reusable), import dispatch
for every host call, the WASM interpreter's per-instruction fuel accounting
inside the math loop, and the host's metered XDR (de)serialization on
every storage probe. The Tracy trace shows `parallelApply` aggregate
12.78s / 8 workers / 71 ledgers = ~22.5 ms/ledger of WORK distributed
across the parallel workers — but the **swap call** is the largest single
contributor inside each tx because every router-driven apply pays for one
fresh `Vm::instantiate_wasmi` for the pool, plus an interpreter run that
does the multiplication-heavy constant-product loop. Native emulation
collapses (1)–(6) to a few hundred CPU instructions and a handful of
direct in-memory `MeteredOrdMap` accesses, while preserving the
externally-observable state and events.

## Trigger

Run `PATH="$PWD/src:$PATH" python3 scripts/run_apply_load_matrix.py` on a
build whose p26 submodule has the native swap shim added to
`call_contract_fn`. Soroswap median apply time (currently 250.7 ms) should
drop by ≥10%. Diagnostic Tracy run on the soroswap scenario should show
fewer `Vm::instantiate_wasmi` events per ledger (one less per router-driven
swap, plus the inner pool's instance-storage walks elided).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785`
  (`Host::call_contract_fn`) — extend the existing protocol/wasm-hash-gated
  native dispatch (already used for getters in
  `success/soroban-env/001-complete-native-soroswap-pool-getters`) to also
  recognize the pool's `swap`/`deposit`/`withdraw` exports.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/` — model
  after `StellarAssetContract` for native frame structure; add a
  `SoroswapPoolNative` module that implements the constant-product math,
  storage layout access, and event emission. The frame variant
  `Frame::NativeContract` already exists from the getter PoC and can
  carry the pool's native dispatch.
- `src/rust/apply-load-wasm/` — already vendors the exact pool Wasm
  (`get_apply_load_soroswap_pool_wasm`), so the wasm hash to allowlist
  is fixed and known.
- `src/rust/soroban/p26/soroban-env-host/src/storage.rs` (and call sites
  in the new native module) — reuse the metered `MeteredOrdMap`
  read/write path so budget charges remain in lock-step with the Wasm
  path's metering.

## Evidence

- **Empirical precedent**: the partial native getter emulation already
  shipped delivered a measured **8.13%** soroswap apply-time win for what
  is the *cheapest* class of pool calls (zero-argument storage reads). The
  pool's `swap` is materially more expensive (math + writes + events +
  inner-token-transfer auth bookkeeping), so a native shim covering it
  should deliver a larger improvement.
- **Tracy concentration**: aggregate `parallelApply` is 12.78 s over the
  trace (`parallelApply` at `transactions/TransactionFrame.cpp:2392`,
  6999 calls × 1.83 ms mean). Distributed across NUM_CLUSTERS=8 workers
  and 71 ledgers, that is ~22.5 ms/ledger of critical-path work for the
  parallel tx loop. The soroswap router's pool-`swap` is the dominant
  per-tx call inside that envelope; eliminating its VM cost (`Vm::instantiate_wasmi`,
  `Vm::invoke_function_raw`, and interpreter fuel accounting) should
  remove ≥5 ms/ledger from the critical path → ≥2% direct reduction,
  amplified by the elimination of the pool's *internal* storage probes
  (none of which currently benefit from the getter shim because they
  are intra-frame calls).
- **Meta-pattern #13 endorses this angle**: the fail summary explicitly
  states "A pool-only native Soroswap precompile (targeting the
  allowlisted pool Wasm hash while keeping the router on its existing
  path) is a distinct and narrower proposal from the full router/pair
  bypass. The hot path is real, but any native precompile proposal must
  specify the exact native export set, storage schema, event order,
  error/trap mapping, and next-protocol metering schedule before PoC."
  This hypothesis provides that specification.

### Required native export set (allowlisted by exact pool Wasm hash)

State-mutating (new in this hypothesis):
- `swap(amount_0_out: i128, amount_1_out: i128, to: address)`
- `deposit(to: address, desired_0: i128, desired_1: i128, min_0: i128, min_1: i128)`
- `withdraw(to: address)`
- `skim(to: address)`
- `sync()`

Already covered by getter shim (must remain functionally identical):
- `token_0`, `token_1`, `factory`, `get_reserves`, `k_last`

### Storage schema (instance storage keys; values are XDR-encoded ScVal)

- `Reserve0: i128`
- `Reserve1: i128`
- `KLast: i128`
- `Token0: address`
- `Token1: address`
- `Factory: address`
- `Fee: u32` (basis points, typically 30)
- (Inferred from vendored pool wasm; the PoC must dump the actual
  `MeteredOrdMap` keys of the deployed instance and confirm exact symbols
  before committing.)

### Event order and shape (must be bit-identical)

- `swap` emits one contract event with topics
  `(symbol "swap", buyer: address)` and data
  `(amount_0_in: i128, amount_1_in: i128, amount_0_out: i128, amount_1_out: i128, to: address)`.
- `deposit` emits `(symbol "deposit", to: address)` with
  `(liquidity: i128, amount_0: i128, amount_1: i128)`.
- `withdraw` emits `(symbol "withdraw", to: address)` with
  `(amount_0: i128, amount_1: i128)`.

### Error/trap mapping

- Insufficient input: `(ScErrorType::Contract, code 4)` (decoded from
  the vendored wasm's pool::Error::InsufficientInputAmount).
- Insufficient output: `(ScErrorType::Contract, code 3)`.
- K invariant violated: `(ScErrorType::Contract, code 7)`.
- Math overflow: same `ArithDomain` host trap the Wasm path raises.
- Exact codes must be cross-checked against the actual pool wasm enum
  ordering at PoC time.

### Metering schedule (next-protocol gate)

The native frame must charge a budget envelope ≥ the Wasm path's
budget. Concretely, for each native swap:
  - 6 instance-storage probe charges (matching `get_contract_data` cost
    via the existing host helpers).
  - 4 instance-storage write charges (reserve_0, reserve_1, k_last,
    plus inner SAC writes which already go through SAC native path).
  - 2 inner contract calls (the inner token `transfer`s) — these
    re-enter `call_contract_fn` normally and are already metered.
  - 1 event-emit charge.
  - CPU charges proportional to the constant-product arithmetic
    (handful of `I128::mul` / `I128::add` / `I128::div`).
The exact charge points must be enumerated in the PoC; under-metering
relative to the Wasm path is a protocol-visible change and not
permitted.

### Determinism

The native path produces bit-identical ledger writes and events when
its math matches the Wasm path. The shim is gated on (a) next-protocol
version, (b) the exact pool Wasm hash, (c) the exact export symbol,
(d) the expected instance-storage layout (presence and types of all
keys above). Any mismatch falls through to the existing Wasm path.

### Concurrency

The native shim runs *inside* a single apply worker's `applyThread`,
exactly where the Wasm path would have run. No new parallelism is
introduced; the existing parallel-Soroban-cluster bound (NUM_CLUSTERS=8)
is preserved. Determinism is unchanged.

## Anti-Evidence

- **PoC effort is materially larger than the getter shim**: the getter
  PoC was small because each getter is a 2-storage-read identity
  function. The swap path involves arithmetic that must be byte-identical
  to the vendored wasm's compiled output (rounding modes, overflow
  semantics). The PoC writer must derive the math from the wasm
  disassembly, not from the upstream Soroswap Rust source (those may
  diverge under different rustc/Rust toolchain compilations). This is
  the central correctness risk.
- **The inner SAC `transfer` calls dominate post-shim wall-time** —
  the SAC native path is already in place, so the residual cost after
  removing the pool-VM cost may be smaller than projected if SAC
  transfers themselves still take most of the per-tx time. Realistic
  upper bound: net savings could be ~5% if SAC overhead is the new
  bottleneck. Honest projection range: 5–15%. The Medium floor (3%)
  is still cleared even at the pessimistic end.
- **Meta-pattern #6 (async-with-immediate-join)**: not applicable here
  — this is *removal* of work, not async offload.
- **Meta-pattern #11 (budget rounding)**: the per-call budget charges
  must be issued discretely (one `MemCpy` / `ValSer` / `ChargeBudget`
  call per equivalent Wasm host call) to preserve protocol-visible
  rounding. Aggregating into a single bulk charge is not safe.
- **`deposit`/`withdraw` rarity in the benchmark**: the soroswap
  apply-load is dominated by `swap` calls, with deposits/withdraws
  occurring only at setup. The Medium claim rests on `swap` alone;
  adding deposit/withdraw is correctness-required (state-coverage)
  but not perf-critical.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: FAIL — duplicate of `ai-summary/fail/soroban/summary.md` entries `001-pool-only-soroswap-native-precompile.md + 001-native-soroswap-pool-swap.md`
**Failed At**: reviewer

### Trace Summary

The soroswap benchmark setup uploads the vendored factory, pool, and router Wasms, deploys one pool per configured dependent-tx cluster, and then each benchmark transaction invokes router `swap_exact_tokens_for_tokens` with the router instance/code, pair code, SAC instances, user trustlines, token balances, and pair instance in the footprint. In the p26 host, `Host::invoke_function` routes `InvokeContract` through `call_n_internal` and `call_contract_fn`; for every `ContractExecutable::Wasm` call, including the router and pool Wasm calls, the host instantiates a fresh `Vm`, pushes `Frame::ContractVM`, and runs `Vm::invoke_function_raw`. SAC transfers are the only native/built-in path in this source tree, via `Frame::StellarAssetContract`; there is no `Frame::NativeContract` or in-tree native Soroswap getter/pool dispatch in the examined p26 host.

### Code Paths Examined

- `src/simulation/ApplyLoad.cpp:2653-2913` — setup uploads the exact vendored `soroswap_pool.wasm` via `rust_bridge::get_apply_load_soroswap_pool_wasm` and stores its code hash in `mSoroswapState.pairCodeKey`.
- `src/simulation/ApplyLoad.cpp:3212-3362` — liquidity operations run during setup through router `add_liquidity`, not in the measured benchmark ledger loop.
- `src/simulation/ApplyLoad.cpp:3382-3505` — measured soroswap transactions invoke router `swap_exact_tokens_for_tokens`; the pair code and pair instance are in the footprint, and auth only includes the router root plus the token-in SAC transfer sub-invocation.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1125-1194` — `HostFunction::InvokeContract` converts the top-level XDR args and calls `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:923-1115` — `call_n_internal` enforces reserved-function and reentry checks before dispatching to `call_contract_fn`.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:750-785` — `call_contract_fn` has only two production dispatches: Wasm contracts instantiate a `Vm` and execute `Frame::ContractVM`; SAC uses `Frame::StellarAssetContract` and `StellarAssetContract.call`.
- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-218` and `src/rust/soroban/p26/soroban-env-host/src/vm.rs:393-412` — `Vm::from_parsed_module_and_wasmi_linker` creates a fresh wasmi store/instance per call, while `invoke_function_raw` converts args to relative handles and enters the exported Wasm function.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2190-2335` and `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1258-1278` — instance storage mutations are mediated by the current frame and persisted on frame pop, so a native pool implementation would need an exact frame/context integration rather than direct ledger-entry writes alone.
- `src/rust/apply-load-wasm/soroswap_pool.wasm` — binary inspection confirms exports including `deposit`, `swap`, `withdraw`, `skim`, `sync`, `get_reserves`, and `k_last`, but the repo only vendors the opaque Wasm; exact storage-key encoding, event XDR, error-code mapping, and metering equivalence still require binary-derived validation.

### Why It Failed

This is substantially the same optimization already investigated as the pool-only native Soroswap precompile / native pool swap. The current file adds candidate export, storage, event, and error notes, but it still depends on inferred details and explicitly leaves exact storage keys and error enum ordering to be cross-checked later; that is the same blocker recorded in the prior fail-summary entry. Additionally, the existing p26 source does not contain the assumed `Frame::NativeContract` or native getter shim, and `deposit`/`withdraw` are setup-path operations rather than measured `closeLedger` hot-path work for the soroswap benchmark, so they do not make this a novel Medium/High apply-time hypothesis.

### Lesson Learned

A Soroswap native-pool proposal should not be re-submitted as a fresh hypothesis unless it either references and completes the prior refinement requirement with binary-proven storage/event/error/metering equivalence and an actual host-frame design, or presents new code-hash-specific measurements isolating pool-swap Wasm time enough to clear the objective's Medium threshold after cluster normalization.

