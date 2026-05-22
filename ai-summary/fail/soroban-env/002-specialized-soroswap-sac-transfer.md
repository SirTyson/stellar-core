# H002: Specialized Soroswap SAC transfer path for account-to-pair and pair-to-account swaps

**Date**: 2026-05-22
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction by replacing generic SAC transfer scaffolding on the fixed swap token-movement path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

For the credit-asset SAC transfers used by the apply-load Soroswap swap path, the host should update the same user trustline and pair contract-balance entries, enforce the same authorization and trustline flag checks, extend the same SAC instance/code and balance TTLs, emit the same SAC `transfer` event, and return the same errors as `StellarAssetContract::transfer`. Non-credit assets, issuer mint/burn cases, muxed-address transfers, auth-required/clawback variants not matching the benchmark shape, and all released p26 ledgers should fall back to the generic SAC implementation.

## Mechanism

Even after native pair `swap` emulation, token movement still enters the generic SAC `transfer` implementation for both the router's input transfer and the pair's output transfer. That generic path converts `MuxedAddress`/`Address` wrappers, performs issuer/mint/burn discrimination, reads asset metadata for event naming, routes through generic account-vs-contract balance helpers, and constructs events through host `Vec`/`Val` objects. A next-protocol specialized path for the exact apply-load transfer shapes (account trustline -> pair contract balance and pair contract balance -> account trustline, no muxed id, non-issuer endpoints) could reuse the accepted typed SAC balance/storage helpers and emit the known transfer event directly while preserving deterministic ordering and state changes.

## Trigger

Run the current accepted soroswap benchmark. Each swap authorizes and executes the input token SAC `transfer(user, pair, 100)` from the router path, and the native pair `swap` executes the output token SAC `transfer(pair, user, amount_out)`.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1327-1345` at accepted p26 commit `03d78248` — native pair helper `soroswap_pool_invoke_sac_transfer` still constructs a `transfer` symbol and calls `call_n_internal` into the generic SAC.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — generic SAC `transfer` wrapper: amount check, muxed-address extraction, `require_auth`, instance/code TTL extension, spend/receive, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:100-145,156-229,376-403` — account/contract balance mutation paths used by the two Soroswap transfer directions.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — generic issuer/mint/burn discrimination and transfer event construction.
- `src/simulation/ApplyLoad.cpp:3477-3496` — auth tree for the input transfer; the output transfer is performed by the pair contract during native pair `swap`.

## Evidence

The current diagnostic trace shows `SAC transfer` at `soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:212` with 2.224016571s total and 563.092035ms self across 14,912 calls, all under the apply path after native pair `swap` was accepted. Supporting hot zones include `push context` (107.411306ms self), `push auth frame` (116.272794ms self), `storage get` (211.277885ms self), `Val to ScVal` (217.928299ms self), `ScVal to Val` (434.182945ms self), and event/XDR conversion work. This hypothesis targets the whole exact SAC transfer shape, not the previously rejected narrow trustline-field clone/update micro-optimization.

The generated workload creates plain credit assets issued by the root account, establishes trustlines for all swap accounts, and uses non-issuer user/pair endpoints for swaps. That makes the common path narrow enough to gate by asset type, endpoint shape, protocol, caller context, and absence of muxed IDs.

## Anti-Evidence

Most SAC transfer work is semantically mandatory: authorization, TTL extension, trustline bounds/flags, contract-balance authorization, storage writes, and the observable transfer event cannot be skipped. Prior narrow SAC/trustline optimizations failed below the Medium floor, so a PoC must demonstrate that avoiding the generic wrapper/event/issuer-discrimination/conversion scaffolding moves soroswap by at least 3% after the accepted typed balance fast path. The specialization must also avoid changing auth-frame semantics; if it cannot preserve SAC frame behavior or event contract IDs without re-entering the generic path, the removable subset may fall below threshold.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-22
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS — no exact duplicate in `ai-summary/fail/soroban-env` or `ai-summary/success/soroban-env`; related prior failures cover direct SAC event emission, SAC issuer-check deduplication, classic trustline update narrowing, and SAC balance read/write fusion.
**Failed At**: reviewer

### Trace Summary

The accepted native Soroswap pair `swap` path still invokes output-token SAC `transfer` through `call_n_internal`, and the router Wasm still invokes the input-token SAC `transfer`, so the hypothesis targets a real apply-path call site. However, a correctness-preserving shortcut must still push a SAC contract frame, advance authorization tracking, run `require_auth`, extend SAC instance/code TTL, perform the trustline and contract-balance authorization/bounds checks, write storage, and emit a SAC event with the SAC contract id. After tracing the current accepted p26 source, the removable part is mostly wrapper dispatch, muxed-address/no-issuer discrimination, repeated address/object conversions, and intermediate event construction, which is the same low-impact class already rejected in adjacent SAC investigations.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:780-834` — `call_contract_fn` pushes a `Frame::StellarAssetContract` for SAC calls; preserving auth stack/current-contract event semantics requires keeping this frame or manually reimplementing equivalent frame effects.
- `src/rust/soroban/p26/soroban-env-host/src/host/frame.rs:1010-1344` — native pair `swap` is next-protocol/hash gated but delegates token movement to `soroswap_pool_invoke_sac_transfer`, which calls SAC `transfer` through `call_n_internal`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/contract.rs:206-225` — SAC `transfer` performs amount validation, muxed-address extraction, `require_auth`, SAC TTL extension, `spend_balance`, `receive_balance`, and event emission.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:33-178,213-323,335-405` — the accepted baseline already has typed ScVal helpers for contract-balance keys/values; contract-balance updates still require authorization checks, current-entry reads, storage writes, and balance TTL extension.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:543-570,751-795,923-1009` — account sides still require asset lookup, issuer checks, trustline authorization flags, min/max balance checks, trustline update, and storage put.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/event.rs:47-113` — transfer-event dispatch performs equality/issuer discrimination and builds host Vec/Val event payloads; bypassing this only removes intermediate event scaffolding, not the final observable event materialization.
- `src/rust/soroban/p26/soroban-env-host/src/auth.rs:1340-1370` and `src/rust/soroban/p26/soroban-env-host/src/host.rs:3629-3656` — every SAC frame must push auth tracker state, and `require_auth` uses the current frame's function arguments; skipping or faking the frame would change authorization behavior.
- `src/rust/soroban/p26/soroban-env-host/src/events/mod.rs:249-263` and `src/rust/soroban/p26/soroban-env-host/src/events/internal.rs:207-248` — even a direct event path must preserve contract id, event buffering, rollback marking, final ScVal conversion, and externalization.
- `src/simulation/ApplyLoad.cpp:2672-2853,3382-3505` — the benchmark uses root-issued credit assets, pre-created trustlines, non-issuer swap accounts, pair contract-balance keys, and an auth tree containing the input SAC transfer.

### Why It Failed

This does not meet the optimize-soroswap Medium severity floor. The large `SAC transfer` aggregate is dominated by work that a correct specialization cannot remove: SAC frame/auth semantics, `require_auth`, instance/code TTL extension, trustline and contract-balance storage access, balance/flag validation, storage writes, event buffering, rollback behavior, and final XDR materialization. The current accepted baseline already includes typed SAC contract-balance storage helpers, and prior reviewed work shows the adjacent removable subsets — direct SAC event emission, issuer-check deduplication, trustline-only reconstruction, TTL shortcutting, address-object caching, and SAC balance read/write fusion — are below Medium or regress in benchmark runs. A new exact-shape transfer wrapper would mainly combine those same small residual savings, while any larger shortcut would skip or reimplement protocol-visible frame/auth/storage/event behavior and would not be the stated safe specialization.

### Lesson Learned

For SAC transfer optimizations, the full `SAC transfer` Tracy zone is an upper bound, not a removable-cost estimate. A viable future hypothesis needs isolated measurement of a new mandatory-work reduction that is not already covered by typed contract-balance storage or failed SAC event/issuer/storage-fusion attempts; simply recognizing the soroswap transfer shape does not make the remaining generic scaffolding large enough to clear the 3% apply-time threshold.
