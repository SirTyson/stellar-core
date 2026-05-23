# H002: Memoize repeated Soroswap `get_contract_id` hash preimages inside host invocation

**Date**: 2026-05-23
**Subsystem**: crypto, rust, soroban-env
**Severity**: Medium
**Impact**: Soroswap apply-time reduction in Rust host contract-ID hashing path
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

Repeated `get_contract_id(deployer, salt)` calls with the same deployer address,
salt, and network ID should return the same `ContractId` while charging the same
observable budget as today. The host should not repeatedly clone the deployer,
parse the salt, build a full contract-ID preimage, XDR-serialize it into a fresh
buffer, and SHA256-hash it when the same tuple is requested repeatedly during a
soroswap invocation or ledger apply run.

## Mechanism

`Host::get_contract_id` calls `get_contract_id_hash`, which constructs
`ContractIdPreimage::Address`, calls `get_full_contract_id_preimage`, and then
hashes the XDR with `metered_hash_xdr`. `metered_hash_xdr` currently allocates a
`Vec`, metered-XDR serializes the preimage into it, and calls
`sha256_hash_from_bytes_raw`. A small deterministic cache keyed by the canonical
input tuple `(network_id, deployer ScAddress, salt)` could still apply the same
budget charges but return the cached `ContractId` for repeats, skipping the
clone/preimage/XDR/SHA work. This is significant for soroswap because the
benchmark repeatedly exercises pool/pair address derivation through the host
syscall path.

## Trigger

Run the current soroswap apply-load benchmark. The trigger is any contract path
that derives the same pair/pool or helper contract address more than once using
`Env.deployer().with_address(...).deployed_address(salt)` or equivalent host
`get_contract_id` calls. Soroswap performs about three `get_contract_id` syscalls
per successful host invocation in the current trace, so repeated preimages
should become cache hits if the workload is deriving stable pool/pair addresses.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2505-2513` —
  `Host::get_contract_id` syscall entry point, returning a contract-address host
  object.
- `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs:213-225` —
  `get_contract_id_hash` clones deployer/salt data and invokes
  `metered_hash_xdr`.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:32-38` —
  `metered_hash_xdr` serializes to a temporary `Vec` and hashes the bytes.
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:410-420` —
  metered Rust SHA256 primitive used by the contract-ID hash.

## Evidence

The latest accepted soroswap Tracy trace from `ai-summary/CURRENT_STATE.md` is
`/mnt/nvme2/apply-load/62ee1ffb5d05-20260523-010230/logs/62ee1ffb5d05-20260523-010230-02-soroswap-tx-2000-t-8.tracy`.
`csvexport-release -e` reports `get_contract_id`
(`soroban-env-host/src/vm/dispatch.rs:304`) at 68,196,959 ns self over 23,649
calls, `hash xdr` (`src/host/metered_xdr.rs:45`) at 13,185,774 ns self over
23,678 calls, and Rust `sha256` (`src/crypto/mod.rs:414`) at 21,131,003 ns self
over 47,422 calls. Timestamp-filtering individual `get_contract_id` events to
`applyLedger` windows confirms the zone is in scope: 175,440,213 ns total over
23,517 events occurs inside `applyLedger`. This total is just above the 3%
Medium floor on the 4.475 s Tracy `applyLedger` envelope, and the call count
matches the soroswap pattern of repeated deterministic address derivations.

## Anti-Evidence

The hypothesis depends on actual preimage reuse. If each `get_contract_id` call
uses a unique salt or deployer, a cache only adds overhead and should be
rejected. The cache also must preserve deterministic observable behavior:
budget charges must be identical to the uncached path, cache size must be
bounded or scoped to the host invocation/ledger apply run, and returning a
cached `ContractId` must still create or account for host objects exactly as
the current syscall semantics require. Prior H047 rejected merely streaming
`metered_hash_xdr`; this hypothesis is different because it skips the entire
preimage build/serialize/hash path on repeated inputs rather than optimizing a
single hash operation.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS - not previously investigated
**Failed At**: reviewer

### Trace Summary

The local inefficiency exists: every `get_contract_id` syscall visits and clones the deployer address, copies the 32-byte salt, wraps the network ID into a full `HashIdPreimage`, serializes that XDR into a fresh `Vec`, and hashes it with the metered Rust SHA256 primitive. The Soroswap router Wasm imports ledger host function `l.a` (`get_contract_id`) and its `pair_for` helper contains the single static call; the generated benchmark repeatedly swaps across a small fixed set of pairs, so repeated address derivation is plausible. However, the measured work runs inside `applySorobanStageClustersInParallel`, where the Soroswap benchmark intentionally spreads pairs across 8 independent clusters. The hypothesis sizes aggregate worker time against wall-clock `applyLedger`; after parallelism normalization, even eliminating the whole zone is below the objective's Medium threshold.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2505-2513` - confirmed `get_contract_id` delegates to `get_contract_id_hash` and must still allocate/add a contract-address host object for the return value.
- `src/rust/soroban/p26/soroban-env-host/src/host/lifecycle.rs:213-225` - confirmed each call constructs `ContractIdPreimage::Address`, clones the deployer `ScAddress`, copies/parses the salt, builds the full preimage, and hashes it.
- `src/rust/soroban/p26/soroban-env-host/src/host/data_helper.rs:329-337` - confirmed full preimage construction reads the ledger network ID and embeds the contract-id preimage.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:32-38` - confirmed `metered_hash_xdr` allocates a new `Vec`, calls metered XDR serialization, then hashes the buffer.
- `src/rust/soroban/p26/soroban-env-host/src/crypto/mod.rs:410-420` - confirmed the final SHA256 is charged as `ComputeSha256Hash` over the serialized preimage bytes.
- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:234-294` - traced the VM-to-host dispatch wrapper around every host function call, including budget transfer, dispatch charging, argument conversion, syscall execution, and return-value conversion.
- `src/rust/src/soroban_proto_any.rs:391-448` - confirmed each C++ bridge invocation creates a fresh host execution path and calls `e2e_invoke::invoke_function`.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:91-114,351-373` - confirmed `HostImpl` has no existing contract-id cache and `Host::with_storage_and_budget` constructs per-invocation host state.
- `src/transactions/InvokeHostFunctionOpFrame.cpp:557-584,1358-1378` - confirmed Soroban apply calls `rust_bridge::invoke_host_function` from `doParallelApply` for protocol versions using the parallel Soroban phase.
- `src/ledger/LedgerManagerImpl.cpp:2483-2520,2530-2554,2622-2640` - traced `applySorobanStageClustersInParallel`: one async apply thread per stage cluster, each applying its cluster's transactions and then joining before commit.
- `src/simulation/ApplyLoad.cpp:2653-2678,3382-3505` - confirmed the Soroswap benchmark creates one pair per configured dependent cluster and generates swap transactions round-robin across those pairs, balancing this work across the configured `T=8` clusters.
- `src/rust/apply-load-wasm/soroswap_router.wasm` - `wasm-tools print` confirmed the router imports host function `("l","a")` (`get_contract_id` per `env.json:1560-1573`) and has one static call site in its pair-address helper, which multiple router helpers call dynamically.

### Why It Failed

The hypothesis relies on a Medium projection from 175.4 ms of aggregate in-apply `get_contract_id` Tracy time over a 4.475 s apply envelope. That arithmetic is not valid for this path: `get_contract_id` executes in Soroban transaction worker threads spawned by `applySorobanStageClustersInParallel`, and the Soroswap benchmark deliberately distributes its fixed pairs across 8 independent clusters. The serial-equivalent ceiling for eliminating the entire reported zone is therefore roughly `175.4 ms / 8 = 21.9 ms`, or about 0.5% of the cited apply envelope; the realistic cache-hit saving is smaller because dispatch, argument conversion, host-object return allocation, budget charging, and any cache lookup/key construction remain. This is below the optimize-soroswap objective's 3% Medium floor, so the hypothesis is rejected despite the local redundancy being real.

### Lesson Learned

For Soroban host-function micro-optimizations, distinguish aggregate Tracy worker time from wall-clock apply impact. A syscall can appear to clear the Medium threshold in summed thread time but still be sub-1% after normalizing by `APPLY_LOAD_LEDGER_MAX_DEPENDENT_TX_CLUSTERS`; future hypotheses against `applySorobanStageClustersInParallel` must size only the serial-equivalent removable fraction, not the aggregate per-thread zone total.
