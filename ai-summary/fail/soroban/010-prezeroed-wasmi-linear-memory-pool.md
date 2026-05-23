# H010: Per-Cluster Pre-zeroed Linear-Memory Buffer Pool for `Vm::instantiate_wasmi`

**Date**: 2026-05-23
**Subsystem**: soroban-env-host, rust
**Severity**: Low (sub-threshold)
**Impact**: Soroswap apply-time reduction by skipping per-invocation zero-initialization of the wasmi linear-memory backing for repeated swap calls
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

Each `Vm::instantiate_wasmi` call allocates a fresh `wasmi::Store` and a
fresh linear-memory backing (one initial page = 17 wasm pages = ~1.1 MiB
for a soroswap pool/router contract). The buffer is currently `vec![0u8; n]`
which both allocates and zero-initializes. If a per-cluster lock-free pool
of pre-zeroed buffers were kept, then on instantiation the buffer could be
*moved* out of the pool (skipping zero-init), the contract's `data` segments
applied normally, and on `Drop` the buffer would be returned to the pool
after a quick re-zero (either eagerly on the drop thread or lazily when
the buffer is next pulled out).

The expected effect is that the per-invocation `vec![0u8; 1.1MiB]` cost
is replaced by a swap of an `Arc<RefCell<…>>` (or `Box<[u8]>`) in/out of
a `thread_local!` pool, with no zero-init on the apply critical path.

## Mechanism

The current Tracy trace shows `Vm::instantiate_wasmi - instantiate` at
~460 ms aggregate worker time across the benchmark; the
`MemoryEntity::new` zero-init step is a substantial sub-cost. Pre-zeroed
buffer pooling moves the zero-init out of the apply critical path and amortizes
it across pool returns. With 8 parallel-apply clusters and 7891 soroswap
invocations, even a 5 µs/call saving would compound to a meaningful aggregate
worker-time reduction — but normalization by `NUM_CLUSTERS=8` and 71 ledgers
collapses it.

## Trigger

Run the soroswap apply-load benchmark with Tracy. Each `InvokeHostFunctionOp`
that calls a non-SAC contract (router, pool) instantiates a fresh wasmi
linear memory of ~1.1 MiB.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/vm.rs:155-187` — `instantiate_wasmi`
  store/instance construction
- (wasmi crate, pinned) `crates/wasmi/src/memory/mod.rs` — `MemoryEntity::new`
  performs `vec![0u8; initial_len_in_bytes]`
- `src/rust/soroban/p26/soroban-env-host/src/e2e_invoke.rs:380-520` —
  per-invocation `Host` construction site where a pool handle would live

## Evidence

- `Vm::instantiate_wasmi` has 7891 calls in the soroswap trace; each
  invocation allocates a fresh 1.1 MiB linear-memory buffer.
- Linux `vec![0u8; 1.1MiB]` is backed by `mmap`/`MAP_ANONYMOUS`, which
  the kernel does zero on first-touch — but the wasmi crate touches the
  full range during `MemoryEntity::new` initialization checks, so the
  zero-fill is realized eagerly. Replacing the allocation with a pre-zeroed
  pool buffer skips the touch.
- Per-cluster thread-local pools preserve determinism: contents observable
  to the Wasm program are unchanged (still all-zero before `data` segments
  apply).

## Anti-Evidence

- Per fail/soroban/summary.md entry `001-cached-wasmi-initial-memory-images`:
  "a fresh 17-page zero-initialized memory must be allocated per invocation
  regardless; cached images still require a full 1.1 MiB copy to a new
  allocation; memory initialization dominates the benefit." Pre-zeroed
  pool variants face the same physical-write cost when the kernel must
  back the pages with real RAM.
- Per fail/soroban/summary.md entry `016-wasmi-linear-memory-vec-allocation`:
  any wasmi-internal change carries large protocol-risk surface area and
  cannot be confidently bounded without measuring the actual `MemoryEntity::new`
  sub-cost (no Tracy sub-zone exists today).
- Per meta-pattern #14 / cluster normalization: aggregate
  `Vm::instantiate_wasmi - instantiate` of 460 ms ÷ 8 clusters ÷ 71 ledgers
  ≈ 0.81 ms/ledger ≈ 0.37% of the 218 ms soroswap baseline. The
  zero-init slice is a *fraction* of that, so the achievable saving is
  well below the 1% Low threshold even under optimistic assumptions.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-23
**Failed At**: hypothesis (self-rejected)
**Novelty**: PASS — distinct from prior cached initial-memory-image
proposals (which kept a *copy* source) and from prior pristine-snapshot
proposals (which targeted the `Store`/`Instance`, not the linear-memory
backing). This isolates pre-zeroed buffer pooling as a separate mechanism.

### Why It Failed

Two converging blockers:

1. **Sizing**: After cluster normalization (8 workers) and division by
   ledger count, the entire `Vm::instantiate_wasmi - instantiate` zone
   is ~0.37% of apply. Pre-zeroed pooling targets only the zero-init
   slice of `MemoryEntity::new`, which is a sub-portion of that. Even
   100% removal of the targeted slice cannot reach the 1% Low floor,
   let alone the 3% Medium objective floor.

2. **Wasmi modification scope**: This change requires modifying the
   pinned `soroban-wasmi` crate's `MemoryEntity::new` to accept an
   external buffer. Per meta-pattern in fail summary entry
   `016-wasmi-linear-memory-vec-allocation`, wasmi-internal changes
   "carry large protocol-risk surface area" (page-fault / overcommit
   divergence across nodes, interpreter pointer aliasing assumptions).
   The risk/reward ratio is unfavorable for a sub-1% saving.

### Lesson Learned

Per-invocation wasmi linear-memory backing zero-init is real but
structurally sub-Medium after cluster normalization. Any wasmi-internal
memory optimization needs (a) a dedicated Tracy sub-zone wrapped around
`MemoryEntity::new` to isolate the targetable slice, and (b) a saving
projection that survives 8x cluster division and ledger normalization.
Without both, the proposal cannot clear the objective's Medium floor.
