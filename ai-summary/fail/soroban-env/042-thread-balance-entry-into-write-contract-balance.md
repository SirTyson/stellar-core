# H042: Thread Pre-Fetched Balance Entry Into `write_contract_balance` To Skip Third `try_get_full` Probe

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: SAC transfer per-call storage probe + key reconstruction reduction (soroswap headline path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

`write_contract_balance` should accept the pre-built `Rc<LedgerKey>` and the
already-fetched `(Rc<LedgerEntry>, Option<u32> live_until_ledger)` tuple from
its caller (`receive_balance`, `spend_balance_no_authorization_check`,
`write_authorization`) and mutate-in-place rather than re-constructing the
key from scratch and issuing its own `Storage::try_get_full` probe to
re-discover the entry it is about to overwrite.

## Mechanism

Actual code (`balance.rs:235-300` `write_contract_balance`) re-constructs
the key three times across the spend/receive code path: once by the caller
(`read_contract_balance` of the upstream read), once at line 244 via
`contract_balance_key_scval` + `metered_clone(&_witness_addr_contract_id)`,
and once at line 248 via `e.storage_key_from_scval(key_scval.metered_clone, …)`
— with a second `metered_clone` on the just-built `ScVal`. It then issues
`storage.try_get_full(&key, e, None)` at line 256 — a **third** probe of
the same balance entry already read by `is_authorized` and by
`read_contract_balance` upstream — purely to recover the full `LedgerEntry`
and `live_until_ledger` needed for the write. Threading the pre-fetched
entry through saves one full storage probe, one full ScVal-vec construction,
two `metered_clone` calls on the key components, and one
`storage_key_from_scval` call per write.

Estimated savings on the soroswap path: 17,381 SAC transfers × 2 writes per
transfer × (~1.5 µs storage probe + ~1.5 µs key reconstruction
+ ~0.5 µs metered_clones) = ~120 ms cpu time / 8-way parallelism /
70 ledgers ≈ **0.21 ms / ledger ≈ 0.10 % of soroswap apply** — still well
below the 1 % Low floor.

## Trigger

Any SAC `transfer`, `mint`, `burn`, `clawback`, or `set_authorized` call
targeting a contract address. Soroswap exercises this on every pair-side
SAC transfer (both spend and receive).

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:235-300` — `write_contract_balance` redundant key build + `try_get_full`.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:323-346` — `receive_balance` already has key + decoded balance; could pass entry + key to writer.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:373-407` — `spend_balance_no_authorization_check` already has key + decoded balance; same.

## Evidence

The current code path performs three full key constructions and three
storage probes per contract-to-contract spend or receive (one in
`is_authorized`, one in the spend/receive body, one in
`write_contract_balance.try_get_full`). The third probe is purely
redundant: the caller already holds the matching `Rc<LedgerKey>` and the
upstream `try_get` already returned the same entry's data. Threading the
entry through is a straightforward refactor with no observable behavior
change for the contract-address branch.

## Anti-Evidence

1. **Protocol-visible metering preservation** — every removed
   `Storage::try_get_full` carries `charge()` calls (`Storage::Get`,
   `MemCpy` for the key compare, `MeteredClone` for the returned
   entry) that are protocol-visible. Preserving budget semantics
   requires replaying the charges, leaving only the bare physical
   storage-map probe and ScVal allocation as actual savings — the
   same pattern that defeated fail `003` and fail `023`.
2. **Adjacent fail `002-typed-classic-trustline-sac-transfer.md`** —
   "p26 metering makes shallow clone/allocation charges protocol-visible
   (`MemCpy`/`MemAlloc`); replaying them leaves only tiny physical
   field-copy overhead; storage layer still requires a complete
   immutable `LedgerEntry` regardless." The same wall applies here.
3. **Adjacent fail `002-specialized-soroswap-sac-transfer.md`** —
   "Full `SAC transfer` zone is dominated by mandatory work that a
   correct specialization cannot remove (frame/auth semantics,
   `require_auth`, instance/code TTL extension, trustline and
   contract-balance storage access/validation, storage writes, event
   buffering and XDR materialization)." Removing one of three probes
   without touching the mandatory frame/auth/event scaffolding is
   sub-Low.
4. **Per-call savings too small** — at ~1.5 µs storage probe + ~2 µs
   key reconstruction × 2 writes / transfer × 17K transfers / 8-way
   parallelism / 70 ledgers, the total is well under the 1 % Low floor.
5. **Cache pattern regression risk** — fail
   `001-protocol-gated-sac-balance-readwrite-fusion` demonstrates that
   reordering / consolidating SAC storage probes can regress soroswap
   wall time even when individual probe counts go down; threading the
   entry through changes the access pattern at the call site and could
   trigger the same regression.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — distinct from fail `001-protocol-gated-sac-balance-readwrite-fusion`
(which fused the get + put into a single primitive); this hypothesis only
eliminates the redundant `try_get_full` re-read inside
`write_contract_balance`. Distinct from H041 (which targets the
`is_authorized` read). Not present in any prior fail/hypothesis/reviewed/poc file.

### Why It Failed

Same wall as H041 and the broader SAC-residual class:
1. Projected wall-clock ≈0.10 % of soroswap apply after parallel-worker
   normalization — 10× below the 1 % Low floor and 30× below the 3 %
   Medium floor.
2. Protocol-visible metering preservation forces replay of every removed
   `Storage::Get` / `MeteredClone` / `MemCpy` charge, reducing the
   removable substrate to bare physical hash + binary-search + allocation
   work that is too small at per-call scale.
3. Empirical precedent (`001-protocol-gated-sac-balance-readwrite-fusion`)
   shows that reordering SAC storage probes can regress soroswap measured
   apply time even when probe counts decrease; the access-pattern change
   risks the same regression.

### Lesson Learned

Per-probe elimination within the existing SAC transfer code path is a
sub-Low class of optimization regardless of how structurally obvious the
redundancy looks. Combined with H041 and `002-return-post-transfer-pair-balance`,
this completes the negative-result picture for "remove one SAC balance
read" — future SAC transfer wins require either restructuring the
frame/auth/event scaffolding wholesale or a next-protocol storage
representation redesign that lets a single typed `mutate_contract_balance`
primitive replace the entire read-modify-write sequence with metered cost
proportional to the unique key + amount-delta only.
