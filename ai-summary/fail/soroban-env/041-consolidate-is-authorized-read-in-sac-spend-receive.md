# H041: Consolidate `is_authorized` Balance Read Into Subsequent Spend/Receive Read

**Date**: 2026-05-25
**Subsystem**: soroban-env
**Severity**: Low
**Impact**: SAC transfer per-call storage probe reduction (soroswap headline path)
**Hypothesis by**: claude-opus-4.7, high

## Expected Behavior

For a contract-address transfer, `spend_balance` and `receive_balance` should
read the contract balance entry from storage exactly once per side and reuse
that value for both the authorization check (testing `balance.authorized`) and
the amount mutation. Each SAC transfer should issue at most 2 distinct
`Storage::try_get` calls per side: one to fetch the balance (covering the
authorized check + amount), and one full `try_get_full` to obtain the
`LedgerEntry` + TTL needed to write back.

## Mechanism

The actual code (`balance.rs:303-345` `receive_balance`, `balance.rs:418-427`
`spend_balance`) issues an extra `read_contract_balance` call up-front via
`is_authorized` (`balance.rs:431-449`), which performs its own
`contract_balance_ledger_key` construction + `Storage::try_get` +
`balance_value_from_scval` solely to test the `balance.authorized` flag.
The same key is then rebuilt and the same balance re-read inside
`spend_balance_no_authorization_check` / the body of `receive_balance`.
Folding the authorization check into the primary balance read would remove
one `Storage::try_get` per spend and per receive (i.e. two per SAC transfer).

For the soroswap path the savings are: 17,381 SAC transfers × 2 redundant
reads × ~1.5 µs (storage.try_get + map_lookup_indexed + ScVal→BalanceValue) =
~52 ms cpu time / 8-way parallelism / 70 ledgers ≈ **0.09 ms / ledger ≈
0.04 % of soroswap apply** — far below the Low (1 %) and Medium (3 %) floors.

## Trigger

Any SAC `transfer` invocation between contract addresses. In the soroswap
benchmark every pair swap calls `SAC.transfer(pair, user, amount)` (output
side) and the prior `SAC.transferFrom` produces a `spend_balance` on the
user → pair side, both of which hit the redundant `is_authorized` read.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:303-345` — `receive_balance` calls `is_authorized` then re-reads balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:418-427` — `spend_balance` calls `is_authorized` then `spend_balance_no_authorization_check` which re-reads balance.
- `src/rust/soroban/p26/soroban-env-host/src/builtin_contracts/stellar_asset_contract/balance.rs:431-449` — `is_authorized` performs the redundant `read_contract_balance`.

## Evidence

The same `contract_balance_ledger_key` + `Storage::try_get` +
`balance_value_from_scval` sequence is invoked twice per side of every
contract-to-contract SAC transfer. Tracy shows 357K total `storage get`
calls across the soroswap apply window at ~748 ns mean self-time; SAC
transfer accounts for a large share of these via the duplicated
`is_authorized` probe.

## Anti-Evidence

1. **Prior fail `001-protocol-gated-sac-balance-readwrite-fusion.md`** —
   coalescing SAC R/W storage accesses passed unit tests but regressed
   soroswap in all three authoritative non-Tracy benchmark runs; the
   cited mechanism is "storage-access coalescing overhead and changed
   cache access patterns negated the saved lookup work". The same
   regression vector would apply to consolidating is_authorized into
   the main read.
2. **Meta-Pattern from fail `002-return-post-transfer-pair-balance.md`** —
   "After the accepted direct-balance helper, further SAC transfer
   savings require redesigning mandatory SAC semantics, not removing one
   read; individual read-elision on top of the accepted fast path is
   sub-Low."
3. **Protocol-visible metering preservation** — each removed `Storage::get`
   carries a `charge()` call that is protocol-visible; preserving budget
   semantics requires replaying the charges, leaving only the bare
   hash/binary-search/copy savings — the same wall this hits in fail/003
   and fail/023.
4. **Per-call cost too low** — after the accepted typed-SAC-balance
   storage fast path (success #001), each balance read is already ~1.5 µs.
   Removing 2 per transfer × 17K transfers / 8-way / 70 ledgers gives
   sub-0.1 ms / ledger.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-25
**Failed At**: hypothesis
**Novelty**: PASS — not previously investigated as a standalone hypothesis;
adjacent fails covered fusion (`001-protocol-gated-sac-balance-readwrite-fusion`)
and post-spend balance capture (`002-return-post-transfer-pair-balance`)
but not `is_authorized`-read elision specifically.

### Why It Failed

Three independent reasons compound:
1. Projected wall-clock impact ≈0.04 % of soroswap apply after 8-way
   parallel-worker normalization — three orders of magnitude below the
   3 % Medium floor and 25× below the 1 % Low floor.
2. Protocol-visible metering preservation forces replay of every removed
   `Storage::get`/`MeteredClone` charge, leaving only the un-metered
   substrate (hash + binary search + ScVal scan) as actual savings —
   well under the per-call estimate above.
3. The closest precedent (R/W fusion) regressed soroswap by changing
   cache access patterns; reordering / consolidating storage probes on
   the SAC transfer path is empirically known to perturb measured
   apply time in the wrong direction.

### Lesson Learned

Residual SAC transfer storage-probe consolidation on top of the accepted
typed-balance fast path is a sub-Low class of optimization. Future SAC
transfer hypotheses must either (a) restructure mandatory SAC semantics
(frame/auth/event scaffolding), or (b) bundle the elimination of *all*
redundant probes (is_authorized + spend/receive + write_contract_balance
try_get_full) into a single typed `mutate_contract_balance` primitive
with an isolated benchmark demonstrating that the access-pattern change
does not cause the same cache regression that defeated fail `001`.
