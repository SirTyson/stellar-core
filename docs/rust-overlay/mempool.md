# Mempool

The Rust overlay owns an account-aware mempool. Core validates locally
submitted transactions, asks the overlay for nomination candidates, builds and
validates the transaction set, and tells the overlay which hashes were applied
or are permanently invalid.

The implementation is in `overlay/src/flood/mempool.rs`; the command manager
is in `overlay/src/integrated.rs`.

## Limits and indexes

The default pool holds 100,000 transactions for at most 300 seconds, with at
most eight pending transactions per source account. It maintains:

- a hash index for lookup and deduplication;
- a sequence-ordered chain for every source account;
- separate fee-ordered classic and Soroban **head** sets;
- an arrival queue for expiry; and
- a ledger-aged, bounded ban map for applied or invalid hashes.

An account head is its lowest pending sequence number. Only heads are returned
for nomination, so a candidate response never contains two transactions from
one source account, including across classic and Soroban phases. Removing a
head promotes the account's next pending sequence number.

## Fee priority and replacement

Heads are ordered by inclusion fee per operation. Soroban resource fees are
excluded from inclusion-fee priority, and rate comparison uses wide integer
arithmetic to avoid multiplication overflow. Ties prefer fewer operations and
then use the transaction hash.

There is at most one resident transaction for an `(account, sequence)` slot. A
higher-rate transaction replaces a lower-rate transaction in the same slot.

At global capacity, immediately nominatable account heads are preserved before
future tails. A new account head displaces the cheapest tail before replacing
another head, increasing next-ledger source diversity. An existing account can
replace its own farther tail with a closer sequence; otherwise a new tail must
outbid the actual tail it displaces. This prevents storing a future transaction
by dropping its predecessor or another account's sole head.

## Nomination

Core uses the correlated, per-phase `GET_TOP_TXS` request:

```
[request_id:u64][classic_count:u32][soroban_count:u32]
```

The response echoes `request_id` and contains classic heads followed by
Soroban heads. The legacy one-count request remains available for compatibility.

Core starts with twice each phase's ledger capacity. If transiently invalid or
resource-nonfitting heads leave room, it grows that phase's window and rebuilds
until the phase is full or all returned heads have been examined. Permanently
invalid or stale heads are removed immediately and the promoted successors are
queried in the same nomination attempt. Transient failures—including a short
future sequence chain or near-future time bound—remain queued for a later
ledger.

Transaction-set construction reserves fees incrementally in surge-priority
order. If individually valid transactions share a fee source but their combined
fees are unaffordable, the highest-priority affordable subset is proposed; the
rest remain pending rather than causing the entire fee-source group to be
dropped.

## Removal and maintenance

Applied and permanently invalid hashes are removed and banned for ten ledger
closes. `LEDGER_CLOSED` advances the ban horizon and expires old entries. Both
commands share the ordered mempool-manager channel with nomination queries, so
a later query observes removals, promotions, expiry, and ban pruning.

## Current configuration caveat

The global capacity, maximum age, per-account cap, and ban horizon are currently
compile-time defaults rather than operator configuration options.
