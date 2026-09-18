# Leader-driven ballots (latency experiment)

This branch removes SCP nomination. For the next ledger, one deterministic
leader constructs a transaction set and pushes it to connected peers, then signs
a validated value and starts ballot `(1, value)`. A validator without a ballot
adopts a structurally validated value from a peer PREPARE. Prepare, confirm, externalize,
ballot counters and value overrides retain their existing SCP rules.

This experiment assumes live, honest validators, eventual message delivery,
compatible clocks, and identical election configuration. It has no leader
rotation. A configured validator that remains offline can stop progress when it
is elected. It is not a fault-tolerant replacement for the complete SCP protocol.
The latency campaign runs protocol 28. Networked operation requires generalized
transaction sets: the Rust transport does not distribute pre-Soroban sets.

## Election and validation

The election reuses the weighted, round-based hash schedule. Its input is the
slot, previous ledger's encoded SCP value, flattened quorum-set validators
(including the local validator), and validator weights. With automatic validator
weight configuration, quality and home-domain weights apply. Without that
configuration, all candidates receive the same maximum weight. Quorum thresholds
and the observer's identity do not influence weights. The lowest NodeID breaks
an exact priority tie. The election helper has no live slot, timer or emission
side effects; subsequent rounds remain available for a future rotation design.

**Every validator must have the same candidate set and the same weights.**
Uniform election and weighted election cannot be mixed. Heterogeneous candidate
sets are unsupported even when their quorum sets intersect. SSC preflight checks
all generated validator configurations before starting load.

For LCL+1, value validation requires the elected leader's signature in addition
to existing signature, close-time, transaction-set and apply-valid upgrade
checks. Older or future values retain contextual validation for catchup.
Followers adopt only while they have no ballot and can validate the current
slot. Watchers do not initiate a vote. Federated state advancement runs before
adoption, so accepted commit/prepared state takes precedence. Restored ballots
also prevent a second proposal.

One permitted signer does **not** prove that there is only one value: a signer
could equivocate, restart with lost state, or yield an empty-transaction-set twin.
The experiment relies on the stated honest-node assumptions and the existing
ballot safety rules, rather than a new uniqueness proof. CAP-0083 replacement
retains the original proposal for a later counter bump when its body arrives;
confirmed value overrides still take precedence.

## Parallel delivery and early voting

`EXPERIMENTAL_PARALLEL_TX_SET_DOWNLOAD` defaults to true on this experimental
branch and takes effect at protocol 28. It can be disabled for comparisons.
The leader still validates its own proposal before signing and starting a ballot.
Followers check the proposal's signature, elected leader, slot context,
close time, and upgrades before voting. They can then emit early
PREPARE votes while the transaction-set body is downloading or awaits full
validation. This also applies when an early push delivered the body first.

Full validation is scheduled once per slot/value through Core's existing
main-thread entry point, retaining its snapshot and batch-executor machinery.
The main thread still waits for validation to finish, but the initial PREPARE
can travel and peers can vote during this work.
The result is cached against the previous ledger and close-time offset. A queued
job whose ledger context changed is discarded. If commit evidence arrives first,
the commit-vote gate performs the full validation synchronously.

The existing CAP-0083 gate still prohibits setting `nC` (voting to commit the
original value) without full validation. Missing or invalid bodies cannot unlock
that vote or local externalization. Receiving and validating the body explicitly
reconsiders stored ballot evidence, including an already confirmed-prepared
`nH` with `nC == 0`; no higher ballot or additional peer message is needed.
The first nonzero `nC` is consequently a newer PREPARE even when its ballot,
prepared ballots, and `nH` are unchanged; duplicates and the reverse update
remain stale.

The CAP-0083 empty-set value remains the fallback. A missing body that exceeds
`TX_SET_DOWNLOAD_TIMEOUT` (default 5000 ms) can be replaced on a ballot bump
while still in PREPARE and before commitment. A present body awaiting queued
validation is not treated as a failed fetch. The empty-set value still needs
normal ballot agreement. Received CONFIRM/EXTERNALIZE statements retain their
full-validation checks, including the existing federated accept-commit rules.

## Timing and dissemination

The normal next-ledger trigger and close-time checks remain. Only the elected
leader prepares a local set. When selection excludes valid candidates, the final
XDR is cached and broadcast immediately, overlapping Core's remaining roundtrip
and final validity checks. Reusing that prepared set at the trigger does not send
it again. Underfilled early snapshots stay local because they will be refreshed;
their replacement is broadcast when selected at the trigger.

Early delivery distributes unsigned, content-addressed bytes. It does not start
a ballot or bypass value validation. A discarded snapshot may remain in peer
caches, but only a successfully validated proposal can produce PREPARE. IPC
ordering ensures publication precedes the broadcast command; independent QUIC
streams do not guarantee that every peer receives the body before PREPARE.
Receivers cache unsolicited sets and retain pull/prefetch as a fallback.

A failed proposal construction schedules another attempt after 250 ms, then
500 ms, capped at 1 second. Each attempt rechecks current ledger state and whether
a ballot already exists. Applying a newer ledger cancels the old trigger.
Close-time validation is retained: acceptance of the previous close time does
not establish that every possible next value is valid at every peer's clock.

Core reissues unresolved transaction-set requests every 2 seconds. Rust keeps a
reservation for a connected peer for 5 seconds, then can retry another peer,
cycling through connected peers before reuse. Core owns the retry schedule;
a second independent periodic retry loop in Rust is unnecessary. Successful
unsolicited delivery also clears a reservation. Failed SCP sends and disconnects
clear per-peer send deduplication so later rebroadcast can retry them.

An overdue-slot recovery timer rebroadcasts local ballot state and republishes
the leader's body. It can also restart proposal construction when the ledger is
synced and no ballot exists. Recovery is deliberately outside the normal fast
path. It does not elect a replacement leader.

After loading a persisted ledger beyond genesis, a restarted next-slot leader
leaves the ledger manager's booting state so it can propose without waiting for
its own proposal to externalize. A restored ballot is retained; otherwise the
normal trigger cadence is armed. Genesis still needs explicit bootstrap.

NOMINATE remains a wire enum for decoding old messages, but the Rust receive
boundary and Core intake reject it before nomination-specific processing.
Persisted nomination envelopes are skipped during restore. There is no runtime
switch back to nomination.

## Behavior changes and measurement

Followers accept apply-valid upgrades carried by the leader. They no longer
require matching local nomination upgrade settings; nomination-timeout upgrade
stripping no longer exists. The leader still creates upgrades from its own
configuration. This is a change in upgrade coordination, not an assertion that
existing operator approval semantics have been preserved.

The expected benefit is reduced trigger-to-externalize work and latency. The
configured cadence remains, so idle ledger intervals need not become shorter.
Measure proposal time, ballot time, externalization lag, transaction-set fetch
wait, complete ledger intervals and full-window completed throughput. Report
sample coverage and backlog alongside percentiles; a harness latency PASS alone
does not establish sustained offered TPS.

SSC starts at 2000 ms / 3000 TPS on the existing 30-validator fixture, then tests
1500, 1250 and 1000 ms before increasing offered TPS. All arms use the same
explicit-millisecond harness path, resources, network delays, workload and
2000 ms ballot timeout. Compare first against this branch's immediate parent
`0ed3e540ecf53f73a4f845aea925c05a71892954`; older controls provide context.
