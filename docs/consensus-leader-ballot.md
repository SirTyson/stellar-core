# Leader-driven ballots (latency experiment)

This branch removes SCP nomination. For the next ledger, one deterministic
leader constructs and signs a value, pushes its transaction set to connected
peers, and starts ballot `(1, value)`. A validator without a ballot adopts a
validated value from a peer ballot statement. Prepare, confirm, externalize,
ballot counters and value overrides retain their existing SCP rules.

This experiment assumes live, honest validators, eventual message delivery,
compatible clocks, and identical election configuration. It has no leader
rotation. A configured validator that remains offline can stop progress when it
is elected. It is not a fault-tolerant replacement for the complete SCP protocol.

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

## Timing and dissemination

The normal next-ledger trigger and close-time checks remain. Only the elected
leader prepares a local set. At the trigger it publishes the body through the
existing cache IPC, requests broadcast to connected peers, then emits PREPARE.
IPC ordering ensures publication precedes the broadcast command; independent
QUIC streams do not guarantee that every peer receives the body before PREPARE.
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
