# Direct Leader Flooding — Design & Progress

> Status: **experimental.** This document tracks the design and progress of an
> experiment to flood transactions directly to the next SCP leader instead of
> gossiping them to the whole network.

## Goal

Today the Rust overlay floods every transaction to **all** connected peers via a
three-phase pull protocol (INV → GETDATA → TX, see
[`docs/rust-overlay/tx-propagation.md`](rust-overlay/tx-propagation.md)). The
pull protocol exists to avoid shipping full TX bodies redundantly across a
broadcast fan-out.

The experiment: instead of flooding to everyone, **send each transaction
directly to the node(s) that will actually propose the next ledger** (the SCP
nomination leader set). The payoff is bandwidth — we stop distributing, in full,
the large fraction of submitted transactions that never get included in a ledger.
Only *nominated* transactions ever need network-wide distribution, and that
already rides the existing TxSet fetch-by-hash path.

## Key assumptions

- **Dense mesh.** A separate change enforces that the relevant topology is fully
  connected: every quorum member is a directly-connected `PREFERRED_PEERS` peer.
  This makes "send to the leader" a single hop — no routing layer needed.
- **Leader topology ⊆ `PREFERRED_PEERS`.** For the experiment we assume the set
  of possible leaders is exactly our quorum, and that our quorum is wholly
  contained in our preferred peers. Step 0 *asserts* this at runtime.

## Threat model note (why identity must be authenticated)

In today's flood-to-everyone model, a peer that lies about being the leader and
then drops transactions is harmless — the TX still reaches the real leader via
other peers. In a **leader-only** model, an attacker who convinces us they are
the next leader can vacuum up all our transactions and silently drop them: a
clean censorship / liveness attack. Narrowing the flood therefore *raises* the
stakes on peer identity. Every `nodeID → connection` binding the overlay relies
on must be **cryptographically authenticated**, never inferred from network
address.

## Roadmap

| Step | Description | Status |
|------|-------------|--------|
| **0** | Authenticated `nodeID → QUIC connection` mapping + bootstrap topology assert | **Implemented & tested** (cross-language identity vectors + e2e connectivity test) |
| **1** | Pipelined N-2 leader schedule: seed slot N's leaders from `hash(N-2)` so the schedule is computable a full ledger ahead (consensus-level, C++) | **Implemented & tested** (unit equivalence + live-network prediction test) |
| **2** | Each ledger close, compute the top-K leaders for L+2 and push them to the overlay via a new `SET_LEADERS` IPC message; overlay maps `NodeID → PeerId` (reusing Step 0) and stores them | **Implemented & tested** (e2e push test via metrics snapshot) |
| **3** | Route TXs directly to the leader connection(s): push full bodies, skip the INV/GETDATA round-trip; TxSet fetch for non-leaders + INV-flood fallback when no leader is connected | **Implemented & tested** (unit push/fallback/relay tests + e2e inclusion test) |
| 4 | Hardening: production-grade identity (cert instead of seed-in-overlay), continuous connectivity monitoring, metrics | Future |

Each step is a self-contained, reviewable change. We stay in the loop between
steps — read the result before deciding the next one.

---

## Step 0 — Authenticated identity + topology assert  *(Implemented)*

**Objective.** Give the overlay a trustworthy `validator pubkey (NodeID) → live
QUIC connection` mapping, and fail fast if, after a bootstrap grace period, we
are not connected to every quorum member. This is the foundation every later
step reuses: Step 2 routes to a leader by looking that leader's pubkey up in this
map.

It has three parts, matching the three things the experiment needs:

### 0a. Bind overlay identity to `NODE_SEED` (authenticated handshake)

The Rust overlay previously generated a **random** libp2p ed25519 keypair, so its
`PeerId` had no relationship to the validator's Stellar identity, and no Stellar
NodeID/signature was ever exchanged. We now derive the overlay's libp2p ed25519
identity directly from `NODE_SEED`, so:

- `PeerId = f(validator ed25519 public key)`, deterministically and publicly.
- The libp2p **QUIC/Noise handshake itself** cryptographically proves the peer
  controls that key — i.e. proves the validator's identity. No separate
  application-level signature exchange is needed; we strengthened identity
  verification on the handshake by *binding* the connection key to the node key.
- Core precomputes each quorum member's expected `PeerId` from the pubkeys it
  already has in config.

Security tradeoff accepted for the experiment: the node secret now also lives in
the network-facing overlay process. The production-grade alternative — a separate
overlay key certified by the node key (the old `AuthCert` pattern), keeping the
signing key in Core — is deferred to Step 4.

**Components**
- `overlay/src/config.rs`: startup `node_seed` (hex) and `quorum_check_grace_secs`.
- `overlay/src/main.rs`: `libp2p_keypair_from_config()` derives the keypair from
  the seed (falls back to a random key only when no `node_seed` is provided, e.g.
  overlay-only tests; Core always sends it in normal operation).
- `src/crypto/SecretKey.{h,cpp}`: `getSeedBytes()` exposes the raw 32-byte seed.
- `src/overlay/OverlayIPC.cpp`: the seed is delivered via a `mkstemp` +
  `fchmod(0600)` TOML file passed as `--config` (never argv/env, so it is not
  visible in `ps`), and `unlink`ed promptly once the overlay connects.

### 0b. Maintain `nodeID → connection` mapping

The overlay keeps, keyed by the **authenticated** libp2p `PeerId`:
- `expected_quorum: HashMap<PeerId, strkey>` — quorum members, set from config.
- `connected_peers: HashSet<PeerId>` and `connected_quorum: HashSet<PeerId>` —
  updated on `PeerConnected` / `PeerDisconnected`.

Because membership keys off the handshake-authenticated `PeerId`, a peer can only
appear in `connected_quorum` by actually holding that validator's key —
impersonation is impossible by construction. This map is the artifact Step 2
consumes to route to a leader.

**Components**
- `src/overlay/RustOverlayManager.cpp`: enumerates quorum members via
  `LocalNode::forAllNodes(QUORUM_SET, …)`, **excludes self**, sends their strkeys
  to the overlay.
- `src/overlay/OverlayIPC.cpp` / `overlay/src/main.rs`: `quorum_members` added to
  the `SetPeerConfig` JSON; overlay decodes each strkey → ed25519 pubkey →
  expected `PeerId`.

### 0c. Bootstrap topology assert

A one-shot timer (`quorum_check_grace_secs`, default 30s) starts when the quorum
config arrives. On fire, the overlay computes the quorum members with no
connected matching `PeerId` and sends a `QuorumConnectivityReport` (IPC type
`106`) listing the missing strkeys. By default Core logs an error for a
non-empty list (and success otherwise); with
`QUORUM_CONNECTIVITY_CHECK_FATAL=true` it throws a fatal error instead —
the experiment's fail-fast dense-mesh assert, opt-in because the full-feature
review found the unconditional abort (a) kills legitimate deployments that
restart while one quorum member is briefly down, and (b) killed pre-existing
tests that intentionally run nodes with unreachable quorum members. With
Step 3's INV-flood fallback, an incomplete topology costs bandwidth, not
liveness, so warn-by-default is safe.

**Components**
- `overlay/src/ipc/messages.rs`, `src/overlay/IPC.h`: new
  `QuorumConnectivityReport = 106`.
- `overlay/src/main.rs`: grace timer + `missing_quorum_members()` + report.
- `src/overlay/OverlayIPC.cpp`: parses the report, fires a callback.
- `src/overlay/RustOverlayManager.cpp`: callback throws on incomplete topology.

### Default, no flag

Step 0 is unconditional on this experimental branch — there is no gating flag.
Every node always derives its libp2p identity from `NODE_SEED`, Core always sends
the quorum members, and the bootstrap topology assert always runs (same as
Step 1).

### Known caveats / follow-ups

- **Cross-language equivalence is the linchpin — now tested at three levels.**
  The scheme assumes `ed25519_from_bytes(NODE_SEED.getSeedBytes())` produces the
  same public key bytes that `KeyUtils::toStrKey(NODE_SEED.getPublicKey())`
  encodes. This is pinned by a shared RFC 8032 test vector on both sides
  (`CryptoTests.cpp` "ed25519 cross-language identity vector" ↔ `main.rs`
  `test_cross_language_identity_vector`), and proven end-to-end by
  `OverlayIPCTests.cpp` "Rust overlay quorum connectivity report": two overlays
  seeded from real `SecretKey`s, each given the other's strkey as a quorum
  member, must both report full connectivity through an authenticated QUIC
  handshake (plus a never-connecting third validator reported missing).
- **The fatal assert is now opt-in (`QUORUM_CONNECTIVITY_CHECK_FATAL`,
  default false).** The review confirmed the original unconditional throw was
  an **uncatchable abort** (it escapes the main-loop crank and reaches
  `std::terminate` → core dump, not clean shutdown), demanded *all* members
  connected (stricter than "quorum satisfiable"), and — verified empirically —
  crashed pre-existing tests that legitimately run nodes with unreachable
  quorum members past the 30 s wall-clock grace. The check itself still always
  runs and logs; deployments wanting fail-fast set the flag. Step 4 should add
  continuous monitoring and a graceful shutdown path for the fatal mode.
- **Seed hygiene (deferred to Step 4 with the cert design).** `getSeedBytes()`
  copies the seed out of the self-zeroizing `Seed` wrapper; the hex string in
  `OverlayIPC::mNodeSeedHex` and the fmt'd config text live un-wiped in plain
  heap memory for the process lifetime (a core dump reveals them). The
  seed-in-overlay tradeoff is documented above; if Step 4 keeps this scheme,
  consume-and-zeroize the hex after spawn. Also: a SIGKILL during the
  spawn→connect window (100 ms–1 s) orphans the 0600 seed file in /tmp (name
  embeds the dead pid; nothing cleans it later).

---

## Step 1 — Pipelined N-2 leader schedule  *(Implemented)*

**Objective.** Make the upcoming nomination leaders for a slot knowable a full
ledger *before* that slot is nominated, so the overlay (Step 2) has time to
pre-flood transactions to the proposer. This is the consensus-affecting part
only: it changes *which* node leads and makes the schedule computable ahead of
time. Overlay push (Step 2) and TX routing (Step 3) build on it.

### The problem

SCP elects a slot's nomination leaders by hashing a per-round priority that is
seeded by the *previous value*. Historically slot N's leaders were seeded by the
N-1 value, so the leader was only knowable once N-1 closed — too late to
pre-flood for slot N.

### The N-2 seed rule

Leader election for slot N is now seeded by `hash(N-2)` instead of the N-1
value. The leaders of slot N are therefore determined the moment ledger N-2
closes, giving the entire N-1 window to flood them.

Steady-state rule: with `lcl = L`, the leaders of `L+2` are seeded by `hash(L)`
(the current LCL hash); the ledger being nominated now (`L+1`) is seeded by
`hash(L-1)`.

**Key simplification.** When nominating slot N, `lcl = N-1`, so `hash(N-2)` is
exactly `lcl.header.previousLedgerHash` — already in hand, no extra lookup. The
seed is a 32-byte hash wrapped as an opaque `Value`.

### Scope: leader election only

`SCPDriver::computeHashNode` (leader election) moves to the N-2 seed;
`computeValueHash` (value selection) is untouched and still uses the N-1
previous value. Safety is preserved — leaders are only a nomination heuristic;
agreement/validity do not depend on the seed.

### Ownership: C++ computes, Rust consumes

The leader schedule is computed authoritatively in C++ — it is the SCP election
and owns the quorum set + validator weights, so a single implementation
guarantees the flood target equals the real proposer. The Rust overlay never
runs the election; Step 2 hands it the resolved ordered `NodeID` list, which it
maps to `PeerId`s via the Step 0 identity layer.

### Components

- `src/scp/NominationProtocol.{h,cpp}`:
  - `mLeaderElectionSeed` (a `Value`) stores the seed once per slot (constant
    across rounds; only the round number varies).
  - `nominate()` takes a `leaderElectionSeed` parameter (threaded from
    `SCP::nominate` → `Slot::nominate`), stored into `mLeaderElectionSeed`.
  - The leader-election core is extracted into two pure static functions of
    explicit inputs (seed, slot, round, qset, localID), preserving the historical
    priority algorithm verbatim (the former `getNodePriority`/`hashNode` helpers
    are folded into `computeRoundLeaders` and removed):
    - `computeRoundLeaders(...)` — leaders elected for a single round.
    - `computeLeaderSchedule(..., count, ...)` — the ordered top-K upcoming
      leaders, walking rounds 1, 2, … and accumulating (skipping rounds that
      elect no one, exactly as the live fast-timeout does) until `count`
      distinct leaders are collected. Ordering is by round, then NodeID within a
      round (within a round all leaders share the top priority, so NodeID is the
      deterministic tie-break).
  - `updateRoundLeaders()` (live path) now calls `computeRoundLeaders` with
    `mLeaderElectionSeed`; behavior is otherwise unchanged.
- `src/scp/SCP.{h,cpp}`, `src/scp/Slot.{h,cpp}`: thread the seed parameter
  through `nominate`.
- `src/herder/HerderSCPDriver.{h,cpp}`:
  - `nominate()` passes `lcl.header.previousLedgerHash` (= `hash(N-2)`) as the
    seed.
  - `computeLeaderSchedule(seed, slotIndex, count)` — the ahead-of-time entry
    point Step 2 will call (seed = `hash(slotIndex-2)`). Uses the local quorum
    set (normalized, self excluded) and the application-specific
    `getNodeWeight`, so the result matches the leaders SCP elects live.
- `src/main/Config.{h,cpp}`: `FLOOD_LEADER_COUNT` (`size_t`, default 2) bounds
  the top-K; consumed by Step 2, defined here.

### Default, no flag

This is unconditional behavior on the experimental branch — as is Step 0; neither
is gated by a flag. Because it changes which node leads, convergence requires
every participating validator to run the same rule — guaranteed here since it is
the branch default.

### Verification

- **Core invariant (linchpin).** For a slot S, the ahead-of-time
  `computeLeaderSchedule(hash(S-2), S)` equals the actual leaders SCP elects for
  S during live nomination (predicted == actual). This is what makes Steps 2/3
  target the real proposer. Tested at two levels:
  - `SCPUnitTests.cpp` "computeLeaderSchedule matches live leader election" —
    pure logic, explicit seed.
  - `OverlayIPCTests.cpp` "leader schedule prediction matches live nomination" —
    a real 3-validator network; for every closed slot S, each node's
    `HerderSCPDriver::computeLeaderSchedule(hash(S-2), S)` must equal the
    leaders its SCP elected live, exercising the real seed threading
    (`lcl.header.previousLedgerHash`) and weight function.
- Top-K ordering is deterministic for repeated calls and, under weights that
  ignore `isLocalNode` (as production's application-specific weights do),
  identical across nodes.
- Simulation/Herder/SCP suites must still reach consensus (leaders changed, but
  liveness/agreement hold).

### Grinding note

N-2's proposer has marginal influence over `hash(N-2)` and thus N's schedule —
comparable to the historical N-1 seed, shifted back one ledger. The extra
lookahead gives more *time*, not more *control*. Acceptable for the experiment;
revisit for any production path.

---

## Step 2 — Push top-K leaders to overlay  *(Implemented)*

**Objective.** Wire the Step 1 schedule across the IPC boundary: each ledger
close, Core computes the upcoming flood leaders and pushes them to the overlay,
which maps them to authenticated `PeerId`s (Step 0) and stores them. Pure
transport + storage — actual TX routing is Step 3.

**Rule.** On each ledger close with LCL = L (and only when in sync /
`latest`), a validator pushes the top `FLOOD_LEADER_COUNT` leaders of slot
`L+2`, computed from `hash(L)` — the seed that just became known. The overlay
keeps one current flood-target set, replaced on every push. Self may appear in
the set (harmless: no self-connection); self-exclusion policy is a Step 3
routing decision. Non-validators don't push (revisited with routing).

### Components

- `src/herder/HerderImpl.{h,cpp}`: `pushLeaderSchedule()` — computes the
  schedule and sends it; called from `lastClosedLedgerIncreased` inside the
  `latest` block (main thread, apply finished, so the
  `getNodeWeight`/`isApplying` constraint holds by construction).
- `src/overlay/IPC.h` / `overlay/src/ipc/messages.rs`: `SET_LEADERS = 14`,
  payload JSON `{"slot": u64, "leaders": ["G...", ...]}` ordered by election
  priority. The slot is included for observability and so Step 3 knows which
  slot the targets belong to.
- `src/overlay/OverlayIPC.{h,cpp}`: `updateLeaders(slotIndex, strkeys)` —
  mirrors the `setPeerConfig` JSON/send pattern.
- `overlay/src/main.rs`:
  - `parse_leaders_payload()` — parses + maps strkey → `PeerId` via the Step 0
    identity layer; any invalid entry rejects the whole payload so a
    partially-mapped leader set is never installed (previous set kept).
  - `App.leaders: (slot, Vec<(strkey, PeerId)>)`, replaced per push; each push
    logs every leader with its live connectivity status.
  - The metrics snapshot (`REQUEST_OVERLAY_METRICS`) now carries
    `flood_leaders_slot`, `flood_leaders` (ordered strkeys) and
    `flood_leaders_connected` (per-leader bool) — operator-visible proof of the
    pipeline, also used by the e2e test.

### Verification

- Rust: `SetLeaders` codec roundtrip / `try_from` (messages.rs);
  `test_parse_leaders_payload` (ordering, empty set, whole-payload rejection on
  any bad entry, malformed JSON).
- C++ e2e: `OverlayIPCTests.cpp` "flood leaders pushed to overlay" — a real
  3-validator network closes 5 ledgers; each node's overlay must then report
  exactly `computeLeaderSchedule(hash(L), L+2)` for that node's final LCL in
  its metrics snapshot, with every non-self leader connected+authenticated.

## Step 3 — Targeted routing  *(Implemented)*

**Objective.** Actually use the leader targets: push the **full TX body
directly** to the K leader connections, skipping the INV/GETDATA round-trip
(pure overhead when sending to a known recipient that needs the TX). This is
where the bandwidth win materializes — non-leaders stop receiving most TX
bodies; nominated TXs still reach everyone via the existing TxSet
fetch-by-hash at nomination time.

### Routing rules

All in the Rust overlay (`libp2p_overlay.rs`); Core is unchanged apart from
metrics. The overlay keeps `flood_leaders: Vec<PeerId>` (ordered), replaced on
every `SET_LEADERS` from Step 2 (written through a shared lock rather than the
bounded overlay command channel, so installing a new set can never stall
SCP/TX dispatch behind slow per-peer sends).

- **Submit path (`broadcast_tx`).** After the usual `tx_seen` dedup +
  `tx_buffer` insert (unchanged, so GETDATA serving still works):
  - leaders known ∧ ≥1 connected → send `TX` (0x01, full body) to each
    connected leader on the existing TX stream; **no INV**. Receivers accept
    unsolicited `TX` messages and dedup via `tx_seen`, exactly as for pulled
    TXs — no wire-format change.
  - leaders known ∧ none connected → **fallback**: INV-flood to all peers as
    before (liveness valve; counted in `flood.leader-fallback`).
  - no leaders known (non-validator, or before the first push) → legacy
    INV-flood.
- **Relay path (`handle_tx_response`).** On receiving a TX (pulled or pushed):
  forward to Core/mempool as before, then instead of INV-announcing to all
  peers, push the full body to connected leaders that don't already have it
  (excluding the sender and `inv_tracker` known-sources). This closes coverage
  holes when the origin couldn't reach every leader. Same fallback rules as
  the submit path.
- Self may appear in the leader set; it is never in `peer_streams`, so it is
  naturally skipped. `FLOOD_LEADER_COUNT` (default 2) covers the early
  nomination rounds; rounds beyond K still lead and produce valid, possibly
  emptier, blocks — TXs simply resubmit.

### Failure modes (review findings: fixed vs accepted)

A full-feature review flagged that the initial push path removed all three
redundancy mechanisms of the pull protocol (N-peer fan-out, GETDATA retry,
resupply-from-any-holder) with a single delivery attempt to K connections.
Addressed as follows.

**Fixed:**
- *Failed push = lost TX.* A direct push is often the TX's only delivery
  attempt; a send failure (e.g. the leader drops between the connectivity
  check and the write) now falls back to INV-announcing the TX to all peers,
  restoring pull-mode recoverability. `flood.leader-push{,-bytes}` count
  successful sends only, and successful pushes are counted in
  `message_write`/`byte_write`.
- *Resubmission was a no-op.* `tx_seen` dedup used to swallow Core
  resubmissions entirely; a resubmitted TX is now re-pushed to the *current*
  connected leaders (receivers dedup; no INV re-flood), so the documented
  "TXs simply resubmit" recovery actually works — including after leader
  misprediction, since a new window has new targets. Note Core has no
  periodic TX rebroadcast on this branch; resubmission is client-driven.
- *Leader-set installation could block the IPC dispatch loop* (bounded
  command channel, backed up by inline slow sends) — replaced with the direct
  shared-lock write described above.

**Accepted / deferred to Step 4:**
- *Leader upcall-drop concentration.* Push mode concentrates the network's TX
  receive load on K leaders; if a leader's bounded TX→Core channel (10k)
  overflows, the upcall is dropped, and because dedup precedes the upcall a
  redelivered body cannot repair it. Client resubmission via a different node
  recovers. Step 4 should add a bounded retry on `try_send` failure.
- *Stale targets while out of sync.* A non-`latest` node stops pushing
  schedules but its overlay keeps the last set; TXs relayed through it target
  stale leaders until resync (Core rejects direct submissions while out of
  sync, so exposure is relay-only).
- *Prediction/live skew at a protocol-upgrade boundary.* `getNodeWeight`
  selects the weight algorithm from the current LCL's protocol version, so a
  schedule computed at close of L for slot L+2 can differ from the live L+2
  election if the network upgrades at L+1 — one slot of approximate targeting
  per upgrade, covered by the fallback/relay paths.
- *Old-style election weights are self-biased* (`isLocalNode` boost when
  `VALIDATOR_WEIGHT_CONFIG` is absent, pre-upgrade, or forced), so each node
  pushes a different schedule and targeting is approximate;
  `pushLeaderSchedule` warns once when this regime is active.
- *Leader relay redundancy.* Leaders relay pushed TXs to each other (L1 can't
  tell whether the origin already reached L2), so up to K·(K-1) duplicate
  bodies circulate among the K leaders per TX, deduped on arrival. At K=2
  this is one redundant body — negligible next to eliminating body+INV
  traffic to all N peers.

### Metrics

`overlay.flood.leader-push` (bodies pushed), `overlay.flood.leader-push-bytes`,
and `overlay.flood.leader-fallback` (TXs that INV-flooded because no leader was
connected), flowing through the snapshot into medida
(`RustOverlayManager::syncMetrics`) for live observability of routing hit rate.

### Verification

- Rust integration tests (`libp2p_overlay.rs`): `test_leader_push_direct`
  (full body reaches the leader, zero INVs), 
  `test_leader_push_fallback_when_leader_disconnected` (INV fallback keeps the
  TX flowing), `test_leader_relay_after_pull` (A—B—C topology: B pulls from A
  and direct-pushes to its leader C).
- C++ e2e (`OverlayIPCTests.cpp` "TX routed directly to leader"): on a real
  3-validator network with the schedule flowing, a TX submitted to one node is
  included and applied on all nodes, and the submitter's overlay reports
  `flood_leader_push ≥ 1`.

## Later steps (sketch)

- **Step 4 — Hardening.** Cert-based identity (keep the signing key in Core),
  continuous connectivity monitoring, and richer observability (leader-coverage,
  pull-vs-push latency; routing hit-rate meters landed with Step 3).
