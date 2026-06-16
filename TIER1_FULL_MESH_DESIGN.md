# Quorum Peering: A Fully Connected Tier 1 Without Config Changes

**Status:** Brainstorm / design exploration — no code changes yet.

## 1. Summary

Today the ~21 tier 1 validators reach each other through whatever overlay
topology happens to form from `KNOWN_PEERS`, gossip, and random dialing. SCP
traffic between two tier 1 nodes may transit several watcher hops. The
`PREFERRED_PEERS` mechanism could pin tier 1 together, but nobody maintains IP
lists in practice.

This document proposes **quorum peering**: a node automatically treats peers
whose public keys appear in its own `QUORUM_SET` as *trusted*, and the overlay
forms and aggressively maintains direct connections between mutually-trusting
nodes. Because every tier 1 node has every other tier 1 org in its quorum set,
this produces a self-healing full mesh over tier 1 — derived entirely from
configuration that already exists (`QUORUM_SET`), with zero new IP lists.

Key properties:

- **No config changes for tier 1.** Trust is derived from `QUORUM_SET` +
  `NODE_IS_VALIDATOR`, both already set.
- **Mutual trust gates privilege.** A connection is *privileged* only if both
  endpoints have each other in quorum. A watcher that has tier 1 in its quorum
  is *not* privileged from tier 1's perspective and — critically — does not
  retry aggressively, because privilege requires the remote side's confirmation.
- **Watcher headroom is guaranteed.** Each node reserves a floor of inbound
  slots (default ≥ 20) that trusted peers can never occupy or evict.
- **Explicit, polite rejection.** When a tier 1 node has no free unprivileged
  slot, it rejects with a new `ERR_NOT_IN_QUORUM`-style error telling the
  dialer "you are not high priority to me; back off" instead of the generic
  `ERR_LOAD`.
- **No new discovery protocol.** The mesh forms organically from today's
  `KNOWN_PEERS` + `PEERS` gossip plus handshake-verified bindings, made
  permanent by the peers DB; the only addition is a rate-limited hunting pass
  while any quorum key's disposition is still unresolved (§3.6).
- **Confined to the peer-management layer.** Changes touch
  `src/overlay/` + `Config` (+ a small XDR addition). Herder, SCP, ledger are
  untouched. Consensus semantics do not change — only which TCP edges exist.

## 2. Background: what the peer-management system does today

This section is the factual basis for the reuse argument; all behavior was
verified against the current tree.

### 2.1 Slot accounting

- Outbound authenticated connections are capped at `TARGET_PEER_CONNECTIONS`
  (default **8**, `Config.cpp:246`); enforced both as the outbound `PeersList`
  cap and in `availableOutboundAuthenticatedSlots()`
  (`OverlayManagerImpl.cpp:814`).
- Inbound authenticated connections are capped at
  `MAX_ADDITIONAL_PEER_CONNECTIONS` (default `8 × TARGET = 64`,
  `Config::adjust()`, `Config.cpp:2167`).
- Pending (pre-auth) connections are capped by
  `MAX_INBOUND/OUTBOUND_PENDING_CONNECTIONS`, derived from
  `MAX_PENDING_CONNECTIONS` (default 500).

### 2.2 Preferred peers — the existing priority mechanism

`OverlayManagerImpl::isPreferred()` (`OverlayManagerImpl.cpp:1071`) returns
true if:

1. the peer's address is in `PREFERRED_PEERS` (resolved from config), or
2. the peer is authenticated and its `NodeID` is in **`PREFERRED_PEER_KEYS`** —
   i.e., key-based priority already exists.

Preferred peers get:

- **Guaranteed admission with eviction.** `PeersList::acceptAuthenticatedPeer()`
  (`OverlayManagerImpl.cpp:208`) admits a preferred peer even at capacity by
  evicting an arbitrary non-preferred victim with `ERR_LOAD`.
- **Aggressive reconnection.** `tick()` runs every 3 s
  (`OverlayManagerImpl.cpp:660`) and dials preferred-typed addresses *first*,
  allowing them to consume slots currently held by non-preferred peers
  (`OverlayManagerImpl.cpp:744-758`).
- **Persistence.** After a successful handshake, the peer's address is written
  to the peers DB with type `PREFERRED` (`Peer::updatePeerRecordAfterEcho`,
  `Peer.cpp:1738`). The `PREFERRED` `RandomPeerSource` then re-dials it forever
  after, across restarts. **This is an existing authenticated key→IP discovery
  memory** — the DB schema needs no pubkey column.
- **Out-of-sync protection.** The "drop a random peer when out of sync" logic
  explicitly spares preferred peers (`OverlayManagerImpl.cpp:603`).

### 2.3 Retry/backoff

- Every outbound dial *pre-increments* the failure count
  (`BackOffUpdate::INCREASE`, `OverlayManagerImpl.cpp:423`); successful
  authentication resets it (`Peer.cpp:1771`).
- Backoff is randomized-exponential: `rand % ((1 << min(n,10)) * 10s) + 1`
  (`PeerManager.cpp:366`) — i.e., jittered, doubling from a 10 s window up to a
  ~2.8 h window. Preferred dialing **respects** `nextAttempt`
  (`RandomPeerSource::nextAttemptCutoff`), so even preferred reconnection is
  exponentially polite, just first in line.
- Addresses with ≥ 120 failures are purged
  (`REALLY_DEAD_NUM_FAILURES_CUTOFF`, `Config.h:717`).

### 2.4 Handshake and identity

- `HELLO` carries `peerID` and an `AuthCert` signed by that key, verified in
  `recvHello` (`Peer.cpp:1794`), and the HMAC session keys are derived from the
  cert's ephemeral key — so by the time admission decisions are made, the
  **NodeID↔IP binding is cryptographically authenticated.** No new handshake
  field is needed for the *receiver* to decide "is this peer in my quorum."
- `AUTH.flags` is an `int` that today must equal
  `AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED = 200` exactly (`Peer.cpp:1952`)
  — extendable behind an overlay-version gate (current version 41, min 40,
  `Config.cpp:163`).
- Message ordering guarantees each side knows the remote's `NodeID` (from
  HELLO) *before* sending its own AUTH, and receives the remote's AUTH *before*
  making its own admission decision (`recvAuth`, `Peer.cpp:1926`). So an
  AUTH-borne trust signal is available exactly when needed.
- Admission rejection today is `sendErrorAndDrop(ERR_LOAD, "peer rejected")`
  (`Peer.cpp:1963`); `recvError` just logs and drops (`Peer.cpp:1700`).

### 2.5 Peer discovery

- `PEERS` gossip exchanges bare `PeerAddress{ip, port, numFailures}` — **no
  public keys** (`Stellar-overlay.x:76`, `recvPeers` at `Peer.cpp:1990` only
  calls `ensureExists`). There is currently no way to ask "what is the IP of
  key X"; key→IP bindings are only learned by dialing and completing a
  handshake.

## 3. Design

### 3.1 Trust classification

Define a node's **trusted key set** as all validator keys reachable in its
configured `QUORUM_SET` (enumerated with the existing
`LocalNode::forAllNodes`, `scp/LocalNode.h:50` — this descends into the
org-grouped inner sets, so it covers all ~21 tier 1 validators). Computed once
at config load; no herder dependency, no runtime qset tracking needed for v1.

A *connection* is then classified per side:

| Classification | Condition (evaluated by node N for peer P) |
|---|---|
| **trusted (privileged)** | `N.NODE_IS_VALIDATOR` ∧ `P.key ∈ N.trustedKeys` ∧ P's AUTH confirmed `N.key ∈ P.trustedKeys` |
| **unprivileged** | everything else (today's behavior, unchanged) |

The two guards beyond the naive "in my quorum" check are what prevent the
watcher-stampede problem:

1. **Mutual confirmation (remote) — the real gate.** A node cannot tell from
   its own config whether it is tier 1: a non-tier-1 validator's config looks
   exactly like a member's, so locally it must presume it is in tier 1 until
   proven otherwise. The remote's AUTH flag is that proof. If it says "you
   are not in my quorum," the link is unprivileged on both sides — no
   aggressive redialing, no privileged slot — and the verdict is remembered
   per key in the disposition table (§3.6). Trust is only ever symmetric;
   self-classification is learned from the protocol, never assumed from
   config.
2. **`NODE_IS_VALIDATOR` gate (self) — a load optimization only.** Plain
   watchers (`validator = false`) skip even the bounded one-time hunt
   (§3.6), since they can never hold privileged links. Nothing rests on this
   flag being honest: misconfiguring it buys one bounded hunt wave, nothing
   more.

For tier 1 specifically: every pair of tier 1 nodes satisfies all conditions →
every pair maintains a privileged link → full mesh.

`PREFERRED_PEERS` / `PREFERRED_PEER_KEYS` remain as manual operator overrides
with their existing (stronger, unconditional) semantics; trusted is a new,
automatically-derived tier just below them.

### 3.2 Handshake signaling (wire change #1)

Bump `OVERLAY_PROTOCOL_VERSION` 41 → 42 and, when the remote's advertised
overlay version ≥ 42, treat `Auth.flags` as a bitmask:

```
AUTH_MSG_FLAG_FLOW_CONTROL_BYTES_REQUESTED = 200   (existing, still required)
AUTH_MSG_FLAG_PEER_IN_QUORUM               = 0x100 (new; 200 = 0b11001000, no collision)
```

Sender sets `PEER_IN_QUORUM` iff it is a validator and the remote's
authenticated `NodeID` (known from HELLO) is in its trusted key set. No XDR
struct layout changes; v41 peers still see `flags == 200`.

Note the flag is consumed on **every** handshake outcome — acceptance
included — to resolve the dialer's per-key disposition (§3.6). The rejection
error alone could not do this: most contacts with a tier 1 node *succeed*
(into a reserved unprivileged slot), and it is precisely the politely
*accepted* node that must learn its link is unprivileged.

### 3.3 Rejection signaling (wire change #2)

New error code in `Stellar-overlay.x`:

```
ERR_PEER_UNPRIVILEGED = 5  // no slots for peers outside my quorum; do not retry aggressively
```

Sent (version-gated; `ERR_LOAD` to v41 peers) from the `recvAuth` admission
path when an unprivileged peer is rejected for capacity. On receipt, the
dialer applies `PeerManager::update(addr, ENSURE_NOT_PREFERRED)`, demoting
any stale `PREFERRED` DB typing for that address.

The retry cadence needs one ordering fix to work. Today the dialer resets the
address's failure counter when the handshake *completes*
(`updatePeerRecordAfterAuthentication`, `Peer.cpp:1958`) — before the
remote's admission verdict arrives (the responder sends AUTH first, then the
rejection). A dial→authenticate→reject cycle therefore ends with
`numFailures` oscillating between 0 and 1, and a dialer facing a full node
re-knocks every ~10–20 s for as long as that node stays full. Fix: fire the
`RESET` only on *admission* (e.g., the dialer defers it until the responder's
first post-AUTH flow-control message, which only admitted connections
receive). Polite rejections then accumulate ordinary exponential backoff —
and since `numFailures`/`nextAttempt` live in the peers DB, the "they were
full last time" cadence **persists across restarts** with no new state: a
restarted watcher does not re-churn against tier 1 (see also §3.6 on why this
memory is deliberately address-keyed, and open question 8).

One cadence tweak on top: "alive but full" needs re-checking far less often
than "possibly dead," so backoff driven by `ERR_PEER_UNPRIVILEGED` should be
allowed to grow past the ordinary `MAX_BACKOFF_EXPONENT` cap (~2.8 h window,
`PeerManager.cpp:369`) to day-scale windows. At the ordinary cap, a rejected
watcher still re-knocks a full tier 1 node ~17×/day on average — across
thousands of watchers, roughly a sustained handshake per second of pure
rejection traffic per tier 1 node. Day-scale windows cut that by an order of
magnitude while keeping re-knocks frequent enough that reserved slots
redistribute over time.

### 3.4 Slot policy

Two pools per direction, with the trusted pool sized by the quorum, not by
operator config:

- **Inbound:** trusted peers may occupy at most
  `min(|trustedKeys| − 1, inboundCap − RESERVED_UNPRIVILEGED_INBOUND_SLOTS)`
  slots. New config `RESERVED_UNPRIVILEGED_INBOUND_SLOTS` (default **20**) is a
  hard floor that trusted peers can neither fill nor evict into. The eviction
  loop in `acceptAuthenticatedPeer` gains one condition: a trusted peer may
  evict an unprivileged victim only while trusted occupancy is below its cap.
  With mainnet defaults (inbound cap 64, |tier 1| = 21): worst case 20 trusted
  + 44 unprivileged ≥ the 20-slot floor. `Config::adjust()` gains a check that
  `inboundCap ≥ (|trustedKeys| − 1) + RESERVED_UNPRIVILEGED_INBOUND_SLOTS`,
  auto-raising with a warning otherwise.
- **Outbound:** trusted connections get their **own budget** of up to
  `|trustedKeys| − 1` and do not count against `TARGET_PEER_CONNECTIONS`.
  This is not optional tuning — it is required for the mesh to exist: a
  21-node mesh has C(21,2) = 210 edges and each edge is *some* node's outbound
  connection, so average outbound degree is 10 and worst case 20, while
  21 × TARGET(8) = 168 < 210. Concretely: the outbound `PeersList` cap becomes
  `TARGET_PEER_CONNECTIONS + trustedOutboundCount`, and `tick()` gets a
  trusted-dial pass (budgeted separately) ahead of the existing preferred /
  outbound / promotion passes. Watcher-facing outbound behavior
  (`TARGET_PEER_CONNECTIONS` worth of ordinary peers) is unchanged.

Pending-connection headroom: reuse the existing `POSSIBLY_PREFERRED_EXTRA`
mechanism (`haveSpaceForConnection`, `OverlayManagerImpl.cpp:917`) by also
counting IPs that previously completed a *trusted* handshake.

### 3.5 Reconnection policy ("how tier 1 stays strongly connected")

Almost entirely existing machinery, re-pointed:

1. After a mutually-trusted handshake, both sides persist the peer's address
   as `PREFERRED`-typed in the peers DB (today's
   `updatePeerRecordAfterEcho` flow, with the type decision moved to
   post-AUTH, since mutual trust is only known then).
2. From then on, each side's `tick()` (every 3 s) re-dials it whenever
   disconnected, first in line, subject to jittered backoff.
3. If tier 1 node B goes down, the other 20 tier 1 nodes each run an
   independent jittered-exponential retry loop against B's last known address;
   the first side to succeed re-establishes the edge for both (an edge needs
   only one side to dial). 20 dialers × backoff capped as below is negligible
   load on a recovering node.
4. Optional tuning: cap the backoff exponent for trusted addresses (e.g., max
   ~80 s window instead of ~2.8 h). The trusted set is ≤ 20 addresses, so even
   the tight cap is trivial network load, and it bounds mesh-healing time
   after long outages.
5. Restart-safe: the `PREFERRED` DB records survive restarts, so a rebooted
   tier 1 node immediately re-dials the whole mesh.
6. The out-of-sync random-drop logic already spares preferred/trusted peers.

Simultaneous crossed dials (A→B and B→A racing) are handled by the existing
duplicate-peer checks in `recvHello`/`moveToAuthenticated`
(`Peer.cpp:1883-1911`); in the rare case both connections die, jittered
backoff desynchronizes the retry. A deterministic tiebreak (e.g., keep the
connection initiated by the lower NodeID) is a cheap optional hardening.

### 3.6 Peer discovery: keep today's organic discovery (no new wire messages)

Decision: v1 ships with **no discovery protocol changes at all**. Today's
machinery — `KNOWN_PEERS` seeding, the one-shot `PEERS` push per connection,
the peers DB, random dialing — stays as-is, and the mesh forms from the fact
that any mutually-trusted handshake permanently pins the key→IP binding as a
`PREFERRED` record (§3.5). The only addition is a small, rate-limited
**hunting pass**, because without it exploration stalls: once a node's
`TARGET_PEER_CONNECTIONS` outbound slots are full and stable, today's `tick()`
stops dialing new candidates entirely, so a tier 1 node with an unfilled
trusted budget would discover new tier 1 addresses only through churn.

Why organic convergence is sufficient:

1. **Each pair needs one lucky direction, once, ever.** An edge forms when
   either side dials the other; the handshake then pins the binding on *both*
   sides (the receiver learns the dialer's address from observed IP +
   `listeningPort`). Pinned records persist across restarts, so the mesh only
   ever densifies.
2. **The seed graph is already substantial.** Tier 1 operators' `KNOWN_PEERS`
   today already point at other well-known validators (stable DNS names,
   re-resolved every 10 min). Those edges pin within seconds of enabling the
   feature.
3. **IP changes heal from the mover's side — no lookup protocol needed.** A
   tier 1 node that changes address keeps its own DB of the other 20 pinned
   addresses (they didn't move) and immediately redials them; each remote
   re-learns the mover's *new* address from the inbound handshake and re-pins
   it. Healing time is the mover's restart time plus seconds, and the stale
   records on the remotes purge after 120 failures. This removes the main
   selling point of an advertisement protocol.
4. **Trusted edges enrich the gossip.** Every connection's `PEERS` push draws
   from the sender's DB; tier 1 DBs are tier-1-enriched, so candidate
   addresses circulate to exactly the nodes hunting for them (unlabeled, but
   the hunting pass authenticates them).

**The hunting pass, driven by per-key dispositions.** A node cannot know from
local config whether its quorum reciprocates: a non-tier-1 validator's config
looks exactly like a tier 1 member's, so locally it must presume it *is*
tier 1 until proven otherwise. The hunt is therefore gated not on what kind
of node you are but on what you have not yet learned. Each node persists a
small **disposition table**, one entry per key in its quorum set (bounded at
|trustedKeys|, ~21 rows):

- `UNKNOWN` — never completed a handshake with this key: **hunt for it.**
- `MUTUAL` — the last handshake's AUTH flag said "you are in my quorum too":
  pinned `PREFERRED`, aggressive reconnect (§3.5). Not hunted — the address
  is known and the redial loop owns it.
- `NON_MUTUAL` — the last handshake said "you are not in my quorum," whether
  it ended in *polite rejection* or *polite acceptance* into an unprivileged
  slot: **never hunt this key again**; polite cadence only (§3.3). The
  verdict is key-scoped, so it survives the remote changing address, and it
  carries no address tracking — there is no reason to follow a
  non-reciprocating member around.

While any quorum key is `UNKNOWN`, `tick()` makes up to K (e.g., 2) extra
probe dials per tick beyond `TARGET_PEER_CONNECTIONS`, drawn from
least-recently-tried DB candidates and respecting per-address backoff. Every
completed handshake resolves the disposition of whatever key it reveals, and
every probe harvests the responder's free `PEERS` push. Hunting ends when no
key is `UNKNOWN`: for a tier 1 member that is mesh completion (all
`MUTUAL`); for a non-tier-1 validator it is the one-time discovery that
nobody reciprocates (all `NON_MUTUAL`), after which it settles permanently
into watcher behavior — including across restarts, since the table persists.
Probe intensity decays for keys that remain `UNKNOWN` after full sweeps of
the candidate pool (an offline or misconfigured quorum member), falling to a
slow background cadence rather than hunting forever.

Dispositions are re-evaluated on every handshake, so qset changes self-heal:
if tier 1 promotes a new member, existing members' tables gain an `UNKNOWN`
entry and they hunt for it — and the *promoted* node learns of its promotion
from the inbound flags, flipping entries to `MUTUAL` without ever probing.
`NODE_IS_VALIDATOR` is deliberately **not** a correctness gate anywhere here:
a watcher misconfigured with `validator = true` buys exactly one bounded hunt
wave on a fresh DB, after which its persisted dispositions hold it to polite
behavior. (Nodes with `validator = false` may skip hunting entirely as a load
optimization — they can never hold privileged links, and if some qset
unexpectedly lists their key, the other side's hunt finds *them*.)

Cost bounds: a few thousand candidate addresses on mainnet are swept in hours
at K=2 per 3 s tick; steady-state hunters are the ~21 tier 1 nodes during
mesh formation plus a one-time, decaying wave per fresh-DB validator.

**Worked example: fresh tier 1 node, clean DB, 10/20 edges formed — how the
rest arrive.** Two searches run simultaneously. (1) The fresh node's own hunt:
each of its 10 tier-1 connections delivered a one-shot `PEERS` push of 50
records sampled from the sender's non-inbound records — a pool that *includes
the sender's 20 pinned tier-1 addresses*, since the gossip filter
`ANY_OUTBOUND` matches `PREFERRED`-typed records (`PeerManager.cpp:111`). The
union of 10 such pushes almost certainly already contains the missing
addresses, unlabeled in a pool of a few hundred; at K=2 probes per tick the
hunt sweeps that pool in tens of minutes worst case, and every probe (even of
a watcher) harvests another 50-address push. (2) The missing 10 hunt back:
each unformed pair leaves the *other* node with an unfilled trusted slot too,
so its hunting pass is also active, and the fresh node's address circulates
quickly (every node it dials records its address at handshake, dials back via
the promotion pass, then gossips it outbound-typed). Each pair needs one
direction to succeed, once. If tens of minutes is deemed too slow, the free
accelerator — before reaching for the deferred ads — is **provenance-biased
probing**: tag in memory which candidates arrived via a trusted peer's push
and probe those first; tier-1 pushes have roughly an order of magnitude
better hit rate, cutting completion to minutes. (A restarted member that
*kept its address* doesn't need any of this: the other 20 still have it
pinned and redial it from their side. A genuinely *new* member implies a
network-wide qset config edit anyway — which both reactivates everyone's
hunting pass via the grown `|trustedKeys|` and gives operators a natural
moment to add one optional `KNOWN_PEERS` line.)

Residual gaps, and why they are acceptable:

- **Cold start with an empty DB** falls back to `KNOWN_PEERS`, exactly like
  today's first boot.
- **A node that simultaneously loses its DB and changes IP** re-seeds from its
  own `KNOWN_PEERS`, dials out, and heals all 20 of its edges from its side.
- **Whole-network cold boot** is unchanged from today: config seeds.
- **First-activation convergence is hours, not seconds.** The
  mesh-completeness metric (§6 phase 2) tells us whether that is ever a
  real problem.

**Deferred option: signed self-advertisements.** If live metrics show
convergence is too slow, a flooded
`ValidatorAddressAd{nodeID, address, timestamp, sig}` — relayed only for keys
in the receiver's own trusted set, newest-per-key, per-key rate-limited,
verified by signature, consumed by upserting a `PREFERRED` DB record — can be
added later as a pure overlay extension; it composes cleanly with everything
above (the Bitcoin-`addr`/Lightning-`node_announcement` shape, scoped to
quorum members). Note it also requires solving "how does a node know its own
public address" (likely a `PUBLIC_ADDRESS` config), which organic discovery
sidesteps entirely because addresses are always learned from the remote's
observation, never self-reported. Keep it in the back pocket; do not build it
in v1.

**The disposition table is the design's one piece of key-indexed state.** An
earlier draft avoided any key→IP memory on non-tier-1 nodes, fearing it
enables tier-1 seeking; the disposition model instead *embraces bounded
seeking* and gets safety from memory. Every node may hunt its quorum until
each key has answered once — and the answer, including a polite acceptance,
is persisted key-scoped, so no node ever re-enters the aggressive stage on
restart. The anti-stampede property no longer rests on nodes being unable to
seek (or on them knowing their own place from config); it rests on them
remembering the protocol's verdict. Two deliberate limits remain: the table
only ever contains the node's own quorum keys — it is not a general key→IP
gossip database — and `NON_MUTUAL` entries track no addresses. Reserved-slot
redistribution is preserved because `NON_MUTUAL` keys still get rare polite
re-knocks via address-level backoff expiry (§3.3), deprioritize-with-decay
rather than blacklist.

The resulting **non-tier-1 lifecycle** (validator-configured or not), end to
end:

1. **Fresh DB:** all quorum keys `UNKNOWN` → hunt mode, exactly like a tier 1
   bootstrap, because the node cannot yet know it isn't tier 1. (A
   `validator = false` watcher may skip this; it observes consensus via
   transitive flooding either way.) Each quorum member found resolves to
   `NON_MUTUAL` — by polite rejection or polite acceptance — and is
   remembered.
2. **Steady state / restart:** dispositions persisted → hunting never
   recurs. Outbound slots fill from DB candidates exactly as today.
3. **Polite acceptance:** if tier 1 had a spare unprivileged slot, the node
   holds a normal connection (the reserved slots exist exactly for this,
   first-come-first-served) — while *knowing*, from the AUTH flag, that the
   link is unprivileged: no `PREFERRED` pinning, no aggressive redial when it
   drops.
4. **Polite rejection** (`ERR_PEER_UNPRIVILEGED`): demote, day-scale-capped
   DB-persisted backoff (§3.3). Done with it.
5. **Backoff expiry:** a single polite re-knock — rare enough to be
   negligible load, frequent enough that reserved slots redistribute over
   time rather than being squatted by the first claimants.

## 4. Reuse map: preferred-peer infrastructure → quorum peering

| Existing mechanism | Role in this design | Change needed |
|---|---|---|
| `PREFERRED_PEER_KEYS` key check in `isPreferred()` | template for trusted-key check | generalize: union config keys with auto-derived `trustedKeys`; add mutuality + validator gates for the auto tier |
| Eviction in `acceptAuthenticatedPeer()` | trusted admission under load | add trusted-occupancy cap / reserved floor |
| `PREFERRED` DB type + `RandomPeerSource(PREFERRED)` + `tick()` priority pass | persistent mesh memory + aggressive redial | type decision moves post-AUTH (mutual trust); add trusted dial budget |
| Jittered exponential backoff (`computeBackoff`) | polite retry everywhere | optional lower cap for trusted addresses |
| `updatePeerRecordAfterEcho/Authentication` | records key→IP binding | gate `SET_PREFERRED` on mutual trust |
| Out-of-sync random drop sparing preferred | mesh stability | include trusted |
| `POSSIBLY_PREFERRED_EXTRA` pending headroom | handshake headroom for trusted IPs | include trusted IPs |
| `ERR_LOAD` rejection + `recvError` | rejection path | add `ERR_PEER_UNPRIVILEGED` + demote-on-receipt |
| `PEERS` gossip / `KNOWN_PEERS` | the entire discovery mechanism (§3.6) | none on the wire; add the hunting pass in `tick()` |

What is genuinely new: the mutual-trust AUTH flag, the two-pool slot
accounting with a reserved unprivileged floor, the rejection code, and the
hunting pass. The signed address ad is explicitly deferred (§3.6). Everything
else is plumbing through existing code paths.

## 5. Implementation inventory

XDR (`Stellar-overlay.x`, lives in the `protocol-curr/xdr` submodule):
- `ERR_PEER_UNPRIVILEGED` and `AUTH_MSG_FLAG_PEER_IN_QUORUM` only — no new
  message types. `OVERLAY_PROTOCOL_VERSION` → 42.

`Config` (`src/main/Config.{h,cpp}`):
- `AUTOMATIC_QUORUM_PEERING` (bool, default true), 
  `RESERVED_UNPRIVILEGED_INBOUND_SLOTS` (default 20).
- Compute `trustedKeys` from `QUORUM_SET` via `LocalNode::forAllNodes` when
  `NODE_IS_VALIDATOR`; capacity validation in `adjust()`.

`src/overlay/`:
- `Peer`: track `mWeTrustRemote` (set in `recvHello` once `mPeerID` is known)
  and `mRemoteTrustsUs` (from AUTH flags); `isMutuallyTrusted()`; set the flag
  in `sendAuth()` for v42+ peers; send `ERR_PEER_UNPRIVILEGED` on capacity
  rejection of unprivileged peers; demote + back off on receiving it; move the
  `SET_PREFERRED` persistence decision from `updatePeerRecordAfterEcho` to the
  post-AUTH path.
- `OverlayManagerImpl`: `isTrusted(peer)` alongside `isPreferred(peer)`;
  trusted occupancy counters per `PeersList`; eviction floor; trusted outbound
  budget + trusted dial pass in `tick()`; include trusted in out-of-sync
  spare-list and pending headroom.
- Hunting pass in `tick()`: up to K probe dials beyond
  `TARGET_PEER_CONNECTIONS` while any quorum key's disposition is `UNKNOWN`
  (§3.6), with per-key decay.
- `PeerManager` / DB: the peer-address table is unchanged; add the small
  persisted **disposition table** (quorum key → {UNKNOWN | MUTUAL |
  NON_MUTUAL} + last-resolved timestamp, ≤ |trustedKeys| rows) that gates
  hunting and aggressive-redial classification. Trust itself is still
  re-verified cryptographically at every handshake.

Rough size: ≈ 450–700 lines plus tests, hunting pass included; the deferred
ad option would add ≈ 300–400 more if ever needed. Test surface:
`OverlayTests`-style simulations asserting (a) mesh formation among N
mutually-trusting validators with no preferred config, (b) watcher admission
with full trusted pool (floor honored), (c) watcher retry cadence unchanged
vs. baseline, (d) mesh healing after node restart and after an IP change
(mover-initiated, §3.6), (e) hunting terminates for tier 1 (all `MUTUAL`)
and for a non-tier-1 validator (all `NON_MUTUAL`) and does not recur after
restart in either case, (f) a fresh-DB non-tier-1 validator's hunt resolves
via both polite rejection *and* polite acceptance, (g) mixed v41/v42
networks.

## 6. Phased rollout

1. **Phase 1 — trusted peering core.** Auto-derived trusted keys, AUTH
   mutual-trust flag, slot pools + reserved floor, `ERR_PEER_UNPRIVILEGED`,
   trusted reconnect budget, hunting pass. No discovery protocol changes: the
   mesh forms organically and persists (§3.6). Mixed-version safe: v41 peers
   see today's exact behavior (flags == 200, `ERR_LOAD`).
2. **Phase 2 — observe and tune.** Mesh-completeness gauge
   (`overlay.trusted.connected / |trustedKeys|`) so operators can see mesh
   health at a glance; trusted-backoff cap; crossed-dial tiebreak if the
   jitter-only approach proves noisy. Decide from live data whether discovery
   needs anything beyond organic.
3. **Phase 3 (only if metrics demand it) —** signed address ads per the
   deferred sketch in §3.6.

## 7. Safety analysis

### 7.1 Why this cannot partition or weaken watcher connectivity

- **Strictly additive edges.** The feature adds tier1↔tier1 edges and removes
  none, except via eviction — which is now *floored* at
  `RESERVED_UNPRIVILEGED_INBOUND_SLOTS`. Note today's preferred eviction has
  **no floor at all**: a fully-configured preferred set may evict every
  unprivileged inbound peer. The proposal is therefore a strict improvement in
  worst-case watcher guarantees, not a regression.
- **Capacity arithmetic.** Per tier 1 node: ≤ 20 inbound slots consumed by the
  mesh in the worst case (typically ~10, since edge direction splits), ≥ 20
  reserved for watchers, 44 available under today's *default* config — and
  tier 1 operators run far larger inbound caps. Network-wide that is ≥ 420
  guaranteed watcher-facing tier 1 slots, and watchers also relay SCP traffic
  to each other transitively, exactly as today.
- **Non-tier-1 retry behavior is unchanged or gentler — validator-configured
  or not.** Privileged classification requires the remote's confirmation, so
  no non-tier-1 node ever pins a tier 1 address as `PREFERRED` or redials it
  aggressively, regardless of what its own config claims about itself. The
  only new traffic from non-tier-1 nodes is one bounded, decaying hunt wave
  per fresh DB (§3.6), after which persisted `NON_MUTUAL` dispositions hold
  them to polite, day-scale cadence permanently — including across restarts.
  The rejection code additionally demotes stale preferred typing.
- **No fork risk from topology.** SCP safety is a property of quorum-set
  configuration, not of the overlay graph; topology affects liveness and
  latency only. This change touches neither qsets nor SCP. Watchers keep
  observing consensus through reserved slots and watcher↔watcher flooding; a
  watcher that loses one tier 1 connection rotates to another exactly as
  today (`updateTimerAndMaybeDropRandomPeer` unchanged for them).

### 7.2 Why tier 1 stays strongly connected

- 21 nodes, each pair redialed independently from both ends every 3 s tick
  (jitter-backed), addresses persisted across restarts, links immune to
  out-of-sync random drops and to eviction by unprivileged peers, admission
  guaranteed by eviction rights up to the trusted cap. A full partition of the
  mesh requires simultaneously severing 210 independently-healing edges.
- Even with the mesh fully healed, tier 1 nodes retain their normal
  `TARGET_PEER_CONNECTIONS` of unprivileged outbound peers, so tier 1 is never
  *only* connected to itself — SCP traffic continues to flow outward.

### 7.3 Adversarial considerations

- **Trust spoofing:** impossible below key compromise — `NodeID` is proven by
  the signed auth cert and session HMAC binding before any privileged decision.
- **Slot exhaustion by fake "validators":** claiming `PEER_IN_QUORUM` in AUTH
  grants nothing; privilege requires *my* config to contain *your* key.
- **Hunting probes are polite:** rate-limited (K per tick, only while the
  mesh is incomplete), respect per-address backoff, and occupy a remote's
  inbound pending slot for only one handshake round-trip.
- **Ad-specific attacks (flood DoS, stale/replayed ads)** are out of scope
  unless the deferred advertisement option is ever adopted; its sketch in
  §3.6 contains them via the qset-scoped relay rule, per-key rate limits, and
  timestamp freshness windows.
- **Eclipse:** direct, mutually-authenticated tier 1 links *reduce* eclipse
  exposure relative to today's watcher-mediated paths.

## 8. Open questions

1. **Direct qset vs. transitive quorum.** v1 uses the configured `QUORUM_SET`
   only (covers tier 1 fully, zero herder coupling). Extending to the
   herder-tracked transitive quorum (`QuorumTracker`) would auto-mesh deeper
   topologies but adds runtime trust-set churn — defer.
2. **Org-internal meshes.** An org's own validators typically include each
   other → they mesh too. Likely desirable (intra-org resilience); worth
   confirming slot math for large orgs.
3. **Should `RESERVED_UNPRIVILEGED_INBOUND_SLOTS` scale** with inbound
   capacity (e.g., max(20, 30%)) instead of a flat 20?
4. **Backoff cap value for trusted addresses** — pick after simulating a
   tier 1 node rejoining after a multi-hour outage.
5. **Interaction with `PREFERRED_PEERS_ONLY`** — proposal: trusted peers
   satisfy the predicate (they are "preferred" in spirit); needs a decision.
6. **Tiebreak for crossed simultaneous dials** — ship phase 1 with jitter only,
   or include the lower-NodeID rule from the start?
7. **Hunting probe rate K** (and whether probes should linger one round-trip
   to harvest the responder's `PEERS` push before dropping) — pick after
   simulating first-activation convergence time.
8. **Disposition table details.** Where it persists (a small new DB table vs.
   a flat file), the decay schedule for keys stuck `UNKNOWN`, and whether
   `NON_MUTUAL` should ever expire on its own. The design says it need not —
   a promotion into tier 1's qsets is discovered via the *promoted* side's
   inbound handshakes — but a months-scale re-verify is cheap insurance.
   Relatedly: with dispositions carrying the "alive but full" memory, the
   address-level `numFailures` conflation (rejections slowly walking an
   address toward the 120-failure purge) becomes mostly cosmetic; decide
   whether it still needs cleaning up after observing real rejection rates.
