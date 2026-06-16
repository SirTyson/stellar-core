# Pitch: A Self-Assembling, Fully Connected Tier 1

*(Companion to `TIER1_FULL_MESH_DESIGN.md`, which has the file-level details,
code references, and capacity math. This is the conversational version.)*

## The idea in one paragraph

Tier 1 validators should be directly connected to each other — a full mesh —
instead of hoping the overlay's random topology puts them within a few hops.
Everything we need to build that mesh automatically is already in the
configs: every tier 1 node lists every other tier 1 org in its `QUORUM_SET`.
The proposal is to let the overlay *act* on the quorum set: add one bit to
the existing handshake that says "you're in my quorum," remember the answer,
and aggressively maintain connections wherever the answer was "yes" in both
directions. No node ever lists another node's IP address. The whole thing
lives in the peer-management layer — no changes to herder, SCP, or consensus
semantics.

## What's wrong today

Two tier 1 validators talk to each other through whatever path the overlay
happened to build from `KNOWN_PEERS`, gossip, and random dialing — SCP
traffic between them may bounce through several watcher hops. We have a
mechanism that could pin them together (`PREFERRED_PEERS`), but it requires
operators to maintain lists of each other's IPs, and in practice nobody
does.

The underlying gap is that our configs and our discovery speak different
languages. Configs name *public keys*; gossip and dialing only know
*IP addresses*; and the only moment the two ever meet is a completed
handshake, which cryptographically proves who's at the address you just
dialed. There is no way to ask the network "where is key X right now?"

## The two questions a node can't answer from config

Everything in this design falls out of two observations.

**First: a node doesn't know whether its trust is reciprocated.** A non-tier-1
validator's config looks *exactly* like a tier 1 member's — quorum set full
of tier 1 orgs, `NODE_IS_VALIDATOR = true`. Locally, every validator has to
presume it might be tier 1. Only the other side knows the difference: tier 1
nodes have your key in their quorum set, or they don't. So reciprocity has
to be learned from the network, not assumed from config. That's the new
handshake bit.

**Second: a node doesn't know where its quorum members live.** It knows
their keys, gossip gives it anonymous addresses, and only dialing reveals
who's who. So finding your quorum is a search problem — but a search you
only ever need to win *once per key*, because the result can be remembered.
That's the hunting phase plus the new annotations.

## What changes on the wire (in general terms)

Surprisingly little, and no new message types:

- **One flag in the existing AUTH message.** During the handshake, after both
  sides have proven their identities, each side sets a bit meaning "your key
  is in my quorum set." Both sides therefore finish every handshake knowing
  whether the relationship is mutual, one-sided, or neither.
- **One new error code.** Today, a node that's out of capacity rejects you
  with a generic "I'm overloaded" error. We add a more honest one:
  *"I have no free slots for peers outside my quorum — you're welcome to
  exist, but don't hurry back."* The dialer remembers this and backs way off.
- **An overlay version bump** so old nodes keep seeing exactly the messages
  they expect. Mixed-version networks behave like today.

That's it. Gossip messages, transaction flooding, SCP — untouched.

## Remembering the answer: quorum annotations on the peer records

Today the peers database is a list of addresses with a type
(inbound/outbound/preferred) and some backoff bookkeeping. We extend this
world with a small annotation table — one row per key in *your own* quorum
set (~21 rows), recording what the network has told you about each one:

- **Unknown** — never completed a handshake with this key. This is what
  drives the hunt (below).
- **Mutual** — they confirmed we're in each other's quorums. Their address
  gets pinned as a preferred peer, and the *existing* preferred-peer
  machinery takes over: reconnect aggressively on every tick, survive
  restarts, never get evicted by ordinary peers. This is the mesh.
- **Not mutual** — they told us, via the flag, that we're not in their
  quorum. This is the "be polite" memory: never hunt for this key again,
  never pin it, knock again only on a slow, day-scale cadence. Crucially,
  this is recorded *whether they rejected us or accepted us* — a watcher
  sitting happily in one of tier 1's spare slots still learns, from the
  flag, that the link is a courtesy and not a privilege.

The annotations persist across restarts. That's the heart of the politeness
story: a node figures out its own place in the network **once**, by asking,
and never re-learns it the loud way. A freshly-wiped non-tier-1 validator
will do one bounded round of searching, collect "not mutual" verdicts from
the tier 1 nodes it finds, and then behave like a watcher forever — even
though its own config never said "you're a watcher."

## The hunting phase

While any quorum key is still *unknown*, the node hunts: each connection
tick, it dials a couple of extra candidates from its address book beyond its
normal outbound quota, just to see who they turn out to be. Every completed
handshake resolves somebody's annotation, and every dial also harvests the
standard peer-list exchange, which keeps feeding the candidate pool. The
hunt ends when no key is unknown — and what "done" looks like is the node's
self-classification:

- A **tier 1 member** ends with all keys mutual: the full mesh, formed and
  pinned. From then on the preferred-peer reconnect loop owns it; hunting
  never runs again.
- A **non-tier-1 validator** ends with all keys not-mutual: it now *knows*
  it isn't tier 1, remembers that, and settles down permanently.

Some guardrails: probes respect per-address backoff; the probe rate decays
for keys that stay unresolved after the candidate pool has been swept (an
offline quorum member shouldn't keep anyone hunting forever); and plain
non-validator watchers can skip hunting entirely — they can never hold
privileged links, so there's nothing for them to learn.

How fast does it converge? A fresh tier 1 node gets a partial mesh within
seconds just from `KNOWN_PEERS`, and the rest within tens of minutes of
hunting — helped by the fact that *both* sides of every missing edge are
hunting for each other, and only one needs to succeed. A node that merely
restarted (kept its database) doesn't hunt at all: its pins and annotations
are already there, and even if it comes back with a new IP, it re-dials the
other twenty from its side and they re-learn its address from the handshake.
Nobody has to *find* anybody after the first time.

## Watchers keep their seat at the table

Two hard guarantees protect non-tier-1 connectivity:

- **A reserved floor of inbound slots — at least 20 per node — that the
  tier 1 mesh can neither fill nor evict into.** Worth noting: today's
  preferred-peer eviction has *no* floor at all — a fully-configured
  preferred set may legally evict every ordinary peer. We'd be adding a
  guarantee that doesn't currently exist, so watchers come out strictly
  ahead.
- **The mesh gets its own outbound budget** instead of consuming the
  watcher-facing one. (It has to — a 21-node mesh needs more total outbound
  connections than today's default quota of 8 per node can mathematically
  supply — and as a side effect, every tier 1 node keeps its usual
  complement of ordinary outbound peers, so tier 1 never talks only to
  itself.)

And the retry story actively improves. While designing this we found that a
capacity rejection today *resets* the dialer's backoff counter (the
handshake "succeeded" before the rejection arrived), so a rejected peer
re-knocks every 15 seconds or so for as long as the other side stays full.
We'd fix that — rejections accumulate real, persistent backoff — and the new
error code plus the not-mutual annotation push rejected peers out to roughly
daily check-ins. Rare enough to be negligible load; frequent enough that the
reserved slots redistribute over time instead of being squatted by whoever
got there first.

## Why this can't partition the network

- **Edges are strictly additive.** The feature creates tier1↔tier1
  connections; the only thing it takes away from anyone is bounded by the
  reserved floor, which doesn't exist today at all.
- **Consensus safety doesn't depend on topology.** SCP safety is a property
  of quorum set configuration; topology affects latency and liveness only.
  We're not touching quorum sets — just making the physical graph match the
  trust graph that already exists.
- **Watchers still see everything.** With 21 nodes × ≥20 reserved slots,
  there are hundreds of guaranteed watcher-facing tier 1 slots, plus all the
  watcher↔watcher flooding that exists today.
- **Identity can't be spoofed.** The handshake proves keys before any
  privileged decision; claiming "you're in my quorum" gets you nothing — the
  privilege requires *my* config to name *your* key. A watcher misconfigured
  as a validator buys itself one bounded hunt, after which its own
  annotations pin it to polite behavior.
- **Tier 1 becomes much harder to isolate.** 210 independent edges, each
  re-dialed from both ends, each pinned in persistent storage, immune to the
  out-of-sync peer-shuffling logic and to eviction by ordinary peers.

## What we reuse vs. what we build

Most of the heavy machinery already exists and is just being re-aimed: the
key-based preferred-peer check, preferred eviction rights, the
preferred-typed peer records with their aggressive reconnect pass, the
jittered exponential backoff, peer-list gossip, and the persistent peers
database. What's genuinely new: the handshake flag, the error code, the
quorum annotations, the hunting pass, the slot floors/budgets, and the
backoff-reset fix. No new discovery protocol, no signed address
advertisements (we sketched one; it's parked unless real-world convergence
metrics demand it), no herder coupling, no changes outside peer management.

## Rollout

1. **Phase 1 — the core.** Flag, error code, annotations, hunting, slot
   policy. Mesh forms organically and persists. Old-version peers see
   today's behavior exactly.
2. **Phase 2 — observe.** A mesh-completeness gauge (how many of my quorum
   are mutual-and-connected), tune backoff caps and probe rates from live
   data.
3. **Phase 3 — only if the data says so.** Signed address advertisements for
   instant cold-start convergence. We suspect we'll never need them.

## Open questions for the team

- Direct `QUORUM_SET` only, or follow the transitive quorum? (v1 says
  direct: covers tier 1 fully, zero herder coupling.)
- Should the reserved watcher floor scale with inbound capacity instead of
  being a flat 20?
- Backoff caps: how aggressive should mesh-edge redial be, and how lazy
  should rejected-peer re-knocks be?
- Where do the annotations live — a small new DB table, or a flat file — and
  should "not mutual" ever expire on its own? (Design says it doesn't need
  to: if tier 1 ever promotes you, *their* hunt finds *you*.)
- Tie-break for simultaneous crossed dials between two tier 1 nodes, or is
  jittered retry enough?
