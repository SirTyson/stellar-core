# SCP direct flooding

SCP envelopes are pushed on a dedicated QUIC stream
(`/stellar/scp/1.0.0`). They are small and latency-sensitive, so there is no
batching, backpressure, or INV/GETDATA round trip.

This experimental branch assumes a dense validator mesh. Each node broadcasts
its **own** SCP envelopes directly to every connected peer. An envelope received
from a peer is validated and consumed locally but is not re-broadcast. This
avoids an all-to-all relay amplification in which every first-hop recipient
sends the originator's already-direct-flooded envelope to the rest of the mesh.

## Outbound: `broadcast_scp(envelope)`

Core calls `BroadcastScp` only for a locally-created SCP statement. The overlay:

1. Hashes the envelope with Blake2b.
2. Marks it in the `scp_seen` LRU so a copy received back from a peer is
   discarded.
3. Looks up the per-envelope `scp_sent_to` set and selects every connected peer
   not already recorded there.
4. Records the intended recipients before sending, preventing concurrent
   duplicate broadcasts of the same local statement.
5. Spawns independent sends on each peer's SCP stream.

Therefore a local statement from a node with `N-1` connected peers produces at
most `N-1` network sends.

## Inbound: SCP stream handler

Each peer has a dedicated inbound SCP stream task. For every frame it:

1. Decodes the SCP message or state request.
2. Hashes and deduplicates the envelope through `scp_seen`.
3. Records the sender in `scp_sent_to`.
4. Emits `ScpReceived { envelope, from }` to Core.

Core verifies and processes the envelope. `PendingEnvelopes::envelopeReady`
does not send it back to the overlay, so receipt does not start another flood.

## Why received envelopes are not relayed

In a complete `N`-node mesh, the origin already sends a local envelope to all
`N-1` peers. Relaying at every receiver would add up to
`(N-1) * (N-2)` redundant sends. At `N=90`, that is 7,832 relay sends in
addition to the 89 useful direct sends for a single unique envelope.

Receiver-side deduplication prevents duplicate SCP processing but cannot avoid
the network packets, QUIC work, task scheduling, framing, and parsing needed to
deliver those copies. Direct-only flooding removes that amplification.

The tradeoff is topology dependence: a peer not directly connected to the
origin will not learn the statement through opportunistic relay. This is
intentional for the branch's authenticated dense-quorum experiment. A
production sparse topology would need a bounded relay tree or another explicit
repair mechanism rather than restoring all-to-all relay.

## Deduplication state

| Field | Type | Capacity | Purpose |
|---|---|---:|---|
| `scp_seen` | `RwLock<LruCache<[u8; 32], ()>>` | 10,000 | Prevent processing the same envelope twice |
| `scp_sent_to` | `RwLock<LruCache<[u8; 32], HashSet<PeerId>>>` | 10,000 | Prevent sending a local envelope to the same peer twice |

The inbound handler still records the sender in `scp_sent_to`. This makes an
explicit repeat of `broadcast_scp` safe and supports low-level overlay tests,
but the normal Core receive path does not request such a repeat.

## Channel and send mechanics

The event channel from the overlay to Core for SCP and TX sets is unbounded, so
SCP messages are not dropped at the overlay/Core boundary.

Each peer has its own SCP stream and mutex. Sends are fire-and-forget per peer;
a slow peer does not block sends to other peers. A failed send is retried up to
three times, reopening the stream when necessary.

SCP shares a QUIC connection with TX and TX-set traffic but uses an independent
stream. This avoids stream-level head-of-line blocking, though connection-level
congestion control remains shared.

## Properties

- Every locally-created SCP envelope is pushed directly to every connected
  peer.
- Received SCP envelopes are never re-flooded by Core.
- There is no autonomous overlay relay.
- There is no fan-out limit for local envelopes.
- There is no batching or pull phase.
- Wire traffic for one local envelope is `O(N)`, not `O(N^2)`.

The overlay still has explicit rebroadcast tests for the low-level
`broadcast_scp` primitive and its no-echo deduplication. Those tests do not
represent the normal Core receive path.
