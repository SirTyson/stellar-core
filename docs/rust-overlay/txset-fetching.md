# TX set fetching

SCP envelopes reference transaction sets by hash. Rust prefetches their bodies
from peers and keeps them in the tx-set cache. Core receives a set only after
it establishes demand with `RequestTxSet`.

## Wire formats and routes

Requests use a four-byte big-endian frame length followed by a
`StellarMessage::GetTxSet` containing the 32-byte hash. Responses require
`/stellar/txset/zstd/2.0.0` and contain an outer four-byte big-endian frame
length, a four-byte big-endian original XDR length, and exactly one zstd frame.
There is no raw encoding or legacy protocol fallback on this experimental branch.

The decoder bounds both encoded and original sizes, requires one complete zstd
frame and an exact output length, and strict-parses `GeneralizedTransactionSet`.
The response hash is computed from the recovered canonical XDR without
re-encoding. The XDR limit remains 16 MiB minus four bytes; the encoded-frame
limit also permits zstd's worst-case expansion for incompressible input.

Requests share the highest-priority control route with SCP. Responses use the
next-priority tx-set route. All routes share QUIC connection limits.
See [transport](transport.md).

## Encoding ownership

Only the elected slot leader constructs a local proposal. Followers adopt the
leader-signed value from a ballot statement without pulling the mempool, building
a private set, or compressing it. The leader may prepare before the normal ledger
trigger. There is no nomination phase or timeout-based leader promotion.

Core sends `CacheTxSet` as soon as a locally constructed proposal's final XDR is
available, before the builder's roundtrip and final validation. Rust eagerly
compresses it at zstd level 1 on a blocking worker while Core continues those
checks. App awaits the prepared representation before processing another IPC
message or application event; the network dispatcher remains independent.
Repeated local publication of an already cached hash reuses its encoding.

A receiving overlay retains the original encoded allocation while decompressing
and strict-parsing on a blocking worker. The cache shares an immutable
`Arc<TxSetData>` containing both original XDR and encoded bytes. Peer responses
borrow those encoded bytes directly, so relays never recompress received sets.
Encoding is complete before cache insertion; sending has no lazy initialization
or compression decision. Core continues receiving uncompressed XDR over IPC.

## Core requests and network prefetches

`RequestTxSet` IPC carries `[hash:32][slot:u32 LE]`. App records the newest
requested slot for each pending hash. A cache hit immediately satisfies that
demand. A miss initiates a network fetch; the eventual matching arrival is
cached and satisfies the pending demand once. Duplicate arrivals remain cached.

A network prefetch arriving before the Core request stays in the cache. A later
explicit request still receives it, even if Core has requested the same hash
before. Locally built sets supplied with `CacheTxSet` can also satisfy pending
demand. There is no permanent delivered marker. Failed IPC enqueueing retains
the pending request.

## Leader push

For a set whose selection excluded valid candidates, Core sends `BroadcastTxSet`
with `[hash:32][slot:u32 LE]` immediately after `CacheTxSet`. The final XDR is
already fixed, so delivery can overlap the remaining local validation. Ballot
start still waits for successful validation. Reusing the set at the trigger does
not repeat the broadcast. Underfilled early snapshots are expected to be
replaced and are not broadcast; their final replacement is pushed at the trigger.

Rust looks up the prepared cache entry and starts an
independent response send for every connected peer. Each send uses the existing
bulk admission limits and shares the encoded representation. A cache miss logs
`TXSET_BROADCAST_MISS`; the normal pull path remains available. Receivers cache
unsolicited sets and satisfy a later Core request directly from that cache.

## Peer requests

The reader emits `TxSetRequested { hash, from }`. App looks up the cache and
starts a response send. Send admission and the stream write happen outside the
App and network dispatcher loops. Count and byte permits bound admitted bulk
sends; per-route stream locks preserve complete frame ordering.

A cache miss has no network reply. There is no `DontHave` message in this path; the fetch retry scheduler handles it.

## Fetch selection

Before spawning the request write, the dispatcher reserves the hash with its
peer, send time, slot and previously tried peers. A connected peer suppresses
another request for 5 seconds. Selection first prefers the recorded SCP source
if untried, then another connected peer. After all connected peers have been
tried, selection starts a new cycle. With no peer, no new reservation is made.

Core reissues unresolved requests every 2 seconds, preserving the original
fetch-start timestamp. This is the retry scheduler, including for a connected
peer that never responds or a lost IPC request. Rust has no second periodic
retry loop. A failed write removes only its own reservation; a stale failure
cannot erase a newer attempt. Disconnect cleanup removes reservations assigned
to that peer. Any matching received body, including an unsolicited push, clears
the reservation. Reservations beyond the retained slot window are pruned.

## Cache and externalization

The cache holds up to 100 sets in App. Each entry contains its content hash,
canonical XDR, encoded response, and ledger sequence. Capacity eviction uses insertion order;
updating an existing hash does not move it. `LedgerClosed` evicts entries older
than `sequence - 12`, using saturating subtraction. Pending Core demand expires
against the same retained-slot boundary.

`CacheTxSet` IPC carries `[hash:32][slot:u32 LE][txset_xdr]`. Core's bytes are
trusted for encoding, but their content hash is checked before insertion.
Network bytes are strict-decoded and content-hashed by the reader before App
caches them. Unrequested arrivals are not sent to Core.

`TxSetExternalized` supplies the set hash and included transaction hashes.
App awaits mempool removal before processing the next Core message. The cached
set remains available for peer requests until normal capacity or slot eviction.
See [mempool](mempool.md).

## Remaining limitations

- Cache misses have no explicit negative response; retries wait for expiry.
- An arbitrary connected peer may not have the body; retries cycle through peers.
- Push reaches connected peers only. Other validators depend on normal SCP
  propagation and pull. Eventual progress assumes a live source and delivery.
