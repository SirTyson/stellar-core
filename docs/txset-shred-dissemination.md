# Eager erasure-coded TX-set dissemination

This performance branch distributes nominated transaction sets as
Reed–Solomon-coded shreds instead of eagerly sending the complete set to every
validator.

## Topology and flow

The design intentionally targets the branch's fully-connected Tier-1 topology.
If the nominator has `N` connected validators:

1. It creates at most `2N` shreds (capped at 255), with 50% recovery data.
2. It assigns each shred to `b` branch roots, balancing root assignments
   round-robin. `b` is 1 (see below).
3. The roots deterministically partition the remaining validators. Each root
   immediately forwards the shred to its share of the partition. Forwarded
   shreds have TTL 0, so this is exactly one hop, and each validator receives
   each shred over exactly one edge.
4. A validator reconstructs after receiving any `original_shards` distinct
   shreds and immediately sends the canonical generalized TX set to Core.

With `N` receiving validators, a set of size `S`, branch factor `b` and recovery
fraction `r`, the traffic is:

- nominator egress `b * (1 + r) * S`, **independent of `N`** (versus `N * S` for
  eager full broadcast);
- aggregate mesh traffic `(1 + r) * N * S`, because each coded shred still
  crosses exactly `N` edges regardless of `b` — extra source edges replace relay
  edges rather than adding copies;
- per-receiver ingress `(1 + r) * S`.

Nominator egress is the binding constraint: it is the only term that grows with
validator count, so it is what puts a bandwidth-limited leader over a consensus
timeout. At `N = 22` and a 5 MB set, eager full broadcast asks the leader for
110 MB per ledger — about 880 ms of serialization on a 1 Gbit/s link — while
coding at `b = 1` asks for 7.5 MB, about 60 ms.

**Branch factor is 1.** The 15-validator baseline below measured one root at
224.6 ms / 7.87 MB of leader traffic against two roots at 218.8 ms / 15.73 MB:
double the leader bytes — the scarce resource — for a latency difference well
inside the noise of three samples. Two roots buy independence from any single
root, but 50% recovery already covers that far more cheaply: losing a root costs
only the shreds it is root for, roughly `total/N` of them, against a budget of
`total/3`. So a third of the roots can fail before reconstruction does.

The legacy `GetTxSet` request/response path remains as a safety net. Eager
reconstruction cancels an in-flight fetch for the same hash.

## Wire and safety properties

Shreds use a dedicated QUIC stream protocol,
`/stellar/txset-shard/3.0.0`, so they do not queue behind full-body fetch
responses or SCP traffic. The shred header is versioned and carries the TX-set
hash, coding parameters, index, encoded length, codec, TTL, branch index/count,
and payload length. Codec 0 is raw and codec 1 is zstd. Nominators hash the
canonical XDR first, then opportunistically compress it at zstd level 1 before
planning and coding shreds. Compression that expands the payload falls back to
raw bytes. `EXPERIMENTAL_TXSET_COMPRESSION=false` disables compression on the
nominator for A/B testing; receivers always accept both codecs.

The protocol bump is intentionally not negotiated with v2. During a rolling
upgrade, v2 and v3 peers still share the main overlay but cannot open a common
TX-set-shred stream, so mixed-version edges use `GetTxSet` instead. Expect eager
reconstruction metrics to dip and fetch traffic to rise mid-roll; that rollout
shape is not evidence that zstd made dissemination slower.

Receivers enforce:

- a 16 MiB TX-set wire limit and at most 255 total shreds;
- bounded padded size, even Reed–Solomon shard dimensions, and strict lengths;
- at most 16 incomplete accumulators (under 400 MiB at the maximum set and
  recovery sizes), expired after 60 seconds;
- duplicate and conflicting-shred detection;
- clean fetch fallback for unknown codecs and dictionary IDs;
- a declared and independently enforced 16 MiB decompressed-size cap;
- content-hash verification and strict generalized-TX-set XDR decoding before
  delivering reconstructed bytes to Core. The hash covers decompressed
  canonical XDR, never the transport encoding.

Encoding and recovery decoding are split into independent byte-column ranges
and executed on a private Rayon pool. Its size is capped by the current
`ledgerMaxDependentTxClusters` (`num_clusters`) value supplied by Core and is
updated on ledger close. Small sets use fewer workers when there is not enough
work to amortize another task. Coding and strict XDR validation remain on
Tokio's blocking pool, outside the libp2p swarm task, so a large set cannot
stall SCP polling. Broadcasts are latest-wins: a newer local nomination or a
ledger close cancels unsent shreds from older coding/sending tasks.

## Defaults

- target shred size: 1024 bytes (smaller for tiny sets, raised automatically
  for large sets or small peer counts);
- recovery data: 50%;
- initial TTL: 1;
- branch roots per shred: 1 (or the connected peer count when smaller);
- target total shreds: 2 per connected peer.

`TXSET_SHARD_BRANCHING_FACTOR` may be raised to
`TXSET_MAX_SHARD_BRANCHING_FACTOR`, which is the largest value peers accept on
the wire; a static assertion keeps the two in order, because a nominator that
exceeded the wire bound would have every shred rejected network-wide.

For large sets the peer-count limit produces shreds close to `1/N` of the
TX-set size, matching the reference experiment's best-performing larger-shred
variant. Tiny sets are not padded to 1024-byte payloads.

## Verification

`overlay/src/txset_shards.rs` covers codec wire validation, raw and zstd
round-trips, expansion fallback, concatenated frames, missing content sizes,
truncated/corrupt frames, decompression bombs, unknown dictionary IDs,
compressed recovery reconstruction, parameter planning, balanced assignment,
exact reconstruction, every supported recovery-loss count, duplicates/conflicts,
bounded parallel coding equivalence, two-root partition coverage, bandwidth
bounds, and a failed-root dense-mesh model. Its ignored
`benchmark_txset_coding_throughput` test reports 10 MiB encode and
recovery-decode latency/throughput.

`test_broadcast_txset_to_all_peers` in `overlay/src/libp2p_overlay.rs` runs a
three-validator full mesh and verifies eager reconstruction, one-hop
forwarding, recovery-shred creation, and absence of fetch requests.

The ignored `benchmark_txset_full_mesh_latency_and_bandwidth` test builds a
15-validator full mesh and compares eager-full and coded dissemination of the
same-size valid generalized TX set in one process. It measures both branch
factors on the same warm mesh before asserting the production factor. Run the
two release baselines with:

```sh
cargo test -p stellar-overlay --release --lib \
  benchmark_txset_full_mesh_latency_and_bandwidth -- --ignored --nocapture
cargo test -p stellar-overlay --release --lib \
  benchmark_txset_coding_throughput -- --ignored --nocapture
```

The latest local release baseline used a 5,243,028-byte canonical set and 15
validators. Eager-full completed in 171.0 ms with 73.4 MB from the leader.
Across three alternating samples, one root had 224.6 ms median latency and 7.87
MB of leader traffic; two roots had 218.8 ms median latency and 15.73 MB of
leader traffic. Both coded variants used exactly 110.13 MB aggregate, confirming
that the second source edge replaces a relay edge rather than adding mesh-wide
copies. This loopback test does not rate-limit links; the 1 Gbit/s serialization
figures above are the applicable bandwidth floor.

The 10 MiB coding baseline measured:

| `num_clusters` | Encode | Recovery decode |
|---:|---:|---:|
| 1 | 10.92 ms (915 MiB/s) | 33.49 ms (299 MiB/s) |
| 2 | 5.98 ms (1,671 MiB/s) | 15.55 ms (643 MiB/s) |
| 4 | 4.52 ms (2,214 MiB/s) | 9.87 ms (1,013 MiB/s) |
| 8 | 4.20 ms (2,381 MiB/s) | 8.48 ms (1,179 MiB/s) |
