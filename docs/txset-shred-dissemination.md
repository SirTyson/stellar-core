# Eager erasure-coded TX-set dissemination

This performance branch distributes nominated transaction sets as
Reed–Solomon-coded shreds instead of eagerly sending the complete set to every
validator.

## Topology and flow

The design intentionally targets the branch's fully-connected Tier-1 topology.
If the nominator has `N` connected validators:

1. It creates at most `2N` shreds (capped at 255), with 50% recovery data.
2. It assigns each shred to two branch roots, balancing root assignments
   round-robin.
3. The two roots deterministically partition the remaining validators. Each
   root immediately forwards the shred to its half of the partition. Forwarded
   shreds have TTL 0, so this is exactly one hop, and each validator receives
   each shred over exactly one edge.
4. A validator reconstructs after receiving any `original_shards` distinct
   shreds and immediately sends the canonical generalized TX set to Core.

For a large set, coding produces about 1.5 copies of the set. The branch factor
of two makes the nominator upload about 3 copies, independent of `N`, instead of
`N` full copies. Those extra source edges replace relay edges: each coded shred
still crosses exactly `N` edges in total (for `N` receiver validators), so
aggregate traffic remains roughly 1.5 times eager full broadcast rather than
doubling with the branch factor.

For the target case of a 5 MB TX set and a 1 Gbit/s link, one body takes about
40 ms to serialize. The coded body is 7.5 MB, and two roots therefore cost the
leader about 15 MB / 120 ms at line rate. A branch factor of three would raise
that floor to 22.5 MB / 180 ms. Two is the latency-oriented compromise: it
removes dependence on a single root for every shred while keeping leader
serialization comfortably below a consensus timeout.

The legacy `GetTxSet` request/response path remains as a safety net. Eager
reconstruction cancels an in-flight fetch for the same hash.

## Wire and safety properties

Shreds use a dedicated QUIC stream protocol,
`/stellar/txset-shard/2.0.0`, so they do not queue behind full-body fetch
responses or SCP traffic. The shred header is versioned and carries the TX-set
hash, coding parameters, index, original length, TTL, branch index/count, and
payload length.

Receivers enforce:

- a 16 MiB TX-set wire limit and at most 255 total shreds;
- bounded padded size, even Reed–Solomon shard dimensions, and strict lengths;
- at most 16 incomplete accumulators (under 400 MiB at the maximum set and
  recovery sizes), expired after 60 seconds;
- duplicate and conflicting-shred detection;
- content-hash verification and strict generalized-TX-set XDR decoding before
  delivering reconstructed bytes to Core.

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
- branch roots per shred: 2 (or the connected peer count when smaller);
- target total shreds: 2 per connected peer.

For large sets the peer-count limit produces shreds close to `1/N` of the
TX-set size, matching the reference experiment's best-performing larger-shred
variant. Tiny sets are not padded to 1024-byte payloads.

## Verification

`overlay/src/txset_shards.rs` covers wire validation, parameter planning,
balanced assignment, exact reconstruction, every supported recovery-loss count,
duplicates/conflicts, bounded parallel coding equivalence, two-root partition
coverage, bandwidth bounds, and a failed-root dense-mesh model. Its ignored
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
