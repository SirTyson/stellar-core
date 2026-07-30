# Plan: dictionary compression for TX-set dissemination

Status: phases 1–2 implemented. Protocol v3 carries a codec byte, nominators
use bounded zstd level 1 with raw fallback, receivers perform bounded
decompression before canonical hash/XDR validation, and the configuration and
metrics below are wired through Core. Dictionary training, dictionary
selection, and parallel chunk compression remain measurement-driven follow-up
work (phases 3–5); the repository does not contain representative captured
TX-set samples from which to train or evaluate a production dictionary.

## Objective

Not "maximise ratio". The thing to minimise is the dissemination critical path,
which for a set of size `S`, link rate `R`, coding overhead `(1 + r)`, and
compression ratio `c` is roughly

```
t ≈ t_compress + (1+r)·S/(c·R)        [nominator upload]
              + (1+r)·S/(c·R)        [relay hop]
              + t_decompress + t_rs_decode(S/c)
```

Compression is worth it only where `t_compress + t_decompress` is small against
the bytes it removes from three separate terms: nominator egress, relay egress,
and — because coding runs on the compressed bytes — Reed–Solomon decode as well.
That third term is easy to forget and is a meaningful part of the win.

At 89 peers, `S` = 5 MB, `R` = 125 MB/s, `r` = 0.5 the baseline is ~60 ms
nominator, ~59 ms relay, ~17 ms decode.

## What is actually compressible

A single-signed payment envelope is about 196 bytes, of which the
`DecoratedSignature` is 68 (4-byte hint plus a 64-byte Ed25519 signature).
Signatures are indistinguishable from random and will not compress at all, so
for a payment-heavy 5 MB set:

| portion | size | compressible |
|---|---:|---|
| signatures | ~1.7 MB | no |
| everything else | ~3.3 MB | yes, highly |

That sets a **hard ceiling of ~2.9×** and makes 1.8–2.2× the realistic target.
Measure the split on real traffic before trusting it: Soroban transactions carry
large footprints and arguments, so their signature share is much lower and the
achievable ratio correspondingly higher.

The compressible part is repetitive in a specific way that matters for the
dictionary decision: account IDs (32 B), asset codes, muxed prefixes, operation
discriminants, and XDR zero-padding. Many account IDs appear **once per set but
recur across consecutive sets**, because the active account population is stable.
A plain compressor cannot exploit that — its window is one set. A dictionary can,
and that is where most of the gain over plain zstd will come from.

## Placement in the pipeline

```
nominator:  Core builds set → IPC → verify hash (raw) → COMPRESS → plan → code → send
receiver:   collect shreds → RS decode → DECOMPRESS → verify hash → strict XDR → IPC to Core
```

Two properties fall out of hashing the *uncompressed* canonical bytes, and both
are load-bearing:

1. **Compression cannot corrupt consensus.** The tx-set hash is computed over
   the canonical XDR, so it validates the decompressed output. A bad decode is
   caught by the existing hash check and falls through to the existing fetch
   path. Compression is purely a transport encoding.
2. **Compressed output need not be deterministic.** Only the nominator
   compresses, and nothing consensus-visible depends on the compressed bytes.
   That frees us to use multi-threaded compression, change levels at runtime, and
   tolerate zstd version differences between nodes — none of which would be safe
   if the compressed form were hashed. Only the *decompressor* has a
   compatibility requirement, which the zstd format guarantees.

## Wire format

One byte in the shred header: `codec` (0 = raw, 1 = zstd). The zstd frame header
already carries the dictionary ID and the decompressed content size, so nothing
else is needed on the wire. `TXSET_SHARD_HEADER_LEN` goes 58 → 59; at 177 shreds
that is 177 extra bytes per set.

`original_len` then describes the compressed payload being sharded. The
decompressed size comes from the frame and **must be bounded** — see safety.

Bump `TXSET_SHARD_PROTOCOL_VERSION` to 3. Nominator and receivers ship together,
so no negotiation is required, but an unknown `codec` must be a clean drop rather
than a parse failure.

## Dictionary strategy — two candidates, measure both

**A. Static trained dictionary.** Train offline with `zstd --train` over captured
canonical tx sets, embed the result in the binary, and let the zstd dictionary ID
identify it on the wire. Predictable, no runtime dependency, works for a node
that just started. Goes stale as the active account set drifts, and updating it
is a binary rollout.

**B. Previous tx set as a prefix dictionary.** Compress set N with set N−1
referenced as raw content (`ZSTD_CCtx_refPrefix` / `ZSTD_DCtx_refPrefix`). Every
validator already holds the previously externalised set, so there is **nothing to
distribute, nothing to train, and no staleness** — it tracks the active account
population automatically. Setup cost is near zero because a prefix reference
skips dictionary preprocessing entirely.

The cost of B is a new dependency: a node that lacks set N−1 (just joined, or
catching up) cannot decompress and must fall back. That is exactly the path the
`codec` byte and the existing fetch fallback already handle, but it is a real
coupling between dissemination and ledger state, and it means compression
effectiveness degrades for precisely the nodes that are already behind.

Recommendation: implement A first because it has no state dependency and gives a
stable baseline, then measure B against it. B is plausibly better on ratio and
strictly better on operations, but it should not be the thing that also
introduces the encoding path.

## Finding the size/speed knee

The search is over (level, dictionary size), evaluated on held-out sets:

1. **Capture.** Dump 200–500 consecutive canonical tx sets from a representative
   loadgen run. Hold out the last 20% for evaluation — training and evaluating on
   the same sets will overstate the ratio badly, because account IDs repeat.
2. **Train.** `zstd --train` at dictionary sizes 16 KB, 64 KB, 256 KB, 1 MB. Small
   dictionaries mostly prime the entropy tables; large ones start holding actual
   account IDs, which is the effect we want here. Expect the curve to keep
   improving well past the 110 KB default because the useful content is the
   account population, not the grammar.
3. **Sweep levels** 1, 2, 3, 5 against each dictionary. Levels above ~5 are
   already disqualified: zstd-9 runs at tens of MB/s, so 5 MB would cost
   100 ms+ and lose more than it saves.
4. **Score by the objective at the top of this document**, not by ratio. A
   configuration that gains 5% ratio for 20 ms of compression is a regression.

Rough expectations to sanity-check measurements against, single core:

| codec | compress | decompress | ratio (structured part) |
|---|---:|---:|---|
| lz4 | ~8 ms | ~1.5 ms | modest |
| zstd-1 | ~12–16 ms | ~4 ms | good |
| zstd-3 | ~35–50 ms | ~4 ms | slightly better |

Decompression is nearly level-independent, which matters because it is paid on
**every** validator while compression is paid once. That asymmetry argues for
spending compression time fairly freely — but see parallelism.

## Parallelism, and why the dictionary enables it

Chunking the input for parallel compression normally costs ratio, because matches
spanning chunk boundaries are lost. With a content dictionary most matches are
against the dictionary rather than across the input, so chunking costs much less.
Dictionary and parallelism reinforce each other.

Use the existing `TxSetCodingExecutor` pool rather than adding another: split the
set into `num_clusters` chunks, compress each against the same `CDict`, and
concatenate the frames. This is safe precisely because the output need not be
deterministic. At 4 workers a 14 ms compression becomes ~4 ms, which changes the
level calculus — a slower, higher-ratio level may become affordable.

Note the pool is currently sized by `ledgerMaxDependentTxClusters`, an apply-side
budget being reused for an overlay concern. Compression makes that mismatch worse
and is a good moment to decouple them.

## Safety

- **Bound the decompressed size.** A malicious shred set can declare an enormous
  content size. Cap it at `TXSET_MAX_WIRE_SIZE` and use a bounded decompression
  call, so a compression bomb is a rejected shred rather than an allocation.
- **Unknown codec or dictionary ID** → drop and fall back to fetch, never a parse
  error and never an abort.
- **Hash mismatch after decompression** is already handled by the existing check;
  make sure the failure is attributed to decompression in logs, since it will
  otherwise look like shred corruption.
- **A config flag to disable compression** on the nominator, so the perf net can
  A/B on one image. Receivers must always accept both codecs regardless.

## Metrics

Same `(sum_us, count)` pattern as the existing dissemination timers:

- `overlay.txset-shard.compress` and `.decompress` — time per set.
- `overlay.txset-shard.compressed-bytes` and `.plain-bytes` — the ratio actually
  achieved, which is the number that decides whether to keep going.
- `overlay.txset-shard.raw-sent` and `.raw-received` — codec-0 decisions at the
  nominator and successful raw reconstructions at receivers.
- `overlay.txset-shard.dictionary-miss` — compressed sets that could not be
  decoded because their dictionary was unavailable. For strategy B this is the
  metric that says whether the previous-set dependency is costing anything in
  practice.

## Expected outcome

At ratio 1.8 with zstd-1 and 4-way parallel compression, the dissemination path
should go from roughly 136 ms (119 ms network plus 17 ms decode) to about 90 ms;
at 2.2 with the dictionary working well, closer to 70 ms. Call it **30–45% off
the dissemination critical path**, applied to nominator egress, relay egress and
Reed–Solomon decode simultaneously.

This composes with everything else under consideration. It is independent of
leader pre-shipping — if that lands, compression then applies to the much smaller
descriptor and the pre-shipped bundles alike — and it stacks with dropping
proactive recovery, which removes the `(1 + r)` factor from the same expression.

## Phasing

1. Codec byte, raw path only, plus the config flag and metrics. Proves the wire
   change and the fallback without touching compression at all.
2. zstd-1, no dictionary, single-threaded. Establishes the honest baseline ratio
   on real sets and validates the bomb cap and hash-after-decompress path.
3. Capture and train; sweep dictionary size and level; pick the knee.
4. Parallel chunked compression on the existing pool.
5. Measure strategy B against A, and keep whichever the objective function
   prefers.

Stop after step 2 if the measured ratio on real traffic is below ~1.5 — that
would mean the signature share is larger than assumed and the ceiling is too low
to justify the rest.
