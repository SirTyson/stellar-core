# Reading the TX-set dissemination metrics

These metrics exist to answer one question: **of the wall-clock time between a
nominator building a TX set and every validator holding it, where does the time
go?** Until that is broken down, further dissemination work is guesswork.

All are exported on `/metrics` under `overlay.txset-shard.*`. The Rust overlay
keeps `(sum_us, count)` pairs and Core replays them into medida timers, so the
**mean is meaningful but the percentiles are not** — the sync feeds `count`
copies of the mean, so p50/p75/p99 all equal the mean. Read `sum/count`, not
percentiles.

## Reference numbers for 90 validators, 5 MB sets, 1 Gbit/s

At 89 peers a 5 MB set plans to **118 original + 59 recovery = 177 shreds of
42,374 B**, so 7.50 MB of coded data. At 125 MB/s:

| quantity | expected |
|---|---:|
| nominator egress (branch factor 1) | 7.50 MB → **60 ms** |
| each relay's egress | 7.42 MB → **59 ms** |
| each receiver's ingress | 7.50 MB → **60 ms** |
| reconstruct threshold ingress | 5.00 MB → **40 ms** |
| RS decode, `num_clusters=1` | **~17 ms** |

If measurements land near these, the mesh is running at line rate and the only
remaining lever is sending fewer bytes. If they land well above, something other
than bandwidth is the constraint and that is worth finding before optimizing.

## The four timers, in critical-path order

**`overlay.txset-shard.broadcast-span`** — nominator only. Reed–Solomon coding
start until the last shred of that set has left the wire. Divide the coded size
by this to get the achieved uplink rate.

- ≈60 ms at 5 MB → the uplink is saturated; only compression or sending
  identifiers instead of bodies will help.
- ≫60 ms → the nominator is not bandwidth-bound. Suspect per-peer stream
  contention, blocking-pool starvation, or the swarm task being busy.
- ≪60 ms → shreds are being buffered rather than transmitted; trust
  `assembly` over this number.

**`overlay.txset-shard.assembly`** — receiver only, and **the headline number**.
First shred of a set seen locally until the threshold shred that makes it
decodable. This is dissemination latency exactly as consensus experiences it. It
excludes the nominator's coding time and any delay before the first shred
arrives, so compare it against `broadcast-span` rather than reading it alone.

**`overlay.txset-shard.forward-latency`** — relay only. Shred receipt until its
forwarded copy finished sending. Separates a slow relay uplink from slow
nominator upload when `assembly` is high. With branch factor 1 each relay pushes
~7.4 MB per set, so a mean far above ~59 ms points at that node's uplink.

**`overlay.txset-shard.reconstruct`** — decode plus content-hash plus strict XDR
validation, on the blocking pool. Now recorded only for reconstructions that
actually delivered, so its count equals
`reconstruct-original + reconstruct-recovery`. Watch this against
`num_clusters`: at 1 cluster a 5 MB set costs ~17 ms of decode on **every**
validator, every ledger.

## Topology and health meters

**`recv-direct` vs `recv-relayed`** — a shred still carrying TTL came straight
from the nominator; one at zero has taken its single hop. In a healthy 90-node
mesh at branch factor 1, expect roughly **1 direct per 89 relayed**. A much
higher direct share means relays are not forwarding and receivers are only
getting what the nominator sent them, which cannot reconstruct.

**`root-mismatch`** — the important new one. A shred was dropped because this
node did not compute itself as the designated branch root. Two causes are
indistinguishable from inside the node: it genuinely is not the root (normal, but
this path is only reached for shreds it received with TTL intact, so it should be
rare), or **its peer set differs from the nominator's and every offset it derived
is wrong**. Branch offsets are computed `mod peer_count`, so a single validator
joining or leaving shifts the mapping for everyone at once.

This is the deferred correctness gap made visible. Expect ~0 in steady state. A
rate that spikes around membership changes means shreds are silently losing
coverage, and the fix — carrying the nominator's peer count in the shred header
and relaying to all non-roots on mismatch — becomes necessary rather than
theoretical. Correlate spikes against restarts and against `overlay.fetch.txset`
activity, which is what rescues the affected slots.

**`bytes-in`** — total shred bytes accepted. Divide by the run duration for
per-node shred ingress rate, and compare against link capacity to see how much
headroom the tx flood and SCP traffic actually have.

**`reconstruct-original` vs `reconstruct-recovery`** — whether receivers took the
cheap concatenation path or paid the Reed–Solomon decode. With zero loss this
still splits roughly evenly, because recovery shreds race the originals and
reconstruction fires at the threshold regardless of composition. A large recovery
share is expected, not a fault, but it is what makes the ~17 ms decode a
per-ledger cost on every node rather than an exceptional one.

**`accumulator-evicted`** — incomplete accumulators dropped by the 16-slot cap or
the 60 s age sweep. Non-zero under normal load means concurrent sets are
competing for slots and some dissemination is being abandoned.

**`flood.txset-push-dropped`** — shreds never sent because a newer nomination or
a ledger close superseded them. Steady non-zero means coding is finishing after
its own slot is over, which points straight back at `broadcast-span`.

## What the numbers would imply

- `broadcast-span` ≈ 60 ms and `assembly` ≈ 60–120 ms: the design is at line
  rate. Total consensus time is then dominated by something outside
  dissemination, and the next measurement should be SCP-side, not overlay-side.
- `assembly` ≫ `broadcast-span` + 60 ms: relays are the problem. Check
  `forward-latency` and `root-mismatch`.
- `root-mismatch` non-trivial: coverage gaps; fix the header before tuning
  anything else, because every other number is being measured on a mesh that is
  quietly dropping shreds.
- Everything at line rate and still too slow: the remaining lever is not
  topology but payload — see the compact-TX-set direction in
  `docs/txset-shred-dissemination.md`.
