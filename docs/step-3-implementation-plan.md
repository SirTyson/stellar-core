# Step 3 Implementation Plan — Push the Leader Schedule to the Overlay

> **Numbering.** This is the "push top-K leaders to the overlay" phase. The
> 0-indexed roadmap in [`direct-leader-flooding.md`](direct-leader-flooding.md)
> lists it as **Step 2**; the 1-indexed count used here calls it **Step 3**. Same
> content.
>
> **Status.** **Implemented** — see the "Step 2" section of
> [`direct-leader-flooding.md`](direct-leader-flooding.md) for the as-built
> record. Deviations from this plan, all additive:
>
> - The payload is `{"slot": u64, "leaders": [...]}` rather than a bare array —
>   the slot makes logs unambiguous and tells the routing step which slot the
>   targets belong to.
> - The overlay parses via a testable free function
>   (`parse_leaders_payload`); any invalid entry rejects the whole payload
>   (previous set kept) so a partially-mapped leader set is never installed.
> - The overlay's metrics snapshot now exposes `flood_leaders_slot`,
>   `flood_leaders`, and `flood_leaders_connected`, giving operators (and the
>   e2e test) direct visibility into the stored set instead of log-only
>   observability.
> - C++ verification is a full e2e test ("flood leaders pushed to overlay",
>   OverlayIPCTests.cpp) asserting the overlay's stored set equals
>   `computeLeaderSchedule(hash(L), L+2)` on a live 3-validator network —
>   OverlayIPC only runs against a real spawned overlay, so a JSON-emission
>   unit test harness would have required new injection seams for less
>   coverage.

## Context

Steps 0–1 are done: the overlay authenticates `NodeID → PeerId` and asserts quorum
connectivity (Step 0), and SCP elects pipelined leaders seeded by `hash(N-2)` with
an ahead-of-time `HerderSCPDriver::computeLeaderSchedule` (Step 1). Nothing yet
*uses* that schedule. This step wires it across the IPC boundary: each ledger
close, Core computes the upcoming flood leaders and pushes them to the overlay,
which maps them to authenticated `PeerId`s and stores them. This is pure transport
+ storage — actual TX routing is the next step.

### What / when to push

Leader of slot N is seeded by `hash(N-2)`. So when LCL advances to `L`, the
newly-computable schedule is for slot `L+2`, seeded by `hash(L)` (the just-closed
ledger's hash). We flood those leaders during `L+1`'s window so their queues are
full before `L+2`'s consensus.

**Rule:** on each ledger close (LCL = L), push the top `FLOOD_LEADER_COUNT` leaders
of slot `L+2`, computed from `hash(L)`. The overlay keeps one current flood-target
set, replaced on each push.

### Ownership (unchanged from Step 1)

C++ computes the schedule (it owns the quorum set + weights and is the single
authoritative election); the overlay only receives the resolved ordered `NodeID`
list and maps it to `PeerId`s via the Step 0 identity layer.

---

## Implementation

### 1. Core: compute + push on ledger close

In `HerderImpl::lastClosedLedgerIncreased` (`src/herder/HerderImpl.cpp:1095`),
inside the existing `if (latest)` block (sync/tracking already asserted there),
add — gated by `if (getSCP().isValidator())` (mirrors `HerderImpl.cpp:1701`):

```cpp
auto const& lcl = mLedgerManager.getLastClosedLedgerHeader();
auto leaders = mHerderSCPDriver.computeLeaderSchedule(
    lcl.hash, lcl.header.ledgerSeq + 2, mApp.getConfig().FLOOD_LEADER_COUNT);
std::vector<std::string> strkeys;
for (auto const& id : leaders) strkeys.emplace_back(KeyUtils::toStrKey(id));
mApp.getOverlayManager().getOverlayIPC().updateLeaders(strkeys);
```

Factor into a small private helper (e.g. `pushLeaderSchedule()`). Notes:
- `lcl.hash` is the ledger HASH (not `previousLedgerHash`); `lcl` is a
  `LedgerHeaderHistoryEntry`.
- Self may appear in `leaders` (the election considers `localID`). Leave it — the
  overlay has no self-connection, so it's a harmless no-op target. Self-exclusion /
  "K distinct others" policy is a routing decision for the next step.

### 2. IPC message `SET_LEADERS = 14`

- `src/overlay/IPC.h`: add `SET_LEADERS = 14` (next free Core→Overlay id) with a
  payload comment: JSON array of leader strkeys, ordered by priority.
- `overlay/src/ipc/messages.rs`: add `SetLeaders = 14` to `MessageType`, its
  `TryFrom<u32>` arm, and the roundtrip / `try_from` tests (mirror the Step 0
  `QuorumConnectivityReport = 106` additions).

### 3. `OverlayIPC::updateLeaders` (Core → Overlay sender)

- `src/overlay/OverlayIPC.{h,cpp}`: `void updateLeaders(std::vector<std::string>
  const& leaderStrkeys)`. Build a JSON array payload and send under `mSendMutex`
  with the `!mChannel || !mChannel->isConnected()` guard — mirror `setPeerConfig`
  (`src/overlay/OverlayIPC.cpp:767`). No new callback needed (Core→Overlay only).

### 4. Overlay: receive, map, store (no routing yet)

- `overlay/src/main.rs`: add `leaders: Arc<RwLock<Vec<PeerId>>>` to `App` (ordered
  by priority; keep the strkeys alongside for logging if convenient).
- Handle `SET_LEADERS` in the IPC dispatch (mirror the `SetPeerConfig` handler,
  ~`main.rs:1278`): parse the JSON array, map each strkey → `PeerId` via the
  existing `quorum_member_peer_id` (Step 0), replace `leaders`. On parse error,
  log and skip (as Step 0's `quorum_members` does).
- **Observability** (valuable for live testing): log the leader set and, for each,
  whether it is currently connected (intersect with `connected_peers` /
  `connected_quorum`). This lets the operator confirm the pipeline end-to-end.

---

## Files to modify

- `src/herder/HerderImpl.{h,cpp}` — `pushLeaderSchedule()` helper + call in
  `lastClosedLedgerIncreased`.
- `src/overlay/IPC.h` — `SET_LEADERS = 14`.
- `src/overlay/OverlayIPC.{h,cpp}` — `updateLeaders`.
- `overlay/src/ipc/messages.rs` — `SetLeaders = 14` (+ tests).
- `overlay/src/main.rs` — `App.leaders`, `SET_LEADERS` handler, mapping + logging.

## Reuse

- `HerderSCPDriver::computeLeaderSchedule(seed, slotIndex, count)` (Step 1).
- `mLedgerManager.getLastClosedLedgerHeader()` → `.hash`, `.header.ledgerSeq`.
- `getSCP().isValidator()` gate (`HerderImpl.cpp:1701` pattern).
- `KeyUtils::toStrKey(NodeID)`.
- `OverlayIPC::setPeerConfig` JSON-build + `mSendMutex` send pattern.
- Overlay `quorum_member_peer_id` strkey→PeerId mapping + the `SetPeerConfig`
  handler structure (Step 0).

## Verification

- **Rust unit tests** (`messages.rs`): `SetLeaders` roundtrip + `try_from(14)`;
  (`main.rs`) handler parses an ordered strkey array into the expected `PeerId`
  vec (reuse Step 0 strkey/keypair test helpers).
- **C++**: a focused test that `OverlayIPC::updateLeaders` emits a `SET_LEADERS`
  message with the correct JSON (or assert the Herder hook calls it once per close
  with `computeLeaderSchedule`'s output).
- **Manual / live**: bring up a small validator net; confirm each ledger close logs
  a `SET_LEADERS` push of the top-K for `L+2`, the overlay logs those leaders and
  that each is a connected quorum member, and the pushed set matches
  `computeLeaderSchedule` (already unit-tested predicted==actual in Step 1).

## Out of scope (next step — routing)

- `broadcast_tx` pushing full TX bodies to the stored leader connections (skip
  INV/GETDATA), TxSet fetch for non-leaders, flood fallback.
- Self-exclusion / "K distinct others" routing policy, and non-validator nodes
  computing/pushing leaders — deferred with the routing step.
