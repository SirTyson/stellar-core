// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "overlay/PeerBareAddress.h"
#include "util/UnorderedMap.h"
#include "xdr/Stellar-types.h"

#include <optional>
#include <set>
#include <vector>

namespace stellar
{

class Application;

// QuorumPeering tracks, for every validator key in the local QUORUM_SET, what
// the network has told us about our relationship with it (its "disposition"):
//
//  - UNKNOWN:    we have never completed a handshake with this key. The
//                overlay "hunts" for it: it probes extra outbound candidates
//                each tick until the key is found (see
//                OverlayManagerImpl::tick).
//  - MUTUAL:     the peer confirmed, via the AUTH_MSG_FLAG_PEER_IN_QUORUM
//                handshake flag, that our key is in its quorum set too. Its
//                address is pinned as a PREFERRED peer record and redialed
//                aggressively; this is what assembles the tier 1 full mesh.
//  - NON_MUTUAL: the peer told us that our key is not in its quorum set --
//                whether it then accepted us into a spare unprivileged slot
//                or rejected us with ERR_PEER_UNPRIVILEGED. We never hunt
//                for this key again and treat its node politely. The verdict
//                is key-scoped, so it survives the peer changing address.
//
// A node cannot know from local configuration whether its quorum reciprocates
// (a non-tier-1 validator's config looks exactly like a tier 1 member's), so
// every validator starts with all keys UNKNOWN and learns its place in the
// network from handshakes. Dispositions persist across restarts
// (PersistentState::kQuorumPeerDispositions), so this learning happens once:
// a node whose whole quorum answered NON_MUTUAL settles into watcher-like
// behavior permanently instead of re-hunting on every startup.
//
// Pinned MUTUAL addresses are invalidated back to UNKNOWN when they go stale
// (the address keeps failing while the key is disconnected), which resumes
// the hunt for that key; see OverlayManagerImpl::tick.
class QuorumPeering
{
  public:
    enum class Disposition
    {
        UNKNOWN,
        MUTUAL,
        NON_MUTUAL
    };

    // While hunting, probe up to this many extra outbound candidates per
    // overlay tick (beyond TARGET_PEER_CONNECTIONS).
    static constexpr int HUNT_PROBES_PER_TICK = 2;
    // After this many probes without resolving any disposition, assume the
    // remaining UNKNOWN keys are offline or misconfigured and decay to one
    // probe burst every HUNT_SLOW_TICK_INTERVAL ticks instead of every tick.
    static constexpr uint64_t HUNT_FULL_RATE_PROBE_LIMIT = 4000;
    static constexpr uint64_t HUNT_SLOW_TICK_INTERVAL = 10;

    explicit QuorumPeering(Application& app);

    // True when automatic quorum peering is active on this node (validator,
    // feature enabled, non-empty quorum set).
    bool enabled() const;

    size_t numTrustedKeys() const;
    bool isTrustedKey(NodeID const& key) const;
    Disposition getDisposition(NodeID const& key) const;

    bool hasUnknownKeys() const;

    // All MUTUAL keys with their pinned addresses.
    std::vector<std::pair<NodeID, PeerBareAddress>> getMutualEntries() const;

    // True if `ip` matches a pinned MUTUAL address (used to extend pending
    // connection headroom, like isPossiblyPreferred).
    bool isMutualAddressIP(std::string const& ip) const;

    // Record the outcome of an authenticated handshake with `key`: `mutual`
    // is what the peer's AUTH flags said about us. Returns the previously
    // pinned address when `key` was MUTUAL somewhere else, so the caller can
    // demote the stale peer record.
    std::optional<PeerBareAddress>
    resolve(NodeID const& key, bool mutual, PeerBareAddress const& address);

    // Drop `key` back to UNKNOWN (its pinned address went stale); hunting
    // resumes for it.
    void invalidate(NodeID const& key);

    // Load persisted dispositions; call once at overlay startup.
    void load();

    // Probe budget for this overlay tick (0 when there is nothing to hunt).
    int probesThisTick();

  private:
    struct Info
    {
        Disposition mDisposition{Disposition::UNKNOWN};
        PeerBareAddress mAddress;
        uint64_t mLastResolved{0};
    };

    void save() const;
    uint64_t now() const;

    Application& mApp;
    std::set<NodeID> mTrustedKeys;
    UnorderedMap<NodeID, Info> mInfo;

    // Hunt pacing
    uint64_t mProbesSinceLastResolution{0};
    uint64_t mTicksSinceLastProbe{0};
};
}
