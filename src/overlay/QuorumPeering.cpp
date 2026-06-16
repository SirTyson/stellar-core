// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "overlay/QuorumPeering.h"
#include "crypto/KeyUtils.h"
#include "database/Database.h"
#include "lib/json/json.h"
#include "main/Application.h"
#include "main/Config.h"
#include "main/PersistentState.h"
#include "scp/LocalNode.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"

namespace stellar
{

namespace
{
std::string
dispositionToString(QuorumPeering::Disposition d)
{
    switch (d)
    {
    case QuorumPeering::Disposition::MUTUAL:
        return "mutual";
    case QuorumPeering::Disposition::NON_MUTUAL:
        return "non_mutual";
    default:
        return "unknown";
    }
}

QuorumPeering::Disposition
dispositionFromString(std::string const& s)
{
    if (s == "mutual")
    {
        return QuorumPeering::Disposition::MUTUAL;
    }
    if (s == "non_mutual")
    {
        return QuorumPeering::Disposition::NON_MUTUAL;
    }
    return QuorumPeering::Disposition::UNKNOWN;
}
}

QuorumPeering::QuorumPeering(Application& app) : mApp(app)
{
    auto const& cfg = mApp.getConfig();
    if (!cfg.AUTOMATIC_QUORUM_PEERING || !cfg.NODE_IS_VALIDATOR)
    {
        return;
    }
    LocalNode::forAllNodes(cfg.QUORUM_SET, [&](NodeID const& n) {
        if (!(n == cfg.NODE_SEED.getPublicKey()))
        {
            mTrustedKeys.insert(n);
        }
        return true;
    });
    for (auto const& k : mTrustedKeys)
    {
        mInfo[k] = Info{};
    }
}

bool
QuorumPeering::enabled() const
{
    return !mTrustedKeys.empty();
}

size_t
QuorumPeering::numTrustedKeys() const
{
    return mTrustedKeys.size();
}

bool
QuorumPeering::isTrustedKey(NodeID const& key) const
{
    return mTrustedKeys.count(key) != 0;
}

QuorumPeering::Disposition
QuorumPeering::getDisposition(NodeID const& key) const
{
    auto it = mInfo.find(key);
    return it == mInfo.end() ? Disposition::UNKNOWN : it->second.mDisposition;
}

bool
QuorumPeering::hasUnknownKeys() const
{
    for (auto const& kv : mInfo)
    {
        if (kv.second.mDisposition == Disposition::UNKNOWN)
        {
            return true;
        }
    }
    return false;
}

std::vector<std::pair<NodeID, PeerBareAddress>>
QuorumPeering::getMutualEntries() const
{
    std::vector<std::pair<NodeID, PeerBareAddress>> res;
    for (auto const& kv : mInfo)
    {
        if (kv.second.mDisposition == Disposition::MUTUAL &&
            !kv.second.mAddress.isEmpty())
        {
            res.emplace_back(kv.first, kv.second.mAddress);
        }
    }
    return res;
}

bool
QuorumPeering::isMutualAddressIP(std::string const& ip) const
{
    for (auto const& kv : mInfo)
    {
        if (kv.second.mDisposition == Disposition::MUTUAL &&
            !kv.second.mAddress.isEmpty() && kv.second.mAddress.getIP() == ip)
        {
            return true;
        }
    }
    return false;
}

std::optional<PeerBareAddress>
QuorumPeering::resolve(NodeID const& key, bool mutual,
                       PeerBareAddress const& address)
{
    releaseAssert(threadIsMain());
    auto it = mInfo.find(key);
    if (it == mInfo.end())
    {
        return std::nullopt;
    }

    auto& info = it->second;
    auto newDisposition =
        mutual ? Disposition::MUTUAL : Disposition::NON_MUTUAL;

    std::optional<PeerBareAddress> staleAddress;
    if (info.mDisposition == Disposition::MUTUAL && !info.mAddress.isEmpty() &&
        !(info.mAddress == address))
    {
        // The key was previously pinned at a different address: hand the old
        // one back so the caller can demote its peer record.
        staleAddress = std::make_optional(info.mAddress);
    }

    bool changed = info.mDisposition != newDisposition ||
                   (mutual && !(info.mAddress == address));

    info.mDisposition = newDisposition;
    info.mAddress = mutual ? address : PeerBareAddress{};
    info.mLastResolved = now();

    if (changed)
    {
        CLOG_INFO(Overlay, "Quorum peer {} resolved as {}{}",
                  mApp.getConfig().toShortString(key),
                  dispositionToString(newDisposition),
                  mutual ? " at " + address.toString() : "");
        mProbesSinceLastResolution = 0;
        save();
    }
    return staleAddress;
}

void
QuorumPeering::invalidate(NodeID const& key)
{
    releaseAssert(threadIsMain());
    auto it = mInfo.find(key);
    if (it == mInfo.end() ||
        it->second.mDisposition == Disposition::UNKNOWN)
    {
        return;
    }
    it->second = Info{};
    mProbesSinceLastResolution = 0;
    save();
}

void
QuorumPeering::load()
{
    releaseAssert(threadIsMain());
    if (!enabled())
    {
        return;
    }

    auto raw = mApp.getPersistentState().getState(
        PersistentState::kQuorumPeerDispositions,
        mApp.getDatabase().getMiscSession());
    if (raw.empty())
    {
        return;
    }

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(raw, root) || !root.isMember("entries"))
    {
        CLOG_WARNING(Overlay,
                     "Failed to parse persisted quorum peer dispositions; "
                     "starting from scratch");
        return;
    }

    size_t loaded = 0;
    for (auto const& e : root["entries"])
    {
        try
        {
            auto key = KeyUtils::fromStrKey<PublicKey>(e["key"].asString());
            auto it = mInfo.find(key);
            if (it == mInfo.end())
            {
                // Key no longer in the quorum set; drop the entry.
                continue;
            }
            Info info;
            info.mDisposition = dispositionFromString(e["disp"].asString());
            if (info.mDisposition == Disposition::MUTUAL)
            {
                info.mAddress = PeerBareAddress{
                    e["ip"].asString(),
                    static_cast<unsigned short>(e["port"].asUInt())};
            }
            info.mLastResolved = e["resolved"].asUInt64();
            it->second = info;
            ++loaded;
        }
        catch (std::exception const& ex)
        {
            CLOG_WARNING(Overlay,
                         "Ignoring bad quorum peer disposition entry: {}",
                         ex.what());
        }
    }
    CLOG_INFO(Overlay,
              "Loaded {} persisted quorum peer dispositions ({} keys in "
              "quorum set, {} still unknown)",
              loaded, mTrustedKeys.size(),
              std::count_if(mInfo.begin(), mInfo.end(), [](auto const& kv) {
                  return kv.second.mDisposition == Disposition::UNKNOWN;
              }));
}

void
QuorumPeering::save() const
{
    releaseAssert(threadIsMain());
    Json::Value root;
    root["v"] = 1;
    Json::Value entries(Json::arrayValue);
    for (auto const& kv : mInfo)
    {
        if (kv.second.mDisposition == Disposition::UNKNOWN)
        {
            continue;
        }
        Json::Value e;
        e["key"] = KeyUtils::toStrKey(kv.first);
        e["disp"] = dispositionToString(kv.second.mDisposition);
        if (kv.second.mDisposition == Disposition::MUTUAL &&
            !kv.second.mAddress.isEmpty())
        {
            e["ip"] = kv.second.mAddress.getIP();
            e["port"] = kv.second.mAddress.getPort();
        }
        e["resolved"] = Json::UInt64(kv.second.mLastResolved);
        entries.append(e);
    }
    root["entries"] = entries;
    mApp.getPersistentState().setMiscState(
        PersistentState::kQuorumPeerDispositions,
        Json::FastWriter().write(root));
}

uint64_t
QuorumPeering::now() const
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            mApp.getClock().system_now().time_since_epoch())
            .count());
}

int
QuorumPeering::probesThisTick()
{
    releaseAssert(threadIsMain());
    if (!hasUnknownKeys())
    {
        return 0;
    }
    if (mProbesSinceLastResolution >= HUNT_FULL_RATE_PROBE_LIMIT)
    {
        // The hunt has swept for a while without learning anything new --
        // the remaining keys are likely offline. Keep looking, but slowly.
        if (++mTicksSinceLastProbe < HUNT_SLOW_TICK_INTERVAL)
        {
            return 0;
        }
        mTicksSinceLastProbe = 0;
    }
    mProbesSinceLastResolution += HUNT_PROBES_PER_TICK;
    return HUNT_PROBES_PER_TICK;
}
}
