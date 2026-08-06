// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SHA.h"
#include "herder/HerderImpl.h"
#include "herder/LedgerCloseData.h"
#include "herder/test/TestTxSetUtils.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerManagerImpl.h"
#include "main/Application.h"
#include "main/Config.h"
#include "medida/meter.h"
#include "simulation/Topologies.h"
#include "test/Catch2.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include <xdrpp/marshal.h>

using namespace stellar;

namespace
{

Application::pointer
makeCacheTestApplication(VirtualClock& clock)
{
    Config cfg(getTestConfig());
    cfg.LEDGER_PROTOCOL_VERSION = Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION =
        Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.PARALLEL_LEDGER_APPLY = false;
    return createTestApplication(clock, cfg);
}

std::vector<TxSetXDRFrameConstPtr>
makeGrowingTxSets(Application& app, size_t count)
{
    auto root = app.getRoot();
    TxFrameList txs;
    std::vector<TxSetXDRFrameConstPtr> txSets;
    txSets.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
        txs.emplace_back(root->tx({txtest::payment(*root, 1)}));
        auto [wireTxSet, applicableTxSet] =
            testtxset::makeNonValidatedTxSetBasedOnLedgerVersion(
                txs, app,
                app.getLedgerManager().getLastClosedLedgerHeader().hash);
        REQUIRE(applicableTxSet);
        txSets.emplace_back(std::move(wireTxSet));
    }
    return txSets;
}

ValueWrapperPtr
addCandidate(HerderImpl& herder, Application& app,
             TxSetXDRFrameConstPtr const& txSet, uint64_t slot)
{
    auto const hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, slot, txSet);
    auto const& lcl = app.getLedgerManager().getLastClosedLedgerHeader();
    auto sv =
        herder.makeStellarValue(hash, lcl.header.scpValue.closeTime + 1,
                                emptyUpgradeSteps, app.getConfig().NODE_SEED);
    return herder.getHerderSCPDriver().wrapStellarValue(sv);
}

ValueWrapperPtr
makeMissingCandidate(HerderImpl& herder, Application& app, Hash const& hash)
{
    auto const& lcl = app.getLedgerManager().getLastClosedLedgerHeader();
    auto sv =
        herder.makeStellarValue(hash, lcl.header.scpValue.closeTime + 1,
                                emptyUpgradeSteps, app.getConfig().NODE_SEED);
    return herder.getHerderSCPDriver().wrapStellarValue(sv);
}

Hash
txSetHash(ValueWrapperPtr const& value)
{
    StellarValue sv;
    xdr::xdr_from_opaque(value->getValue(), sv);
    return sv.txSetHash;
}

TxSetXDRFrameConstPtr
makeStaleTxSet(TxSetXDRFrameConstPtr const& txSet)
{
    auto staleHash = sha256("stale applicable tx set parent");
    if (txSet->isGeneralizedTxSet())
    {
        GeneralizedTransactionSet xdrTxSet;
        txSet->toXDR(xdrTxSet);
        xdrTxSet.v1TxSet().previousLedgerHash = staleHash;
        return TxSetXDRFrame::makeFromWire(xdrTxSet);
    }

    TransactionSet xdrTxSet;
    txSet->toXDR(xdrTxSet);
    xdrTxSet.previousLedgerHash = staleHash;
    return TxSetXDRFrame::makeFromWire(xdrTxSet);
}

std::vector<Hash>
hashesFromApplicable(ApplicableTxSetFrame const& txSet)
{
    std::vector<Hash> hashes;
    for (auto const& phase : txSet.getPhases())
    {
        for (auto const& tx : phase)
        {
            hashes.emplace_back(tx->getFullHash());
        }
    }
    return hashes;
}

std::vector<Hash>
hashesFromWire(TxSetXDRFrame const& txSet, Hash const& networkID)
{
    std::vector<Hash> hashes;
    for (auto const& phase : txSet.createTransactionFrames(networkID))
    {
        for (auto const& tx : phase)
        {
            hashes.emplace_back(tx->getFullHash());
        }
    }
    return hashes;
}

} // namespace

TEST_CASE("applicable tx set cache removes incremental candidate rebuilds",
          "[herder][txsetcache]")
{
    VirtualClock clock;
    auto app = makeCacheTestApplication(clock);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& driver = herder.getHerderSCPDriver();
    auto const slot = app->getLedgerManager().getLastClosedLedgerNum() + 1;
    auto txSets = makeGrowingTxSets(*app, 4);

    ValueWrapperPtrSet candidates;
    ValueWrapperPtr coldComposite;
    for (auto const& txSet : txSets)
    {
        candidates.emplace(addCandidate(herder, *app, txSet, slot));
        coldComposite = driver.combineCandidates(slot, candidates);
    }

    auto const& counters = driver.getApplicableTxSetCacheCounters();
    REQUIRE(counters.mInserts == txSets.size());
    REQUIRE(counters.mMisses == txSets.size());
    REQUIRE(counters.mHits == txSets.size() * (txSets.size() - 1) / 2);
    for (auto const& txSet : txSets)
    {
        // Test-set construction prepared each frame once; candidate
        // combination prepares each distinct wire set only once more.
        REQUIRE(txSet->getPrepareForApplyCount() == 2);
    }

    auto const hitsBeforeWarm = counters.mHits;
    auto warmComposite = driver.combineCandidates(slot, candidates);
    REQUIRE(warmComposite->getValue() == coldComposite->getValue());
    REQUIRE(txSetHash(warmComposite) == txSets.back()->getContentsHash());
    REQUIRE(counters.mHits == hitsBeforeWarm + txSets.size());
    for (auto const& txSet : txSets)
    {
        REQUIRE(txSet->getPrepareForApplyCount() == 2);
    }
}

TEST_CASE("applicable tx set cache candidate pathologies",
          "[herder][txsetcache]")
{
    VirtualClock clock;
    auto app = makeCacheTestApplication(clock);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& driver = herder.getHerderSCPDriver();
    auto const slot = app->getLedgerManager().getLastClosedLedgerNum() + 1;

    SECTION("stale parent is excluded without a build")
    {
        auto valid = makeGrowingTxSets(*app, 1).front();
        auto stale = makeStaleTxSet(valid);
        ValueWrapperPtrSet candidates;
        candidates.emplace(addCandidate(herder, *app, valid, slot));
        candidates.emplace(addCandidate(herder, *app, stale, slot));

        auto composite = driver.combineCandidates(slot, candidates);
        REQUIRE(txSetHash(composite) == valid->getContentsHash());
        REQUIRE(stale->getPrepareForApplyCount() == 0);
        REQUIRE(driver.getApplicableTxSetCacheCounters().mInserts == 1);
    }

    SECTION("absent set follows null ordering")
    {
        auto valid = makeGrowingTxSets(*app, 1).front();
        ValueWrapperPtrSet candidates;
        candidates.emplace(addCandidate(herder, *app, valid, slot));
        candidates.emplace(makeMissingCandidate(
            herder, *app, sha256("missing applicable tx set")));

        auto composite = driver.combineCandidates(slot, candidates);
        REQUIRE(txSetHash(composite) == valid->getContentsHash());
    }

    SECTION("eviction during combination preserves the composite")
    {
        auto txSets = makeGrowingTxSets(*app, 10);
        ValueWrapperPtrSet candidates;
        for (auto const& txSet : txSets)
        {
            candidates.emplace(addCandidate(herder, *app, txSet, slot));
        }

        auto coldComposite = driver.combineCandidates(slot, candidates);
        REQUIRE(txSetHash(coldComposite) == txSets.back()->getContentsHash());
        REQUIRE(driver.getApplicableTxSetCacheCounters().mEvicts > 0);

        auto warmComposite = driver.combineCandidates(slot, candidates);
        REQUIRE(warmComposite->getValue() == coldComposite->getValue());
    }
}

TEST_CASE("applicable tx set validation reuses prepared frame",
          "[herder][txsetcache]")
{
    VirtualClock clock;
    auto app = makeCacheTestApplication(clock);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& driver = herder.getHerderSCPDriver();
    auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
    auto const slot = lcl.header.ledgerSeq + 1;
    auto txSet = TxSetXDRFrame::makeEmpty(lcl);
    auto const hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, slot, txSet);

    auto validateAtOffset = [&](uint64_t offset) {
        auto sv = herder.makeStellarValue(
            hash, lcl.header.scpValue.closeTime + offset, emptyUpgradeSteps,
            app->getConfig().NODE_SEED);
        return driver.validateValue(slot, xdr::xdr_to_opaque(sv), true);
    };

    auto& hitMeter = app->getMetrics().NewMeter(
        {"herder", "txset", "applicable-cache-hit"}, "hit");
    auto const meterBefore = hitMeter.count();
    REQUIRE(validateAtOffset(1) == SCPDriver::kFullyValidatedValue);
    REQUIRE(validateAtOffset(2) == SCPDriver::kFullyValidatedValue);

    auto const& counters = driver.getApplicableTxSetCacheCounters();
    REQUIRE(counters.mInserts == 1);
    REQUIRE(counters.mMisses == 1);
    REQUIRE(counters.mHits == 1);
    REQUIRE(hitMeter.count() == meterBefore + 1);
    REQUIRE(txSet->getPrepareForApplyCount() == 1);
}

TEST_CASE("applicable tx set validation builds fresh while applying",
          "[herder][txsetcache]")
{
    VirtualClock clock;
    Config cfg(getTestConfig(0, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.LEDGER_PROTOCOL_VERSION = Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION =
        Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.PARALLEL_LEDGER_APPLY = true;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& driver = herder.getHerderSCPDriver();
    auto& ledgerManager = app->getLedgerManager();
    auto const lcl = ledgerManager.getLastClosedLedgerHeader();
    auto const slot = lcl.header.ledgerSeq + 1;
    auto txSet = makeGrowingTxSets(*app, 1).front();
    auto const hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, slot, txSet);

    auto validateAtOffset = [&](uint64_t offset) {
        auto sv = herder.makeStellarValue(
            hash, lcl.header.scpValue.closeTime + offset, emptyUpgradeSteps,
            app->getConfig().NODE_SEED);
        return driver.validateValue(slot, xdr::xdr_to_opaque(sv), true);
    };

    REQUIRE(validateAtOffset(1) == SCPDriver::kFullyValidatedValue);
    auto const prepareCountBeforeApply = txSet->getPrepareForApplyCount();

    auto sv = herder.makeStellarValue(
        hash, lcl.header.scpValue.closeTime + 1, emptyUpgradeSteps,
        app->getConfig().NODE_SEED);
    driver.valueExternalized(slot, xdr::xdr_to_opaque(sv));
    REQUIRE(ledgerManager.isApplying());

    auto const& counters = driver.getApplicableTxSetCacheCounters();
    auto const insertsBeforeConcurrentValidation = counters.mInserts;
    auto const hitsBeforeConcurrentValidation = counters.mHits;
    REQUIRE(validateAtOffset(2) == SCPDriver::kFullyValidatedValue);

    // The apply clone and cached frame share transaction-frame validation
    // memos. Validation during apply must construct a throwaway applicable
    // frame rather than touching the cache entry.
    REQUIRE(txSet->getPrepareForApplyCount() == prepareCountBeforeApply + 1);
    REQUIRE(counters.mInserts == insertsBeforeConcurrentValidation);
    REQUIRE(counters.mHits == hitsBeforeConcurrentValidation);

    while (ledgerManager.getLastClosedLedgerNum() < slot)
    {
        clock.crank(true);
    }
}

TEST_CASE("applicable tx set externalize and apply consumers",
          "[herder][txsetcache]")
{
    VirtualClock clock;
    auto app = makeCacheTestApplication(clock);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& driver = herder.getHerderSCPDriver();
    auto const lcl = app->getLedgerManager().getLastClosedLedgerHeader();
    auto const slot = lcl.header.ledgerSeq + 1;
    auto root = app->getRoot();
    auto tx = root->tx({txtest::payment(*root, 1)});
    auto [txSet, initialApplicable] =
        testtxset::makeNonValidatedTxSetBasedOnLedgerVersion({tx}, *app,
                                                             lcl.hash);
    REQUIRE(initialApplicable->checkValid(*app, 0, 0));
    initialApplicable->getPhasesInApplyOrder();
    REQUIRE(initialApplicable->hasApplyOrder());
    auto freshClone = initialApplicable->clone();
    REQUIRE_FALSE(freshClone->hasApplyOrder());

    auto const hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, slot, txSet);
    auto sv =
        herder.makeStellarValue(hash, lcl.header.scpValue.closeTime + 1,
                                emptyUpgradeSteps, app->getConfig().NODE_SEED);
    REQUIRE(driver.validateValue(slot, xdr::xdr_to_opaque(sv), true) ==
            SCPDriver::kFullyValidatedValue);

    auto cached = driver.getCachedApplicableTxSet(hash, lcl);
    REQUIRE(cached);
    REQUIRE_FALSE(cached->hasApplyOrder());
    REQUIRE(hashesFromApplicable(*cached) ==
            hashesFromWire(*txSet, app->getNetworkID()));

    auto applyClone = ApplicableTxSetFrameSharedPtr(cached->clone());
    LedgerCloseData ledgerData(slot, txSet, sv, std::nullopt, applyClone);
    LedgerCloseData copiedLedgerData = ledgerData;
    REQUIRE(copiedLedgerData.getApplicableTxSet() == applyClone);
    applyClone->getPhasesInApplyOrder();
    REQUIRE(applyClone->hasApplyOrder());
    REQUIRE_FALSE(cached->hasApplyOrder());

    auto const prepareCountBeforeApply = txSet->getPrepareForApplyCount();
    auto const hitsBeforeApply = driver.getApplicableTxSetCacheCounters().mHits;
    auto results = txtest::closeLedger(*app, txSet);
    REQUIRE(results.results.size() == 1);
    REQUIRE(static_cast<LedgerManagerImpl&>(app->getLedgerManager())
                .getLastClosedLedgerTxMeta()
                .size() == 1);
    REQUIRE(txSet->getPrepareForApplyCount() == prepareCountBeforeApply);
    REQUIRE(driver.getApplicableTxSetCacheCounters().mHits ==
            hitsBeforeApply + 1);
    REQUIRE_FALSE(cached->hasApplyOrder());
}

TEST_CASE("applicable tx set cache in forced-timeout nomination",
          "[herder][txsetcache][overlay-ipc]")
{
    auto networkID = sha256(getTestConfig().NETWORK_PASSPHRASE);
    auto simulation = Topologies::core(
        3, 1.0, networkID, [](int i) {
            Config cfg(getTestConfig(i));
            cfg.LEDGER_PROTOCOL_VERSION =
                Config::CURRENT_LEDGER_PROTOCOL_VERSION;
            cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION =
                Config::CURRENT_LEDGER_PROTOCOL_VERSION;
            cfg.PARALLEL_LEDGER_APPLY = false;
            cfg.ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING = false;
            // Bootstrap nominates immediately from genesis; keep the next
            // ordinary ledger trigger outside this test's window.
            cfg.ARTIFICIALLY_SET_CLOSE_TIME_FOR_TESTING = 20;
            cfg.ARTIFICIALLY_DELAY_NOMINATION_EMIT_FOR_TESTING =
                std::chrono::seconds(10);
            if (i != 0)
            {
                for (int peer = 1; peer <= 3; ++peer)
                {
                    if (peer != i)
                    {
                        auto const peerPort =
                            static_cast<int>(cfg.PEER_PORT) + (peer - i) * 2;
                        cfg.KNOWN_PEERS.emplace_back(
                            "127.0.0.1:" + std::to_string(peerPort));
                    }
                }
            }
            return cfg;
        });
    auto nodes = simulation->getNodes();
    REQUIRE(nodes.size() == 3);
    simulation->startAllNodes();

    // Let the real QUIC overlays form while the artificial delay holds back
    // their bootstrap nominations. Inject the non-empty proposals before the
    // delay expires; the shorter nomination timer then forces a timeout round.
    simulation->crankForAtLeast(std::chrono::milliseconds(500), false);
    auto const lcl =
        nodes.front()->getLedgerManager().getLastClosedLedgerHeader();
    auto const slot = lcl.header.ledgerSeq + 1;
    for (auto const& node : nodes)
    {
        REQUIRE(node->getLedgerManager().getLastClosedLedgerHeader().hash ==
                lcl.hash);
    }

    std::vector<TxSetXDRFrameConstPtr> candidates;
    std::set<Hash> candidateHashes;
    candidates.reserve(nodes.size());
    for (size_t i = 0; i < nodes.size(); ++i)
    {
        candidates.emplace_back(makeGrowingTxSets(*nodes[i], i + 1).back());
        candidateHashes.emplace(candidates.back()->getContentsHash());
    }

    // Keep tx-set download out of this test: all nodes know all bodies, so the
    // only source of delay and candidate promotion is SCP nomination itself.
    for (auto const& node : nodes)
    {
        auto& herder = static_cast<HerderImpl&>(node->getHerder());
        for (auto const& candidate : candidates)
        {
            herder.getPendingEnvelopes().putTxSet(
                candidate->getContentsHash(), slot, candidate);
            GeneralizedTransactionSet xdrTxSet;
            candidate->toXDR(xdrTxSet);
            node->getOverlayManager().cacheTxSet(
                candidate->getContentsHash(),
                xdr::xdr_to_opaque(xdrTxSet));
        }
    }

    for (size_t i = 0; i < nodes.size(); ++i)
    {
        auto& herder = static_cast<HerderImpl&>(nodes[i]->getHerder());
        auto value = herder.makeStellarValue(
            candidates[i]->getContentsHash(),
            lcl.header.scpValue.closeTime + 1, emptyUpgradeSteps,
            nodes[i]->getConfig().NODE_SEED);
        herder.getHerderSCPDriver().nominate(
            slot, value, candidates[i], lcl.header.scpValue);
    }

    simulation->crankUntil(
        [&]() { return simulation->haveAllExternalized(slot, 1); },
        std::chrono::seconds(15), false);
    REQUIRE(simulation->haveAllExternalized(slot, 1));

    bool sawTimeout = false;
    bool sawApplicableCacheHit = false;
    std::set<Hash> acceptedTxSetHashes;
    std::set<Hash> acceptedCandidateHashes;
    std::optional<Hash> externalizedHash;
    for (auto const& node : nodes)
    {
        auto& herder = static_cast<HerderImpl&>(node->getHerder());
        auto& driver = herder.getHerderSCPDriver();
        auto timeouts = driver.getNominationTimeouts(slot);
        sawTimeout = sawTimeout || (timeouts && *timeouts > 0);
        sawApplicableCacheHit =
            sawApplicableCacheHit ||
            driver.getApplicableTxSetCacheCounters().mHits > 0;
        for (auto const& envelope : herder.getSCP().getLatestMessagesSend(slot))
        {
            if (envelope.statement.pledges.type() == SCP_ST_NOMINATE &&
                envelope.statement.pledges.nominate().accepted.size() > 1)
            {
                for (auto const& accepted :
                     envelope.statement.pledges.nominate().accepted)
                {
                    StellarValue acceptedValue;
                    xdr::xdr_from_opaque(accepted, acceptedValue);
                    acceptedTxSetHashes.emplace(acceptedValue.txSetHash);
                    if (candidateHashes.count(acceptedValue.txSetHash) != 0)
                    {
                        acceptedCandidateHashes.emplace(
                            acceptedValue.txSetHash);
                    }
                }
            }
        }

        auto const& closed =
            node->getLedgerManager().getLastClosedLedgerHeader();
        if (externalizedHash)
        {
            REQUIRE(closed.header.scpValue.txSetHash == *externalizedHash);
        }
        else
        {
            externalizedHash = closed.header.scpValue.txSetHash;
        }
    }
    REQUIRE(sawTimeout);
    REQUIRE(acceptedTxSetHashes.size() > 1);
    REQUIRE_FALSE(acceptedCandidateHashes.empty());
    REQUIRE(sawApplicableCacheHit);
    REQUIRE(candidateHashes.count(*externalizedHash) == 1);
}
