// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "database/Database.h"
#include "herder/HerderImpl.h"
#include "herder/TxSetPersistor.h"
#include "herder/test/TestTxSetUtils.h"
#include "main/Application.h"
#include "main/PersistentState.h"
#include "medida/meter.h"
#include "medida/timer.h"
#include "scp/LocalNode.h"
#include "test/Catch2.h"
#include "test/TestUtils.h"
#include "test/test.h"
#include "util/TmpDir.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <soci.h>
#include <thread>
#include <xdrpp/marshal.h>

using namespace stellar;

namespace
{

TxSetXDRFrameConstPtr
makeTestTxSet(Application& app, Hash const& previousLedgerHash)
{
    return testtxset::makeNonValidatedTxSetBasedOnLedgerVersion(
               {}, app, previousLedgerHash)
        .first;
}

SCPEnvelope
makeNominationEnvelope(HerderImpl& herder, Application& app, uint64_t slot,
                       std::vector<Hash> const& txSetHashes)
{
    SCPEnvelope envelope;
    envelope.statement.nodeID = app.getConfig().NODE_SEED.getPublicKey();
    envelope.statement.slotIndex = slot;
    envelope.statement.pledges.type(SCP_ST_NOMINATE);

    auto& nomination = envelope.statement.pledges.nominate();
    nomination.quorumSetHash =
        herder.getSCP().getLocalNode()->getQuorumSetHash();
    xdr::xvector<UpgradeType, 6> upgrades;
    for (auto const& hash : txSetHashes)
    {
        auto value = herder.makeStellarValue(hash, app.timeNow(), upgrades,
                                             app.getConfig().NODE_SEED);
        nomination.votes.emplace_back(xdr::xdr_to_opaque(value));
    }
    herder.signEnvelope(app.getConfig().NODE_SEED, envelope);
    return envelope;
}

void
installLatestEnvelope(HerderImpl& herder, SCPEnvelope const& envelope)
{
    auto& driver = herder.getHerderSCPDriver();
    herder.getSCP().setStateFromEnvelope(envelope.statement.slotIndex,
                                         driver.wrapEnvelope(envelope));
}

struct ForceSynchronousPersistReset
{
    ~ForceSynchronousPersistReset()
    {
        TxSetPersistor::gForceSynchronousPersist = false;
    }
};

} // namespace

TEST_CASE("background tx-set persistence lifecycle", "[herder][txsetpersist]")
{
    ForceSynchronousPersistReset reset;
    Config cfg(getTestConfig(0, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& persistor = herder.getTxSetPersistor();
    auto& pending = herder.getPendingEnvelopes();
    auto& persistentState = app->getPersistentState();
    auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();

    REQUIRE(persistor.isEnabled());

    SECTION("put is exactly once per cached hash")
    {
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();
        auto& timer =
            app->getMetrics().NewTimer({"herder", "txset", "persist"});
        auto before = timer.count();

        auto first = pending.putTxSet(hash, lcl.header.ledgerSeq + 1, txSet);
        auto second = pending.putTxSet(hash, lcl.header.ledgerSeq + 1, txSet);
        REQUIRE(first == second);
        persistor.drain();

        REQUIRE(timer.count() == before + 1);
        REQUIRE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::DONE);
    }

    SECTION("discard waits behind write and removes the row")
    {
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();
        auto& discardMeter = app->getMetrics().NewMeter(
            {"herder", "txset", "persist-discard"}, "txset");
        auto before = discardMeter.count();

        REQUIRE(
            persistor.kickOffPersist(hash, lcl.header.ledgerSeq + 1, txSet));
        persistor.discardPersist(hash);
        persistor.drain();

        REQUIRE(discardMeter.count() == before + 1);
        REQUIRE_FALSE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::DISCARDED);
    }

    SECTION("validation failure sequences a discard after the write")
    {
        auto txSet = makeTestTxSet(*app, sha256("wrong previous ledger"));
        auto hash = txSet->getContentsHash();
        auto slot = lcl.header.ledgerSeq + 1;
        auto& discardMeter = app->getMetrics().NewMeter(
            {"herder", "txset", "persist-discard"}, "txset");
        auto before = discardMeter.count();

        pending.putTxSet(hash, slot, txSet);
        xdr::xvector<UpgradeType, 6> upgrades;
        auto stellarValue =
            herder.makeStellarValue(hash, lcl.header.scpValue.closeTime + 1,
                                    upgrades, app->getConfig().NODE_SEED);
        auto value = xdr::xdr_to_opaque(stellarValue);
        auto validation =
            herder.getHerderSCPDriver().validateValue(slot, value, true);
        REQUIRE(validation != SCPDriver::kFullyValidatedValue);

        persistor.drain();
        REQUIRE(discardMeter.count() == before + 1);
        REQUIRE_FALSE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::DISCARDED);
    }

    SECTION("validation failure cannot discard a referenced row")
    {
        auto txSet = makeTestTxSet(*app, sha256("wrong previous ledger"));
        auto hash = txSet->getContentsHash();
        auto slot = lcl.header.ledgerSeq + 1;
        auto& discardMeter = app->getMetrics().NewMeter(
            {"herder", "txset", "persist-discard"}, "txset");
        auto before = discardMeter.count();

        pending.putTxSet(hash, slot, txSet);
        persistor.drain();
        REQUIRE(persistentState.hasTxSet(hash));
        persistor.noteReferenced({hash});
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::NONE);

        xdr::xvector<UpgradeType, 6> upgrades;
        auto stellarValue =
            herder.makeStellarValue(hash, lcl.header.scpValue.closeTime + 1,
                                    upgrades, app->getConfig().NODE_SEED);
        auto validation = herder.getHerderSCPDriver().validateValue(
            slot, xdr::xdr_to_opaque(stellarValue), true);
        REQUIRE(validation != SCPDriver::kFullyValidatedValue);

        persistor.drain();
        REQUIRE(discardMeter.count() == before);
        REQUIRE(persistentState.hasTxSet(hash));
    }

    SECTION("kick discard rekick leaves newest write present")
    {
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();

        REQUIRE(
            persistor.kickOffPersist(hash, lcl.header.ledgerSeq + 1, txSet));
        persistor.discardPersist(hash);
        REQUIRE(
            persistor.kickOffPersist(hash, lcl.header.ledgerSeq + 1, txSet));
        persistor.drain();

        REQUIRE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::DONE);
    }

    SECTION("GC protects active entries and prunes stale completed entries")
    {
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();
        auto slot = lcl.header.ledgerSeq + 1;
        REQUIRE(persistor.kickOffPersist(hash, slot, txSet));

        std::unordered_set<Hash> deleteSet{hash};
        persistor.filterGCDeleteSet(deleteSet, slot);
        REQUIRE(deleteSet.empty());
        persistor.drain();
        REQUIRE(persistentState.hasTxSet(hash));

        deleteSet.emplace(hash);
        persistor.filterGCDeleteSet(deleteSet, slot + 1);
        REQUIRE(deleteSet.count(hash) == 1);
        persistentState.deleteTxSets(deleteSet);
        REQUIRE_FALSE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::NONE);
    }

    SECTION("forced synchronous test mode commits before returning")
    {
        TxSetPersistor::gForceSynchronousPersist = true;
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();

        REQUIRE(
            persistor.kickOffPersist(hash, lcl.header.ledgerSeq + 1, txSet));
        REQUIRE(persistentState.hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::DONE);
    }
}

TEST_CASE("tx-set bodies precede emitted statements", "[herder][txsetpersist]")
{
    Config cfg(getTestConfig(1, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& persistor = herder.getTxSetPersistor();
    auto& pending = herder.getPendingEnvelopes();
    auto& persistentState = app->getPersistentState();
    auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
    auto slot = lcl.header.ledgerSeq + 1;

    auto txSet1 = makeTestTxSet(*app, lcl.hash);
    auto txSet2 = makeTestTxSet(*app, sha256("second tx set"));
    auto hash1 = txSet1->getContentsHash();
    auto hash2 = txSet2->getContentsHash();
    pending.putTxSet(hash1, slot, txSet1);
    pending.putTxSet(hash2, slot, txSet2);

    auto envelope = makeNominationEnvelope(herder, *app, slot, {hash1, hash2});
    installLatestEnvelope(herder, envelope);

    bool broadcastObserved = false;
    herder.mBroadcastHook = [&](SCPEnvelope const&) {
        broadcastObserved = true;
        REQUIRE(persistentState.hasTxSet(hash1));
        REQUIRE(persistentState.hasTxSet(hash2));
        auto states = persistentState.getSCPStateAllSlots();
        auto slotIndex = static_cast<uint32_t>(
            slot % (app->getConfig().MAX_SLOTS_TO_REMEMBER + 1));
        REQUIRE(states.count(slotIndex) == 1);
    };

    auto& fallbackMeter = app->getMetrics().NewMeter(
        {"herder", "txset", "persist-fallback"}, "txset");
    auto fallbackBefore = fallbackMeter.count();
    herder.getHerderSCPDriver().emitEnvelope(envelope);

    REQUIRE(broadcastObserved);
    REQUIRE(fallbackMeter.count() == fallbackBefore);
    REQUIRE(persistor.getState(hash1) == TxSetPersistor::State::NONE);
    REQUIRE(persistor.getState(hash2) == TxSetPersistor::State::NONE);
}

TEST_CASE("emission heals a sequenced tx-set discard", "[herder][txsetpersist]")
{
    Config cfg(getTestConfig(2, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto& persistor = herder.getTxSetPersistor();
    auto& persistentState = app->getPersistentState();
    auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
    auto slot = lcl.header.ledgerSeq + 1;

    auto txSet = makeTestTxSet(*app, lcl.hash);
    auto hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, slot, txSet);
    persistor.drain();
    REQUIRE(persistentState.hasTxSet(hash));

    persistor.discardPersist(hash);
    REQUIRE(persistor.getState(hash) == TxSetPersistor::State::IN_FLIGHT);

    auto envelope = makeNominationEnvelope(herder, *app, slot, {hash});
    installLatestEnvelope(herder, envelope);
    bool broadcastObserved = false;
    herder.mBroadcastHook = [&](SCPEnvelope const&) {
        broadcastObserved = true;
        REQUIRE(persistentState.hasTxSet(hash));
    };

    auto& fallbackMeter = app->getMetrics().NewMeter(
        {"herder", "txset", "persist-fallback"}, "txset");
    auto fallbackBefore = fallbackMeter.count();
    herder.getHerderSCPDriver().emitEnvelope(envelope);

    REQUIRE(broadcastObserved);
    REQUIRE(fallbackMeter.count() == fallbackBefore + 1);
    REQUIRE(persistentState.hasTxSet(hash));
}

TEST_CASE("background tx-set persistence auto-disables",
          "[herder][txsetpersist]")
{
    auto runDisabledCase = [](Config cfg) {
        cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg);
        auto& herder = static_cast<HerderImpl&>(app->getHerder());
        auto& persistor = herder.getTxSetPersistor();
        auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();

        REQUIRE_FALSE(persistor.isEnabled());
        herder.getPendingEnvelopes().putTxSet(hash, lcl.header.ledgerSeq + 1,
                                              txSet);
        REQUIRE_FALSE(app->getPersistentState().hasTxSet(hash));
        REQUIRE(persistor.getState(hash) == TxSetPersistor::State::NONE);
    };

    SECTION("in-memory SQLite")
    {
        runDisabledCase(Config(getTestConfig(3, Config::TESTDB_IN_MEMORY)));
    }

    SECTION("flag off")
    {
        Config cfg(getTestConfig(4, Config::TESTDB_BUCKET_DB_PERSISTENT));
        cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = false;
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg);
        auto& herder = static_cast<HerderImpl&>(app->getHerder());
        REQUIRE_FALSE(herder.getTxSetPersistor().isEnabled());
    }

#ifdef USE_POSTGRES
    SECTION("Postgres")
    {
        Config cfg(getTestConfig(5, Config::TESTDB_IN_MEMORY));
        cfg.DATABASE.value = "postgresql://dbname=txsetpersist";
        REQUIRE_FALSE(Database::canUseMiscDB(cfg));
    }
#endif
}

TEST_CASE("tx-set persistence pool opens after database recreation",
          "[herder][txsetpersist]")
{
    TmpDir tmpDir("txset-persist-db-recreation");
    Config cfg(getTestConfig(6, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.DATABASE = SecretValue{"sqlite3://" + tmpDir.getName() + "/stellar.db"};
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;

    auto checkMiscSchema = [](Application& app) {
        int count = 0;
        app.getDatabase().getRawMiscSession()
            << "SELECT COUNT(*) FROM scphistory",
            soci::into(count);
        REQUIRE(count == 0);
    };

    // Create the files once, then force Application::initialize to remove and
    // recreate them while constructing the second application. A pool opened
    // before initialization would remain attached to the unlinked old file.
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg);
        checkMiscSchema(*app);
    }

    {
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg);
        checkMiscSchema(*app);

        auto& herder = static_cast<HerderImpl&>(app->getHerder());
        auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
        auto txSet = makeTestTxSet(*app, lcl.hash);
        auto hash = txSet->getContentsHash();
        herder.getPendingEnvelopes().putTxSet(hash, lcl.header.ledgerSeq + 1,
                                              txSet);
        herder.getTxSetPersistor().drain();
        REQUIRE(app->getPersistentState().hasTxSet(hash));
    }
}

TEST_CASE("tx-set persistence restart ownership and orphan cleanup",
          "[herder][txsetpersist]")
{
    TmpDir tmpDir("txset-persist-restart");
    Config cfg(getTestConfig(7, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.DATABASE = SecretValue{"sqlite3://" + tmpDir.getName() + "/stellar.db"};
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;

    Hash orphanHash;
    Hash referencedHash;
    {
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg);
        auto& herder = static_cast<HerderImpl&>(app->getHerder());
        auto& persistor = herder.getTxSetPersistor();
        auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
        auto slot = lcl.header.ledgerSeq + 1;

        auto orphan = makeTestTxSet(*app, lcl.hash);
        auto referenced =
            makeTestTxSet(*app, sha256("restored wrong previous ledger"));
        orphanHash = orphan->getContentsHash();
        referencedHash = referenced->getContentsHash();
        herder.getPendingEnvelopes().putTxSet(orphanHash, slot, orphan);
        herder.getPendingEnvelopes().putTxSet(referencedHash, slot, referenced);

        auto envelope =
            makeNominationEnvelope(herder, *app, slot, {referencedHash});
        installLatestEnvelope(herder, envelope);
        herder.getHerderSCPDriver().emitEnvelope(envelope);
        persistor.drain();

        REQUIRE(app->getPersistentState().hasTxSet(orphanHash));
        REQUIRE(app->getPersistentState().hasTxSet(referencedHash));
    }

    {
        VirtualClock clock;
        auto app = createTestApplication(clock, cfg, /*newDB=*/false);
        auto& herder = static_cast<HerderImpl&>(app->getHerder());
        auto& persistor = herder.getTxSetPersistor();
        auto& persistentState = app->getPersistentState();
        auto& persistTimer =
            app->getMetrics().NewTimer({"herder", "txset", "persist"});
        auto& discardMeter = app->getMetrics().NewMeter(
            {"herder", "txset", "persist-discard"}, "txset");

        // Startup mark-and-sweep removes the orphan, while restore loads the
        // referenced body without scheduling another persistence task.
        REQUIRE_FALSE(persistentState.hasTxSet(orphanHash));
        REQUIRE(persistentState.hasTxSet(referencedHash));
        REQUIRE(persistTimer.count() == 0);
        REQUIRE(persistor.getState(referencedHash) ==
                TxSetPersistor::State::NONE);

        auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
        xdr::xvector<UpgradeType, 6> upgrades;
        auto stellarValue = herder.makeStellarValue(
            referencedHash, lcl.header.scpValue.closeTime + 1, upgrades,
            app->getConfig().NODE_SEED);
        auto validation = herder.getHerderSCPDriver().validateValue(
            lcl.header.ledgerSeq + 1, xdr::xdr_to_opaque(stellarValue), true);
        REQUIRE(validation != SCPDriver::kFullyValidatedValue);
        persistor.drain();

        // The failed validation has no registry-owned write to discard, so it
        // must not remove the body referenced by restored SCP state.
        REQUIRE(discardMeter.count() == 0);
        REQUIRE(persistentState.hasTxSet(referencedHash));
    }
}

TEST_CASE("shutdown drains queued tx-set persistence", "[herder][txsetpersist]")
{
    TmpDir tmpDir("txset-persist-shutdown");
    Config cfg(getTestConfig(8, Config::TESTDB_BUCKET_DB_PERSISTENT));
    cfg.DATABASE = SecretValue{"sqlite3://" + tmpDir.getName() + "/stellar.db"};
    cfg.EXPERIMENTAL_BACKGROUND_TX_SET_PERSIST = true;

    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());

    std::mutex mutex;
    std::condition_variable cond;
    bool blockerStarted = false;
    bool beginShutdown = false;
    bool releaseBlocker = false;
    REQUIRE(app->postOnTxSetPersistThread(
        [&]() {
            std::unique_lock<std::mutex> lock(mutex);
            blockerStarted = true;
            cond.notify_all();
            cond.wait(lock, [&]() { return releaseBlocker; });
        },
        "block tx-set persistence for shutdown test"));

    {
        std::unique_lock<std::mutex> lock(mutex);
        cond.wait(lock, [&]() { return blockerStarted; });
    }

    auto const& lcl = app->getLedgerManager().getLastClosedLedgerHeader();
    auto txSet = makeTestTxSet(*app, lcl.hash);
    auto hash = txSet->getContentsHash();
    herder.getPendingEnvelopes().putTxSet(hash, lcl.header.ledgerSeq + 1,
                                          txSet);

    std::thread releaseThread([&]() {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&]() { return beginShutdown; });
        }
        // Give the main thread time to enter ApplicationImpl::joinAllThreads;
        // the write remains queued behind the blocker until then.
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        std::lock_guard<std::mutex> lock(mutex);
        releaseBlocker = true;
        cond.notify_all();
    });

    {
        std::lock_guard<std::mutex> lock(mutex);
        beginShutdown = true;
        cond.notify_all();
    }
    app.reset();
    releaseThread.join();

    soci::session session;
    session.open(Database::getMiscDBName(cfg.DATABASE.value));
    auto stateName = "txset" + binToHex(hash);
    int count = 0;
    session << "SELECT COUNT(*) FROM slotstate WHERE statename = :n",
        soci::use(stateName), soci::into(count);
    REQUIRE(count == 1);
}
