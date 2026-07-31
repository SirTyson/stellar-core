// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/Hex.h"
#include "herder/Herder.h"
#include "herder/HerderImpl.h"
#include "herder/TxSetFrame.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "main/Config.h"
#include "test/Catch2.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "util/MetricsRegistry.h"

namespace stellar
{
namespace
{
using namespace txtest;

// Eager receiver-side TX set validation (docs/direct-leader-flooding.md): an
// unsolicited set whose parent is the current LCL is validated on intake --
// applicable frame built, validity proven across the conservative close-time
// window -- so a later referencing envelope validates from cache.
TEST_CASE("unsolicited TX set is eagerly validated on intake",
          "[herder][eagertxset]")
{
    VirtualClock clock;
    Config cfg(getTestConfig());
    Application::pointer app = createTestApplication(clock, cfg);
    auto root = app->getRoot();
    auto& herder = app->getHerder();

    auto& eagerValidated = app->getMetrics().NewMeter(
        {"scp", "txset", "eager-validated"}, "txset");
    auto& eagerDeferred = app->getMetrics().NewMeter(
        {"scp", "txset", "eager-deferred"}, "txset");

    auto makeValidTxSet = [&]() {
        auto tx = transactionFromOperations(
            *app, root->getSecretKey(), root->nextSequenceNumber(),
            {createAccount(getAccount("eager").getPublicKey(),
                           app->getLedgerManager().getLastMinBalance(2))},
            1000);
        PerPhaseTransactionList phases;
        phases.emplace_back(TxFrameList{tx});
        phases.emplace_back(TxFrameList{});
        PerPhaseTransactionList invalid;
        invalid.resize(phases.size());
        auto [xdrSet, applicable] =
            makeTxSetFromTransactions(phases, *app, 0, 0, invalid);
        REQUIRE(applicable);
        REQUIRE(applicable->sizeTxTotal() == 1);
        return xdrSet;
    };

    SECTION("valid set is validated once, idempotently")
    {
        auto txSet = makeValidTxSet();
        auto hash = txSet->getContentsHash();

        REQUIRE(eagerValidated.count() == 0);
        REQUIRE(herder.recvTxSet(hash, txSet));
        REQUIRE(eagerValidated.count() == 1);
        REQUIRE(eagerDeferred.count() == 0);
        REQUIRE(herder.getTxSet(hash) != nullptr);

        // Duplicate delivery does not re-validate.
        REQUIRE(herder.recvTxSet(hash, txSet));
        REQUIRE(eagerValidated.count() == 1);
    }

    SECTION("mismatched announced hash is rejected")
    {
        auto txSet = makeValidTxSet();
        Hash wrongHash = txSet->getContentsHash();
        wrongHash[0] ^= 0xFF;

        REQUIRE(!herder.recvTxSet(wrongHash, txSet));
        REQUIRE(herder.getTxSet(wrongHash) == nullptr);
        REQUIRE(eagerValidated.count() == 0);
    }

    SECTION("set with a stale parent ledger is parked, not mis-validated")
    {
        auto txSet = makeValidTxSet();
        auto hash = txSet->getContentsHash();

        // Advance the LCL so the set's parent no longer matches.
        app->manualClose(std::nullopt, std::nullopt);

        REQUIRE(herder.recvTxSet(hash, txSet));
        REQUIRE(eagerValidated.count() == 0);
        REQUIRE(eagerDeferred.count() == 1);
        // Still stored and retrievable; validation falls back to on-demand.
        REQUIRE(herder.getTxSet(hash) != nullptr);
    }
}

} // namespace
} // namespace stellar
