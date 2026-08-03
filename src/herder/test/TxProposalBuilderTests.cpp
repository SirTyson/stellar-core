// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/Herder.h"
#include "herder/TxProposalBuilder.h"
#include "main/Application.h"
#include "main/Config.h"
#include "test/Catch2.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "util/MetricsRegistry.h"

#include <thread>

namespace stellar
{
namespace
{
using namespace txtest;

TEST_CASE("TxProposalBuilder basic operation", "[herder][proposalbuilder]")
{
    Config cfg(getTestConfig());
    VirtualClock clock;
    Application::pointer app = createTestApplication(clock, cfg);
    auto root = app->getRoot();

    auto makeTx = [&](TestAccount& source, SequenceNumber seq, int64_t fee) {
        return transactionFromOperations(
            *app, source.getSecretKey(), seq,
            {createAccount(getAccount(std::to_string(fee)).getPublicKey(), 1)},
            static_cast<uint32_t>(fee));
    };

    TxProposalBuilder builder;
    builder.setEnabled(true);

    auto acctA = root->create("A", app->getLedgerManager().getLastMinBalance(
                                        2) *
                                        100);
    auto acctB = root->create("B", app->getLedgerManager().getLastMinBalance(
                                        2) *
                                        100);
    auto seqA = acctA.getLastSequenceNumber();
    auto seqB = acctB.getLastSequenceNumber();

    SECTION("add and snapshot, chains in sequence order")
    {
        auto tx2 = makeTx(acctA, seqA + 2, 300);
        auto tx1 = makeTx(acctA, seqA + 1, 200);
        auto txB = makeTx(acctB, seqB + 1, 400);
        // Insert out of order; snapshot must return A's chain seq-ascending.
        builder.addTransaction(tx2);
        builder.addTransaction(tx1);
        builder.addTransaction(txB);
        REQUIRE(builder.size() == 3);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 3);
        REQUIRE(soroban.empty());

        // Find A's txs; they must appear in ascending seq order.
        std::vector<SequenceNumber> aSeqs;
        for (auto const& tx : classic)
        {
            if (tx->getSourceID() == acctA.getPublicKey())
            {
                aSeqs.push_back(tx->getSeqNum());
            }
        }
        REQUIRE(aSeqs == std::vector<SequenceNumber>{seqA + 1, seqA + 2});
    }

    SECTION("duplicate hash is ignored")
    {
        auto tx = makeTx(acctA, seqA + 1, 200);
        builder.addTransaction(tx);
        builder.addTransaction(tx);
        REQUIRE(builder.size() == 1);
    }

    SECTION("same (account, seq): only strictly higher fee rate replaces")
    {
        auto cheap = makeTx(acctA, seqA + 1, 200);
        auto rich = makeTx(acctA, seqA + 1, 500);
        builder.addTransaction(cheap);
        builder.addTransaction(rich);
        REQUIRE(builder.size() == 1);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == rich->getFullHash());

        // A lower-fee replacement is rejected.
        builder.addTransaction(cheap);
        classic.clear();
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == rich->getFullHash());
    }

    SECTION("tentative replacement cannot permanently displace validated tx")
    {
        auto validated = makeTx(acctA, seqA + 1, 200);
        auto tentative = makeTx(acctA, seqA + 1, 500);
        builder.addTransaction(validated);
        builder.addTentativeTransaction(tentative);
        REQUIRE(builder.size() == 2);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == tentative->getFullHash());

        // A failed gate verdict removes only the tentative shadow and reveals
        // the validated incumbent again.
        builder.removeTentativeTransaction(tentative->getFullHash());
        REQUIRE(builder.size() == 1);
        classic.clear();
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == validated->getFullHash());
    }

    SECTION("successful verdict promotes tentative gate frame")
    {
        auto submitted = makeTx(acctA, seqA + 1, 500);
        auto gateFrame = TransactionFrameBase::makeTransactionFromWire(
            app->getNetworkID(), submitted->getEnvelope());
        builder.addTentativeTransaction(submitted);
        builder.addTransaction(gateFrame);

        // Promotion replaces the pre-verdict frame rather than deduplicating
        // against it. A later failure cleanup is therefore a no-op.
        REQUIRE(builder.size() == 1);
        builder.removeTentativeTransaction(submitted->getFullHash());
        REQUIRE(builder.size() == 1);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0] == gateFrame);
    }

    SECTION("tentative and validated sequences merge in chain order")
    {
        auto seq2 = makeTx(acctA, seqA + 2, 300);
        auto seq1 = makeTx(acctA, seqA + 1, 200);
        builder.addTransaction(seq2);
        builder.addTentativeTransaction(seq1);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 2);
        REQUIRE(classic[0]->getSeqNum() == seqA + 1);
        REQUIRE(classic[1]->getSeqNum() == seqA + 2);
    }

    SECTION("tentative capacity never evicts validated candidates")
    {
        auto validated = makeTx(acctA, seqA + 1, 200);
        auto tentative1 = makeTx(acctB, seqB + 1, 500);
        auto tentative2 = makeTx(acctB, seqB + 2, 1000);
        builder.setCapacityAndSweep(1);
        builder.addTransaction(validated);
        builder.addTentativeTransaction(tentative1);
        REQUIRE(builder.size() == 1);
        builder.addTentativeTransaction(tentative2);

        // Validated entries consume capacity first, so tentative submissions
        // are dropped without disturbing validated state.
        REQUIRE(builder.size() == 1);
        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == validated->getFullHash());
    }

    SECTION("removal keeps same-account successors")
    {
        auto tx1 = makeTx(acctA, seqA + 1, 200);
        auto tx2 = makeTx(acctA, seqA + 2, 300);
        builder.addTransaction(tx1);
        builder.addTransaction(tx2);
        builder.removeTransactions({tx1->getFullHash()});
        REQUIRE(builder.size() == 1);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == tx2->getFullHash());
    }

    SECTION("capacity eviction drops the lowest-fee-rate chain tail")
    {
        auto cheap1 = makeTx(acctA, seqA + 1, 150);
        auto cheap2 = makeTx(acctA, seqA + 2, 5000);
        auto rich = makeTx(acctB, seqB + 1, 1000);
        builder.addTransaction(cheap1);
        builder.addTransaction(cheap2);
        builder.addTransaction(rich);
        REQUIRE(builder.size() == 3);

        // Shrinking capacity to 2 evicts the globally-cheapest tx (A, seq+1)
        // together with its now-unusable successor (A, seq+2) even though
        // that successor outbids B: a chain missing its head cannot apply.
        builder.setCapacityAndSweep(2);
        REQUIRE(builder.size() == 1);

        TxFrameList classic, soroban;
        builder.snapshot(classic, soroban);
        REQUIRE(classic.size() == 1);
        REQUIRE(classic[0]->getFullHash() == rich->getFullHash());
    }

    SECTION("disabled builder ignores additions")
    {
        builder.setEnabled(false);
        builder.addTransaction(makeTx(acctA, seqA + 1, 200));
        REQUIRE(builder.size() == 0);
    }

    SECTION("concurrent insertion is safe and lossless")
    {
        // Distinct accounts per thread so insertions cannot collide on
        // (account, seq) replacement.
        std::vector<TestAccount> accounts;
        std::vector<TransactionFrameBasePtr> txs;
        size_t const perThread = 20;
        size_t const numThreads = 4;
        for (size_t t = 0; t < numThreads; ++t)
        {
            accounts.push_back(root->create(
                "acct" + std::to_string(t),
                app->getLedgerManager().getLastMinBalance(2) * 100));
        }
        for (size_t t = 0; t < numThreads; ++t)
        {
            auto seq = accounts[t].getLastSequenceNumber();
            for (size_t i = 0; i < perThread; ++i)
            {
                txs.push_back(makeTx(accounts[t], seq + 1 + i,
                                     200 + static_cast<int64_t>(i)));
            }
        }
        std::vector<std::thread> threads;
        for (size_t t = 0; t < numThreads; ++t)
        {
            threads.emplace_back([&builder, &txs, t]() {
                for (size_t i = 0; i < perThread; ++i)
                {
                    builder.addTransaction(txs[t * perThread + i]);
                }
            });
        }
        for (auto& th : threads)
        {
            th.join();
        }
        REQUIRE(builder.size() == numThreads * perThread);
    }
}

TEST_CASE("rejected local submission leaves proposal builder",
          "[herder][proposalbuilder]")
{
    Config cfg(getTestConfig());
    VirtualClock clock;
    Application::pointer app = createTestApplication(clock, cfg);
    auto missing = SecretKey::pseudoRandomForTesting();
    auto invalid = transactionFromOperations(
        *app, missing, 1, {payment(*app->getRoot(), 1)}, 100);
    auto& builder = app->getHerder().getTxProposalBuilder();

    REQUIRE(app->getHerder().recvTransaction(invalid, true) ==
            TxSubmitStatus::TX_STATUS_PENDING);
    REQUIRE(builder.size() == 1);

    testutil::crankUntil(
        app, [&]() { return builder.size() == 0; }, std::chrono::seconds(5));
    REQUIRE(builder.size() == 0);
}

// Pre-built proposals (docs/direct-leader-flooding.md): with a single-node
// quorum and FLOOD_LEADER_COUNT=1, this validator is always the round-1
// leader, so every apply-finish pre-builds the next slot's proposal and every
// trigger reuses it (the manual-close close-time offset is 1 second, inside
// the pre-trim window [1, U]).
TEST_CASE("round-1 leader pre-builds proposal at apply-finish and trigger "
          "reuses it",
          "[herder][proposalbuilder]")
{
    VirtualClock clock;
    Config cfg(getTestConfig());
    cfg.FLOOD_LEADER_COUNT = 1;
    Application::pointer app = createTestApplication(clock, cfg);

    auto& preBuilt =
        app->getMetrics().NewMeter({"scp", "prebuild", "built"}, "txset");
    auto& reused =
        app->getMetrics().NewMeter({"scp", "prebuild", "reused"}, "txset");
    auto& stale =
        app->getMetrics().NewMeter({"scp", "prebuild", "stale"}, "txset");
    auto& candidateBuild = app->getMetrics().NewMeter(
        {"scp", "txset", "candidate-build"}, "txset");

    // Prime: the first close's apply-finish pre-builds for the next slot.
    app->manualClose(std::nullopt, std::nullopt);
    auto preBuiltAfterFirst = preBuilt.count();
    REQUIRE(preBuiltAfterFirst >= 1);

    auto reusedBefore = reused.count();
    auto candidateBefore = candidateBuild.count();
    app->manualClose(std::nullopt, std::nullopt);

    // The second close's trigger reused the proposal pre-built at the first
    // close's apply-finish -- and still counts as a candidate-path proposal.
    REQUIRE(reused.count() == reusedBefore + 1);
    REQUIRE(candidateBuild.count() == candidateBefore + 1);
    REQUIRE(stale.count() == 0);
    // And that close's apply-finish pre-built the next one.
    REQUIRE(preBuilt.count() == preBuiltAfterFirst + 1);
}

// Outside the candidate window nothing is pre-built: FLOOD_LEADER_COUNT=0
// excludes the sole validator from round-1 leadership.
TEST_CASE("non-leader does not pre-build proposals",
          "[herder][proposalbuilder]")
{
    VirtualClock clock;
    Config cfg(getTestConfig());
    cfg.FLOOD_LEADER_COUNT = 0;
    Application::pointer app = createTestApplication(clock, cfg);

    auto& preBuilt =
        app->getMetrics().NewMeter({"scp", "prebuild", "built"}, "txset");

    app->manualClose(std::nullopt, std::nullopt);
    app->manualClose(std::nullopt, std::nullopt);

    REQUIRE(preBuilt.count() == 0);
}

} // namespace
} // namespace stellar
