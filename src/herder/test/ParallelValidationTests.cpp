// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SecretKey.h"
#include "herder/TxFloodValidation.h"
#include "herder/TxSetFrame.h"
#include "herder/TxSetUtils.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"
#include "main/Config.h"
#include "test/Catch2.h"
#include "test/TestAccount.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "transactions/TransactionBridge.h"
#include "transactions/TransactionFrameBase.h"
#include "util/UnorderedMap.h"
#include "util/UnorderedSet.h"
#include "util/XDROperators.h"

#include <chrono>
#include <future>
#include <iostream>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace stellar
{
namespace
{
using namespace txtest;

// RAII guard that forces the serial reference path for the duration of a
// scope and always restores the default (parallel) afterwards, so no test
// leaks the override into a later one.
class ForceSerialGuard
{
  public:
    explicit ForceSerialGuard(bool force)
    {
        TxSetUtils::gForceSerialValidation = force;
    }
    ~ForceSerialGuard()
    {
        TxSetUtils::gForceSerialValidation = false;
    }
};

// Compare two tx lists by hash and order (the invalid list must be identical,
// in the same order, between the serial and parallel paths).
bool
sameTxOrder(TxFrameList const& a, TxFrameList const& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i)
    {
        if (!(a[i]->getFullHash() == b[i]->getFullHash()))
        {
            return false;
        }
    }
    return true;
}

// Compare two accountFeeMap outputs for exact equality.
bool
sameFeeMap(UnorderedMap<AccountID, int64_t> const& a,
           UnorderedMap<AccountID, int64_t> const& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (auto const& [k, v] : a)
    {
        auto it = b.find(k);
        if (it == b.end() || it->second != v)
        {
            return false;
        }
    }
    return true;
}

// Run getInvalidTxListWithErrors on `txs`, returning the invalid list, the
// aggregate error code, and the populated accountFeeMap.
std::tuple<TxFrameList, TxSetValidationResult, UnorderedMap<AccountID, int64_t>>
runValidation(Application& app, TxFrameList const& txs, bool forceSerial)
{
    ForceSerialGuard guard(forceSerial);
    UnorderedMap<AccountID, int64_t> feeMap;
    auto result =
        TxSetUtils::getInvalidTxListWithErrors(txs, app, feeMap, 0, 0);
    return {std::move(result.first), result.second, std::move(feeMap)};
}

Application::pointer
makeParallelValidationApp(VirtualClock& clock)
{
    Config cfg(getTestConfig());
    cfg.LEDGER_PROTOCOL_VERSION = Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION =
        Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    Application::pointer app = createTestApplication(clock, cfg);
    // The parallel path is only exercised against a bucket-list snapshot; the
    // in-memory ledger mode falls back to the serial path.
    REQUIRE(!app->getConfig().MODE_USES_IN_MEMORY_LEDGER);
    REQUIRE(app->getTxValidationThreadCount() > 0);
    return app;
}

} // namespace

TEST_CASE("parallel getInvalidTxListWithErrors matches serial reference",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;

    auto fund = [&](std::string const& prefix, int count) {
        std::vector<std::string> names;
        names.reserve(count);
        for (int i = 0; i < count; ++i)
        {
            names.push_back(prefix + std::to_string(i));
        }
        return root->createBatch(names, stdBalance);
    };

    // 40 distinct funded sources, each with a single valid payment. This is
    // >= MIN_TXS_FOR_PARALLEL_VALIDATION (32), so the parallel fan-out runs.
    auto accounts = fund("acct", 40);
    TxFrameList validTxs;
    validTxs.reserve(accounts.size());
    for (auto& acct : accounts)
    {
        validTxs.push_back(acct.tx({payment(*root, 1)}));
    }

    SECTION("all valid - empty invalid list, identical fee maps")
    {
        auto [invSerial, errSerial, feeSerial] =
            runValidation(*app, validTxs, /*forceSerial=*/true);
        auto [invPar, errPar, feePar] =
            runValidation(*app, validTxs, /*forceSerial=*/false);

        REQUIRE(invSerial.empty());
        REQUIRE(invPar.empty());
        REQUIRE(errSerial == TxSetValidationResult::VALID);
        REQUIRE(errPar == TxSetValidationResult::VALID);

        // Each account fee-sources exactly one base-fee (100 stroop) tx.
        REQUIRE(feePar.size() == accounts.size());
        for (auto const& entry : feePar)
        {
            REQUIRE(entry.second == 100);
        }
        REQUIRE(sameFeeMap(feeSerial, feePar));
    }

    SECTION("bad signature - TX_VALIDATION_FAILED in both paths")
    {
        // A structurally valid tx whose signature is corrupted (a flipped
        // byte) fails pass-1 checkValid.
        auto badAccount = root->create("badsig", stdBalance);
        auto badTx = badAccount.tx({payment(*root, 1)});
        auto& sigs = txbridge::getSignatures(badTx->getMutableEnvelope());
        REQUIRE(!sigs.empty());
        REQUIRE(!sigs[0].signature.empty());
        sigs[0].signature[0] ^= 0xFF;
        badTx->clearCached();

        TxFrameList txs = validTxs;
        txs.push_back(badTx);

        auto [invSerial, errSerial, feeSerial] =
            runValidation(*app, txs, /*forceSerial=*/true);
        auto [invPar, errPar, feePar] =
            runValidation(*app, txs, /*forceSerial=*/false);

        REQUIRE(errSerial == TxSetValidationResult::TX_VALIDATION_FAILED);
        REQUIRE(errPar == TxSetValidationResult::TX_VALIDATION_FAILED);
        REQUIRE(invPar.size() == 1);
        REQUIRE(invPar[0]->getFullHash() == badTx->getFullHash());

        REQUIRE(sameTxOrder(invSerial, invPar));
        REQUIRE(sameFeeMap(feeSerial, feePar));
    }
}

TEST_CASE("parallel getInvalidTxListWithErrors - per-fee-source accumulation",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;
    int64_t const minBalance0 = app->getLedgerManager().getLastMinBalance(0);
    int64_t const outerFee = 1000;
    int const numFeeBumps = 10;

    auto fund = [&](std::string const& prefix, int count, int64_t balance) {
        std::vector<std::string> names;
        names.reserve(count);
        for (int i = 0; i < count; ++i)
        {
            names.push_back(prefix + std::to_string(i));
        }
        return root->createBatch(names, balance);
    };

    // 30 unrelated valid txs pad the input past the parallel threshold; each
    // fee-sources its own tx so they never interact with the fee-bump source.
    auto padAccounts = fund("pad", 30, stdBalance);
    TxFrameList validTxs;
    for (auto& acct : padAccounts)
    {
        validTxs.push_back(acct.tx({payment(*root, 1)}));
    }

    // One fee source that can pay any single fee bump (available == 3*outerFee)
    // but NOT the sum of all `numFeeBumps` of them.
    auto poor = root->create("poorFeeSource", minBalance0 + 3 * outerFee);
    auto innerAccounts = fund("inner", numFeeBumps, stdBalance);
    TxFrameList feeBumps;
    for (auto& inner : innerAccounts)
    {
        auto innerTx = inner.tx({payment(*root, 1)});
        feeBumps.push_back(feeBump(*app, poor, innerTx, outerFee));
    }

    // Baseline: confirm the fee-bump construction is otherwise valid, i.e. each
    // one is individually affordable and passes checkValid on its own. Without
    // this, an over-spend result could be a false positive from a bad build.
    for (auto const& fb : feeBumps)
    {
        auto [inv, err, feeMap] =
            runValidation(*app, TxFrameList{fb}, /*forceSerial=*/false);
        REQUIRE(inv.empty());
        REQUIRE(err == TxSetValidationResult::VALID);
    }

    SECTION("sum exceeds balance - all ACCOUNT_CANT_PAY_FEE")
    {
        TxFrameList txs = validTxs;
        txs.insert(txs.end(), feeBumps.begin(), feeBumps.end());

        auto [invSerial, errSerial, feeSerial] =
            runValidation(*app, txs, /*forceSerial=*/true);
        auto [invPar, errPar, feePar] =
            runValidation(*app, txs, /*forceSerial=*/false);

        REQUIRE(errPar == TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
        // All (and only) the fee bumps are rejected.
        REQUIRE(invPar.size() == static_cast<size_t>(numFeeBumps));
        UnorderedSet<Hash> feeBumpHashes;
        for (auto const& fb : feeBumps)
        {
            feeBumpHashes.insert(fb->getFullHash());
        }
        for (auto const& tx : invPar)
        {
            REQUIRE(feeBumpHashes.count(tx->getFullHash()) == 1);
            REQUIRE(tx->getFeeSourceID() == poor.getPublicKey());
        }
        // The accumulated fee for the poor source is the full sum.
        REQUIRE(feePar[poor.getPublicKey()] == numFeeBumps * outerFee);

        REQUIRE(errSerial == errPar);
        REQUIRE(sameTxOrder(invSerial, invPar));
        REQUIRE(sameFeeMap(feeSerial, feePar));
    }

    SECTION("pass-1 failure takes priority over pass-2 fee failure")
    {
        // Corrupt-signature tx (pass-1 failure) mixed with the over-spending
        // fee bumps (pass-2 failure). TX_VALIDATION_FAILED must win.
        auto badAccount = root->create("badsig", stdBalance);
        auto badTx = badAccount.tx({payment(*root, 1)});
        auto& sigs = txbridge::getSignatures(badTx->getMutableEnvelope());
        REQUIRE(!sigs.empty());
        REQUIRE(!sigs[0].signature.empty());
        sigs[0].signature[0] ^= 0xFF;
        badTx->clearCached();

        TxFrameList txs = validTxs;
        txs.insert(txs.end(), feeBumps.begin(), feeBumps.end());
        txs.push_back(badTx);

        auto [invSerial, errSerial, feeSerial] =
            runValidation(*app, txs, /*forceSerial=*/true);
        auto [invPar, errPar, feePar] =
            runValidation(*app, txs, /*forceSerial=*/false);

        REQUIRE(errPar == TxSetValidationResult::TX_VALIDATION_FAILED);
        // pass-1 failure (bad sig) + pass-2 failures (the fee bumps).
        REQUIRE(invPar.size() == static_cast<size_t>(numFeeBumps + 1));

        REQUIRE(errSerial == errPar);
        REQUIRE(sameTxOrder(invSerial, invPar));
        REQUIRE(sameFeeMap(feeSerial, feePar));
    }
}

TEST_CASE("parallel getInvalidTxListWithErrors is deterministic",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;
    int64_t const minBalance0 = app->getLedgerManager().getLastMinBalance(0);
    int64_t const outerFee = 1000;
    int const numFeeBumps = 10;

    auto fund = [&](std::string const& prefix, int count, int64_t balance) {
        std::vector<std::string> names;
        names.reserve(count);
        for (int i = 0; i < count; ++i)
        {
            names.push_back(prefix + std::to_string(i));
        }
        return root->createBatch(names, balance);
    };

    // 50 total txs (>= 32): 40 valid plus 10 over-spending fee bumps, so both
    // the invalid list and the fee map are non-trivial. (Keep each createBatch
    // at <= 40 accounts: one batch is a single tx and must fit the test
    // ledger's op limit.)
    auto padAccounts = fund("pad", 40, stdBalance);
    TxFrameList txs;
    for (auto& acct : padAccounts)
    {
        txs.push_back(acct.tx({payment(*root, 1)}));
    }
    auto poor = root->create("poorFeeSource", minBalance0 + 3 * outerFee);
    auto innerAccounts = fund("inner", numFeeBumps, stdBalance);
    for (auto& inner : innerAccounts)
    {
        auto innerTx = inner.tx({payment(*root, 1)});
        txs.push_back(feeBump(*app, poor, innerTx, outerFee));
    }
    REQUIRE(txs.size() == 50);

    // Run the parallel path 5 times; every run must produce byte-for-byte the
    // same invalid list (contents + order), error code, and fee map.
    auto [inv0, err0, fee0] = runValidation(*app, txs, /*forceSerial=*/false);
    REQUIRE(err0 == TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
    REQUIRE(inv0.size() == static_cast<size_t>(numFeeBumps));

    for (int run = 0; run < 5; ++run)
    {
        auto [inv, err, fee] = runValidation(*app, txs, /*forceSerial=*/false);
        REQUIRE(err == err0);
        REQUIRE(sameTxOrder(inv, inv0));
        REQUIRE(sameFeeMap(fee, fee0));
    }
}

TEST_CASE("parallel buildTxFramesParallel matches serial construction",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    // 120 distinct wire envelopes (>= 32 so the parallel path runs). These are
    // only decoded/hashed, never applied, so distinct payment amounts suffice.
    int const count = 120;
    std::vector<TransactionTestFramePtr> srcTxs;
    srcTxs.reserve(count);
    for (int i = 0; i < count; ++i)
    {
        srcTxs.push_back(root->tx({payment(*root, 1 + i)}));
    }
    std::vector<TransactionEnvelope const*> envelopes;
    envelopes.reserve(count);
    for (auto const& tx : srcTxs)
    {
        envelopes.push_back(&tx->getEnvelope());
    }

    TxFrameList serialFrames;
    TxFrameList parallelFrames;
    {
        ForceSerialGuard guard(true);
        serialFrames = TxSetUtils::buildTxFramesParallel(app->getNetworkID(),
                                                         envelopes, *app);
    }
    {
        ForceSerialGuard guard(false);
        parallelFrames = TxSetUtils::buildTxFramesParallel(app->getNetworkID(),
                                                           envelopes, *app);
    }

    REQUIRE(serialFrames.size() == static_cast<size_t>(count));
    REQUIRE(parallelFrames.size() == static_cast<size_t>(count));
    for (int i = 0; i < count; ++i)
    {
        // Order preserved and frames identical to serial construction and to
        // the source envelope at the same index.
        REQUIRE(parallelFrames[i]->getFullHash() ==
                serialFrames[i]->getFullHash());
        REQUIRE(parallelFrames[i]->getFullHash() == srcTxs[i]->getFullHash());
    }
}

// Opt-in timing comparison (run with: stellar-core test "[parallelbench]").
// Reports serial vs parallel wall time for the same input; asserts only a
// loose sanity bound so CI noise can't flake it.
TEST_CASE("parallel validation benchmark", "[!hide][parallelbench]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;
    int const count = 500;

    // Create accounts in <= 40-account batches: one batch is a single tx and
    // must fit the test ledger's op limit.
    std::vector<TestAccount> accounts;
    accounts.reserve(count);
    for (int base = 0; base < count; base += 40)
    {
        std::vector<std::string> names;
        for (int i = base; i < std::min(count, base + 40); ++i)
        {
            names.push_back("bench" + std::to_string(i));
        }
        auto batch = root->createBatch(names, stdBalance);
        for (auto& acct : batch)
        {
            accounts.emplace_back(acct);
        }
    }
    TxFrameList txs;
    txs.reserve(count);
    for (auto& acct : accounts)
    {
        txs.push_back(acct.tx({payment(*root, 1)}));
    }

    auto timeRun = [&](bool forceSerial) {
        // Fresh frames each run so lazy hash caching doesn't skew timing;
        // the global signature cache is cleared for the same reason.
        TxFrameList freshTxs;
        freshTxs.reserve(txs.size());
        for (auto const& tx : txs)
        {
            freshTxs.push_back(TransactionFrameBase::makeTransactionFromWire(
                app->getNetworkID(), tx->getEnvelope()));
        }
        PubKeyUtils::clearVerifySigCache();
        auto start = std::chrono::steady_clock::now();
        auto [inv, err, feeMap] = runValidation(*app, freshTxs, forceSerial);
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start);
        REQUIRE(inv.empty());
        REQUIRE(err == TxSetValidationResult::VALID);
        return elapsed;
    };

    // Warm up bucket caches once, then measure.
    timeRun(true);
    auto serialUs = timeRun(true);
    auto parallelUs = timeRun(false);

    std::cout << "parallel validation benchmark (" << count
              << " txs): serial=" << serialUs.count()
              << "us parallel=" << parallelUs.count() << "us ("
              << app->getTxValidationThreadCount() << " threads, speedup="
              << (parallelUs.count() > 0
                      ? static_cast<double>(serialUs.count()) /
                            static_cast<double>(parallelUs.count())
                      : 0.0)
              << "x)" << std::endl;

    // Loose sanity bound only: the parallel path must not be dramatically
    // slower than serial (allows scheduler noise on loaded CI machines).
    REQUIRE(parallelUs.count() < serialUs.count() * 2);
}

TEST_CASE("validateTxBatchForFlooding classifies a mixed batch",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;
    int64_t const minBalance0 = app->getLedgerManager().getLastMinBalance(0);

    auto senders = root->createBatch(
        std::vector<std::string>{"sendA", "sendB", "sendBad"}, stdBalance);

    std::vector<TransactionEnvelope> batch;

    // (a) Two valid payments from funded accounts -> expected verdict 1.
    batch.push_back(senders[0].tx({payment(*root, 1)})->getEnvelope());
    batch.push_back(senders[1].tx({payment(*root, 1)})->getEnvelope());

    // (b) Valid tx with a corrupted signature -> expected verdict 0.
    {
        auto tx = senders[2].tx({payment(*root, 1)});
        TransactionEnvelope env = tx->getEnvelope();
        auto& sigs = txbridge::getSignatures(env);
        REQUIRE(!sigs.empty());
        REQUIRE(!sigs[0].signature.empty());
        sigs[0].signature[0] ^= 0xFF;
        batch.push_back(env);
    }

    // (c) Source account does not exist -> expected verdict 0.
    {
        auto missing = SecretKey::random();
        auto tx = transactionFromOperations(*app, missing, /*seq=*/1,
                                            {payment(*root, 1)}, /*fee=*/100);
        batch.push_back(tx->getEnvelope());
    }

    // (d) Fee larger than the source's balance -> expected verdict 0.
    {
        auto broke = root->create("broke", minBalance0 + 500);
        auto tx = transactionFromOperations(
            *app, broke.getSecretKey(), broke.nextSequenceNumber(),
            {payment(*root, 1)}, /*fee=*/100000000);
        batch.push_back(tx->getEnvelope());
    }

    auto envelopes = std::make_shared<std::vector<TransactionEnvelope> const>(
        std::move(batch));

    std::promise<TxFloodVerdicts> promise;
    auto future = promise.get_future();
    validateTxBatchForFlooding(*app, envelopes,
                               [&promise](TxFloodVerdicts const& verdicts) {
                                   // Fires exactly once, on a tx-validation
                                   // pool thread.
                                   promise.set_value(verdicts);
                               });

    REQUIRE(future.wait_for(std::chrono::seconds(10)) ==
            std::future_status::ready);
    auto verdicts = future.get();

    REQUIRE(verdicts.size() == 5);
    REQUIRE(verdicts[0] == 1); // valid
    REQUIRE(verdicts[1] == 1); // valid
    REQUIRE(verdicts[2] == 0); // corrupted signature
    REQUIRE(verdicts[3] == 0); // missing source account
    REQUIRE(verdicts[4] == 0); // fee exceeds balance
}

TEST_CASE("validateTxBatchForFlooding admits short seqnum chains",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();

    int64_t const stdBalance =
        app->getLedgerManager().getLastMinBalance(2) + 1000000;
    auto sender = root->create("chainSender", stdBalance);

    // The mempool holds cross-ledger chains, so the gate must pass txs whose
    // seqnum is a short distance ahead of the account's current seqnum (their
    // predecessors are in flight); trimInvalid enforces exact order at
    // nomination. Stale and far-future seqnums must still be rejected.
    auto seqBase = sender.loadSequenceNumber();

    std::vector<TransactionEnvelope> batch;
    // Chain of 3: seq+1, seq+2, seq+3 -> all should flood.
    for (int i = 1; i <= 3; ++i)
    {
        batch.push_back(
            sender.tx({payment(*root, 1)}, seqBase + i)->getEnvelope());
    }
    // Stale: current seq (already used at creation) -> reject.
    batch.push_back(sender.tx({payment(*root, 1)}, seqBase)->getEnvelope());
    // Far future: beyond the allowed gap (64) -> reject.
    batch.push_back(
        sender.tx({payment(*root, 1)}, seqBase + 1000)->getEnvelope());

    auto envelopes = std::make_shared<std::vector<TransactionEnvelope> const>(
        std::move(batch));

    std::promise<TxFloodVerdicts> promise;
    auto future = promise.get_future();
    validateTxBatchForFlooding(*app, envelopes,
                               [&promise](TxFloodVerdicts const& verdicts) {
                                   promise.set_value(verdicts);
                               });

    REQUIRE(future.wait_for(std::chrono::seconds(10)) ==
            std::future_status::ready);
    auto verdicts = future.get();

    REQUIRE(verdicts.size() == 5);
    REQUIRE(verdicts[0] == 1); // seq+1: immediately valid
    REQUIRE(verdicts[1] == 1); // seq+2: chained, floods
    REQUIRE(verdicts[2] == 1); // seq+3: chained, floods
    REQUIRE(verdicts[3] == 0); // stale seq
    REQUIRE(verdicts[4] == 0); // beyond the chain gap
}

} // namespace stellar
