// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/SecretKey.h"
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

#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <tuple>
#include <vector>

namespace stellar
{
namespace
{
using namespace txtest;

using ValidationOutput =
    std::tuple<TxFrameList, TxSetValidationResult,
               UnorderedMap<AccountID, int64_t>>;

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

bool
sameTxOrder(TxFrameList const& a, TxFrameList const& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i)
    {
        if (a[i]->getFullHash() != b[i]->getFullHash())
        {
            return false;
        }
    }
    return true;
}

bool
sameFeeMap(UnorderedMap<AccountID, int64_t> const& a,
           UnorderedMap<AccountID, int64_t> const& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (auto const& [account, fee] : a)
    {
        auto it = b.find(account);
        if (it == b.end() || it->second != fee)
        {
            return false;
        }
    }
    return true;
}

ValidationOutput
runValidation(Application& app, TxFrameList const& txs, bool forceSerial,
              UnorderedMap<AccountID, int64_t> feeMap = {})
{
    ForceSerialGuard guard(forceSerial);
    auto result =
        TxSetUtils::getInvalidTxListWithErrors(txs, app, feeMap, 0, 0);
    return {std::move(result.first), result.second, std::move(feeMap)};
}

void
requireSame(ValidationOutput const& serial, ValidationOutput const& parallel)
{
    REQUIRE(std::get<1>(serial) == std::get<1>(parallel));
    REQUIRE(sameTxOrder(std::get<0>(serial), std::get<0>(parallel)));
    REQUIRE(sameFeeMap(std::get<2>(serial), std::get<2>(parallel)));
}

Application::pointer
makeParallelValidationApp(VirtualClock& clock, int threadCount = 8)
{
    Config cfg(getTestConfig());
    cfg.LEDGER_PROTOCOL_VERSION = Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION =
        Config::CURRENT_LEDGER_PROTOCOL_VERSION;
    cfg.TX_VALIDATION_THREADS = threadCount;
    auto app = createTestApplication(clock, cfg);
    // These guard rails prevent a parallel test from silently comparing the
    // serial path with itself.
    REQUIRE(!app->getConfig().MODE_USES_IN_MEMORY_LEDGER);
    REQUIRE(app->getTxValidationThreadCount() > 0);
    return app;
}

std::vector<TestAccount>
fundAccounts(TestAccount& root, std::string const& prefix, size_t count,
             int64_t balance)
{
    std::vector<TestAccount> accounts;
    accounts.reserve(count);
    for (size_t base = 0; base < count; base += 40)
    {
        std::vector<std::string> names;
        for (size_t i = base; i < std::min(count, base + 40); ++i)
        {
            names.emplace_back(prefix + std::to_string(i));
        }
        auto batch = root.createBatch(names, balance);
        for (auto& account : batch)
        {
            accounts.emplace_back(account);
        }
    }
    return accounts;
}

void
corruptSignature(TransactionFrameBasePtr const& tx)
{
    auto& signatures = txbridge::getSignatures(tx->getMutableEnvelope());
    REQUIRE(!signatures.empty());
    REQUIRE(!signatures[0].signature.empty());
    signatures[0].signature[0] ^= 0xFF;
    tx->clearCached();
}

TransactionFrameBasePtr
cloneFrame(Application& app, TransactionFrameBasePtr const& tx)
{
    return TransactionFrameBase::makeTransactionFromWire(
        app.getNetworkID(), tx->getEnvelope());
}

TxFrameList
makePayments(Application& app, TestAccount& root,
             std::vector<TestAccount>& accounts)
{
    TxFrameList txs;
    txs.reserve(accounts.size());
    for (auto& account : accounts)
    {
        txs.emplace_back(transactionFromOperations(
            app, account.getSecretKey(), account.loadSequenceNumber() + 1,
            {payment(root, 1)}, 100));
    }
    return txs;
}

} // namespace

TEST_CASE("parallel validation matches serial pass-1 results",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto accounts = fundAccounts(*root, "pass1", 40, balance);
    auto txs = makePayments(*app, *root, accounts);

    SECTION("all valid")
    {
        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<0>(parallel).empty());
        REQUIRE(std::get<1>(parallel) == TxSetValidationResult::VALID);
        REQUIRE(std::get<2>(parallel).size() == accounts.size());
        for (auto const& [account, fee] : std::get<2>(parallel))
        {
            REQUIRE(fee == 100);
        }
    }

    SECTION("corrupted signature")
    {
        auto bad = root->create("pass1Bad", balance);
        auto badTx = bad.tx({payment(*root, 1)});
        corruptSignature(badTx);
        txs.emplace_back(badTx);

        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<1>(parallel) ==
                TxSetValidationResult::TX_VALIDATION_FAILED);
        REQUIRE(std::get<0>(parallel).size() == 1);
        REQUIRE(std::get<0>(parallel)[0]->getFullHash() ==
                badTx->getFullHash());
    }
}

TEST_CASE("parallel validation preserves fee accumulation and precedence",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto minBalance = app->getLedgerManager().getLastMinBalance(0);
    int64_t const outerFee = 1000;
    size_t const numFeeBumps = 10;

    auto pads = fundAccounts(*root, "feePad", 30, balance);
    auto txs = makePayments(*app, *root, pads);
    auto poor = root->create("poorFeeSource", minBalance + 3 * outerFee);
    auto innerAccounts =
        fundAccounts(*root, "feeInner", numFeeBumps, balance);
    TxFrameList feeBumps;
    for (auto& inner : innerAccounts)
    {
        auto innerTx = inner.tx({payment(*root, 1)});
        feeBumps.emplace_back(feeBump(*app, poor, innerTx, outerFee));
    }

    // Prove construction validity and individual affordability first.
    for (auto const& tx : feeBumps)
    {
        auto single = runValidation(*app, {tx}, false);
        REQUIRE(std::get<0>(single).empty());
        REQUIRE(std::get<1>(single) == TxSetValidationResult::VALID);
    }
    txs.insert(txs.end(), feeBumps.begin(), feeBumps.end());

    SECTION("aggregate fees exceed the fee source balance")
    {
        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<1>(parallel) ==
                TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
        REQUIRE(std::get<0>(parallel).size() == numFeeBumps);
        REQUIRE(std::get<2>(parallel).at(poor.getPublicKey()) ==
                static_cast<int64_t>(numFeeBumps) * outerFee);
    }

    SECTION("pass-1 failure dominates pass-2 failure")
    {
        auto bad = root->create("feeBad", balance);
        auto badTx = bad.tx({payment(*root, 1)});
        corruptSignature(badTx);
        txs.emplace_back(badTx);

        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<1>(parallel) ==
                TxSetValidationResult::TX_VALIDATION_FAILED);
        REQUIRE(std::get<0>(parallel).size() == numFeeBumps + 1);
    }
}

TEST_CASE("parallel validation is deterministic",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto minBalance = app->getLedgerManager().getLastMinBalance(0);
    int64_t const outerFee = 1000;

    auto accounts = fundAccounts(*root, "det", 40, balance);
    auto txs = makePayments(*app, *root, accounts);
    auto poor = root->create("detPoor", minBalance + 3 * outerFee);
    auto inner = fundAccounts(*root, "detInner", 10, balance);
    for (auto& account : inner)
    {
        txs.emplace_back(
            feeBump(*app, poor, account.tx({payment(*root, 1)}), outerFee));
    }

    auto reference = runValidation(*app, txs, false);
    REQUIRE(std::get<1>(reference) ==
            TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
    REQUIRE(std::get<0>(reference).size() == 10);
    for (int run = 0; run < 5; ++run)
    {
        requireSame(reference, runValidation(*app, txs, false));
    }
}

TEST_CASE("parallel validation preserves duplicate full-hash behavior",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto minBalance = app->getLedgerManager().getLastMinBalance(0);
    auto pads = fundAccounts(*root, "duplicatePad", 30, balance);
    auto padTxs = makePayments(*app, *root, pads);

    SECTION("same frame pointer remains race-free")
    {
        auto source = root->create("duplicatePointer", balance);
        auto duplicate = source.tx({payment(*root, 1)});
        auto txs = padTxs;
        txs.emplace_back(duplicate);
        txs.emplace_back(duplicate);

        auto serial = runValidation(*app, txs, true);
        auto automatic = runValidation(*app, txs, false);
        requireSame(serial, automatic);
        REQUIRE(std::get<0>(automatic).empty());
        REQUIRE(std::get<2>(automatic).at(source.getPublicKey()) == 200);
    }

    SECTION("distinct frames from one affordable envelope count twice")
    {
        auto source = root->create("duplicateAffordable", balance);
        auto original = source.tx({payment(*root, 1)});
        auto txs = padTxs;
        txs.emplace_back(cloneFrame(*app, original));
        txs.emplace_back(cloneFrame(*app, original));

        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<0>(parallel).empty());
        REQUIRE(std::get<2>(parallel).at(source.getPublicKey()) == 200);
    }

    SECTION("pass-2 rejects only the first unaffordable duplicate")
    {
        auto source = root->create("duplicatePoor", minBalance + 150);
        auto original = source.tx({payment(*root, 1)});
        auto txs = padTxs;
        txs.emplace_back(cloneFrame(*app, original));
        txs.emplace_back(cloneFrame(*app, original));

        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<1>(parallel) ==
                TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
        REQUIRE(std::get<0>(parallel).size() == 1);
        REQUIRE(std::get<2>(parallel).at(source.getPublicKey()) == 200);
    }

    SECTION("pass-1 retains every invalid duplicate")
    {
        auto source = root->create("duplicateInvalid", balance);
        auto original = source.tx({payment(*root, 1)});
        corruptSignature(original);
        auto txs = padTxs;
        txs.emplace_back(cloneFrame(*app, original));
        txs.emplace_back(cloneFrame(*app, original));

        auto serial = runValidation(*app, txs, true);
        auto parallel = runValidation(*app, txs, false);
        requireSame(serial, parallel);
        REQUIRE(std::get<1>(parallel) ==
                TxSetValidationResult::TX_VALIDATION_FAILED);
        REQUIRE(std::get<0>(parallel).size() == 2);
    }
}

TEST_CASE("parallel validation saturates a pre-seeded fee map",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto pads = fundAccounts(*root, "saturationPad", 31, balance);
    auto txs = makePayments(*app, *root, pads);
    auto source = root->create("saturationSource", balance);
    auto target = source.tx({payment(*root, 1)});
    txs.emplace_back(target);

    UnorderedMap<AccountID, int64_t> seed;
    seed[source.getPublicKey()] = std::numeric_limits<int64_t>::max() - 50;
    auto serial = runValidation(*app, txs, true, seed);
    auto parallel = runValidation(*app, txs, false, seed);
    requireSame(serial, parallel);
    REQUIRE(std::get<2>(parallel).at(source.getPublicKey()) ==
            std::numeric_limits<int64_t>::max());
    REQUIRE(std::get<1>(parallel) ==
            TxSetValidationResult::ACCOUNT_CANT_PAY_FEE);
    REQUIRE(std::get<0>(parallel).size() == 1);
    REQUIRE(std::get<0>(parallel)[0]->getFullHash() == target->getFullHash());
}

TEST_CASE("parallel validation thread-count sweep",
          "[txset][parallelvalidation]")
{
    for (int threadCount : {1, 2, 8})
    {
        INFO("tx validation threads: " << threadCount);
        VirtualClock clock;
        auto app = makeParallelValidationApp(clock, threadCount);
        auto root = app->getRoot();
        auto balance =
            app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
        auto minBalance = app->getLedgerManager().getLastMinBalance(0);
        int64_t const outerFee = 1000;

        auto accounts = fundAccounts(*root, "sweep", 54, balance);
        auto txs = makePayments(*app, *root, accounts);
        auto poor = root->create("sweepPoor", minBalance + 3 * outerFee);
        auto inner = fundAccounts(*root, "sweepInner", 10, balance);
        for (auto& account : inner)
        {
            txs.emplace_back(feeBump(
                *app, poor, account.tx({payment(*root, 1)}), outerFee));
        }
        REQUIRE(txs.size() == 64);
        requireSame(runValidation(*app, txs, true),
                    runValidation(*app, txs, false));
    }
}

TEST_CASE("parallel validation size boundaries",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto accounts = fundAccounts(*root, "boundary", 50, balance);
    auto allTxs = makePayments(*app, *root, accounts);
    for (size_t i = 0; i < allTxs.size(); i += 7)
    {
        corruptSignature(allTxs[i]);
    }

    for (size_t size : {31, 32, 33, 50})
    {
        INFO("tx set size: " << size);
        TxFrameList txs(allTxs.begin(), allTxs.begin() + size);
        requireSame(runValidation(*app, txs, true),
                    runValidation(*app, txs, false));
    }
}

TEST_CASE("parallel validation propagates overlay-only sequence skipping",
          "[txset][parallelvalidation]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto accounts = fundAccounts(*root, "overlay", 40, balance);
    app->setRunInOverlayOnlyMode(true);
    TxFrameList txs;
    for (auto& account : accounts)
    {
        txs.emplace_back(transactionFromOperations(
            *app, account.getSecretKey(), account.loadSequenceNumber() + 10,
            {payment(*root, 1)}, 100));
    }

    auto serial = runValidation(*app, txs, true);
    auto parallel = runValidation(*app, txs, false);
    requireSame(serial, parallel);
    REQUIRE(std::get<0>(parallel).empty());
    REQUIRE(std::get<1>(parallel) == TxSetValidationResult::VALID);
}

TEST_CASE("seeded mixed parallel validation stress",
          "[txset][parallelvalidation]")
{
    auto seed = Catch::rngSeed();
    CAPTURE(seed);
    auto& rng = getGlobalRandomEngine();

    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    overrideSorobanNetworkConfigForTest(*app);
    auto root = app->getRoot();
    auto balance =
        app->getLedgerManager().getLastMinBalance(2) + 1'000'000'000;
    auto minBalance = app->getLedgerManager().getLastMinBalance(0);
    int64_t const outerFee = 1000;

    auto accounts = fundAccounts(*root, "stress", 120, balance);
    auto lowAccounts =
        fundAccounts(*root, "stressLow", 120, minBalance + 50);
    auto feeSources =
        fundAccounts(*root, "stressFee", 20, minBalance + 3 * outerFee);

    for (size_t iteration = 0; iteration < 20; ++iteration)
    {
        CAPTURE(iteration);
        size_t count = rand_uniform<size_t>(40, 120, rng);
        TxFrameList txs;
        txs.reserve(count);

        // Every iteration contains an over-spending fee-bump group.
        for (size_t i = 0; i < 5; ++i)
        {
            auto inner = transactionFromOperations(
                *app, accounts[i].getSecretKey(),
                accounts[i].loadSequenceNumber() + 1,
                {payment(*root, 1)}, 100);
            txs.emplace_back(
                feeBump(*app, feeSources[iteration], inner, outerFee));
        }

        for (size_t i = 5; i < count; ++i)
        {
            // Guarantee every defect class once per iteration, then use the
            // test runner's seeded RNG for the remaining classic cases.
            int defect = i < 14 ? static_cast<int>(i - 5)
                                : rand_uniform<int>(0, 5, rng);
            auto seq = accounts[i].loadSequenceNumber();
            TransactionFrameBasePtr tx;
            switch (defect)
            {
            case 0: // valid classic
                tx = transactionFromOperations(
                    *app, accounts[i].getSecretKey(), seq + 1,
                    {payment(*root, 1)}, 100);
                break;
            case 1: // invalid signature
                tx = transactionFromOperations(
                    *app, accounts[i].getSecretKey(), seq + 1,
                    {payment(*root, 1)}, 100);
                corruptSignature(tx);
                break;
            case 2: // stale sequence
                tx = transactionFromOperations(
                    *app, accounts[i].getSecretKey(), seq,
                    {payment(*root, 1)}, 100);
                break;
            case 3: // future sequence
                tx = transactionFromOperations(
                    *app, accounts[i].getSecretKey(), seq + 2,
                    {payment(*root, 1)}, 100);
                break;
            case 4: // expired time bounds
            {
                PreconditionsV2 cond;
                cond.timeBounds.activate().maxTime = 1;
                tx = transactionFromOperationsV1(
                    *app, accounts[i].getSecretKey(), seq + 1,
                    {payment(*root, 1)}, 100, cond);
                break;
            }
            case 5: // insufficient balance for the inclusion fee
                tx = transactionFromOperations(
                    *app, lowAccounts[i].getSecretKey(),
                    lowAccounts[i].loadSequenceNumber() + 1,
                    {payment(*root, 1)}, 100);
                break;
            case 6: // valid Soroban upload
            case 7: // resource limit violation
            {
                SorobanResources resources;
                resources.instructions = 800'000;
                resources.diskReadBytes = 1000;
                resources.writeBytes = 1000;
                if (defect == 7)
                {
                    resources.instructions =
                        app->getLedgerManager()
                            .getLastClosedSorobanNetworkConfig()
                            .txMaxInstructions() +
                        1;
                }
                tx = createUploadWasmTx(
                    *app, accounts[i], 1000, 100'000'000, resources,
                    std::nullopt, 0, std::nullopt, seq + 1,
                    iteration * 1000 + i);
                break;
            }
            case 8: // expired ledger bounds
            {
                PreconditionsV2 cond;
                cond.ledgerBounds.activate().maxLedger =
                    app->getLedgerManager().getLastClosedLedgerNum() + 1;
                tx = transactionFromOperationsV1(
                    *app, accounts[i].getSecretKey(), seq + 1,
                    {payment(*root, 1)}, 100, cond);
                break;
            }
            default:
                FAIL("unknown stress defect class");
            }
            txs.emplace_back(std::move(tx));
        }

        REQUIRE(txs.size() == count);
        requireSame(runValidation(*app, txs, true),
                    runValidation(*app, txs, false));
    }
}

// Opt-in timing comparison. Every timed run reconstructs frames and clears the
// signature cache so lazy state cannot favor either path.
TEST_CASE("parallel validation benchmark", "[!hide][parallelbench]")
{
    VirtualClock clock;
    auto app = makeParallelValidationApp(clock);
    auto root = app->getRoot();
    auto balance = app->getLedgerManager().getLastMinBalance(2) + 1'000'000;
    auto accounts = fundAccounts(*root, "parallelBench", 500, balance);
    auto originals = makePayments(*app, *root, accounts);

    auto timeRun = [&](bool forceSerial) {
        TxFrameList fresh;
        fresh.reserve(originals.size());
        for (auto const& tx : originals)
        {
            fresh.emplace_back(cloneFrame(*app, tx));
        }
        PubKeyUtils::clearVerifySigCache();
        auto start = std::chrono::steady_clock::now();
        auto result = runValidation(*app, fresh, forceSerial);
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start);
        REQUIRE(std::get<0>(result).empty());
        REQUIRE(std::get<1>(result) == TxSetValidationResult::VALID);
        return elapsed;
    };

    timeRun(true);
    auto serial = timeRun(true);
    auto parallel = timeRun(false);
    std::cout << "parallel validation benchmark (500 txs): serial="
              << serial.count() << "us parallel=" << parallel.count()
              << "us (" << app->getTxValidationThreadCount()
              << " threads, speedup="
              << static_cast<double>(serial.count()) / parallel.count()
              << "x)" << std::endl;
    REQUIRE(parallel.count() < serial.count() * 2);
}

} // namespace stellar
