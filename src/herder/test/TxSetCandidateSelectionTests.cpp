// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

// Tests for the mempool candidate -> tx set selection helpers in TxSetUtils
// and for the submission-time validation in HerderImpl::recvTransaction.
// The selection helpers are pure functions, so these tests neither need nor
// start an overlay process.

#include "herder/HerderImpl.h"
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
#include "transactions/MutableTransactionResult.h"
#include "transactions/TransactionBridge.h"
#include "transactions/TransactionFrameBase.h"
#include "util/UnorderedMap.h"
#include "util/UnorderedSet.h"

#include <algorithm>
#include <limits>
#include <map>
#include <optional>

using namespace stellar;
using namespace stellar::txtest;

namespace
{

size_t const CLASSIC = static_cast<size_t>(TxSetPhase::CLASSIC);
size_t const SOROBAN = static_cast<size_t>(TxSetPhase::SOROBAN);

// Builds real transaction frames for arbitrary (non-existent) accounts and
// keeps a fake "ledger" of account sequence numbers for the lookups.
struct SelectionFixture
{
    VirtualClock clock;
    Application::pointer app;
    UnorderedMap<AccountID, SequenceNumber> ledgerSeqs;

    SelectionFixture()
    {
        Config cfg = getTestConfig();
        // The helpers under test don't talk to the overlay.
        cfg.MODE_AUTO_STARTS_OVERLAY = false;
        app = createTestApplication(clock, cfg);
    }

    TestAccount
    account(std::optional<SequenceNumber> seqInLedger)
    {
        TestAccount acc(*app, SecretKey::pseudoRandomForTesting());
        if (seqInLedger)
        {
            ledgerSeqs[acc.getPublicKey()] = *seqInLedger;
        }
        return acc;
    }

    TransactionFrameBasePtr
    classic(TestAccount& acc, SequenceNumber seq, uint32_t fee = 100)
    {
        return transactionFromOperations(*app, acc.getSecretKey(), seq,
                                         {payment(acc.getPublicKey(), 1)},
                                         fee);
    }

    TransactionFrameBasePtr
    soroban(TestAccount& acc, SequenceNumber seq, uint32_t inclusionFee = 100)
    {
        SorobanResources resources;
        resources.instructions = 800'000;
        resources.diskReadBytes = 1000;
        resources.writeBytes = 1000;
        return createUploadWasmTx(*app, acc, inclusionFee, 1'000'000,
                                  resources, /*memo=*/std::nullopt,
                                  /*addInvalidOps=*/0,
                                  /*wasmSize=*/std::nullopt, seq);
    }

    // Same account as `acc`, but addressed through a muxed account id.
    TransactionFrameBasePtr
    muxed(TestAccount& acc, SequenceNumber seq)
    {
        auto env = classic(acc, seq)->getEnvelope();
        auto const& pk = acc.getPublicKey();
        auto& src = env.v1().tx.sourceAccount;
        src.type(KEY_TYPE_MUXED_ED25519);
        src.med25519().id = 7;
        src.med25519().ed25519 = pk.ed25519();
        return TransactionFrameBase::makeTransactionFromWire(
            app->getNetworkID(), env);
    }

    TxSetUtils::AccountSeqLookup
    seqOf() const
    {
        return [this](AccountID const& id) -> std::optional<SequenceNumber> {
            auto it = ledgerSeqs.find(id);
            if (it == ledgerSeqs.end())
            {
                return std::nullopt;
            }
            return it->second;
        };
    }
};

std::vector<Hash>
hashesOf(TxFrameList const& txs)
{
    std::vector<Hash> res;
    for (auto const& tx : txs)
    {
        res.push_back(tx->getFullHash());
    }
    return res;
}

bool
contains(std::vector<Hash> const& hashes, TransactionFrameBasePtr const& tx)
{
    return std::find(hashes.begin(), hashes.end(), tx->getFullHash()) !=
           hashes.end();
}

TxFrameList
allSelected(TxSetUtils::TxSetCandidates const& sel)
{
    TxFrameList res;
    for (auto const& phase : sel.phases)
    {
        res.insert(res.end(), phase.begin(), phase.end());
    }
    return res;
}

void
requireOneTxPerSourceAccount(TxSetUtils::TxSetCandidates const& sel)
{
    UnorderedSet<AccountID> seen;
    for (auto const& tx : allSelected(sel))
    {
        REQUIRE(seen.insert(tx->getSourceID()).second);
    }
}

// Result-code lookup backed by a fixed table.
TxSetUtils::TxResultCodeLookup
codeTable(std::map<Hash, TransactionResultCode> const& codes)
{
    return [&codes](TransactionFrameBaseConstPtr const& tx) {
        auto it = codes.find(tx->getFullHash());
        REQUIRE(it != codes.end());
        return it->second;
    };
}
} // namespace

TEST_CASE("mempool candidate selection keeps one tx per source account across "
          "phases",
          "[herder][txset][mempool]")
{
    SelectionFixture f;
    SequenceNumber const n = 10;
    auto a = f.account(n);

    SECTION("classic and soroban at the same seq: fee order wins")
    {
        auto classic = f.classic(a, n + 1, 1000);
        auto soroban = f.soroban(a, n + 1, 100);
        auto sel = TxSetUtils::selectTxSetCandidates({classic, soroban}, true,
                                                     f.seqOf());
        REQUIRE(sel.phases.size() == 2);
        REQUIRE(sel.phases[CLASSIC].size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == classic);
        REQUIRE(sel.phases[SOROBAN].empty());
        // The loser is a legitimate competitor, not garbage.
        REQUIRE(sel.toRemove.empty());
        requireOneTxPerSourceAccount(sel);

        // Reverse the fee order: the soroban tx now wins.
        sel = TxSetUtils::selectTxSetCandidates({soroban, classic}, true,
                                                f.seqOf());
        REQUIRE(sel.phases[CLASSIC].empty());
        REQUIRE(sel.phases[SOROBAN].size() == 1);
        REQUIRE(sel.phases[SOROBAN][0] == soroban);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("classic n+1 and soroban n+2: the next seq wins regardless of fee")
    {
        auto classic = f.classic(a, n + 1, 100);
        auto soroban = f.soroban(a, n + 2, 100'000);
        auto sel = TxSetUtils::selectTxSetCandidates({soroban, classic}, true,
                                                     f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC].size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == classic);
        REQUIRE(sel.toRemove.empty());
        requireOneTxPerSourceAccount(sel);
    }

    SECTION("soroban n+1 and classic n+2")
    {
        auto soroban = f.soroban(a, n + 1, 100);
        auto classic = f.classic(a, n + 2, 100'000);
        auto sel = TxSetUtils::selectTxSetCandidates({classic, soroban}, true,
                                                     f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[SOROBAN].size() == 1);
        REQUIRE(sel.phases[SOROBAN][0] == soroban);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("many accounts, each with classic and soroban candidates")
    {
        TxFrameList candidates;
        std::vector<TestAccount> accounts;
        for (int i = 0; i < 20; ++i)
        {
            accounts.push_back(f.account(n));
        }
        for (auto& acc : accounts)
        {
            candidates.push_back(f.soroban(acc, n + 2));
            candidates.push_back(f.classic(acc, n + 1));
            candidates.push_back(f.classic(acc, n + 3));
        }
        auto sel =
            TxSetUtils::selectTxSetCandidates(candidates, true, f.seqOf());
        REQUIRE(sel.numSourceAccounts == 20);
        REQUIRE(allSelected(sel).size() == 20);
        REQUIRE(sel.phases[CLASSIC].size() == 20);
        REQUIRE(sel.phases[SOROBAN].empty());
        REQUIRE(sel.toRemove.empty());
        requireOneTxPerSourceAccount(sel);
        for (auto const& tx : sel.phases[CLASSIC])
        {
            REQUIRE(tx->getSeqNum() == n + 1);
        }
    }
}

TEST_CASE("mempool candidate selection prefers the next sequence number",
          "[herder][txset][mempool]")
{
    SelectionFixture f;
    SequenceNumber const n = 100;
    auto a = f.account(n);

    SECTION("next seq is not the first candidate")
    {
        auto tx3 = f.classic(a, n + 3, 5000);
        auto tx1 = f.classic(a, n + 1, 200);
        auto tx2 = f.classic(a, n + 2, 100);
        auto sel = TxSetUtils::selectTxSetCandidates({tx3, tx1, tx2}, true,
                                                     f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == tx1);
        // Chained txs wait for their predecessor; they are not garbage.
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("same seq twice: the first (best fee rate) candidate is kept")
    {
        auto hi = f.classic(a, n + 1, 1000);
        auto lo = f.classic(a, n + 1, 100);
        auto sel =
            TxSetUtils::selectTxSetCandidates({hi, lo}, true, f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == hi);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("only chained txs: the lowest future seq is selected")
    {
        auto tx4 = f.classic(a, n + 4);
        auto tx2 = f.classic(a, n + 2);
        auto tx3 = f.classic(a, n + 3);
        auto sel = TxSetUtils::selectTxSetCandidates({tx4, tx2, tx3}, true,
                                                     f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == tx2);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("next seq beats a lower-fee future seq and vice versa")
    {
        auto tx5 = f.classic(a, n + 5, 100'000);
        auto tx1 = f.classic(a, n + 1, 100);
        auto sel =
            TxSetUtils::selectTxSetCandidates({tx5, tx1}, true, f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == tx1);
        REQUIRE(sel.toRemove.empty());
    }
}

TEST_CASE("mempool candidate selection removes stale txs",
          "[herder][txset][mempool]")
{
    SelectionFixture f;
    SequenceNumber const n = 50;
    auto a = f.account(n);

    SECTION("stale txs are removed and the next seq is selected in the same "
            "pass")
    {
        auto stale1 = f.classic(a, n - 1);
        auto stale2 = f.classic(a, n);
        auto next = f.classic(a, n + 1);
        auto sel = TxSetUtils::selectTxSetCandidates({stale1, stale2, next},
                                                     true, f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == next);
        REQUIRE(sel.toRemove.size() == 2);
        REQUIRE(contains(sel.toRemove, stale1));
        REQUIRE(contains(sel.toRemove, stale2));
    }

    SECTION("stale soroban txs are removed too")
    {
        auto stale = f.soroban(a, n);
        auto sel =
            TxSetUtils::selectTxSetCandidates({stale}, true, f.seqOf());
        REQUIRE(allSelected(sel).empty());
        REQUIRE(sel.toRemove == hashesOf({stale}));
    }

    SECTION("an account with only stale txs contributes nothing")
    {
        auto b = f.account(n);
        auto stale = f.classic(a, n - 5);
        auto bNext = f.classic(b, n + 1);
        auto sel =
            TxSetUtils::selectTxSetCandidates({stale, bNext}, true, f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == bNext);
        REQUIRE(sel.toRemove == hashesOf({stale}));
        REQUIRE(sel.numSourceAccounts == 2);
    }

    SECTION("unknown source account is not selected and is removed")
    {
        auto nobody = f.account(std::nullopt);
        auto tx = f.classic(nobody, 1);
        auto known = f.classic(a, n + 1);
        auto sel =
            TxSetUtils::selectTxSetCandidates({tx, known}, true, f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == known);
        REQUIRE(sel.toRemove == hashesOf({tx}));
    }
}

TEST_CASE("mempool candidate selection handles soroban support and order",
          "[herder][txset][mempool]")
{
    SelectionFixture f;
    SequenceNumber const n = 7;

    SECTION("soroban candidates before soroban protocol are dropped but not "
            "removed")
    {
        auto a = f.account(n);
        auto b = f.account(n);
        auto sorobanA = f.soroban(a, n + 1);
        auto classicB = f.classic(b, n + 1);
        auto sel = TxSetUtils::selectTxSetCandidates({sorobanA, classicB},
                                                     false, f.seqOf());
        REQUIRE(sel.phases.size() == 1);
        REQUIRE(sel.phases[CLASSIC].size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == classicB);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("a dropped soroban tx does not shadow the account's classic tx")
    {
        auto a = f.account(n);
        auto sorobanA = f.soroban(a, n + 1);
        auto classicA = f.classic(a, n + 2);
        auto sel = TxSetUtils::selectTxSetCandidates({sorobanA, classicA},
                                                     false, f.seqOf());
        REQUIRE(sel.phases.size() == 1);
        REQUIRE(sel.phases[CLASSIC].size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == classicA);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("candidate fee order is preserved and distinct accounts are all "
            "kept")
    {
        TxFrameList candidates;
        std::vector<TestAccount> accounts;
        for (int i = 0; i < 50; ++i)
        {
            accounts.push_back(f.account(n));
        }
        // Interleave a stale tx and a chained tx to make sure dropping
        // candidates does not reorder the kept ones.
        for (size_t i = 0; i < accounts.size(); ++i)
        {
            if (i % 10 == 3)
            {
                candidates.push_back(f.classic(accounts[i], n));
            }
            candidates.push_back(i % 2 == 0 ? f.classic(accounts[i], n + 1)
                                            : f.soroban(accounts[i], n + 1));
            if (i % 10 == 6)
            {
                candidates.push_back(f.classic(accounts[i], n + 2));
            }
        }
        auto sel =
            TxSetUtils::selectTxSetCandidates(candidates, true, f.seqOf());
        REQUIRE(sel.numSourceAccounts == 50);
        REQUIRE(sel.phases[CLASSIC].size() == 25);
        REQUIRE(sel.phases[SOROBAN].size() == 25);
        REQUIRE(sel.toRemove.size() == 5);
        requireOneTxPerSourceAccount(sel);
        for (size_t i = 0; i < 25; ++i)
        {
            REQUIRE(sel.phases[CLASSIC][i]->getSourceID() ==
                    accounts[2 * i].getPublicKey());
            REQUIRE(sel.phases[SOROBAN][i]->getSourceID() ==
                    accounts[2 * i + 1].getPublicKey());
        }
    }

    SECTION("muxed source is the same account as its ed25519 key")
    {
        auto a = f.account(n);
        auto plain = f.classic(a, n + 1);
        auto mux = f.muxed(a, n + 2);
        auto sel =
            TxSetUtils::selectTxSetCandidates({mux, plain}, true, f.seqOf());
        REQUIRE(sel.numSourceAccounts == 1);
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == plain);
        REQUIRE(sel.toRemove.empty());
    }

    SECTION("seq at INT64_MAX does not overflow the next-seq test")
    {
        auto const maxSeq = std::numeric_limits<SequenceNumber>::max();
        auto almost = f.account(maxSeq - 1);
        auto full = f.account(maxSeq);
        auto txAlmost = f.classic(almost, maxSeq);
        auto txFull = f.classic(full, maxSeq);
        auto sel = TxSetUtils::selectTxSetCandidates({txAlmost, txFull}, true,
                                                     f.seqOf());
        REQUIRE(allSelected(sel).size() == 1);
        REQUIRE(sel.phases[CLASSIC][0] == txAlmost);
        REQUIRE(sel.toRemove == hashesOf({txFull}));
    }

    SECTION("empty input")
    {
        auto sel = TxSetUtils::selectTxSetCandidates({}, true, f.seqOf());
        REQUIRE(sel.phases.size() == 2);
        REQUIRE(sel.phases[CLASSIC].empty());
        REQUIRE(sel.phases[SOROBAN].empty());
        REQUIRE(sel.toRemove.empty());
        REQUIRE(sel.numSourceAccounts == 0);

        sel = TxSetUtils::selectTxSetCandidates({}, false, f.seqOf());
        REQUIRE(sel.phases.size() == 1);
        REQUIRE(sel.phases[CLASSIC].empty());
    }
}

TEST_CASE("permanently invalid tx classification", "[herder][txset][mempool]")
{
    SelectionFixture f;
    SequenceNumber const n = 1000;
    auto a = f.account(n);
    auto nobody = f.account(std::nullopt);

    SECTION("transient failures are kept")
    {
        struct Case
        {
            TransactionResultCode code;
            SequenceNumber seq;
        };
        std::vector<Case> cases = {
            {txTOO_EARLY, n + 1},
            {txBAD_MIN_SEQ_AGE_OR_GAP, n + 1},
            // Chained behind a pending tx from the same account.
            {txBAD_SEQ, n + 2},
            {txBAD_SEQ, n + 100},
            // Only trimmed by the cumulative fee-source balance check.
            {txSUCCESS, n + 1},
        };
        for (auto const& c : cases)
        {
            INFO("code " << c.code << " seq " << c.seq);
            REQUIRE(TxSetUtils::isTransientValidationFailure(c.code, c.seq,
                                                             n));
            auto tx = f.classic(a, c.seq);
            std::map<Hash, TransactionResultCode> codes = {
                {tx->getFullHash(), c.code}};
            REQUIRE(TxSetUtils::permanentlyInvalidTxHashes(
                        {{tx}}, codeTable(codes), f.seqOf())
                        .empty());
        }
    }

    SECTION("permanent failures are removed")
    {
        struct Case
        {
            TransactionResultCode code;
            SequenceNumber seq;
        };
        std::vector<Case> cases = {
            // Stale or duplicate sequence numbers.
            {txBAD_SEQ, n},
            {txBAD_SEQ, n - 10},
            {txBAD_SEQ, n + 1},
            {txNO_ACCOUNT, n + 1},
            {txINSUFFICIENT_FEE, n + 1},
            {txBAD_AUTH, n + 1},
            {txBAD_AUTH_EXTRA, n + 1},
            {txINSUFFICIENT_BALANCE, n + 1},
            {txMALFORMED, n + 1},
            {txSOROBAN_INVALID, n + 1},
            {txTOO_LATE, n + 1},
            {txMISSING_OPERATION, n + 1},
            {txNOT_SUPPORTED, n + 1},
            {txFAILED, n + 1},
            {txINTERNAL_ERROR, n + 1},
            {txBAD_SPONSORSHIP, n + 1},
            // Any non-seq error on a chained tx is permanent as well.
            {txBAD_AUTH, n + 5},
            {txINSUFFICIENT_FEE, n + 5},
        };
        for (auto const& c : cases)
        {
            INFO("code " << c.code << " seq " << c.seq);
            REQUIRE(!TxSetUtils::isTransientValidationFailure(c.code, c.seq,
                                                              n));
            auto tx = f.classic(a, c.seq);
            std::map<Hash, TransactionResultCode> codes = {
                {tx->getFullHash(), c.code}};
            REQUIRE(TxSetUtils::permanentlyInvalidTxHashes(
                        {{tx}}, codeTable(codes), f.seqOf()) ==
                    hashesOf({tx}));
        }
    }

    SECTION("future txBAD_SEQ without an account is permanent")
    {
        REQUIRE(!TxSetUtils::isTransientValidationFailure(txBAD_SEQ, 5,
                                                          std::nullopt));
        auto tx = f.classic(nobody, 5);
        std::map<Hash, TransactionResultCode> codes = {
            {tx->getFullHash(), txBAD_SEQ}};
        REQUIRE(TxSetUtils::permanentlyInvalidTxHashes(
                    {{tx}}, codeTable(codes), f.seqOf()) == hashesOf({tx}));
    }

    SECTION("txBAD_SEQ at INT64_MAX is permanent")
    {
        auto const maxSeq = std::numeric_limits<SequenceNumber>::max();
        REQUIRE(!TxSetUtils::isTransientValidationFailure(txBAD_SEQ, maxSeq,
                                                          maxSeq));
        REQUIRE(TxSetUtils::isTransientValidationFailure(txBAD_SEQ, maxSeq,
                                                         maxSeq - 2));
    }

    SECTION("mixed phases")
    {
        auto keepClassic = f.classic(a, n + 3);
        auto dropClassic = f.classic(a, n + 1);
        auto keepSoroban = f.soroban(a, n + 1);
        auto dropSoroban = f.soroban(a, n + 2);
        std::map<Hash, TransactionResultCode> codes = {
            {keepClassic->getFullHash(), txBAD_SEQ},
            {dropClassic->getFullHash(), txBAD_AUTH},
            {keepSoroban->getFullHash(), txTOO_EARLY},
            {dropSoroban->getFullHash(), txSOROBAN_INVALID},
        };
        auto res = TxSetUtils::permanentlyInvalidTxHashes(
            {{keepClassic, dropClassic}, {keepSoroban, dropSoroban}},
            codeTable(codes), f.seqOf());
        REQUIRE(res.size() == 2);
        REQUIRE(contains(res, dropClassic));
        REQUIRE(contains(res, dropSoroban));
    }

    SECTION("empty input")
    {
        std::map<Hash, TransactionResultCode> codes;
        REQUIRE(TxSetUtils::permanentlyInvalidTxHashes({}, codeTable(codes),
                                                       f.seqOf())
                    .empty());
        REQUIRE(TxSetUtils::permanentlyInvalidTxHashes(
                    {{}, {}}, codeTable(codes), f.seqOf())
                    .empty());
    }
}

TEST_CASE("recvTransaction validates submissions against the last closed "
          "ledger",
          "[herder][txset][mempool]")
{
    Config cfg = getTestConfig();
    cfg.MODE_AUTO_STARTS_OVERLAY = false;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto root = app->getRoot();
    auto rootSeq = root->loadSequenceNumber();

    auto submit = [&](TransactionFrameBasePtr tx) {
        return herder.recvTransactionWithResult(tx, /*submittedFromSelf=*/true);
    };
    auto requireError = [&](TransactionFrameBasePtr tx,
                            TransactionResultCode code) {
        auto [status, result] = submit(tx);
        REQUIRE(status == TxSubmitStatus::TX_STATUS_ERROR);
        REQUIRE(result);
        REQUIRE(result->getInnermostResultCode() == code);
    };
    auto payment1 = [&](TestAccount& acc, SequenceNumber seq,
                        uint32_t fee = 100) {
        return transactionFromOperations(*app, acc.getSecretKey(), seq,
                                         {payment(acc.getPublicKey(), 1)},
                                         fee);
    };

    SECTION("valid next-seq tx is pending")
    {
        auto [status, result] = submit(payment1(*root, rootSeq + 1));
        REQUIRE(status == TxSubmitStatus::TX_STATUS_PENDING);
        REQUIRE(result);
        REQUIRE(result->isSuccess());
    }

    SECTION("stale seq is an error")
    {
        requireError(payment1(*root, rootSeq), txBAD_SEQ);
    }

    SECTION("bad signature is an error")
    {
        auto tx = payment1(*root, rootSeq + 1);
        txbridge::getSignatures(tx).clear();
        requireError(tx, txBAD_AUTH);
    }

    SECTION("unknown source account is an error")
    {
        TestAccount nobody(*app, SecretKey::pseudoRandomForTesting());
        requireError(payment1(nobody, 1), txNO_ACCOUNT);
    }

    SECTION("fee below the minimum is an error")
    {
        requireError(payment1(*root, rootSeq + 1, 1), txINSUFFICIENT_FEE);
    }

    SECTION("malformed fee is an error")
    {
        SorobanResources resources;
        resources.instructions = 800'000;
        resources.diskReadBytes = 1000;
        resources.writeBytes = 1000;
        auto tx = createUploadWasmTx(*app, *root, 100, /*resourceFee=*/-1,
                                     resources, std::nullopt, 0, std::nullopt,
                                     rootSeq + 1);
        requireError(tx, txMALFORMED);
    }

    SECTION("chained tx is pending")
    {
        auto [status, result] = submit(payment1(*root, rootSeq + 2));
        REQUIRE(status == TxSubmitStatus::TX_STATUS_PENDING);
        auto [status2, result2] = submit(payment1(
            *root, rootSeq + 1 + HerderImpl::MAX_PENDING_SEQ_GAP));
        REQUIRE(status2 == TxSubmitStatus::TX_STATUS_PENDING);
    }

    SECTION("chained tx is still fully validated")
    {
        auto tx = payment1(*root, rootSeq + 2);
        txbridge::getSignatures(tx).clear();
        requireError(tx, txBAD_AUTH);
        requireError(payment1(*root, rootSeq + 2, 1), txINSUFFICIENT_FEE);
    }

    SECTION("seq gap beyond the pending chain limit is try again later")
    {
        auto [status, result] = submit(payment1(
            *root, rootSeq + 2 + HerderImpl::MAX_PENDING_SEQ_GAP));
        REQUIRE(status == TxSubmitStatus::TX_STATUS_TRY_AGAIN_LATER);
        REQUIRE(!result);
    }

    SECTION("banned tx is try again later until the ban expires")
    {
        auto tx = payment1(*root, rootSeq + 1);
        herder.banTxs({tx->getFullHash()});
        REQUIRE(herder.isBannedTx(tx->getFullHash()));
        auto [status, result] = submit(tx);
        REQUIRE(status == TxSubmitStatus::TX_STATUS_TRY_AGAIN_LATER);
        REQUIRE(!result);

        // A different tx from the same account is unaffected.
        REQUIRE(submit(payment1(*root, rootSeq + 1, 200)).first ==
                TxSubmitStatus::TX_STATUS_PENDING);

        for (size_t i = 0; i < HerderImpl::TX_BAN_LEDGERS - 1; ++i)
        {
            herder.shiftBannedTxs();
            REQUIRE(herder.isBannedTx(tx->getFullHash()));
        }
        herder.shiftBannedTxs();
        REQUIRE(!herder.isBannedTx(tx->getFullHash()));
        REQUIRE(submit(tx).first == TxSubmitStatus::TX_STATUS_PENDING);
    }

    SECTION("fee bump is validated like any other tx")
    {
        auto inner = payment1(*root, rootSeq + 1);
        auto fb = feeBump(*app, *root, inner, 1000);
        auto [status, result] = submit(fb);
        REQUIRE(status == TxSubmitStatus::TX_STATUS_PENDING);
        auto badInner = payment1(*root, rootSeq);
        requireError(feeBump(*app, *root, badInner, 1000), txBAD_SEQ);
    }
}

TEST_CASE("recvTransaction rejects soroban txs before protocol 20",
          "[herder][txset][mempool]")
{
    Config cfg = getTestConfig();
    cfg.MODE_AUTO_STARTS_OVERLAY = false;
    cfg.LEDGER_PROTOCOL_VERSION = 19;
    cfg.TESTING_UPGRADE_LEDGER_PROTOCOL_VERSION = 19;
    VirtualClock clock;
    auto app = createTestApplication(clock, cfg);
    auto& herder = static_cast<HerderImpl&>(app->getHerder());
    auto root = app->getRoot();
    auto rootSeq = root->loadSequenceNumber();

    SorobanResources resources;
    resources.instructions = 800'000;
    resources.diskReadBytes = 1000;
    resources.writeBytes = 1000;
    auto tx = createUploadWasmTx(*app, *root, 100, 1'000'000, resources,
                                 std::nullopt, 0, std::nullopt, rootSeq + 1);
    auto [status, result] = herder.recvTransactionWithResult(tx, true);
    REQUIRE(status == TxSubmitStatus::TX_STATUS_ERROR);
    REQUIRE(result);
    REQUIRE(result->getInnermostResultCode() == txNOT_SUPPORTED);
}
