// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/PathPaymentOpFrameBase.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "ledger/TrustLineWrapper.h"
#include "transactions/TransactionUtils.h"
#include "util/GlobalChecks.h"
#include "util/ProtocolVersion.h"
#include "util/XDROperators.h"

namespace stellar
{

PathPaymentOpFrameBase::PathPaymentOpFrameBase(Operation const& op,
                                               TransactionFrame const& parentTx)
    : OperationFrame(op, parentTx)
{
}

AccountID
PathPaymentOpFrameBase::getDestID() const
{
    return toAccountID(getDestMuxedAccount());
}

void
PathPaymentOpFrameBase::insertLedgerKeysToPrefetch(
    UnorderedSet<LedgerKey>& keys) const
{
    auto destID = getDestID();
    keys.emplace(accountKey(destID));

    if (getDestAsset().type() != ASSET_TYPE_NATIVE)
    {
        keys.emplace(trustlineKey(destID, getDestAsset()));
    }
    if (getSourceAsset().type() != ASSET_TYPE_NATIVE)
    {
        keys.emplace(trustlineKey(getSourceID(), getSourceAsset()));
    }
}

bool
PathPaymentOpFrameBase::isDexOperation() const
{
    auto const& src = getSourceAsset();
    auto const& dest = getDestAsset();
    return !getPath().empty() || !(src == dest);
}

bool
PathPaymentOpFrameBase::checkIssuer(AbstractLedgerTxn& ltx,
                                    uint32_t ledgerVersion, Asset const& asset,
                                    OperationResult& res) const
{
    if (asset.type() != ASSET_TYPE_NATIVE)
    {
        if (protocolVersionIsBefore(ledgerVersion, ProtocolVersion::V_13) &&
            !stellar::loadAccountWithoutRecord(ltx, getIssuer(asset)))
        {
            setResultNoIssuer(asset, res);
            return false;
        }
    }
    return true;
}

bool
PathPaymentOpFrameBase::convert(
    AbstractLedgerTxn& ltx, uint32_t ledgerVersion, uint32_t baseReserve,
    uint32_t ledgerSeq, bool poolTradingDisabled, int64_t maxOffersToCross,
    Asset const& sendAsset, int64_t maxSend, int64_t& amountSend,
    Asset const& recvAsset, int64_t maxRecv, int64_t& amountRecv,
    RoundingType round, std::vector<ClaimAtom>& offerTrail,
    OperationResult& res) const
{
    releaseAssertOrThrow(offerTrail.empty());
    releaseAssertOrThrow(!(sendAsset == recvAsset));

    // sendAsset -> recvAsset
    ConvertResult r = convertWithOffersAndPools(
        ltx, ledgerVersion, baseReserve, ledgerSeq, poolTradingDisabled,
        sendAsset, maxSend, amountSend, recvAsset, maxRecv, amountRecv, round,
        [this](LedgerTxnEntry const& o) {
            auto const& offer = o.current().data.offer();
            if (offer.sellerID == getSourceID())
            {
                // we are crossing our own offer
                return OfferFilterResult::eStopCrossSelf;
            }
            return OfferFilterResult::eKeep;
        },
        offerTrail, maxOffersToCross);

    if (amountSend < 0 || amountRecv < 0)
    {
        throw std::runtime_error("amount transferred out of bounds");
    }

    switch (r)
    {
    case ConvertResult::eFilterStopCrossSelf:
        setResultOfferCrossSelf(res);
        return false;
    case ConvertResult::eOK:
        if (checkTransfer(maxSend, amountSend, maxRecv, amountRecv))
        {
            break;
        }
    // fall through
    case ConvertResult::ePartial:
        setResultTooFewOffers(res);
        return false;
    case ConvertResult::eCrossedTooMany:
        res.code(opEXCEEDED_WORK_LIMIT);
        return false;
    default:
        throw std::runtime_error("unexpected convert result");
    }

    return true;
}

bool
PathPaymentOpFrameBase::shouldBypassIssuerCheck(
    std::vector<Asset> const& path) const
{
    // if the payment doesn't involve intermediate accounts
    // and the destination is the issuer we don't bother
    // checking if the destination account even exist
    // so that it's always possible to send credits back to its issuer
    return (getDestAsset().type() != ASSET_TYPE_NATIVE) && (path.size() == 0) &&
           (getSourceAsset() == getDestAsset()) &&
           (getIssuer(getDestAsset()) == getDestID());
}

bool
PathPaymentOpFrameBase::updateSourceBalance(AbstractLedgerTxn& ltx,
                                            uint32_t ledgerVersion,
                                            uint32_t baseReserve,
                                            OperationResult& res,
                                            int64_t amount,
                                            bool bypassIssuerCheck,
                                            bool doesSourceAccountExist) const
{
    auto const& asset = getSourceAsset();

    if (asset.type() == ASSET_TYPE_NATIVE)
    {
        LedgerTxnEntry sourceAccount;
        if (protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_8))
        {
            sourceAccount = stellar::loadAccount(ltx, getSourceID());
            if (!sourceAccount)
            {
                setResultMalformed(res);
                return false;
            }
        }
        else
        {
            // Legacy pre-V8 path: need header for loadSourceAccount
            auto header = ltx.loadHeader();
            sourceAccount = loadSourceAccount(ltx, header);
        }

        if (amount > getAvailableBalance(ledgerVersion, baseReserve,
                                         sourceAccount))
        { // they don't have enough to send
            setResultUnderfunded(res);
            return false;
        }

        if (!doesSourceAccountExist)
        {
            throw std::runtime_error("modifying account that does not exist");
        }

        auto ok = addBalance(ledgerVersion, baseReserve, sourceAccount, -amount);
        releaseAssertOrThrow(ok);
    }
    else
    {
        if (!bypassIssuerCheck && !checkIssuer(ltx, ledgerVersion, asset, res))
        {
            return false;
        }

        auto sourceLine = loadTrustLine(ltx, getSourceID(), asset);
        if (!sourceLine)
        {
            setResultSourceNoTrust(res);
            return false;
        }

        if (!sourceLine.isAuthorized())
        {
            setResultSourceNotAuthorized(res);
            return false;
        }

        if (!sourceLine.addBalance(ledgerVersion, baseReserve, -amount))
        {
            setResultUnderfunded(res);
            return false;
        }
    }

    return true;
}

bool
PathPaymentOpFrameBase::updateDestBalance(AbstractLedgerTxn& ltx,
                                          uint32_t ledgerVersion,
                                          uint32_t baseReserve, int64_t amount,
                                          bool bypassIssuerCheck,
                                          OperationResult& res) const
{
    auto destID = getDestID();
    auto const& asset = getDestAsset();

    if (asset.type() == ASSET_TYPE_NATIVE)
    {
        auto destination = stellar::loadAccount(ltx, destID);
        if (!addBalance(ledgerVersion, baseReserve, destination, amount))
        {
            if (protocolVersionStartsFrom(ledgerVersion, ProtocolVersion::V_11))
            {
                setResultLineFull(res);
            }
            else
            {
                setResultMalformed(res);
            }
            return false;
        }
    }
    else
    {
        if (!bypassIssuerCheck && !checkIssuer(ltx, ledgerVersion, asset, res))
        {
            return false;
        }

        auto destLine = stellar::loadTrustLine(ltx, destID, asset);
        if (!destLine)
        {
            setResultDestNoTrust(res);
            return false;
        }

        if (!destLine.isAuthorized())
        {
            setResultDestNotAuthorized(res);
            return false;
        }

        if (!destLine.addBalance(ledgerVersion, baseReserve, amount))
        {
            setResultLineFull(res);
            return false;
        }
    }

    return true;
}
}
