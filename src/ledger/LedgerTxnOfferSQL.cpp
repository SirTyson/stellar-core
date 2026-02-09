// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/BucketListSnapshot.h"
#include "bucket/BucketManager.h"
#include "bucket/LedgerCmp.h"
#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "database/Database.h"
#include "database/DatabaseTypeSpecificOperation.h"
#include "ledger/LedgerTxnImpl.h"
#include "ledger/LedgerTypeUtils.h"
#include "main/Application.h"
#include "main/Config.h"
#include "transactions/TransactionUtils.h"
#include "util/Decoder.h"
#include "util/GlobalChecks.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "util/types.h"
#include "xdrpp/marshal.h"
#include <Tracy.hpp>

namespace stellar
{

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadOffer(LedgerKey const& key) const
{
    ZoneScoped;
    int64_t offerID = key.offer().offerID;
    if (offerID < 0)
    {
        return nullptr;
    }

    std::string actIDStrKey = KeyUtils::toStrKey(key.offer().sellerID);

    std::string sql = "SELECT sellerid, offerid, sellingasset, buyingasset, "
                      "amount, pricen, priced, flags, lastmodified, extension, "
                      "ledgerext "
                      "FROM offers "
                      "WHERE sellerid= :id AND offerid= :offerid";
    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(actIDStrKey));
    st.exchange(soci::use(offerID));

    std::vector<LedgerEntry> offers;
    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        offers = loadOffers(prep);
    }

    return offers.empty() ? nullptr
                          : std::make_shared<LedgerEntry const>(offers.front());
}

std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadAllOffers() const
{
    ZoneScoped;
    std::string sql = "SELECT sellerid, offerid, sellingasset, buyingasset, "
                      "amount, pricen, priced, flags, lastmodified, extension, "
                      "ledgerext FROM offers";
    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());

    std::vector<LedgerEntry> offers;
    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        offers = loadOffers(prep);
    }
    return offers;
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadBestOffers(std::deque<LedgerEntry>& offers,
                                    Asset const& buying, Asset const& selling,
                                    size_t numOffers) const
{
    ZoneScoped;
    // price is an approximation of the actual n/d (truncated math, 15 digits)
    // ordering by offerid gives precedence to older offers for fairness
    std::string sql = "SELECT sellerid, offerid, sellingasset, buyingasset, "
                      "amount, pricen, priced, flags, lastmodified, extension, "
                      "ledgerext FROM offers "
                      "WHERE sellingasset = :v1 AND buyingasset = :v2 "
                      "ORDER BY price, offerid LIMIT :n";

    std::string buyingAsset, sellingAsset;
    buyingAsset = decoder::encode_b64(xdr::xdr_to_opaque(buying));
    sellingAsset = decoder::encode_b64(xdr::xdr_to_opaque(selling));

    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(numOffers));

    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        return loadOffers(prep, offers);
    }
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadBestOffers(
    std::deque<LedgerEntry>& offers, Asset const& buying, Asset const& selling,
    size_t numOffers,
    UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>& colocatedDeps)
    const
{
    ZoneScoped;
    std::string sql = "SELECT sellerid, offerid, sellingasset, buyingasset, "
                      "amount, pricen, priced, flags, lastmodified, extension, "
                      "ledgerext, accountentry, sellingtlentry, buyingtlentry "
                      "FROM offers "
                      "WHERE sellingasset = :v1 AND buyingasset = :v2 "
                      "ORDER BY price, offerid LIMIT :n";

    std::string buyingAsset, sellingAsset;
    buyingAsset = decoder::encode_b64(xdr::xdr_to_opaque(buying));
    sellingAsset = decoder::encode_b64(xdr::xdr_to_opaque(selling));

    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(numOffers));

    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        return loadOffersWithDeps(prep, offers, colocatedDeps);
    }
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadBestOffers(std::deque<LedgerEntry>& offers,
                                    Asset const& buying, Asset const& selling,
                                    OfferDescriptor const& worseThan,
                                    size_t numOffers) const
{
    ZoneScoped;
    // ManageOffer and related operations won't work correctly with an offerID
    // equal to or exceeding INT64_MAX, so there is no reason to support it
    // here. We are far from this limit anyway.
    if (worseThan.offerID == INT64_MAX)
    {
        throw std::runtime_error("maximum offerID encountered");
    }

    // price is an approximation of the actual n/d (truncated math, 15 digits)
    // ordering by offerid gives precedence to older offers for fairness
    std::string sql =
        "WITH r1 AS "
        "(SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, "
        "pricen, priced, flags, lastmodified, extension, "
        "ledgerext FROM offers "
        "WHERE sellingasset = :v1 AND buyingasset = :v2 AND price > :v3 "
        "ORDER BY price, offerid LIMIT :v4), "
        "r2 AS "
        "(SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, "
        "pricen, priced, flags, lastmodified, extension, "
        "ledgerext FROM offers "
        "WHERE sellingasset = :v5 AND buyingasset = :v6 AND price = :v7 "
        "AND offerid >= :v8 ORDER BY price, offerid LIMIT :v9) "
        "SELECT sellerid, offerid, sellingasset, buyingasset, "
        "amount, pricen, priced, flags, lastmodified, extension, "
        "ledgerext "
        "FROM (SELECT * FROM r1 UNION ALL SELECT * FROM r2) AS res "
        "ORDER BY price, offerid LIMIT :v10";

    std::string buyingAsset, sellingAsset;
    buyingAsset = decoder::encode_b64(xdr::xdr_to_opaque(buying));
    sellingAsset = decoder::encode_b64(xdr::xdr_to_opaque(selling));

    double worseThanPrice =
        (double)worseThan.price.n / (double)worseThan.price.d;
    int64_t worseThanOfferID = worseThan.offerID + 1;

    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(worseThanPrice));
    st.exchange(soci::use(numOffers));
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(worseThanPrice));
    st.exchange(soci::use(worseThanOfferID));
    st.exchange(soci::use(numOffers));
    st.exchange(soci::use(numOffers));

    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        return loadOffers(prep, offers);
    }
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadBestOffers(
    std::deque<LedgerEntry>& offers, Asset const& buying, Asset const& selling,
    OfferDescriptor const& worseThan, size_t numOffers,
    UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>& colocatedDeps)
    const
{
    ZoneScoped;
    if (worseThan.offerID == INT64_MAX)
    {
        throw std::runtime_error("maximum offerID encountered");
    }

    std::string sql =
        "WITH r1 AS "
        "(SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, "
        "pricen, priced, flags, lastmodified, extension, "
        "ledgerext, accountentry, sellingtlentry, buyingtlentry FROM offers "
        "WHERE sellingasset = :v1 AND buyingasset = :v2 AND price > :v3 "
        "ORDER BY price, offerid LIMIT :v4), "
        "r2 AS "
        "(SELECT sellerid, offerid, sellingasset, buyingasset, amount, price, "
        "pricen, priced, flags, lastmodified, extension, "
        "ledgerext, accountentry, sellingtlentry, buyingtlentry FROM offers "
        "WHERE sellingasset = :v5 AND buyingasset = :v6 AND price = :v7 "
        "AND offerid >= :v8 ORDER BY price, offerid LIMIT :v9) "
        "SELECT sellerid, offerid, sellingasset, buyingasset, "
        "amount, pricen, priced, flags, lastmodified, extension, "
        "ledgerext, accountentry, sellingtlentry, buyingtlentry "
        "FROM (SELECT * FROM r1 UNION ALL SELECT * FROM r2) AS res "
        "ORDER BY price, offerid LIMIT :v10";

    std::string buyingAsset, sellingAsset;
    buyingAsset = decoder::encode_b64(xdr::xdr_to_opaque(buying));
    sellingAsset = decoder::encode_b64(xdr::xdr_to_opaque(selling));

    double worseThanPrice =
        (double)worseThan.price.n / (double)worseThan.price.d;
    int64_t worseThanOfferID = worseThan.offerID + 1;

    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(worseThanPrice));
    st.exchange(soci::use(numOffers));
    st.exchange(soci::use(sellingAsset));
    st.exchange(soci::use(buyingAsset));
    st.exchange(soci::use(worseThanPrice));
    st.exchange(soci::use(worseThanOfferID));
    st.exchange(soci::use(numOffers));
    st.exchange(soci::use(numOffers));

    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        return loadOffersWithDeps(prep, offers, colocatedDeps);
    }
}

bool
isBetterOffer(OfferDescriptor const& lhs, OfferDescriptor const& rhs)
{
    double lhsPrice = double(lhs.price.n) / double(lhs.price.d);
    double rhsPrice = double(rhs.price.n) / double(rhs.price.d);
    if (lhsPrice < rhsPrice)
    {
        return true;
    }
    else if (lhsPrice == rhsPrice)
    {
        return lhs.offerID < rhs.offerID;
    }
    else
    {
        return false;
    }
}

bool
isBetterOffer(OfferDescriptor const& lhs, LedgerEntry const& rhsEntry)
{
    auto const& rhs = rhsEntry.data.offer();
    return isBetterOffer(lhs, {rhs.price, rhs.offerID});
}

// Note: The order induced by this function must match the order used in the
// SQL query for loadBestOffers above.
bool
isBetterOffer(LedgerEntry const& lhsEntry, LedgerEntry const& rhsEntry)
{
    auto const& lhs = lhsEntry.data.offer();
    auto const& rhs = rhsEntry.data.offer();

    releaseAssert(lhs.buying == rhs.buying);
    releaseAssert(lhs.selling == rhs.selling);

    return isBetterOffer({lhs.price, lhs.offerID}, {rhs.price, rhs.offerID});
}

// Note: This function is currently only used in AllowTrustOpFrame, which means
// the asset parameter will never satisfy asset.type() == ASSET_TYPE_NATIVE. As
// a consequence, this function throws in that case.
std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadOffersByAccountAndAsset(AccountID const& accountID,
                                                 Asset const& asset) const
{
    ZoneScoped;
    std::string sql = "SELECT sellerid, offerid, sellingasset, buyingasset, "
                      "amount, pricen, priced, flags, lastmodified, extension, "
                      "ledgerext "
                      "FROM offers WHERE sellerid = :v1 AND "
                      "(sellingasset = :v2 OR buyingasset = :v3)";
    // Note: v2 == v3 but positional parameters are faster

    std::string accountStr = KeyUtils::toStrKey(accountID);

    if (asset.type() == ASSET_TYPE_NATIVE)
    {
        throw std::runtime_error("Invalid asset type");
    }
    std::string assetStr = decoder::encode_b64(xdr::xdr_to_opaque(asset));

    auto prep = mApp.getDatabase().getPreparedStatement(sql, getSession());
    auto& st = prep.statement();
    st.exchange(soci::use(accountStr));
    st.exchange(soci::use(assetStr));
    st.exchange(soci::use(assetStr));

    std::vector<LedgerEntry> offers;
    {
        auto timer = mApp.getDatabase().getSelectTimer("offer");
        offers = loadOffers(prep);
    }
    return offers;
}

static Asset
processAsset(std::string const& asset)
{
    Asset res;
    std::vector<uint8_t> assetOpaque;
    decoder::decode_b64(asset, assetOpaque);
    xdr::xdr_from_opaque(assetOpaque, res);
    return res;
}

static bool
needsTrustlineDep(AccountID const& sellerID, Asset const& asset)
{
    if (asset.type() == ASSET_TYPE_NATIVE)
    {
        return false;
    }
    if (asset.type() == ASSET_TYPE_POOL_SHARE)
    {
        return true;
    }
    return !isIssuer(sellerID, asset);
}

template <typename T>
static typename T::const_iterator
loadOffersHelper(StatementContext& prep, T& offers)
{
    ZoneScoped;

    std::string actIDStrKey;
    int64_t offerID;
    std::string sellingAsset, buyingAsset;
    int64_t amount;
    Price price;
    uint32_t flags, lastModified;
    std::string extensionStr;
    std::string ledgerExtStr;

    auto& st = prep.statement();
    st.exchange(soci::into(actIDStrKey));
    st.exchange(soci::into(offerID));
    st.exchange(soci::into(sellingAsset));
    st.exchange(soci::into(buyingAsset));
    st.exchange(soci::into(amount));
    st.exchange(soci::into(price.n));
    st.exchange(soci::into(price.d));
    st.exchange(soci::into(flags));
    st.exchange(soci::into(lastModified));
    st.exchange(soci::into(extensionStr));
    st.exchange(soci::into(ledgerExtStr));
    st.define_and_bind();
    st.execute(true);

    size_t n = 0;
    while (st.got_data())
    {
        ++n;
        offers.emplace_back();
        auto& le = offers.back();
        le.data.type(OFFER);
        auto& oe = le.data.offer();

        oe.sellerID = KeyUtils::fromStrKey<PublicKey>(actIDStrKey);
        oe.offerID = offerID;
        oe.selling = processAsset(sellingAsset);
        oe.buying = processAsset(buyingAsset);
        oe.amount = amount;
        oe.price = price;
        oe.flags = flags;
        le.lastModifiedLedgerSeq = lastModified;

        decodeOpaqueXDR(extensionStr, oe.ext);

        decodeOpaqueXDR(ledgerExtStr, le.ext);

        st.fetch();
    }

    return offers.cend() - n;
}

// Variant of loadOffersHelper that also reads co-located account/trustline
// columns and populates a dependency map.
static std::deque<LedgerEntry>::const_iterator
loadOffersWithDepsHelper(
    StatementContext& prep, std::deque<LedgerEntry>& offers,
    UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>& colocatedDeps)
{
    ZoneScoped;

    std::string actIDStrKey;
    int64_t offerID;
    std::string sellingAsset, buyingAsset;
    int64_t amount;
    Price price;
    uint32_t flags, lastModified;
    std::string extensionStr;
    std::string ledgerExtStr;
    std::string accountEntryStr;
    std::string sellingTLEntryStr;
    std::string buyingTLEntryStr;

    auto& st = prep.statement();
    st.exchange(soci::into(actIDStrKey));
    st.exchange(soci::into(offerID));
    st.exchange(soci::into(sellingAsset));
    st.exchange(soci::into(buyingAsset));
    st.exchange(soci::into(amount));
    st.exchange(soci::into(price.n));
    st.exchange(soci::into(price.d));
    st.exchange(soci::into(flags));
    st.exchange(soci::into(lastModified));
    st.exchange(soci::into(extensionStr));
    st.exchange(soci::into(ledgerExtStr));
    st.exchange(soci::into(accountEntryStr));
    st.exchange(soci::into(sellingTLEntryStr));
    st.exchange(soci::into(buyingTLEntryStr));
    st.define_and_bind();
    st.execute(true);

    size_t n = 0;
    while (st.got_data())
    {
        ++n;
        offers.emplace_back();
        auto& le = offers.back();
        le.data.type(OFFER);
        auto& oe = le.data.offer();

        oe.sellerID = KeyUtils::fromStrKey<PublicKey>(actIDStrKey);
        oe.offerID = offerID;
        oe.selling = processAsset(sellingAsset);
        oe.buying = processAsset(buyingAsset);
        oe.amount = amount;
        oe.price = price;
        oe.flags = flags;
        le.lastModifiedLedgerSeq = lastModified;

        decodeOpaqueXDR(extensionStr, oe.ext);
        decodeOpaqueXDR(ledgerExtStr, le.ext);

        // Decode co-located data.
        if (accountEntryStr.empty())
        {
            throw std::runtime_error(
                "missing co-located account dependency for "
                "offer " +
                std::to_string(oe.offerID));
        }
        auto acctLE = std::make_shared<LedgerEntry>();
        fromOpaqueBase64(*acctLE, accountEntryStr);
        auto expectedKey = accountKey(oe.sellerID);
#ifndef BUILD_TESTS
        if (LedgerEntryKey(*acctLE) != expectedKey)
        {
            throw std::runtime_error(
                "mismatched co-located account dependency for offer " +
                std::to_string(oe.offerID));
        }
#endif
        colocatedDeps[expectedKey] = acctLE;
        if (needsTrustlineDep(oe.sellerID, oe.selling))
        {
            if (sellingTLEntryStr.empty())
            {
                throw std::runtime_error("missing co-located selling trustline "
                                         "dependency for offer " +
                                         std::to_string(oe.offerID));
            }
            auto tlLE = std::make_shared<LedgerEntry>();
            fromOpaqueBase64(*tlLE, sellingTLEntryStr);
            auto expectedKey = trustlineKey(oe.sellerID, oe.selling);
#ifndef BUILD_TESTS
            if (LedgerEntryKey(*tlLE) != expectedKey)
            {
                throw std::runtime_error(
                    "mismatched co-located selling trustline dependency "
                    "for offer " +
                    std::to_string(oe.offerID));
            }
#endif
            colocatedDeps[expectedKey] = tlLE;
        }
        if (needsTrustlineDep(oe.sellerID, oe.buying))
        {
            if (buyingTLEntryStr.empty())
            {
                throw std::runtime_error("missing co-located buying trustline "
                                         "dependency for offer " +
                                         std::to_string(oe.offerID));
            }
            auto tlLE = std::make_shared<LedgerEntry>();
            fromOpaqueBase64(*tlLE, buyingTLEntryStr);
            auto expectedKey = trustlineKey(oe.sellerID, oe.buying);
#ifndef BUILD_TESTS
            if (LedgerEntryKey(*tlLE) != expectedKey)
            {
                throw std::runtime_error(
                    "mismatched co-located buying trustline dependency "
                    "for offer " +
                    std::to_string(oe.offerID));
            }
#endif
            colocatedDeps[expectedKey] = tlLE;
        }

        st.fetch();
    }

    return offers.cend() - n;
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadOffers(StatementContext& prep,
                                std::deque<LedgerEntry>& offers) const
{
    return loadOffersHelper(prep, offers);
}

std::deque<LedgerEntry>::const_iterator
LedgerTxnRoot::Impl::loadOffersWithDeps(
    StatementContext& prep, std::deque<LedgerEntry>& offers,
    UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>& colocatedDeps)
    const
{
    return loadOffersWithDepsHelper(prep, offers, colocatedDeps);
}

std::vector<LedgerEntry>
LedgerTxnRoot::Impl::loadOffers(StatementContext& prep) const
{
    std::vector<LedgerEntry> offers;
    loadOffersHelper(prep, offers);
    return offers;
}

class BulkUpsertOffersOperation : public DatabaseTypeSpecificOperation<void>
{
    Database& mDB;
    SessionWrapper& mSession;
    std::vector<std::string> mSellerIDs;
    std::vector<int64_t> mOfferIDs;
    std::vector<std::string> mSellingAssets;
    std::vector<std::string> mBuyingAssets;
    std::vector<int64_t> mAmounts;
    std::vector<int32_t> mPriceNs;
    std::vector<int32_t> mPriceDs;
    std::vector<double> mPrices;
    std::vector<int32_t> mFlags;
    std::vector<int32_t> mLastModifieds;
    std::vector<std::string> mExtensions;
    std::vector<std::string> mLedgerExtensions;
    std::vector<std::string> mAccountEntries;
    std::vector<std::string> mSellingTLEntries;
    std::vector<std::string> mBuyingTLEntries;

    void
    accumulateEntry(LedgerEntry const& entry)
    {
        releaseAssert(entry.data.type() == OFFER);
        auto const& offer = entry.data.offer();

        mSellerIDs.emplace_back(KeyUtils::toStrKey(offer.sellerID));
        mOfferIDs.emplace_back(offer.offerID);

        mSellingAssets.emplace_back(
            decoder::encode_b64(xdr::xdr_to_opaque(offer.selling)));
        mBuyingAssets.emplace_back(
            decoder::encode_b64(xdr::xdr_to_opaque(offer.buying)));

        mAmounts.emplace_back(offer.amount);
        mPriceNs.emplace_back(offer.price.n);
        mPriceDs.emplace_back(offer.price.d);
        double price = double(offer.price.n) / double(offer.price.d);
        mPrices.emplace_back(price);

        mFlags.emplace_back(unsignedToSigned(offer.flags));
        mLastModifieds.emplace_back(
            unsignedToSigned(entry.lastModifiedLedgerSeq));
        mExtensions.emplace_back(
            decoder::encode_b64(xdr::xdr_to_opaque(offer.ext)));
        mLedgerExtensions.emplace_back(
            decoder::encode_b64(xdr::xdr_to_opaque(entry.ext)));
        // Co-located data defaults to empty; filled by bulkUpdateOfferDeps
        mAccountEntries.emplace_back("");
        mSellingTLEntries.emplace_back("");
        mBuyingTLEntries.emplace_back("");
    }

  public:
    BulkUpsertOffersOperation(Database& DB,
                              std::vector<LedgerEntry> const& entries,
                              SessionWrapper& session)
        : mDB(DB), mSession(session)
    {
        mSellerIDs.reserve(entries.size());
        mOfferIDs.reserve(entries.size());
        mSellingAssets.reserve(entries.size());
        mBuyingAssets.reserve(entries.size());
        mAmounts.reserve(entries.size());
        mPriceNs.reserve(entries.size());
        mPriceDs.reserve(entries.size());
        mPrices.reserve(entries.size());
        mFlags.reserve(entries.size());
        mLastModifieds.reserve(entries.size());
        mExtensions.reserve(entries.size());
        mLedgerExtensions.reserve(entries.size());
        mAccountEntries.reserve(entries.size());
        mSellingTLEntries.reserve(entries.size());
        mBuyingTLEntries.reserve(entries.size());

        for (auto const& e : entries)
        {
            accumulateEntry(e);
        }
    }

    BulkUpsertOffersOperation(Database& DB,
                              std::vector<EntryIterator> const& entries,
                              SessionWrapper& session)
        : mDB(DB), mSession(session)
    {
        mSellerIDs.reserve(entries.size());
        mOfferIDs.reserve(entries.size());
        mSellingAssets.reserve(entries.size());
        mBuyingAssets.reserve(entries.size());
        mAmounts.reserve(entries.size());
        mPriceNs.reserve(entries.size());
        mPriceDs.reserve(entries.size());
        mPrices.reserve(entries.size());
        mFlags.reserve(entries.size());
        mLastModifieds.reserve(entries.size());
        mExtensions.reserve(entries.size());
        mLedgerExtensions.reserve(entries.size());
        mAccountEntries.reserve(entries.size());
        mSellingTLEntries.reserve(entries.size());
        mBuyingTLEntries.reserve(entries.size());

        for (auto const& e : entries)
        {
            releaseAssert(e.entryExists());
            releaseAssert(e.entry().type() ==
                          InternalLedgerEntryType::LEDGER_ENTRY);
            accumulateEntry(e.entry().ledgerEntry());
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql =
            "INSERT INTO offers ( "
            "sellerid, offerid, sellingasset, buyingasset, "
            "amount, pricen, priced, price, flags, lastmodified, extension, "
            "ledgerext, accountentry, sellingtlentry, buyingtlentry "
            ") VALUES ( "
            ":v1, :v2, :v3, :v4, :v5, :v6, :v7, :v8, :v9, :v10, :v11, "
            ":v12, :v13, :v14, :v15 "
            ") ON CONFLICT (offerid) DO UPDATE SET "
            "sellerid = excluded.sellerid, "
            "sellingasset = excluded.sellingasset, "
            "buyingasset = excluded.buyingasset, "
            "amount = excluded.amount, "
            "pricen = excluded.pricen, "
            "priced = excluded.priced, "
            "price = excluded.price, "
            "flags = excluded.flags, "
            "lastmodified = excluded.lastmodified, "
            "extension = excluded.extension, "
            "ledgerext = excluded.ledgerext, "
            "accountentry = CASE WHEN excluded.accountentry = '' "
            "THEN offers.accountentry ELSE excluded.accountentry END, "
            "sellingtlentry = CASE WHEN excluded.sellingtlentry = '' "
            "THEN offers.sellingtlentry ELSE excluded.sellingtlentry END, "
            "buyingtlentry = CASE WHEN excluded.buyingtlentry = '' "
            "THEN offers.buyingtlentry ELSE excluded.buyingtlentry END";
        auto prep = mDB.getPreparedStatement(sql, mSession);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(mSellerIDs));
        st.exchange(soci::use(mOfferIDs));
        st.exchange(soci::use(mSellingAssets));
        st.exchange(soci::use(mBuyingAssets));
        st.exchange(soci::use(mAmounts));
        st.exchange(soci::use(mPriceNs));
        st.exchange(soci::use(mPriceDs));
        st.exchange(soci::use(mPrices));
        st.exchange(soci::use(mFlags));
        st.exchange(soci::use(mLastModifieds));
        st.exchange(soci::use(mExtensions));
        st.exchange(soci::use(mLedgerExtensions));
        st.exchange(soci::use(mAccountEntries));
        st.exchange(soci::use(mSellingTLEntries));
        st.exchange(soci::use(mBuyingTLEntries));
        st.define_and_bind();
        {
            auto timer = mDB.getUpsertTimer("offer");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mOfferIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {

        std::string strSellerIDs, strOfferIDs, strSellingAssets,
            strBuyingAssets, strAmounts, strPriceNs, strPriceDs, strPrices,
            strFlags, strLastModifieds, strExtensions, strLedgerExtensions,
            strAccountEntries, strSellingTLEntries, strBuyingTLEntries;

        PGconn* conn = pg->conn_;
        marshalToPGArray(conn, strSellerIDs, mSellerIDs);
        marshalToPGArray(conn, strOfferIDs, mOfferIDs);

        marshalToPGArray(conn, strSellingAssets, mSellingAssets);
        marshalToPGArray(conn, strBuyingAssets, mBuyingAssets);

        marshalToPGArray(conn, strAmounts, mAmounts);
        marshalToPGArray(conn, strPriceNs, mPriceNs);
        marshalToPGArray(conn, strPriceDs, mPriceDs);
        marshalToPGArray(conn, strPrices, mPrices);
        marshalToPGArray(conn, strFlags, mFlags);
        marshalToPGArray(conn, strLastModifieds, mLastModifieds);
        marshalToPGArray(conn, strExtensions, mExtensions);
        marshalToPGArray(conn, strLedgerExtensions, mLedgerExtensions);
        marshalToPGArray(conn, strAccountEntries, mAccountEntries);
        marshalToPGArray(conn, strSellingTLEntries, mSellingTLEntries);
        marshalToPGArray(conn, strBuyingTLEntries, mBuyingTLEntries);

        std::string sql =
            "WITH r AS (SELECT "
            "unnest(:v1::TEXT[]), "
            "unnest(:v2::BIGINT[]), "
            "unnest(:v3::TEXT[]), "
            "unnest(:v4::TEXT[]), "
            "unnest(:v5::BIGINT[]), "
            "unnest(:v6::INT[]), "
            "unnest(:v7::INT[]), "
            "unnest(:v8::DOUBLE PRECISION[]), "
            "unnest(:v9::INT[]), "
            "unnest(:v10::INT[]), "
            "unnest(:v11::TEXT[]), "
            "unnest(:v12::TEXT[]), "
            "unnest(:v13::TEXT[]), "
            "unnest(:v14::TEXT[]), "
            "unnest(:v15::TEXT[]) "
            ")"
            "INSERT INTO offers ( "
            "sellerid, offerid, sellingasset, buyingasset, "
            "amount, pricen, priced, price, flags, lastmodified, extension, "
            "ledgerext, accountentry, sellingtlentry, buyingtlentry "
            ") SELECT * from r "
            "ON CONFLICT (offerid) DO UPDATE SET "
            "sellerid = excluded.sellerid, "
            "sellingasset = excluded.sellingasset, "
            "buyingasset = excluded.buyingasset, "
            "amount = excluded.amount, "
            "pricen = excluded.pricen, "
            "priced = excluded.priced, "
            "price = excluded.price, "
            "flags = excluded.flags, "
            "lastmodified = excluded.lastmodified, "
            "extension = excluded.extension, "
            "ledgerext = excluded.ledgerext, "
            "accountentry = CASE WHEN excluded.accountentry = '' "
            "THEN offers.accountentry ELSE excluded.accountentry END, "
            "sellingtlentry = CASE WHEN excluded.sellingtlentry = '' "
            "THEN offers.sellingtlentry ELSE excluded.sellingtlentry END, "
            "buyingtlentry = CASE WHEN excluded.buyingtlentry = '' "
            "THEN offers.buyingtlentry ELSE excluded.buyingtlentry END";
        auto prep = mDB.getPreparedStatement(sql, mSession);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(strSellerIDs));
        st.exchange(soci::use(strOfferIDs));
        st.exchange(soci::use(strSellingAssets));
        st.exchange(soci::use(strBuyingAssets));
        st.exchange(soci::use(strAmounts));
        st.exchange(soci::use(strPriceNs));
        st.exchange(soci::use(strPriceDs));
        st.exchange(soci::use(strPrices));
        st.exchange(soci::use(strFlags));
        st.exchange(soci::use(strLastModifieds));
        st.exchange(soci::use(strExtensions));
        st.exchange(soci::use(strLedgerExtensions));
        st.exchange(soci::use(strAccountEntries));
        st.exchange(soci::use(strSellingTLEntries));
        st.exchange(soci::use(strBuyingTLEntries));
        st.define_and_bind();
        {
            auto timer = mDB.getUpsertTimer("offer");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mOfferIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

class BulkDeleteOffersOperation : public DatabaseTypeSpecificOperation<void>
{
    Database& mDB;
    LedgerTxnConsistency mCons;
    SessionWrapper& mSession;
    std::vector<int64_t> mOfferIDs;

  public:
    BulkDeleteOffersOperation(Database& DB, LedgerTxnConsistency cons,
                              std::vector<EntryIterator> const& entries,
                              SessionWrapper& session)
        : mDB(DB), mCons(cons), mSession(session)
    {
        for (auto const& e : entries)
        {
            releaseAssert(!e.entryExists());
            releaseAssert(e.key().type() ==
                          InternalLedgerEntryType::LEDGER_ENTRY);
            releaseAssert(e.key().ledgerKey().type() == OFFER);
            auto const& offer = e.key().ledgerKey().offer();
            mOfferIDs.emplace_back(offer.offerID);
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql = "DELETE FROM offers WHERE offerid = :id";
        auto prep = mDB.getPreparedStatement(sql, mSession);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(mOfferIDs));
        st.define_and_bind();
        {
            auto timer = mDB.getDeleteTimer("offer");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mOfferIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        PGconn* conn = pg->conn_;
        std::string strOfferIDs;
        marshalToPGArray(conn, strOfferIDs, mOfferIDs);
        std::string sql = "WITH r AS (SELECT "
                          "unnest(:ids::BIGINT[]) "
                          ") "
                          "DELETE FROM offers WHERE "
                          "offerid IN (SELECT * FROM r)";
        auto prep = mDB.getPreparedStatement(sql, mSession);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(strOfferIDs));
        st.define_and_bind();
        {
            auto timer = mDB.getDeleteTimer("offer");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mOfferIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

void
LedgerTxnRoot::Impl::bulkUpsertOffers(std::vector<EntryIterator> const& entries)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(entries.size()));
    BulkUpsertOffersOperation op(mApp.getDatabase(), entries, getSession());
    mApp.getDatabase().doDatabaseTypeSpecificOperation(getSession(), op);
}

void
LedgerTxnRoot::Impl::bulkDeleteOffers(std::vector<EntryIterator> const& entries,
                                      LedgerTxnConsistency cons)
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(entries.size()));
    BulkDeleteOffersOperation op(mApp.getDatabase(), cons, entries,
                                 getSession());
    mApp.getDatabase().doDatabaseTypeSpecificOperation(getSession(), op);
}

void
LedgerTxnRoot::Impl::bulkUpdateOfferDeps(
    BulkLedgerEntryChangeAccumulator const& bleca)
{
    ZoneScoped;

    auto const& changedAccounts = bleca.getChangedAccounts();
    auto const& changedTrustlines = bleca.getChangedTrustlines();
    auto const& deletedAccounts = bleca.getDeletedAccounts();
    auto const& deletedTrustlines = bleca.getDeletedTrustlines();

    if (changedAccounts.empty() && changedTrustlines.empty() &&
        deletedAccounts.empty() && deletedTrustlines.empty())
    {
        return;
    }

    auto& session = getSession().session();

    // Update accountentry for changed accounts
    for (auto const& [accountID, le] : changedAccounts)
    {
        std::string blob = toOpaqueBase64(le);
        std::string sellerStr = KeyUtils::toStrKey(accountID);
        session << "UPDATE offers SET accountentry = :blob WHERE sellerid = "
                   ":sid",
            soci::use(blob), soci::use(sellerStr);
    }

    // Deleted accounts must not own any remaining offers.
    for (auto const& accountID : deletedAccounts)
    {
        std::string sellerStr = KeyUtils::toStrKey(accountID);
        int64_t danglingOffers = 0;
        session << "SELECT COUNT(*) FROM offers WHERE sellerid = :sid",
            soci::into(danglingOffers), soci::use(sellerStr);
        if (danglingOffers != 0)
        {
            throw std::runtime_error(
                "dangling offers for deleted account while updating deps");
        }
    }

    // Update trustline entries for changed trustlines
    for (auto const& [tlKey, le] : changedTrustlines)
    {
        std::string blob = toOpaqueBase64(le);
        std::string sellerStr = KeyUtils::toStrKey(tlKey.trustLine().accountID);
        std::string assetStr =
            decoder::encode_b64(xdr::xdr_to_opaque(tlKey.trustLine().asset));

        // Update sellingtlentry where this trustline's asset is the selling
        // asset
        session << "UPDATE offers SET sellingtlentry = :blob WHERE sellerid "
                   "= :sid AND sellingasset = :asset",
            soci::use(blob), soci::use(sellerStr), soci::use(assetStr);

        // Update buyingtlentry where this trustline's asset is the buying
        // asset
        session << "UPDATE offers SET buyingtlentry = :blob WHERE sellerid = "
                   ":sid AND buyingasset = :asset",
            soci::use(blob), soci::use(sellerStr), soci::use(assetStr);
    }

    // Deleted trustlines must not be referenced by any remaining offers.
    for (auto const& tlKey : deletedTrustlines)
    {
        std::string sellerStr = KeyUtils::toStrKey(tlKey.trustLine().accountID);
        std::string assetStr =
            decoder::encode_b64(xdr::xdr_to_opaque(tlKey.trustLine().asset));
        int64_t danglingOffers = 0;
        session << "SELECT COUNT(*) FROM offers "
                   "WHERE sellerid = :sid "
                   "AND (sellingasset = :sasset OR buyingasset = :basset)",
            soci::into(danglingOffers), soci::use(sellerStr),
            soci::use(assetStr), soci::use(assetStr);
        if (danglingOffers != 0)
        {
            throw std::runtime_error(
                "dangling offers for deleted trustline while updating deps");
        }
    }
}

void
LedgerTxnRoot::Impl::bulkPopulateNewOfferDeps(
    BulkLedgerEntryChangeAccumulator const& bleca)
{
    ZoneScoped;

    auto const& upsertedOffers = bleca.getUpsertedOffers();
    auto const& changedAccounts = bleca.getChangedAccounts();
    auto const& deletedAccounts = bleca.getDeletedAccounts();
    auto const& changedTrustlines = bleca.getChangedTrustlines();
    auto const& deletedTrustlines = bleca.getDeletedTrustlines();

    // Refresh deps for all offers owned by any seller whose account/trustline
    // changed, plus sellers with upserted offers.
    UnorderedSet<AccountID> sellersToRefresh;
    sellersToRefresh.reserve(upsertedOffers.size() + changedAccounts.size() +
                             deletedAccounts.size() + changedTrustlines.size() +
                             deletedTrustlines.size());
    for (auto const& info : upsertedOffers)
    {
        sellersToRefresh.emplace(info.sellerID);
    }
    for (auto const& [sellerID, _] : changedAccounts)
    {
        sellersToRefresh.emplace(sellerID);
    }
    for (auto const& sellerID : deletedAccounts)
    {
        sellersToRefresh.emplace(sellerID);
    }
    for (auto const& [tlKey, _] : changedTrustlines)
    {
        sellersToRefresh.emplace(tlKey.trustLine().accountID);
    }
    for (auto const& tlKey : deletedTrustlines)
    {
        sellersToRefresh.emplace(tlKey.trustLine().accountID);
    }

    if (sellersToRefresh.empty())
    {
        return;
    }

    struct OfferDepInfo
    {
        int64_t offerID;
        AccountID sellerID;
        Asset selling;
        Asset buying;
    };
    UnorderedMap<int64_t, OfferDepInfo> offersToRefresh;
    for (auto const& sellerID : sellersToRefresh)
    {
        std::string sellerStr = KeyUtils::toStrKey(sellerID);
        int64_t offerID = 0;
        std::string sellingAssetStr;
        std::string buyingAssetStr;
        auto prep = mApp.getDatabase().getPreparedStatement(
            "SELECT offerid, sellingasset, buyingasset "
            "FROM offers WHERE sellerid = :sid",
            getSession());
        auto& st = prep.statement();
        st.exchange(soci::use(sellerStr));
        st.exchange(soci::into(offerID));
        st.exchange(soci::into(sellingAssetStr));
        st.exchange(soci::into(buyingAssetStr));
        st.define_and_bind();
        st.execute(true);
        while (st.got_data())
        {
            offersToRefresh.emplace(offerID,
                                    OfferDepInfo{offerID, sellerID,
                                                 processAsset(sellingAssetStr),
                                                 processAsset(buyingAssetStr)});
            st.fetch();
        }
    }

    if (offersToRefresh.empty())
    {
        return;
    }

    UnorderedSet<LedgerKey> missingKeys;
    for (auto const& [_, info] : offersToRefresh)
    {
        if (changedAccounts.find(info.sellerID) == changedAccounts.end())
        {
            missingKeys.emplace(accountKey(info.sellerID));
        }

        if (needsTrustlineDep(info.sellerID, info.selling))
        {
            auto key = trustlineKey(info.sellerID, info.selling);
            if (changedTrustlines.find(key) == changedTrustlines.end())
            {
                missingKeys.emplace(key);
            }
        }

        if (needsTrustlineDep(info.sellerID, info.buying))
        {
            auto key = trustlineKey(info.sellerID, info.buying);
            if (changedTrustlines.find(key) == changedTrustlines.end())
            {
                missingKeys.emplace(key);
            }
        }
    }

    UnorderedMap<LedgerKey, std::string> blobMap;
    for (auto const& [sellerID, le] : changedAccounts)
    {
        blobMap.emplace(accountKey(sellerID), toOpaqueBase64(le));
    }
    for (auto const& [tlKey, le] : changedTrustlines)
    {
        blobMap.emplace(tlKey, toOpaqueBase64(le));
    }
    if (!missingKeys.empty())
    {
        auto const& snapshot = getSearchableLiveBucketListSnapshot();
        std::set<LedgerKey, LedgerEntryIdCmp> orderedKeys(missingKeys.begin(),
                                                          missingKeys.end());
        auto loaded =
            snapshot.loadKeys(orderedKeys, "bulkPopulateNewOfferDeps");
        for (auto const& le : loaded)
        {
            blobMap.emplace(LedgerEntryKey(le), toOpaqueBase64(le));
        }
    }

    auto& session = getSession().session();
    for (auto const& offerToRefresh : offersToRefresh)
    {
        auto const& info = offerToRefresh.second;
        int64_t const offerID = info.offerID;
        auto getRequiredBlob = [&](LedgerKey const& key,
                                   char const* depType) -> std::string const& {
            auto blobIter = blobMap.find(key);
            if (blobIter == blobMap.end() || blobIter->second.empty())
            {
                throw std::runtime_error(std::string("missing required ") +
                                         depType + " dependency for offer " +
                                         std::to_string(offerID));
            }
            return blobIter->second;
        };

        auto const& accountBlob =
            getRequiredBlob(accountKey(info.sellerID), "account");

        std::string sellingTlBlob;
        if (needsTrustlineDep(info.sellerID, info.selling))
        {
            sellingTlBlob = getRequiredBlob(
                trustlineKey(info.sellerID, info.selling), "selling trustline");
        }

        std::string buyingTlBlob;
        if (needsTrustlineDep(info.sellerID, info.buying))
        {
            buyingTlBlob = getRequiredBlob(
                trustlineKey(info.sellerID, info.buying), "buying trustline");
        }

        session << "UPDATE offers "
                   "SET accountentry = :acct, "
                   "sellingtlentry = :stl, "
                   "buyingtlentry = :btl "
                   "WHERE offerid = :oid",
            soci::use(accountBlob), soci::use(sellingTlBlob),
            soci::use(buyingTlBlob), soci::use(offerID);
    }
}

void
LedgerTxnRoot::Impl::populateOfferDeps()
{
    ZoneScoped;
    throwIfChild();

    LOG_INFO(DEFAULT_LOG, "Populating offer dependency data (co-located "
                          "account/trustline entries)");

    // Load all offers to determine needed accounts and trustlines
    auto allOffers = loadAllOffers();

    if (allOffers.empty())
    {
        LOG_INFO(DEFAULT_LOG, "No offers to populate dependencies for");
        return;
    }

    // Collect unique keys needed
    UnorderedSet<LedgerKey> keysToLoad;
    for (auto const& le : allOffers)
    {
        auto const& oe = le.data.offer();
        keysToLoad.emplace(accountKey(oe.sellerID));
        if (needsTrustlineDep(oe.sellerID, oe.selling))
        {
            keysToLoad.emplace(trustlineKey(oe.sellerID, oe.selling));
        }
        if (needsTrustlineDep(oe.sellerID, oe.buying))
        {
            keysToLoad.emplace(trustlineKey(oe.sellerID, oe.buying));
        }
    }

    LOG_INFO(DEFAULT_LOG,
             "Loading {} dependency entries for {} offers from BucketList",
             keysToLoad.size(), allOffers.size());

    // Bulk-load from BucketList
    auto const& snapshot = getSearchableLiveBucketListSnapshot();
    std::set<LedgerKey, LedgerEntryIdCmp> orderedKeys(keysToLoad.begin(),
                                                      keysToLoad.end());
    auto loaded = snapshot.loadKeys(orderedKeys, "populateOfferDeps");

    // Build a map from key -> LedgerEntry blob
    UnorderedMap<LedgerKey, std::string> blobMap;
    for (auto const& le : loaded)
    {
        blobMap[LedgerEntryKey(le)] = toOpaqueBase64(le);
    }

    LOG_INFO(DEFAULT_LOG,
             "Loaded {} entries from BucketList, updating offers table",
             loaded.size());

    // Update offers in batches
    auto& session = getSession().session();
    size_t updated = 0;
    for (auto const& le : allOffers)
    {
        auto const& oe = le.data.offer();

        auto getRequiredBlob = [&](LedgerKey const& key,
                                   char const* depType) -> std::string const& {
            auto blobIter = blobMap.find(key);
            if (blobIter == blobMap.end() || blobIter->second.empty())
            {
                throw std::runtime_error(std::string("missing required ") +
                                         depType + " dependency for offer " +
                                         std::to_string(oe.offerID));
            }
            return blobIter->second;
        };

        auto const& acctBlob =
            getRequiredBlob(accountKey(oe.sellerID), "account");

        std::string sellingTLBlob;
        if (needsTrustlineDep(oe.sellerID, oe.selling))
        {
            sellingTLBlob = getRequiredBlob(
                trustlineKey(oe.sellerID, oe.selling), "selling trustline");
        }

        std::string buyingTLBlob;
        if (needsTrustlineDep(oe.sellerID, oe.buying))
        {
            buyingTLBlob = getRequiredBlob(trustlineKey(oe.sellerID, oe.buying),
                                           "buying trustline");
        }

        int64_t offerID = oe.offerID;
        session << "UPDATE offers SET accountentry = :acct, sellingtlentry = "
                   ":stl, buyingtlentry = :btl WHERE offerid = :oid",
            soci::use(acctBlob), soci::use(sellingTLBlob),
            soci::use(buyingTLBlob), soci::use(offerID);
        ++updated;
    }

    LOG_INFO(DEFAULT_LOG, "Populated co-located data for {} offers", updated);
}

void
LedgerTxnRoot::Impl::dropOffers()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffers.clear();

    getSession().session() << "DROP TABLE IF EXISTS offers;";

    std::string coll = mApp.getDatabase().getSimpleCollationClause();
    mApp.getDatabase().getRawSession()
        << "CREATE TABLE offers"
        << "("
        << "sellerid         VARCHAR(56) " << coll << "NOT NULL,"
        << "offerid          BIGINT           NOT NULL CHECK (offerid >= "
           "0),"
        << "sellingasset     TEXT " << coll << " NOT NULL,"
        << "buyingasset      TEXT " << coll << " NOT NULL,"
        << "amount           BIGINT           NOT NULL CHECK (amount >= 0),"
           "pricen           INT              NOT NULL,"
           "priced           INT              NOT NULL,"
           "price            DOUBLE PRECISION NOT NULL,"
           "flags            INT              NOT NULL,"
           "lastmodified     INT              NOT NULL,"
           "extension        TEXT             NOT NULL,"
           "ledgerext        TEXT             NOT NULL,"
           "accountentry     TEXT             NOT NULL DEFAULT '',"
           "sellingtlentry   TEXT             NOT NULL DEFAULT '',"
           "buyingtlentry    TEXT             NOT NULL DEFAULT '',"
           "PRIMARY KEY      (offerid)"
           ");";
    mApp.getDatabase().getRawSession()
        << "CREATE INDEX bestofferindex ON offers "
           "(sellingasset,buyingasset,price,offerid);";
    mApp.getDatabase().getRawSession()
        << "CREATE INDEX offerbyseller ON offers "
           "(sellerid);";
    if (!mApp.getDatabase().isSqlite())
    {
        mApp.getDatabase().getRawSession() << "ALTER TABLE offers "
                                           << "ALTER COLUMN sellerid "
                                           << "TYPE VARCHAR(56) COLLATE \"C\", "
                                           << "ALTER COLUMN buyingasset "
                                           << "TYPE TEXT COLLATE \"C\", "
                                           << "ALTER COLUMN sellingasset "
                                           << "TYPE TEXT COLLATE \"C\"";
    }
}

class BulkLoadOffersOperation
    : public DatabaseTypeSpecificOperation<std::vector<LedgerEntry>>
{
    Database& mDb;
    SessionWrapper& mSession;
    std::vector<int64_t> mOfferIDs;
    UnorderedSet<LedgerKey> mKeys;

    std::vector<LedgerEntry>
    executeAndFetch(soci::statement& st)
    {
        std::string sellerID, sellingAsset, buyingAsset;
        int64_t amount;
        int64_t offerID;
        uint32_t flags, lastModified;
        std::string extension;
        std::string ledgerExtension;
        Price price;

        st.exchange(soci::into(sellerID));
        st.exchange(soci::into(offerID));
        st.exchange(soci::into(sellingAsset));
        st.exchange(soci::into(buyingAsset));
        st.exchange(soci::into(amount));
        st.exchange(soci::into(price.n));
        st.exchange(soci::into(price.d));
        st.exchange(soci::into(flags));
        st.exchange(soci::into(lastModified));
        st.exchange(soci::into(extension));
        st.exchange(soci::into(ledgerExtension));
        st.define_and_bind();
        {
            auto timer = mDb.getSelectTimer("offer");
            st.execute(true);
        }

        std::vector<LedgerEntry> res;
        while (st.got_data())
        {
            auto pubKey = KeyUtils::fromStrKey<PublicKey>(sellerID);

            res.emplace_back();
            auto& le = res.back();
            le.data.type(OFFER);
            auto& oe = le.data.offer();

            oe.sellerID = pubKey;
            oe.offerID = offerID;

            oe.selling = processAsset(sellingAsset);
            oe.buying = processAsset(buyingAsset);

            oe.amount = amount;
            oe.price = price;
            oe.flags = flags;
            le.lastModifiedLedgerSeq = lastModified;

            decodeOpaqueXDR(extension, oe.ext);

            decodeOpaqueXDR(ledgerExtension, le.ext);

            st.fetch();
        }
        return res;
    }

  public:
    BulkLoadOffersOperation(Database& db, UnorderedSet<LedgerKey> const& keys,
                            SessionWrapper& session)
        : mDb(db), mSession(session)
    {
        mOfferIDs.reserve(keys.size());
        for (auto const& k : keys)
        {
            releaseAssert(k.type() == OFFER);
            if (k.offer().offerID >= 0)
            {
                mOfferIDs.emplace_back(k.offer().offerID);
            }
        }
    }

    virtual std::vector<LedgerEntry>
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        std::string sql =
            "SELECT sellerid, offerid, sellingasset, buyingasset, "
            "amount, pricen, priced, flags, lastmodified, extension, "
            "ledgerext "
            "FROM offers WHERE offerid IN carray(?, ?, 'int64')";

        auto prep = mDb.getPreparedStatement(sql, mSession);
        auto be = prep.statement().get_backend();
        if (be == nullptr)
        {
            throw std::runtime_error("no sql backend");
        }
        auto sqliteStatement =
            dynamic_cast<soci::sqlite3_statement_backend*>(be);
        releaseAssertOrThrow(sqliteStatement);
        auto st = sqliteStatement->stmt_;

        sqlite3_reset(st);
        sqlite3_bind_pointer(st, 1, (void*)mOfferIDs.data(), "carray", 0);
        sqlite3_bind_int(st, 2, static_cast<int>(mOfferIDs.size()));
        return executeAndFetch(prep.statement());
    }

#ifdef USE_POSTGRES
    std::vector<LedgerEntry>
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strOfferIDs;
        marshalToPGArray(pg->conn_, strOfferIDs, mOfferIDs);

        std::string sql =
            "WITH r AS (SELECT unnest(:v1::BIGINT[])) "
            "SELECT sellerid, offerid, sellingasset, buyingasset, "
            "amount, pricen, priced, flags, lastmodified, extension, "
            "ledgerext "
            "FROM offers WHERE offerid IN (SELECT * FROM r)";
        auto prep = mDb.getPreparedStatement(sql, mSession);
        auto& st = prep.statement();
        st.exchange(soci::use(strOfferIDs));
        return executeAndFetch(st);
    }
#endif
};

UnorderedMap<LedgerKey, std::shared_ptr<LedgerEntry const>>
LedgerTxnRoot::Impl::bulkLoadOffers(UnorderedSet<LedgerKey> const& keys) const
{
    ZoneScoped;
    ZoneValue(static_cast<int64_t>(keys.size()));
    if (!keys.empty())
    {
        BulkLoadOffersOperation op(mApp.getDatabase(), keys, getSession());
        return populateLoadedEntries(
            keys, mApp.getDatabase().doDatabaseTypeSpecificOperation(
                      getSession(), op));
    }
    else
    {
        return {};
    }
}
}
