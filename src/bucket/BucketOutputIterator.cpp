// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/BucketOutputIterator.h"
#include "bucket/BucketIndexUtils.h"
#include "bucket/BucketManager.h"
#include "bucket/HotArchiveBucket.h"
#include "bucket/LiveBucket.h"
#include "bucket/LiveBucketIndex.h"
#include "ledger/LedgerTypeUtils.h"
#include "util/GlobalChecks.h"
#include "util/ProtocolVersion.h"
#include "util/XDROperators.h"
#include <Tracy.hpp>
#include <filesystem>
#include <fmt/format.h>

#ifdef __linux__
#include <cstdlib>
#include <signal.h>
#endif

namespace stellar
{

/**
 * Helper class that points to an output tempfile. Absorbs BucketEntries and
 * hashes them while writing to either destination. Produces a Bucket when done.
 */
template <typename BucketT>
BucketOutputIterator<BucketT>::BucketOutputIterator(
    std::string const& tmpDir, bool keepTombstoneEntries,
    BucketMetadata const& meta, MergeCounters& mc, asio::io_context& ctx,
    bool doFsync, BucketWriteMode mode, std::string const& bucketDir)
    : mMode(mode)
#ifdef __linux__
    , mSink(mode == BucketWriteMode::MmapCrashOnlyLinux
                ? std::variant<XDROutputFileStream, MmapWriter>(
                      std::in_place_type<MmapWriter>)
                : std::variant<XDROutputFileStream, MmapWriter>(
                      std::in_place_type<XDROutputFileStream>, ctx, doFsync))
#else
    , mSink(ctx, doFsync)
#endif
    , mBucketDir(bucketDir)
    , mCtx(ctx)
    , mBuf(nullptr)
    , mKeepTombstoneEntries(keepTombstoneEntries)
    , mMeta(meta)
    , mMergeCounters(mc)
{
    ZoneScoped;

#ifdef __linux__
    if (mode == BucketWriteMode::MmapCrashOnlyLinux)
    {
        releaseAssert(!bucketDir.empty());
        // Estimate initial capacity based on typical bucket sizes
        // Start with 8MB, will grow as needed
        size_t initialCap = 8 << 20;
        auto& sink = std::get<MmapWriter>(mSink);
        sink.openInDir(bucketDir, "top", initialCap);
        mFilename = sink.tempPath();
        CLOG_TRACE(Bucket, "BucketOutputIterator opened mmap file: {}",
                   mFilename);

        // Test hook: crash after opening
        if (std::getenv("STELLAR_FAULT_AFTER_MMAP_OPEN"))
        {
            CLOG_ERROR(Bucket,
                       "Test fault injection: crashing after mmap open");
            raise(SIGSEGV);
        }
    }
    else
#endif
    {
        mFilename = BucketT::randomBucketName(tmpDir);
        CLOG_TRACE(Bucket, "BucketOutputIterator opening file to write: {}",
                   mFilename);
#ifdef __linux__
        std::get<XDROutputFileStream>(mSink).open(mFilename.string());
#else
        mSink.open(mFilename.string());
#endif
    }

    if (protocolVersionStartsFrom(
            meta.ledgerVersion,
            LiveBucket::FIRST_PROTOCOL_SUPPORTING_INITENTRY_AND_METAENTRY))
    {

        if constexpr (std::is_same_v<BucketT, LiveBucket>)
        {
            BucketEntry bme;
            bme.type(METAENTRY);
            bme.metaEntry() = mMeta;
            put(bme);
        }
        else
        {
            static_assert(std::is_same_v<BucketT, HotArchiveBucket>,
                          "unexpected bucket type");
            releaseAssertOrThrow(protocolVersionStartsFrom(
                meta.ledgerVersion,
                BucketT::FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION));

            HotArchiveBucketEntry bme;
            bme.type(HOT_ARCHIVE_METAENTRY);
            bme.metaEntry() = mMeta;
            releaseAssertOrThrow(bme.metaEntry().ext.v() == 1);
            put(bme);
        }

        mPutMeta = true;
    }
}

template <typename BucketT>
void
BucketOutputIterator<BucketT>::writeOneViaSink(
    typename BucketT::EntryT const& e)
{
    ZoneScoped;

#ifdef __linux__
    if (mMode == BucketWriteMode::MmapCrashOnlyLinux)
    {
        // Serialize XDR directly to a temp buffer then write to mmap
        // This mimics XDROutputFileStream::writeOne
        uint32_t sz = (uint32_t)xdr::xdr_size(e);
        releaseAssertOrThrow(sz < 0x80000000);

        // Reuse serialization buffer to avoid per-entry allocations
        mSerBuf.resize(sz + 4);

        // Write 4 bytes of size, big-endian, with XDR 'continuation' bit set
        // The high bit (0x80) marks this as XDR framing, not a fragment
        mSerBuf[0] = static_cast<char>(((sz >> 24) & 0xFF) | 0x80);
        mSerBuf[1] = static_cast<char>((sz >> 16) & 0xFF);
        mSerBuf[2] = static_cast<char>((sz >> 8) & 0xFF);
        mSerBuf[3] = static_cast<char>(sz & 0xFF);
        xdr::xdr_put p(mSerBuf.data() + 4, mSerBuf.data() + 4 + sz);
        xdr_argpack_archive(p, e);

        // xdr_argpack_archive throws if it can't write all bytes, so if we
        // reach this point, exactly sz bytes were written

        // Write serialized data to mmap
        auto& sink = std::get<MmapWriter>(mSink);
        sink.write(mSerBuf.data(), sz + 4);

        // Update hasher and counters
        mHasher.add(ByteSlice(mSerBuf.data(), sz + 4));
        mBytesPut += (sz + 4);
    }
    else
#endif
    {
#ifdef __linux__
        std::get<XDROutputFileStream>(mSink).writeOne(e, &mHasher, &mBytesPut);
#else
        mSink.writeOne(e, &mHasher, &mBytesPut);
#endif
    }
    mObjectsPut++;
}

template <typename BucketT>
void
BucketOutputIterator<BucketT>::put(typename BucketT::EntryT const& e)
{
    ZoneScoped;

    if constexpr (std::is_same_v<BucketT, LiveBucket>)
    {
        LiveBucket::checkProtocolLegality(e, mMeta.ledgerVersion);
        if (e.type() == METAENTRY)
        {
            if (mPutMeta)
            {
                throw std::runtime_error(
                    "putting META entry in bucket after initial entry");
            }
        }

        if (!mKeepTombstoneEntries && BucketT::isTombstoneEntry(e))
        {
            ++mMergeCounters.mOutputIteratorTombstoneElisions;
            return;
        }
    }
    else
    {
        static_assert(std::is_same_v<BucketT, HotArchiveBucket>,
                      "unexpected bucket type");
        if (e.type() == HOT_ARCHIVE_METAENTRY)
        {
            if (mPutMeta)
            {
                throw std::runtime_error(
                    "putting META entry in bucket after initial entry");
            }
        }
        else
        {
            if (e.type() == HOT_ARCHIVE_ARCHIVED)
            {
                if (!isSorobanEntry(e.archivedEntry().data))
                {
                    throw std::runtime_error(
                        "putting non-soroban entry in hot archive bucket");
                }
            }
            else
            {
                if (!isSorobanEntry(e.key()))
                {
                    throw std::runtime_error(
                        "putting non-soroban entry in hot archive bucket");
                }
            }
        }

        // HOT_ARCHIVE_LIVE entries are dropped in the last bucket level
        // (similar to DEADENTRY) on live BucketLists
        if (!mKeepTombstoneEntries && BucketT::isTombstoneEntry(e))
        {
            ++mMergeCounters.mOutputIteratorTombstoneElisions;
            return;
        }
    }

    // Check to see if there's an existing buffered entry.
    if (mBuf)
    {
        // mCmp(e, *mBuf) means e < *mBuf; this should never be true since
        // it would mean that we're getting entries out of order.
        releaseAssert(!mCmp(e, *mBuf));

        // Check to see if the new entry should flush (greater identity), or
        // merely replace (same identity), the buffered entry.
        if (mCmp(*mBuf, e))
        {
            ++mMergeCounters.mOutputIteratorActualWrites;
            writeOneViaSink(*mBuf);
        }
    }
    else
    {
        mBuf = std::make_unique<typename BucketT::EntryT>();
    }

    // In any case, replace *mBuf with e.
    ++mMergeCounters.mOutputIteratorBufferUpdates;
    *mBuf = e;
}

template <typename BucketT>
std::shared_ptr<BucketT>
BucketOutputIterator<BucketT>::getBucket(
    BucketManager& bucketManager, MergeKey* mergeKey,
    std::optional<std::vector<typename BucketT::EntryT>> inMemoryState,
    bool shouldIndex, RenameDurability durability)
{
    ZoneScoped;
    if (mBuf)
    {
        writeOneViaSink(*mBuf);
        mBuf.reset();
    }

#ifdef __linux__
    if (mMode == BucketWriteMode::MmapCrashOnlyLinux)
    {
        auto& sink = std::get<MmapWriter>(mSink);

        // Test hook: crash before rename
        if (std::getenv("STELLAR_FAULT_BEFORE_RENAME"))
        {
            CLOG_ERROR(Bucket, "Test fault injection: crashing before rename");
            raise(SIGSEGV);
        }

        // Finalize the file: shrink to actual size, msync, mark read-only
        sink.finalize();
        sink.close();
    }
    else
    {
        std::get<XDROutputFileStream>(mSink).close();
    }
#else
    mSink.close();
#endif
    if (mObjectsPut == 0 || mBytesPut == 0)
    {
        releaseAssert(mObjectsPut == 0);
        releaseAssert(mBytesPut == 0);
        CLOG_DEBUG(Bucket, "Deleting empty bucket file {}", mFilename);
        std::filesystem::remove(mFilename);
        if (mergeKey)
        {
            bucketManager.noteEmptyMergeOutput<BucketT>(*mergeKey);
        }
        return std::make_shared<BucketT>();
    }

    auto hash = mHasher.finish();
    std::unique_ptr<typename BucketT::IndexT const> index{};

    // either it's a new bucket or we just reconstructed a bucket
    // we already have, in any case ensure we have an index
    if (auto b = bucketManager.getBucketIfExists<BucketT>(hash);
        ((!b || !b->isIndexed()) && shouldIndex))
    {
        // Create index using in-memory state instead of file IO if available
        if constexpr (std::is_same_v<BucketT, LiveBucket>)
        {
            if (inMemoryState)
            {
                index = std::make_unique<LiveBucketIndex>(
                    bucketManager, *inMemoryState, mMeta);
            }
        }

        if (!index)
        {
            index = createIndex<BucketT>(bucketManager, mFilename, hash, mCtx,
                                         nullptr);
        }
    }

    auto b = bucketManager.adoptFileAsBucket<BucketT>(
        mFilename.string(), hash, mergeKey, std::move(index), durability);

    if constexpr (std::is_same_v<BucketT, LiveBucket>)
    {
        if (inMemoryState)
        {
            b->setInMemoryEntries(std::move(*inMemoryState));
        }
    }

    return b;
}

template class BucketOutputIterator<LiveBucket>;
template class BucketOutputIterator<HotArchiveBucket>;
}
