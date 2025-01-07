// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "historywork/DownloadBucketsWork.h"
#include "bucket/BucketManager.h"
#include "catchup/LedgerApplyManager.h"
#include "history/FileTransferInfo.h"
#include "history/HistoryArchive.h"
#include "historywork/GetAndUnzipRemoteFileWork.h"
#include "historywork/VerifyBucketWork.h"
#include "work/WorkWithCallback.h"
#include <Tracy.hpp>
#include <fmt/format.h>

namespace stellar
{

DownloadBucketsWork::DownloadBucketsWork(
    Application& app,
    std::map<std::string, std::shared_ptr<LiveBucket>>& liveBuckets,
    std::map<std::string, std::shared_ptr<HotArchiveBucket>>& hotBuckets,
    std::vector<std::string> liveHashes, std::vector<std::string> hotHashes,
    TmpDir const& downloadDir, std::shared_ptr<HistoryArchive> archive)
    : BatchWork{app, "download-verify-buckets"}
    , mLiveBuckets{liveBuckets}
    , mHotBuckets{hotBuckets}
    , mLiveHashes{liveHashes}
    , mHotHashes{hotHashes}
    , mNextLiveBucketIter{mLiveHashes.begin()}
    , mNextHotBucketIter{mHotHashes.begin()}
    , mDownloadDir{downloadDir}
    , mArchive{archive}
{
}

std::string
DownloadBucketsWork::getStatus() const
{
    if (!isDone() && !isAborting())
    {
        if (!mLiveHashes.empty())
        {
            auto numStarted =
                std::distance(mLiveHashes.begin(), mNextLiveBucketIter) +
                std::distance(mHotHashes.begin(), mNextHotBucketIter);
            auto numDone = numStarted - getNumWorksInBatch();
            auto total =
                static_cast<uint32_t>(mLiveHashes.size() + mHotHashes.size());
            auto pct = (100 * numDone) / total;
            return fmt::format(
                FMT_STRING(
                    "downloading and verifying buckets: {:d}/{:d} ({:d}%)"),
                numDone, total, pct);
        }
    }
    return Work::getStatus();
}

bool
DownloadBucketsWork::hasNext() const
{
    return mNextLiveBucketIter != mLiveHashes.end() ||
           mNextHotBucketIter != mHotHashes.end();
}

void
DownloadBucketsWork::resetIter()
{
    mNextLiveBucketIter = mLiveHashes.begin();
    mNextHotBucketIter = mHotHashes.begin();
}

std::shared_ptr<BasicWork>
DownloadBucketsWork::yieldMoreWork()
{
    ZoneScoped;
    if (!hasNext())
    {
        throw std::runtime_error("Nothing to iterate over!");
    }

    // Iterate through live hashes then Hot Archive hashes
    auto isHotHash = mNextLiveBucketIter == mLiveHashes.end();
    auto hash = isHotHash ? *mNextHotBucketIter : *mNextLiveBucketIter;

    FileTransferInfo ft(mDownloadDir, FileType::HISTORY_FILE_TYPE_BUCKET, hash);
    auto w1 = std::make_shared<GetAndUnzipRemoteFileWork>(mApp, ft, mArchive);

    auto getFileWeak = std::weak_ptr<GetAndUnzipRemoteFileWork>(w1);
    OnFailureCallback failureCb = [getFileWeak, hash]() {
        auto getFile = getFileWeak.lock();
        if (getFile)
        {
            auto ar = getFile->getArchive();
            if (ar)
            {
                CLOG_INFO(History, "Bucket {} from archive {}", hash,
                          ar->getName());
            }
        }
    };
    std::weak_ptr<DownloadBucketsWork> weak(
        std::static_pointer_cast<DownloadBucketsWork>(shared_from_this()));
    auto successCb = [weak, ft, hash, isHotHash](Application& app) -> bool {
        auto self = weak.lock();
        if (self)
        {
            auto bucketPath = ft.localPath_nogz();

            if (isHotHash)
            {
                auto b =
                    app.getBucketManager().adoptFileAsBucket<HotArchiveBucket>(
                        bucketPath, hexToBin256(hash),
                        /*mergeKey=*/nullptr,
                        /*index=*/nullptr);
                self->mHotBuckets[hash] = b;
            }
            else
            {
                auto b = app.getBucketManager().adoptFileAsBucket<LiveBucket>(
                    bucketPath, hexToBin256(hash),
                    /*mergeKey=*/nullptr,
                    /*index=*/nullptr);
                self->mLiveBuckets[hash] = b;
            }
        }
        return true;
    };
    auto w2 = std::make_shared<VerifyBucketWork>(mApp, ft.localPath_nogz(),
                                                 hexToBin256(hash), failureCb);
    auto w3 = std::make_shared<WorkWithCallback>(mApp, "adopt-verified-bucket",
                                                 successCb);
    std::vector<std::shared_ptr<BasicWork>> seq{w1, w2, w3};
    auto w4 = std::make_shared<WorkSequence>(
        mApp, "download-verify-sequence-" + hash, seq);

    if (isHotHash)
    {
        ++mNextHotBucketIter;
    }
    else
    {
        ++mNextLiveBucketIter;
    }
    return w4;
}
}
