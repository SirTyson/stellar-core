#pragma once

// Copyright 2017 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "bucket/BucketManager.h"
#include "bucket/LedgerCmp.h"
#include "util/XDRStream.h"
#include "xdr/Stellar-ledger.h"

#include <memory>
#include <string>

namespace stellar
{

class Bucket;
class BucketManager;

// Helper class that writes new elements to a file and returns a bucket
// when finished.
class BucketOutputIterator
{
  protected:
    std::string mFilename;
    XDROutputFileStream mOut;
    std::unique_ptr<BucketEntry> mBuf;
    SHA256 mHasher;
    size_t mBytesPut{0};
    size_t mObjectsPut{0};
    bool mKeepDeadEntries{true};
    BucketMetadata mMeta;
    bool mPutMeta{false};
    MergeCounters& mMergeCounters;

    // True if file is sorted using BucketEntryIdCmpV2, based on mMeta
    bool mV2Sorted;

    // Either uses BucketEntryIdCmp or BucketEntryIdCmpV2 depending on flags
    // set in mMeta
    bool cmp(BucketEntry const& a, BucketEntry const& b) const;

  public:
    // BucketOutputIterators must _always_ be constructed with BucketMetadata,
    // regardless of the ledger version the bucket is being written from, even
    // if it's pre-METAENTRY support. The BucketOutputIterator constructor
    // inspects the metadata and determines whether it indicates a ledger
    // version new enough that it should _write_ the metadata to the stream in
    // the form of a METAENTRY; but that's not a thing the caller gets to decide
    // (or forget to do), it's handled automatically.
    BucketOutputIterator(std::string const& tmpDir, bool keepDeadEntries,
                         BucketMetadata const& meta, MergeCounters& mc,
                         asio::io_context& ctx, bool doFsync);

    void put(BucketEntry const& e);

    // Publishes constructed bucket to BucketManager and returns constructed
    // bucket. If v2FileIter is given, the file associated with v2FileIter will
    // be included in resulting bucket as v2SortedFile.
    std::shared_ptr<Bucket>
    getBucket(BucketManager& bucketManager, MergeKey* mergeKey = nullptr,
              BucketOutputIterator* v2FileIter = nullptr);

    std::string const& getFilename() const;

    // Returns true if no objects have been written, false otherwise
    bool empty() const;

    // Flushes changes to file and closes file.
    void close();
};
}
