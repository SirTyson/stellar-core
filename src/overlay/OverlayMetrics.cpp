#include "overlay/OverlayMetrics.h"
#include "main/Application.h"

#include "util/MetricsRegistry.h"

namespace stellar
{

OverlayMetrics::OverlayMetrics(Application& app)
    : mMessageRead(
          app.getMetrics().NewMeter({"overlay", "message", "read"}, "message"))
    , mMessageWrite(
          app.getMetrics().NewMeter({"overlay", "message", "write"}, "message"))
    , mMessageDrop(
          app.getMetrics().NewMeter({"overlay", "message", "drop"}, "message"))
    , mByteRead(app.getMetrics().NewMeter({"overlay", "byte", "read"}, "byte"))
    , mByteWrite(
          app.getMetrics().NewMeter({"overlay", "byte", "write"}, "byte"))
    , mErrorRead(
          app.getMetrics().NewMeter({"overlay", "error", "read"}, "error"))
    , mErrorWrite(
          app.getMetrics().NewMeter({"overlay", "error", "write"}, "error"))
    , mRecvTransactionTimer(app.getMetrics().NewSimpleTimer(
          {"overlay", "recv-transaction", ""}, std::chrono::microseconds{1}))
    , mRecvSCPMessageTimer(
          app.getMetrics().NewTimer({"overlay", "recv", "scp-message"}))
    , mSendSCPMessageSetMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "scp-message"}, "message"))
    , mSendTransactionMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "transaction"}, "message"))
    , mSendTxSetMeter(
          app.getMetrics().NewMeter({"overlay", "send", "txset"}, "message"))
    , mSendFloodAdvertMeter(app.getMetrics().NewMeter(
          {"overlay", "send", "flood-advert"}, "message"))
    , mMessagesDemanded(app.getMetrics().NewMeter(
          {"overlay", "flood", "demanded"}, "message"))
    , mMessagesFulfilledMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "fulfilled"}, "message"))
    , mUnknownMessageUnfulfilledMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "unfulfilled-unknown"}, "message"))
    , mTxPullLatency(
          app.getMetrics().NewTimer({"overlay", "flood", "tx-pull-latency"}))
    , mDemandTimeouts(app.getMetrics().NewMeter(
          {"overlay", "demand", "timeout"}, "timeout"))
    , mAbandonedDemandMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "abandoned-demands"}, "message"))
    , mFloodLeaderPushMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "leader-push"}, "message"))
    , mFloodLeaderPushBytesMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "leader-push-bytes"}, "byte"))
    , mFloodLeaderFallbackMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "leader-fallback"}, "message"))
    , mFloodTxSetPushMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "txset-push"}, "shred"))
    , mFloodTxSetPushBytesMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "txset-push-bytes"}, "byte"))
    , mFloodTxSetPushDroppedMeter(app.getMetrics().NewMeter(
          {"overlay", "flood", "txset-push-dropped"}, "shred"))
    , mTxSetShardBroadcast(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "broadcast"}, "txset"))
    , mTxSetShardOriginalSent(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "original-sent"}, "shred"))
    , mTxSetShardRecoverySent(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "recovery-sent"}, "shred"))
    , mTxSetShardRecvUnique(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "recv-unique"}, "shred"))
    , mTxSetShardRecvDuplicate(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "recv-duplicate"}, "shred"))
    , mTxSetShardForwarded(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "forwarded"}, "shred"))
    , mTxSetShardReconstructOriginal(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "reconstruct-original"}, "reconstruction"))
    , mTxSetShardReconstructRecovery(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "reconstruct-recovery"}, "reconstruction"))
    , mTxSetShardInvalid(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "invalid"}, "shred"))
    , mTxSetShardAccumulatorEvicted(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "accumulator-evicted"}, "txset"))
    , mTxSetShardEncodeTimer(
          app.getMetrics().NewTimer({"overlay", "txset-shard", "encode"}))
    , mTxSetShardReconstructTimer(
          app.getMetrics().NewTimer({"overlay", "txset-shard", "reconstruct"}))
    , mTxSetShardBroadcastSpanTimer(app.getMetrics().NewTimer(
          {"overlay", "txset-shard", "broadcast-span"}))
    , mTxSetShardAssemblyTimer(
          app.getMetrics().NewTimer({"overlay", "txset-shard", "assembly"}))
    , mTxSetShardForwardLatencyTimer(app.getMetrics().NewTimer(
          {"overlay", "txset-shard", "forward-latency"}))
    , mTxSetShardRecvDirect(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "recv-direct"}, "shred"))
    , mTxSetShardRecvRelayed(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "recv-relayed"}, "shred"))
    , mTxSetShardRootMismatch(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "root-mismatch"}, "shred"))
    , mTxSetShardBytesIn(app.getMetrics().NewMeter(
          {"overlay", "txset-shard", "bytes-in"}, "byte"))
    , mMessagesBroadcast(app.getMetrics().NewMeter(
          {"overlay", "message", "broadcast"}, "message"))
    , mUniqueFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "unique-recv"}, "byte"))
    , mDuplicateFloodBytesRecv(app.getMetrics().NewMeter(
          {"overlay", "flood", "duplicate-recv"}, "byte"))
    , mTxBatchSizeHistogram(
          app.getMetrics().NewHistogram({"overlay", "flood", "tx-batch-size"}))
    , mPendingPeersSize(
          app.getMetrics().NewCounter({"overlay", "connection", "pending"}))
    , mAuthenticatedPeersSize(app.getMetrics().NewCounter(
          {"overlay", "connection", "authenticated"}))
    , mFetchTxSetTimer(app.getMetrics().NewTimer({"overlay", "fetch", "txset"}))
{
}
}
