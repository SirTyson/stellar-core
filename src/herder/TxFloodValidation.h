// Copyright 2026 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "overlay/StellarXDR.h"
#include <functional>
#include <memory>
#include <vector>

namespace stellar
{

class Application;

// Verdicts for a batch of received transactions, in input order.
using TxFloodVerdicts = std::vector<uint8_t>;

// Invoked once per batch, on a tx-validation pool thread.
using TxFloodVerdictCallback = std::function<void(TxFloodVerdicts const&)>;

// Validate a batch of transactions received from the network before the
// overlay floods them onward: signatures, structural correctness, sequence
// number, and the fee payer's ability to cover this transaction's fee —
// the same checks the mainline TransactionQueue ran at admission
// (checkValidForOverlay), minus queue-specific accumulation (there is no
// queue; the leader's trimInvalid still enforces cross-tx fee accumulation
// at nomination).
//
// The work runs asynchronously on the tx-validation pool against a snapshot
// of the current LCL; this function never blocks. `callback` is invoked
// exactly once, on a pool thread, when every envelope has a verdict.
// Callable from any thread.
void validateTxBatchForFlooding(
    Application& app,
    std::shared_ptr<std::vector<TransactionEnvelope> const> envelopes,
    TxFloodVerdictCallback callback);

} // namespace stellar
