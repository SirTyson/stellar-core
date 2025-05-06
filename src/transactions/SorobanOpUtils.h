#pragma once

// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "rust/RustBridge.h"

namespace stellar
{

class AppConnector;
class AbstractLedgerTxn;
class SorobanNetworkConfig;
struct DiagnosticEventBuffer;
class TransactionFrame;

// Helper class providing utility functions for Soroban operations
class SorobanOpUtils
{
  public:
    // Executes restore logic for RestoreFootprintOp. If the restore violates
    // resource limits, returns false and populates diagnostic events.
    // Otherwise, returns true. Note that this can only fail due to resource
    // limits. Restored entries will be populated via the rustEntryRentChanges
    // and ltx, with read/write limits metered via the ledgerReadByte and
    // ledgerWriteByte.
    static bool restoreFootprintEntries(
        AppConnector& app, AbstractLedgerTxn& ltx,
        TransactionFrame const& parentTx,
        DiagnosticEventBuffer& diagnosticEvents,
        rust::Vec<CxxLedgerEntryRentChange>& rustEntryRentChanges,
        uint32_t& ledgerReadByte, uint32_t& ledgerWriteByte);
};
}