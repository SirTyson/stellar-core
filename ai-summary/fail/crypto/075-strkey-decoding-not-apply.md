# H075: StrKey Decoding and CRC Validation Are Outside Soroswap Apply

**Date**: 2026-05-24
**Subsystem**: crypto
**Severity**: Low
**Impact**: out-of-scope key encoding/decoding optimization
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

If StrKey decoding were a soroswap apply bottleneck, `closeLedger` would repeatedly decode base32 public-key, seed, signer, or contract-address strings while applying benchmark transactions. Optimizing `strKey::fromStrKey` or `KeyUtils::fromStrKey` should then reduce `applyLedger` time without changing decoded key bytes, version validation, CRC rejection, or exception behavior for invalid strings.

## Mechanism

`strKey::fromStrKey` decodes base32, validates a CRC-16 checksum, extracts the version byte, and erases the version byte from the decoded vector. Several call sites in configuration, command handlers, herder persistence, quorum tooling, offer SQL, and diagnostic key logging parse StrKey strings. The tempting optimization would cache parsed public keys or avoid `decoded.erase(decoded.begin())`, but that only matters if these decoders run inside the measured soroswap apply window.

## Trigger

Run the protocol-27 soroswap apply-load benchmark and inspect `applyLedger` descendants for `strKey::fromStrKey`, `KeyUtils::fromStrKey`, or `SecretKey::fromStrKeySeed`. A viable trigger would be repeated per-transaction decoding of account IDs, signers, or contract IDs from StrKey strings while applying Soroban transactions.

## Target Code

- `src/crypto/StrKey.cpp:43-76` — `strKey::fromStrKey` base32-decodes, CRC-checks, extracts the version byte, and erases the leading byte.
- `src/crypto/KeyUtils.h:86-106` — typed `KeyUtils::fromStrKey` validates version/type and builds XDR key values.
- `src/crypto/SecretKey.cpp:318-326` — `SecretKey::fromStrKeySeed` decodes a seed and derives the signing keypair.
- `src/ledger/LedgerTxnOfferSQL.cpp:293,745`, `src/main/Config.cpp:797,1600,2498-2504`, `src/main/CommandHandler.cpp:747,1283`, `src/herder/RustQuorumCheckerAdaptor.cpp:91-147` — representative non-apply callers found by source search.

## Evidence

Source search shows many StrKey parsing callers, and `strKey::fromStrKey` performs allocation-heavy work that could be optimized locally. However, those callers are configuration loading, command/diagnostic processing, SQL persistence for classic offers, herder/quorum paths, and key diagnostic helpers. The crypto failure summary already records the adjacent `toStrKey` investigation: StrKey encoding events precede `applyLedger` windows and are restricted to logging and SQL persistence rather than the soroswap apply critical path.

## Anti-Evidence

The soroswap apply path carries account IDs, contract IDs, signer keys, and ledger keys in typed XDR objects, not StrKey strings. Transaction application verifies signatures and loads ledger entries from XDR/database state; it does not parse public keys from human-readable base32 strings. No available soroswap CSV export contains a StrKey decoder zone under `applyLedger`, and the current accepted trace path is unavailable locally for a fresh export.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-24
**Failed At**: hypothesis
**Novelty**: PASS — `toStrKey` reachability was recorded previously, but `fromStrKey` / decode-side CRC validation was not separately investigated

### Why It Failed

`fromStrKey` is not on the soroswap `closeLedger` apply path. Optimizing base32 decode, CRC validation, or decoded-vector mutation would affect configuration, CLI/API, herder, SQL, or diagnostics work, not the measured apply window for the soroswap benchmark.

### Lesson Learned

Human-readable key formats are almost always boundary/diagnostic concerns. For apply-load performance, require typed-XDR apply-window evidence before treating StrKey encode or decode helpers as relevant crypto bottlenecks.
