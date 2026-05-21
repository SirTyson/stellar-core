# H042: StrKey Encoding Is Diagnostic Work Outside Apply

**Date**: 2026-05-21
**Subsystem**: crypto
**Severity**: Low (zero impact on apply path)
**Impact**: apply-time
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`strKey::toStrKey(uint8_t, ByteSlice)` should not appear on the soroswap
`closeLedger` critical path. StrKey formatting is a human-readable encoding for
configuration, logging, diagnostics, and API surfaces; production apply should
operate on binary XDR keys and hashes rather than repeatedly base32-encoding
public keys.

## Mechanism

The implementation allocates a temporary `std::vector<uint8_t>`, copies the
version byte and payload, appends CRC16 bytes, and then base32-encodes the
buffer. A local optimization could specialize the common 32-byte public-key case
or stack-allocate the preimage buffer. The deviation would matter only if this
formatting occurred at high frequency inside `applyLedger`; in the current
soroswap trace, it does not.

## Trigger

Run the current diagnostic trace from `ai-summary/CURRENT_STATE.md` and compare
unwrapped `toStrKey` events against unwrapped `applyLedger` windows:

```sh
./lib/tracy/csvexport/build/unix/csvexport-release -u -f applyLedger \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
./lib/tracy/csvexport/build/unix/csvexport-release -u -f toStrKey \
  /mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy
```

The `toStrKey` events have 0 ns overlap with the 71 `applyLedger` windows.

## Target Code

- `src/crypto/StrKey.cpp:16-34` — StrKey encoder with temporary vector,
  CRC16 append, and base32 conversion
- `src/crypto/KeyUtils.h:45-67` — generic key-to-StrKey and short-string
  helpers that call `strKey::toStrKey`

## Evidence

The current Tracy self-time profile reports a concrete `toStrKey` zone:
`toStrKey,crypto/StrKey.cpp,19,967459 ns,2147 calls`. The code shape is
optimizable in isolation because it always heap-allocates the encoded preimage
buffer even for fixed-size keys. However, unwrap containment shows all 2,147
events / 967,459 ns are outside `applyLedger`.

## Anti-Evidence

Even before the scope rejection, the entire trace-wide `toStrKey` budget is
under 1 ms, far below the 3% Medium threshold for a 5.23 s traced apply envelope
or the 270-276 ms authoritative non-Tracy soroswap medians. The zero-overlap
containment result makes the apply-time impact exactly zero.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-21
**Failed At**: hypothesis
**Novelty**: PASS — prior crypto failures covered base64 bridge conversion and
key-agreement/HKDF paths, but not StrKey base32 formatting.

### Why It Failed

`strKey::toStrKey` is not an `applyLedger` descendant in the current soroswap
trace. Its aggregate trace-wide cost is already sub-millisecond, and none of it
falls within the measured apply windows.

### Lesson Learned

Human-readable key formatting is generally diagnostic/configuration work. Before
targeting StrKey, `KeyUtils::toShortString`, or logging-oriented crypto helpers,
first prove apply-window containment; otherwise the path should be rejected on
scope grounds immediately.
