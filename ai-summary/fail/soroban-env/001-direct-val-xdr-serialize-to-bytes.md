# H001: Direct Val-to-XDR Serialization for `serialize_to_bytes`

**Date**: 2026-05-20
**Subsystem**: soroban-env
**Severity**: Medium
**Impact**: 3-10% soroswap apply-time reduction by reducing Soroban host buffer serialization work inside `applyLedger`
**Hypothesis by**: gpt-5.5, high

## Expected Behavior

`serialize_to_bytes(v)` should return exactly the XDR byte encoding of the `ScVal` represented by `v`, produce the same host errors for non-representable values, and preserve deterministic event/storage output. On the optimized next-protocol path, successful calls should avoid constructing a full temporary `ScVal` tree when the host can stream the equivalent XDR directly from `Val`/`HostObject` data.

## Mechanism

The current implementation in `soroban-env-host/src/host.rs:2674-2683` converts `Val` to an owned `ScVal` via `Host::from_host_val`, serializes that `ScVal` into a fresh `Vec<u8>` with `metered_write_xdr`, then wraps the bytes in a new `ScBytes` host object. Soroswap calls this buffer path heavily: the current trace reports `serialize_to_bytes` self-time of 65,974,824 ns across 40,648 calls, while adjacent apply-contained conversion/serialization zones report `Val to ScVal` at 245,978,039 ns, `write xdr` at 150,911,171 ns, and `bytes_append` at 82,802,873 ns. A direct XDR writer that walks `Val`/`HostObject` recursively and writes the same ScVal discriminants/payloads into the output buffer would remove the intermediate `ScVal` allocation/copy layer and should reduce the combined buffer-serialization envelope enough to clear the Medium threshold.

## Trigger

Run the soroswap apply-load benchmark at the current baseline (`TX=2000, T=8`) with Tracy enabled. The triggering workload is contract code that repeatedly calls `serialize_to_bytes` on small vectors/maps/addresses and then appends or hashes the resulting bytes during normal `closeLedger` application.

## Target Code

- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2674-2683` — `serialize_to_bytes` currently materializes `ScVal` before writing XDR.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-419,463-520` — `from_host_val` / `from_host_obj` recursively build owned `ScVal` structures that direct serialization could bypass on the successful path.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:61-77` — `metered_write_xdr` is the existing metered XDR output layer that the direct writer must match or replace behind a protocol gate.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:3033-3050` — `bytes_append` is a neighboring hot buffer path frequently consuming serialized bytes in the same workload.

## Evidence

`csvexport-release -e` on `/mnt/nvme2/apply-load/9074352f02c4-20260502-180944/logs/9074352f02c4-20260502-180944-02-soroswap-tx-2000-t-8.tracy` shows `serialize_to_bytes` at `soroban-env-host/src/vm/dispatch.rs:304` with 65,974,824 ns self-time / 40,648 calls. The supporting conversion/output zones are also entirely inside `applyLedger` by unwrap containment: `Val to ScVal` (`soroban-env-host/src/host/conversion.rs:411`) 245,978,039 ns self-time / 446,612 calls, `write xdr` (`soroban-env-host/src/host/metered_xdr.rs:72`) 150,911,171 ns self-time / 202,955 calls, and `bytes_append` (`soroban-env-host/src/vm/dispatch.rs:304`) 82,802,873 ns self-time / 40,643 calls. The source shows the current successful path necessarily allocates and traverses a temporary `ScVal` before writing bytes.

## Anti-Evidence

The direct writer must preserve the exact serialized XDR bytes, depth-limit behavior, object integrity checks, and error ordering for invalid values. If implemented without a protocol gate, it must also reproduce existing budget charges exactly; otherwise it should be gated to the next protocol and benchmarked as a metering-changing optimization. The whole `Val to ScVal` and `write xdr` aggregates include other call sites, so focused instrumentation should first isolate the `serialize_to_bytes` subset before PoC work claims the full envelope.

---

## Review

**Verdict**: NOT_VIABLE
**Date**: 2026-05-20
**Reviewed by**: gpt-5.5, high
**Novelty**: PASS
**Failed At**: reviewer

### Trace Summary

Guest calls to `serialize_to_bytes` enter the generated VM dispatch wrapper, which marshals the argument/result and calls `Host::serialize_to_bytes`. The host function converts the input `Val` to an owned `ScVal` with `Host::from_host_val`, recursively visiting object handles and materializing vectors/maps/addresses, then serializes that `ScVal` through `metered_write_xdr` and stores the resulting `ScBytes` as a new host object. A direct writer could remove some temporary `ScVal` materialization on this one host function, but the final XDR bytes, output buffer, final host object allocation, and most serialization traversal remain mandatory.

### Code Paths Examined

- `src/rust/soroban/p26/soroban-env-host/src/vm/dispatch.rs:206-296` — generated host-function dispatch wraps `serialize_to_bytes`, charges dispatch, translates relative/absolute object handles, calls the host method, then translates the returned object back to the VM.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:2697-2707` — `serialize_to_bytes` currently performs `from_host_val(v)`, `metered_write_xdr(&scv, &mut buf)`, and `add_host_object(scbytes_from_vec(buf))`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:407-419` — `from_host_val` runs under the depth limiter and delegates object conversion to `ScVal::try_from_val`, then checks representability.
- `src/rust/soroban/p26/soroban-env-common/src/convert.rs:419-508` — small `Val` tags convert directly to `ScVal`; object tags delegate to `ScValObject::try_from_val`.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:463-539` — object conversion visits the host object table and constructs owned `ScValObject` payloads; vectors and maps recursively convert child `Val`s.
- `src/rust/soroban/p26/soroban-env-host/src/host/conversion.rs:266-273` — map conversion allocates a `Vec<ScMapEntry>` and recursively converts every key/value pair.
- `src/rust/soroban/p26/soroban-env-host/src/host/metered_xdr.rs:67-100` — `metered_write_xdr` performs actual XDR writing; on the accepted next-protocol path it already coalesces `ValSer` charging to one total-byte charge instead of per-leaf histogram charging.
- `src/rust/soroban/p26/soroban-env-host/src/host.rs:576-582` and `src/rust/soroban/p26/soroban-env-host/src/test/protocol_gate.rs:9-24` — ledger protocol greater than the p26 minimum enables coalesced host metering for the apply-load benchmark's next-protocol baseline.

### Why It Failed

The source-level inefficiency exists, but the Medium-severity projection does not survive the trace. The cited `Val to ScVal` and `write xdr` totals are broad apply-contained aggregates, not work uniquely attributable to `serialize_to_bytes`; `from_host_val` is also used for event materialization, storage writes, host-function results, and other conversion paths. The `write xdr` path is additionally already optimized in the current next-protocol baseline by coalescing `ValSer` metering, so a direct writer cannot claim the previously expensive per-chunk budget-charge overhead there.

Even the hypothesis's generous diagnostic upper bound is about 66 ms of `serialize_to_bytes` wrapper self-time plus at most 246 ms of all `Val to ScVal` and 151 ms of all `write xdr` work, before subtracting unrelated call sites and mandatory XDR/output-object work. The accepted current baseline shows that removing a much larger diagnostic zone (`visit host object`, 1.43 s aggregate) produced only a 2.10% non-Tracy soroswap median improvement, below this objective's Medium floor. This target's truly removable subset is materially smaller than that prior low-severity signal, so it is below the objective severity threshold.

### Lesson Learned

For post-coalescing Soroban host optimizations, do not promote a `serialize_to_bytes` rewrite from aggregate `Val to ScVal`/`write xdr` Tracy totals. Isolate the subset under the specific host function and compare it to prior accepted non-Tracy deltas; broad conversion and XDR zones include many mandatory or unrelated call sites and substantially overstate the removable apply-time impact.
