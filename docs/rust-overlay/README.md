# Rust Overlay — Subsystem Docs

This directory documents the Rust overlay process, one subsystem per
file. Start with [the high-level design doc](../RUST_OVERLAY_DESIGN.md)
for the overall architecture and rationale.

| Doc                                       | Covers                                                          |
|-------------------------------------------|-----------------------------------------------------------------|
| [transport.md](transport.md)              | QUIC over UDP, libp2p, stream protocols, frame formats          |
| [peer-connections.md](peer-connections.md)| Peer membership, dialing, DNS, reconnect logic                  |
| [scp-flooding.md](scp-flooding.md)        | Push-based SCP propagation and dedup                            |
| [tx-propagation.md](tx-propagation.md)    | Pull-based INV/GETDATA TX flooding                              |
| [txset-fetching.md](txset-fetching.md)    | Fetching nominated TX sets, cache lifecycle                     |
| [mempool.md](mempool.md)                  | Fee-ordered pending-TX store                                    |
| [ipc.md](ipc.md)                          | Core ↔ Overlay Unix-socket protocol                             |

All file:line references use paths relative to the repo root (e.g.
`overlay/src/libp2p_overlay.rs:672`). When the implementation changes,
update both the relevant subsystem doc and any high-level claims in
`RUST_OVERLAY_DESIGN.md`.

## Logging

The overlay logs to stdout through a bounded background writer
(`overlay/src/log_writer.rs`): a slow or blocked stdout drops lines
(reported as `LOG_DROPPED`) instead of stalling tokio workers. ANSI
colors are used only when stdout is a terminal. `RUST_LOG` selects what
is logged (default `info`).

Per-message lines are at debug level under dedicated targets, so they can
be enabled for analysis without the rest of the debug output:

| Target                          | Lines                                               |
|---------------------------------|-----------------------------------------------------|
| `stellar_overlay::scp_trace`    | `SCP_RECV`, `SCP_RECV_DUP` (every SCP envelope)     |
| `stellar_overlay::txset_trace`  | `TXSET_REQ_IN`, `TXSET_SEND`, `TXSET_SEND_OK`, serving requests |

e.g. `RUST_LOG=info,stellar_overlay::scp_trace=debug`. In their place an
`OVERLAY_SUMMARY` line reports per-second traffic (first-sighting SCP
messages received, SCP messages and tx sets sent, transactions received,
bytes in and out).
