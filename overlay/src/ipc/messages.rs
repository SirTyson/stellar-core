//! IPC message types for communication between Core and Overlay.
//!
//! These types mirror the C++ definitions in src/overlay/IPC.h exactly.
//! Message format: [type:u32][length:u32][payload]

use std::io::{self, Read, Write};

/// IPC message types matching Core's IPCMessageType enum.
///
/// Value ranges:
/// - 1-99: Core → Overlay messages  
/// - 100-199: Overlay → Core messages
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    // ═══ Core → Overlay (Critical Path) ═══
    /// Broadcast this SCP envelope to all peers
    BroadcastScp = 1,

    /// Request nomination candidates from the mempool. Two payload layouts
    /// are accepted (selected by payload length, see
    /// [`super::payloads::parse_get_top_txs`]):
    /// - legacy, 4 bytes: `[count:u32]` — `count` account heads across both
    ///   phases merged in inclusion-fee order; answered with the legacy
    ///   [`MessageType::TopTxsResponse`] layout (no request id).
    /// - v2, 16 bytes: `[req_id:u64][classic_n:u32][soroban_n:u32]` — up to
    ///   `classic_n` classic and `soroban_n` Soroban account heads; answered
    ///   with the v2 response layout that echoes `req_id` so Core can drop
    ///   late answers to a timed-out request.
    GetTopTxs = 2,

    /// Request current SCP state (peer asked via GET_SCP_STATE)
    RequestScpState = 3,

    // ═══ Core → Overlay (Non-Critical) ═══
    /// A ledger was applied. Payload: `[ledgerSeq:u32][ledgerHash:32]`.
    /// Drives mempool expiry + ban pruning and tx-set-cache eviction.
    LedgerClosed = 4,

    /// We externalized this tx set: remove + ban the listed txs.
    /// Payload: `[txSetHash:32][count:u32][txHash:32]*`
    TxSetExternalized = 5,

    /// Response: here's the SCP state you requested
    ScpStateResponse = 6,

    /// Shutdown the overlay process
    Shutdown = 7,

    /// Configure peer addresses to connect to
    /// Payload: JSON { "known_peers": [...], "preferred_peers": [...], "listen_port": u16 }
    SetPeerConfig = 8,

    /// Submit a transaction for flooding
    /// Payload: [fee:i64][numOps:u32][txEnvelope XDR...]
    SubmitTx = 10,

    /// Request a TX set by hash
    /// Payload: [hash:32]
    RequestTxSet = 11,

    /// Cache a locally-built TX set so Rust can serve it to peers
    /// Payload: [hash:32][txSetXDR...]
    CacheTxSet = 12,

    /// Request overlay metrics snapshot (empty payload)
    RequestOverlayMetrics = 13,

    /// Remove the listed txs from the mempool and ban their hashes for the
    /// default horizon (last closed ledger + BAN_LEDGERS). Replaces the
    /// zero-txSetHash pun on [`MessageType::TxSetExternalized`].
    /// Payload: `[count:u32][txHash:32]*`
    RemoveTxs = 14,

    /// Core's verdict on a peer-received tx previously reported with
    /// [`MessageType::TxReceived`]. `accept != 0` → insert into the mempool
    /// and flood; `accept == 0` → ban the hash, do not flood. `code` is the
    /// `TransactionResultCode` (informational).
    /// Payload: `[hash:32][accept:u8][code:i32]`
    TxVerdict = 15,

    // ═══ Overlay → Core (Critical Path) ═══
    /// Received SCP envelope from network
    ScpReceived = 100,

    /// Response to GET_TOP_TXS. Layout follows the request layout:
    /// - legacy: `[count:u32]{[len:u32][xdr]}*`
    /// - v2:     `[req_id:u64][count:u32]{[len:u32][xdr]}*`
    TopTxsResponse = 101,

    /// Peer requested SCP state
    PeerRequestsScpState = 102,

    // ═══ Overlay → Core (Non-Critical) ═══
    /// TX set fetched from peer (response to REQUEST_TX_SET)
    /// Payload: [hash:32][txSetXDR...]
    TxSetAvailable = 103,

    /// Overlay metrics snapshot response (JSON payload)
    OverlayMetricsResponse = 105,

    /// A tx arrived from a peer and is parked pending Core's validation.
    /// Core validates it against its LCL view (+ ban ring) and answers with
    /// [`MessageType::TxVerdict`]; no answer within the overlay's timeout
    /// (10 s) drops the tx.
    /// Payload: `[hash:32][len:u32][txEnvelope XDR:len]`
    TxReceived = 106,
}

impl TryFrom<u32> for MessageType {
    type Error = InvalidMessageType;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::BroadcastScp),
            2 => Ok(MessageType::GetTopTxs),
            3 => Ok(MessageType::RequestScpState),
            4 => Ok(MessageType::LedgerClosed),
            5 => Ok(MessageType::TxSetExternalized),
            6 => Ok(MessageType::ScpStateResponse),
            7 => Ok(MessageType::Shutdown),
            8 => Ok(MessageType::SetPeerConfig),
            10 => Ok(MessageType::SubmitTx),
            11 => Ok(MessageType::RequestTxSet),
            12 => Ok(MessageType::CacheTxSet),
            13 => Ok(MessageType::RequestOverlayMetrics),
            14 => Ok(MessageType::RemoveTxs),
            15 => Ok(MessageType::TxVerdict),
            100 => Ok(MessageType::ScpReceived),
            101 => Ok(MessageType::TopTxsResponse),
            102 => Ok(MessageType::PeerRequestsScpState),
            103 => Ok(MessageType::TxSetAvailable),
            105 => Ok(MessageType::OverlayMetricsResponse),
            106 => Ok(MessageType::TxReceived),
            _ => Err(InvalidMessageType(value)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidMessageType(pub u32);

impl std::fmt::Display for InvalidMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid IPC message type: {}", self.0)
    }
}

impl std::error::Error for InvalidMessageType {}

/// A single IPC message.
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }
}

/// Maximum payload size (16 MB) - sanity check to prevent OOM
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Header size: 4 bytes type + 4 bytes length
const HEADER_SIZE: usize = 8;

/// Synchronous message reader/writer for Unix sockets.
///
/// Note: We use blocking I/O wrapped in tokio::task::spawn_blocking
/// because Unix domain sockets with Tokio can be tricky on some platforms.
pub struct MessageCodec;

impl MessageCodec {
    /// Read a message from a stream (blocking).
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Message> {
        // Read header
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;

        let msg_type_raw = u32::from_ne_bytes(header[0..4].try_into().unwrap());
        let payload_len = u32::from_ne_bytes(header[4..8].try_into().unwrap()) as usize;

        // Sanity check
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload too large: {} bytes", payload_len),
            ));
        }

        // Parse message type
        let msg_type = MessageType::try_from(msg_type_raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload)?;
        }

        Ok(Message { msg_type, payload })
    }

    /// Write a message to a stream (blocking).
    pub fn write<W: Write>(writer: &mut W, msg: &Message) -> io::Result<()> {
        // Build header
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&(msg.msg_type as u32).to_ne_bytes());
        header[4..8].copy_from_slice(&(msg.payload.len() as u32).to_ne_bytes());

        // Write header + payload
        writer.write_all(&header)?;
        if !msg.payload.is_empty() {
            writer.write_all(&msg.payload)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_roundtrip() {
        let msg = Message::new(MessageType::BroadcastScp, vec![1, 2, 3, 4]);

        let mut buf = Vec::new();
        MessageCodec::write(&mut buf, &msg).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = MessageCodec::read(&mut cursor).unwrap();

        assert_eq!(decoded.msg_type, MessageType::BroadcastScp);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    // ═══ Error Handling Tests ═══

    #[test]
    fn test_invalid_message_type() {
        // Create a message with invalid type (255)
        let mut buf = Vec::new();
        buf.extend_from_slice(&255u32.to_ne_bytes()); // invalid type
        buf.extend_from_slice(&0u32.to_ne_bytes()); // zero length

        let mut cursor = Cursor::new(buf);
        let result = MessageCodec::read(&mut cursor);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_payload_too_large() {
        // Create a message with payload size > MAX_PAYLOAD_SIZE
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_ne_bytes()); // BroadcastScp
        buf.extend_from_slice(&(20 * 1024 * 1024u32).to_ne_bytes()); // 20MB > 16MB limit

        let mut cursor = Cursor::new(buf);
        let result = MessageCodec::read(&mut cursor);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_truncated_header() {
        // Only 4 bytes instead of 8
        let buf = vec![1, 0, 0, 0];
        let mut cursor = Cursor::new(buf);
        let result = MessageCodec::read(&mut cursor);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn test_truncated_payload() {
        // Header says 10 bytes, but only 5 provided
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_ne_bytes()); // BroadcastScp
        buf.extend_from_slice(&10u32.to_ne_bytes()); // claims 10 bytes
        buf.extend_from_slice(&[1, 2, 3, 4, 5]); // only 5 bytes

        let mut cursor = Cursor::new(buf);
        let result = MessageCodec::read(&mut cursor);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    // ═══ All Message Types Roundtrip ═══

    #[test]
    fn test_all_message_types_roundtrip() {
        let test_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let types = [
            MessageType::BroadcastScp,
            MessageType::GetTopTxs,
            MessageType::RequestScpState,
            MessageType::LedgerClosed,
            MessageType::TxSetExternalized,
            MessageType::ScpStateResponse,
            MessageType::Shutdown,
            MessageType::SetPeerConfig,
            MessageType::SubmitTx,
            MessageType::RequestTxSet,
            MessageType::CacheTxSet,
            MessageType::RequestOverlayMetrics,
            MessageType::RemoveTxs,
            MessageType::TxVerdict,
            MessageType::ScpReceived,
            MessageType::TopTxsResponse,
            MessageType::PeerRequestsScpState,
            MessageType::TxSetAvailable,
            MessageType::OverlayMetricsResponse,
            MessageType::TxReceived,
        ];

        for msg_type in types {
            let msg = Message::new(msg_type, test_payload.clone());

            let mut buf = Vec::new();
            MessageCodec::write(&mut buf, &msg).unwrap();

            let mut cursor = Cursor::new(buf);
            let decoded = MessageCodec::read(&mut cursor).unwrap();

            assert_eq!(decoded.msg_type, msg_type, "Failed for {:?}", msg_type);
            assert_eq!(decoded.payload, test_payload);
        }
    }

    // ═══ Boundary Tests ═══

    #[test]
    fn test_max_valid_payload() {
        // Test with a payload just under the limit (1MB for practicality)
        let payload = vec![0u8; 1024 * 1024];
        let msg = Message::new(MessageType::TxSetAvailable, payload.clone());

        let mut buf = Vec::new();
        MessageCodec::write(&mut buf, &msg).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = MessageCodec::read(&mut cursor).unwrap();

        assert_eq!(decoded.payload.len(), 1024 * 1024);
    }

    #[test]
    fn test_message_type_try_from_all_valid() {
        assert_eq!(MessageType::try_from(1).unwrap(), MessageType::BroadcastScp);
        assert_eq!(MessageType::try_from(2).unwrap(), MessageType::GetTopTxs);
        assert_eq!(
            MessageType::try_from(3).unwrap(),
            MessageType::RequestScpState
        );
        assert_eq!(MessageType::try_from(4).unwrap(), MessageType::LedgerClosed);
        assert_eq!(
            MessageType::try_from(5).unwrap(),
            MessageType::TxSetExternalized
        );
        assert_eq!(
            MessageType::try_from(6).unwrap(),
            MessageType::ScpStateResponse
        );
        assert_eq!(MessageType::try_from(7).unwrap(), MessageType::Shutdown);
        assert_eq!(
            MessageType::try_from(8).unwrap(),
            MessageType::SetPeerConfig
        );
        assert_eq!(MessageType::try_from(10).unwrap(), MessageType::SubmitTx);
        assert_eq!(
            MessageType::try_from(11).unwrap(),
            MessageType::RequestTxSet
        );
        assert_eq!(MessageType::try_from(12).unwrap(), MessageType::CacheTxSet);
        assert_eq!(
            MessageType::try_from(13).unwrap(),
            MessageType::RequestOverlayMetrics
        );
        assert_eq!(
            MessageType::try_from(100).unwrap(),
            MessageType::ScpReceived
        );
        assert_eq!(
            MessageType::try_from(101).unwrap(),
            MessageType::TopTxsResponse
        );
        assert_eq!(
            MessageType::try_from(102).unwrap(),
            MessageType::PeerRequestsScpState
        );
        assert_eq!(
            MessageType::try_from(103).unwrap(),
            MessageType::TxSetAvailable
        );
        assert_eq!(
            MessageType::try_from(105).unwrap(),
            MessageType::OverlayMetricsResponse
        );
        assert_eq!(MessageType::try_from(14).unwrap(), MessageType::RemoveTxs);
        assert_eq!(MessageType::try_from(15).unwrap(), MessageType::TxVerdict);
        assert_eq!(MessageType::try_from(106).unwrap(), MessageType::TxReceived);
    }

    #[test]
    fn test_message_type_try_from_invalid() {
        assert!(MessageType::try_from(0).is_err());
        assert!(MessageType::try_from(9).is_err()); // gap between 8 and 10
        assert!(MessageType::try_from(99).is_err());
        assert!(MessageType::try_from(16).is_err());
        assert!(MessageType::try_from(104).is_err());
        assert!(MessageType::try_from(107).is_err());
        assert!(MessageType::try_from(u32::MAX).is_err());
    }
}
