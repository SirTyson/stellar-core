//! Payload codecs for the Core ↔ Overlay IPC messages that carry structured
//! data. Every multi-byte integer is little-endian (Core `memcpy`s host ints;
//! all supported hosts are LE). Hashes are raw 32-byte SHA-256.
//!
//! The wire formats are documented on [`MessageType`](super::MessageType);
//! this module keeps encode/decode in one place so main.rs and the tests
//! share one implementation.

/// Size of a transaction hash on the wire.
pub const HASH_LEN: usize = 32;

/// `GET_TOP_TXS` request, in either of its two accepted layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetTopTxsRequest {
    /// Legacy 4-byte payload `[count:u32]`: `count` heads merged across both
    /// phases in fee order. Answered with the legacy `TOP_TXS_RESPONSE`
    /// layout (no request id).
    Legacy { count: u32 },
    /// 16-byte payload `[req_id:u64][classic_n:u32][soroban_n:u32]`:
    /// per-phase heads. Answered with the v2 layout that echoes `req_id`.
    PerPhase {
        req_id: u64,
        classic_n: u32,
        soroban_n: u32,
    },
}

/// Parse a `GET_TOP_TXS` payload. Returns `None` for any other length so a
/// truncated or unknown layout is answered with an empty legacy response
/// rather than guessed at.
pub fn parse_get_top_txs(payload: &[u8]) -> Option<GetTopTxsRequest> {
    match payload.len() {
        4 => Some(GetTopTxsRequest::Legacy {
            count: read_u32(payload, 0),
        }),
        16 => Some(GetTopTxsRequest::PerPhase {
            req_id: read_u64(payload, 0),
            classic_n: read_u32(payload, 8),
            soroban_n: read_u32(payload, 12),
        }),
        _ => None,
    }
}

/// Encode a legacy `GET_TOP_TXS` request `[count:u32]`.
pub fn encode_get_top_txs_legacy(count: u32) -> Vec<u8> {
    count.to_le_bytes().to_vec()
}

/// Encode a v2 `GET_TOP_TXS` request `[req_id:u64][classic_n:u32][soroban_n:u32]`.
pub fn encode_get_top_txs(req_id: u64, classic_n: u32, soroban_n: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.extend_from_slice(&req_id.to_le_bytes());
    p.extend_from_slice(&classic_n.to_le_bytes());
    p.extend_from_slice(&soroban_n.to_le_bytes());
    p
}

/// Encode a `TOP_TXS_RESPONSE`.
///
/// * `req_id == None` → legacy layout `[count:u32]{[len:u32][xdr]}*`
/// * `req_id == Some(id)` → v2 layout `[req_id:u64][count:u32]{[len:u32][xdr]}*`
pub fn encode_top_txs_response(req_id: Option<u64>, txs: &[&[u8]]) -> Vec<u8> {
    let body: usize = 4 + txs.iter().map(|tx| 4 + tx.len()).sum::<usize>();
    let mut p = Vec::with_capacity(body + 8);
    if let Some(id) = req_id {
        p.extend_from_slice(&id.to_le_bytes());
    }
    p.extend_from_slice(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        p.extend_from_slice(&(tx.len() as u32).to_le_bytes());
        p.extend_from_slice(tx);
    }
    p
}

/// Decoded `TOP_TXS_RESPONSE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopTxsResponse {
    /// `None` for the legacy layout.
    pub req_id: Option<u64>,
    pub txs: Vec<Vec<u8>>,
}

/// Decode a `TOP_TXS_RESPONSE` in the layout selected by `with_req_id`
/// (the receiver knows which layout it asked for). Truncated entries end the
/// list; the count header is trusted only as a capacity hint.
pub fn parse_top_txs_response(payload: &[u8], with_req_id: bool) -> Option<TopTxsResponse> {
    let mut off = 0;
    let req_id = if with_req_id {
        if payload.len() < 8 {
            return None;
        }
        off = 8;
        Some(read_u64(payload, 0))
    } else {
        None
    };
    if payload.len() < off + 4 {
        return None;
    }
    let count = read_u32(payload, off) as usize;
    off += 4;
    let mut txs = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        if payload.len() < off + 4 {
            break;
        }
        let len = read_u32(payload, off) as usize;
        off += 4;
        if payload.len() < off + len {
            break;
        }
        txs.push(payload[off..off + len].to_vec());
        off += len;
    }
    Some(TopTxsResponse { req_id, txs })
}

/// Encode a hash list `[count:u32][hash:32]*` (`REMOVE_TXS` payload).
pub fn encode_hash_list(hashes: &[[u8; HASH_LEN]]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + hashes.len() * HASH_LEN);
    p.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
    for h in hashes {
        p.extend_from_slice(h);
    }
    p
}

/// Parse `REMOVE_TXS` `[count:u32][hash:32]*`. Hashes beyond the payload
/// (count larger than the data) are ignored; extra trailing bytes are
/// ignored. `None` only when the count header is missing.
pub fn parse_remove_txs(payload: &[u8]) -> Option<Vec<[u8; HASH_LEN]>> {
    if payload.len() < 4 {
        return None;
    }
    let count = read_u32(payload, 0) as usize;
    Some(parse_hashes(&payload[4..], count))
}

/// Decoded `TX_SET_EXTERNALIZED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSetExternalized {
    pub tx_set_hash: [u8; HASH_LEN],
    pub tx_hashes: Vec<[u8; HASH_LEN]>,
}

/// Parse `TX_SET_EXTERNALIZED` `[txSetHash:32][count:u32][hash:32]*`.
pub fn parse_tx_set_externalized(payload: &[u8]) -> Option<TxSetExternalized> {
    if payload.len() < HASH_LEN + 4 {
        return None;
    }
    let mut tx_set_hash = [0u8; HASH_LEN];
    tx_set_hash.copy_from_slice(&payload[..HASH_LEN]);
    let count = read_u32(payload, HASH_LEN) as usize;
    Some(TxSetExternalized {
        tx_set_hash,
        tx_hashes: parse_hashes(&payload[HASH_LEN + 4..], count),
    })
}

/// Encode `TX_SET_EXTERNALIZED` (used by tests and the C++ mirror).
pub fn encode_tx_set_externalized(
    tx_set_hash: &[u8; HASH_LEN],
    hashes: &[[u8; HASH_LEN]],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(HASH_LEN + 4 + hashes.len() * HASH_LEN);
    p.extend_from_slice(tx_set_hash);
    p.extend_from_slice(&encode_hash_list(hashes));
    p
}

/// Encode `TX_RECEIVED` (Overlay → Core) `[hash:32][len:u32][xdr]`.
pub fn encode_tx_received(hash: &[u8; HASH_LEN], xdr: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(HASH_LEN + 4 + xdr.len());
    p.extend_from_slice(hash);
    p.extend_from_slice(&(xdr.len() as u32).to_le_bytes());
    p.extend_from_slice(xdr);
    p
}

/// Decoded `TX_RECEIVED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceived {
    pub hash: [u8; HASH_LEN],
    pub xdr: Vec<u8>,
}

/// Parse `TX_RECEIVED`. The declared `len` must match the remaining bytes
/// exactly (Core re-hashes `xdr` and refuses a mismatch with `hash`).
pub fn parse_tx_received(payload: &[u8]) -> Option<TxReceived> {
    if payload.len() < HASH_LEN + 4 {
        return None;
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&payload[..HASH_LEN]);
    let len = read_u32(payload, HASH_LEN) as usize;
    let rest = &payload[HASH_LEN + 4..];
    if rest.len() != len {
        return None;
    }
    Some(TxReceived {
        hash,
        xdr: rest.to_vec(),
    })
}

/// Decoded `TX_VERDICT` (Core → Overlay).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxVerdict {
    pub hash: [u8; HASH_LEN],
    /// `true` → insert into the mempool and flood; `false` → ban, don't flood.
    pub accept: bool,
    /// `TransactionResultCode` from Core's validation (0 = txSUCCESS on
    /// accept; the innermost error code on reject; informational only).
    pub code: i32,
}

/// Encode `TX_VERDICT` `[hash:32][accept:u8][code:i32]`.
pub fn encode_tx_verdict(hash: &[u8; HASH_LEN], accept: bool, code: i32) -> Vec<u8> {
    let mut p = Vec::with_capacity(HASH_LEN + 1 + 4);
    p.extend_from_slice(hash);
    p.push(accept as u8);
    p.extend_from_slice(&code.to_le_bytes());
    p
}

/// Parse `TX_VERDICT`. Any non-zero `accept` byte counts as accept.
pub fn parse_tx_verdict(payload: &[u8]) -> Option<TxVerdict> {
    if payload.len() < HASH_LEN + 1 + 4 {
        return None;
    }
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&payload[..HASH_LEN]);
    Some(TxVerdict {
        hash,
        accept: payload[HASH_LEN] != 0,
        code: i32::from_le_bytes(payload[HASH_LEN + 1..HASH_LEN + 5].try_into().unwrap()),
    })
}

/// Parse `LEDGER_CLOSED` `[seq:u32][hash:32]` → seq. The hash is unused by
/// the overlay; a 4-byte payload is accepted for forward compatibility.
pub fn parse_ledger_closed(payload: &[u8]) -> Option<u32> {
    if payload.len() < 4 {
        return None;
    }
    Some(read_u32(payload, 0))
}

fn parse_hashes(data: &[u8], count: usize) -> Vec<[u8; HASH_LEN]> {
    let available = data.len() / HASH_LEN;
    let n = count.min(available);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(&data[i * HASH_LEN..(i + 1) * HASH_LEN]);
        out.push(h);
    }
    out
}

fn read_u32(p: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(p[off..off + 4].try_into().unwrap())
}

fn read_u64(p: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn get_top_txs_legacy_layout_is_4_bytes() {
        let p = encode_get_top_txs_legacy(2200);
        assert_eq!(p, 2200u32.to_le_bytes());
        assert_eq!(
            parse_get_top_txs(&p),
            Some(GetTopTxsRequest::Legacy { count: 2200 })
        );
    }

    #[test]
    fn get_top_txs_per_phase_layout_is_16_bytes() {
        let p = encode_get_top_txs(0x0102_0304_0506_0708, 2000, 200);
        assert_eq!(p.len(), 16);
        assert_eq!(&p[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&p[8..12], &2000u32.to_le_bytes());
        assert_eq!(&p[12..16], &200u32.to_le_bytes());
        assert_eq!(
            parse_get_top_txs(&p),
            Some(GetTopTxsRequest::PerPhase {
                req_id: 0x0102_0304_0506_0708,
                classic_n: 2000,
                soroban_n: 200,
            })
        );
    }

    #[test]
    fn get_top_txs_rejects_other_lengths() {
        assert_eq!(parse_get_top_txs(&[]), None);
        assert_eq!(parse_get_top_txs(&[0; 3]), None);
        assert_eq!(parse_get_top_txs(&[0; 8]), None);
        assert_eq!(parse_get_top_txs(&[0; 15]), None);
        assert_eq!(parse_get_top_txs(&[0; 17]), None);
    }

    #[test]
    fn top_txs_response_legacy_roundtrip() {
        let a = vec![1u8, 2, 3];
        let b = vec![9u8; 70];
        let p = encode_top_txs_response(None, &[&a, &b]);
        // [count=2][len=3][1 2 3][len=70][9*70]
        assert_eq!(&p[..4], &2u32.to_le_bytes());
        assert_eq!(&p[4..8], &3u32.to_le_bytes());
        assert_eq!(&p[8..11], &a[..]);
        assert_eq!(&p[11..15], &70u32.to_le_bytes());
        assert_eq!(p.len(), 4 + 4 + 3 + 4 + 70);
        let d = parse_top_txs_response(&p, false).unwrap();
        assert_eq!(d.req_id, None);
        assert_eq!(d.txs, vec![a, b]);
    }

    #[test]
    fn top_txs_response_v2_echoes_req_id() {
        let a = vec![7u8; 5];
        let p = encode_top_txs_response(Some(42), &[&a]);
        assert_eq!(&p[..8], &42u64.to_le_bytes());
        assert_eq!(&p[8..12], &1u32.to_le_bytes());
        assert_eq!(&p[12..16], &5u32.to_le_bytes());
        assert_eq!(&p[16..], &a[..]);
        let d = parse_top_txs_response(&p, true).unwrap();
        assert_eq!(d.req_id, Some(42));
        assert_eq!(d.txs, vec![a]);
    }

    #[test]
    fn top_txs_response_empty_both_layouts() {
        assert_eq!(encode_top_txs_response(None, &[]), 0u32.to_le_bytes());
        let v2 = encode_top_txs_response(Some(7), &[]);
        assert_eq!(v2.len(), 12);
        assert_eq!(
            parse_top_txs_response(&v2, true).unwrap(),
            TopTxsResponse {
                req_id: Some(7),
                txs: vec![]
            }
        );
        assert_eq!(parse_top_txs_response(&[0; 3], false), None);
        assert_eq!(parse_top_txs_response(&[0; 11], true), None);
    }

    #[test]
    fn top_txs_response_truncated_entry_ends_list() {
        let mut p = encode_top_txs_response(None, &[&[1, 2, 3], &[4, 5, 6]]);
        p.truncate(p.len() - 1);
        let d = parse_top_txs_response(&p, false).unwrap();
        assert_eq!(d.txs, vec![vec![1, 2, 3]]);
    }

    #[test]
    fn remove_txs_roundtrip() {
        let p = encode_hash_list(&[h(1), h(2)]);
        assert_eq!(p.len(), 4 + 64);
        assert_eq!(&p[..4], &2u32.to_le_bytes());
        assert_eq!(parse_remove_txs(&p), Some(vec![h(1), h(2)]));
        assert_eq!(parse_remove_txs(&encode_hash_list(&[])), Some(vec![]));
        assert_eq!(parse_remove_txs(&[0; 3]), None);
    }

    #[test]
    fn remove_txs_count_larger_than_data_is_clamped() {
        let mut p = 5u32.to_le_bytes().to_vec();
        p.extend_from_slice(&h(9));
        p.extend_from_slice(&[0; 10]); // partial hash
        assert_eq!(parse_remove_txs(&p), Some(vec![h(9)]));
    }

    #[test]
    fn tx_set_externalized_roundtrip() {
        let p = encode_tx_set_externalized(&h(0x42), &[h(1), h(2), h(3)]);
        assert_eq!(p.len(), 32 + 4 + 96);
        let d = parse_tx_set_externalized(&p).unwrap();
        assert_eq!(d.tx_set_hash, h(0x42));
        assert_eq!(d.tx_hashes, vec![h(1), h(2), h(3)]);
        assert_eq!(parse_tx_set_externalized(&[0; 35]), None);
        // Zero-hash "removeTransactions" pun still parses.
        let d = parse_tx_set_externalized(&encode_tx_set_externalized(&[0; 32], &[h(5)])).unwrap();
        assert_eq!(d.tx_hashes, vec![h(5)]);
    }

    #[test]
    fn tx_received_roundtrip() {
        let xdr = vec![0xABu8; 123];
        let p = encode_tx_received(&h(3), &xdr);
        assert_eq!(p.len(), 32 + 4 + 123);
        assert_eq!(&p[..32], &h(3));
        assert_eq!(&p[32..36], &123u32.to_le_bytes());
        let d = parse_tx_received(&p).unwrap();
        assert_eq!(d.hash, h(3));
        assert_eq!(d.xdr, xdr);
    }

    #[test]
    fn tx_received_rejects_length_mismatch() {
        let mut p = encode_tx_received(&h(3), &[1, 2, 3]);
        p.push(0);
        assert_eq!(parse_tx_received(&p), None);
        p.truncate(p.len() - 2);
        assert_eq!(parse_tx_received(&p), None);
        assert_eq!(parse_tx_received(&[0; 35]), None);
    }

    #[test]
    fn tx_verdict_roundtrip() {
        let p = encode_tx_verdict(&h(8), false, -3);
        assert_eq!(p.len(), 37);
        assert_eq!(p[32], 0);
        assert_eq!(&p[33..37], &(-3i32).to_le_bytes());
        assert_eq!(
            parse_tx_verdict(&p),
            Some(TxVerdict {
                hash: h(8),
                accept: false,
                code: -3
            })
        );
        let p = encode_tx_verdict(&h(9), true, 0);
        assert_eq!(p[32], 1);
        let v = parse_tx_verdict(&p).unwrap();
        assert!(v.accept);
        assert_eq!(v.code, 0);
        assert_eq!(parse_tx_verdict(&[0; 36]), None);
        // Any non-zero accept byte is accept.
        let mut p = encode_tx_verdict(&h(9), true, 0);
        p[32] = 0x7f;
        assert!(parse_tx_verdict(&p).unwrap().accept);
    }

    #[test]
    fn ledger_closed_reads_seq_only() {
        let mut p = 1234u32.to_le_bytes().to_vec();
        p.extend_from_slice(&[0xEE; 32]);
        assert_eq!(parse_ledger_closed(&p), Some(1234));
        assert_eq!(parse_ledger_closed(&1u32.to_le_bytes()), Some(1));
        assert_eq!(parse_ledger_closed(&[0; 3]), None);
    }
}
