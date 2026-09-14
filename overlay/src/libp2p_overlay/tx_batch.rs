//! Compression of the complete TX frames already collected for one response.
//! On the negotiated TX protocol, ordinary StellarMessages keep their encoding.
//! A high-bit tag instead contains the decoded batch length, followed by exactly
//! one zstd frame. Its contents are length-prefixed Transaction messages only.
use crate::{flood::TxStreamMessage, wire::ValidatedTx};
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};
use tokio::sync::Semaphore;

pub(super) const MAX_BATCH_BYTES: usize = 64 * 1024;
const COMPRESSED: u32 = 1 << 31;
const CODEC_JOBS: usize = 4;

pub(super) struct Batch {
    pub raw: Vec<u8>,
    pub encoded: Option<Vec<u8>>,
    pub messages: usize,
}

#[derive(Default)]
struct Stats {
    encoded: AtomicU64,
    decoded: AtomicU64,
    encode_us: AtomicU64,
    decode_xdr_us: AtomicU64,
    wait_us: AtomicU64,
    sent: AtomicU64,
    sent_txs: AtomicU64,
    raw_bytes: AtomicU64,
    wire_bytes: AtomicU64,
}

pub(super) struct Codec {
    slots: Arc<Semaphore>,
    stats: Stats,
}

impl Codec {
    pub fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(CODEC_JOBS)),
            stats: Stats::default(),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> io::Result<T> + Send + 'static,
    ) -> io::Result<(T, u64)> {
        let waiting = Instant::now();
        let permit = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(io::Error::other)?;
        let (result, work_us, wait_us) = tokio::task::spawn_blocking(move || {
            // A cancelled async caller must not release its slot while the
            // blocking job is still running.
            let _permit = permit;
            let wait_us = waiting.elapsed().as_micros() as u64;
            let start = Instant::now();
            let result = work();
            (result, start.elapsed().as_micros() as u64, wait_us)
        })
        .await
        .map_err(io::Error::other)?;
        self.stats.wait_us.fetch_add(wait_us, Relaxed);
        Ok((result?, work_us))
    }

    pub async fn encode(&self, raw: Vec<u8>, messages: usize) -> io::Result<Batch> {
        if raw.is_empty() || raw.len() > MAX_BATCH_BYTES || messages == 0 {
            return Err(invalid());
        }
        let (batch, work_us) = self
            .run(move || {
                let compressed = zstd::bulk::compress(&raw, 1)?;
                // Include the new tag and outer length prefix in the comparison.
                let encoded = if compressed.len() + 8 < raw.len() {
                    let mut frame = Vec::with_capacity(compressed.len() + 4);
                    frame.extend_from_slice(&(COMPRESSED | raw.len() as u32).to_be_bytes());
                    frame.extend_from_slice(&compressed);
                    Some(frame)
                } else {
                    None
                };
                Ok(Batch {
                    raw,
                    encoded,
                    messages,
                })
            })
            .await?;
        self.stats.encoded.fetch_add(1, Relaxed);
        self.stats.encode_us.fetch_add(work_us, Relaxed);
        Ok(batch)
    }

    pub async fn decode(&self, frame: Vec<u8>) -> io::Result<Vec<Arc<ValidatedTx>>> {
        let (txs, work_us) = self.run(move || decode(&frame)).await?;
        self.stats.decoded.fetch_add(1, Relaxed);
        self.stats.decode_xdr_us.fetch_add(work_us, Relaxed);
        Ok(txs)
    }

    pub fn record_sent(&self, raw_bytes: usize, wire_bytes: usize, txs: usize) {
        self.stats.sent.fetch_add(1, Relaxed);
        self.stats.sent_txs.fetch_add(txs as u64, Relaxed);
        self.stats.raw_bytes.fetch_add(raw_bytes as u64, Relaxed);
        self.stats.wire_bytes.fetch_add(wire_bytes as u64, Relaxed);
    }

    pub fn log_stats(&self) {
        let s = &self.stats;
        // Cumulative counts expose compression savings and codec work over time. Byte
        // counts include all frame prefixes, but exclude QUIC overhead.
        tracing::info!(
            encoded = s.encoded.load(Relaxed),
            decoded = s.decoded.load(Relaxed),
            encode_us = s.encode_us.load(Relaxed),
            decode_xdr_us = s.decode_xdr_us.load(Relaxed),
            wait_us = s.wait_us.load(Relaxed),
            sent = s.sent.load(Relaxed),
            sent_txs = s.sent_txs.load(Relaxed),
            raw_bytes = s.raw_bytes.load(Relaxed),
            wire_bytes = s.wire_bytes.load(Relaxed),
            "TX_BATCH_STATS"
        );
    }
}

pub(super) fn is_compressed(frame: &[u8]) -> bool {
    frame.first().is_some_and(|b| b & 0x80 != 0)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid compressed TX batch")
}

fn decode(frame: &[u8]) -> io::Result<Vec<Arc<ValidatedTx>>> {
    if frame.len() < 4 || frame.len() > MAX_BATCH_BYTES || !is_compressed(frame) {
        return Err(invalid());
    }
    let length = (u32::from_be_bytes(frame[..4].try_into().unwrap()) & !COMPRESSED) as usize;
    if length == 0 || length > MAX_BATCH_BYTES {
        return Err(invalid());
    }
    let compressed = &frame[4..];
    if zstd::zstd_safe::find_frame_compressed_size(compressed).map_err(|_| invalid())?
        != compressed.len()
    {
        return Err(invalid());
    }
    let mut decoder = zstd::bulk::Decompressor::new()?;
    decoder.window_log_max(16)?;
    let raw = decoder.decompress(compressed, length)?;
    if raw.len() != length {
        return Err(invalid());
    }
    let mut remaining = raw.as_slice();
    let mut txs = Vec::new();
    // Strict-decode the entire batch before admitting any of it. The total
    // uncompressed size bounds both XDR work and the number of transactions.
    while !remaining.is_empty() {
        let prefix = remaining.get(..4).ok_or_else(invalid)?;
        let n = u32::from_be_bytes(prefix.try_into().unwrap()) as usize;
        remaining = &remaining[4..];
        let message = remaining.get(..n).ok_or_else(invalid)?;
        match TxStreamMessage::decode(message)? {
            TxStreamMessage::Tx(tx) => txs.push(tx),
            _ => return Err(invalid()),
        }
        remaining = &remaining[n..];
    }
    if txs.is_empty() {
        return Err(invalid());
    }
    Ok(txs)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn raw_batch(count: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let txs: Vec<_> = (0..count)
            .map(|i| crate::xdr::tests::valid_transaction_xdr(1000, i as i64, 1))
            .collect();
        let mut raw = Vec::new();
        for tx in &txs {
            let frame = crate::xdr::frame_transaction(tx);
            raw.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            raw.extend_from_slice(&frame);
        }
        (raw, txs)
    }

    fn encoded(raw: &[u8]) -> Vec<u8> {
        let mut frame = (COMPRESSED | raw.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&zstd::bulk::compress(raw, 1).unwrap());
        frame
    }

    #[tokio::test]
    async fn roundtrip_preserves_transaction_order_hashes_and_fees() {
        let codec = Codec::new();
        let (raw, expected) = raw_batch(150);
        let batch = codec.encode(raw.clone(), expected.len()).await.unwrap();
        assert_eq!(batch.raw, raw);
        assert!(batch.encoded.as_ref().unwrap().len() + 4 < raw.len());
        let decoded = codec.decode(batch.encoded.unwrap()).await.unwrap();
        assert_eq!(decoded.len(), expected.len());
        for (tx, bytes) in decoded.iter().zip(expected) {
            assert_eq!(tx.bytes(), bytes);
            assert_eq!(*tx.hash(), crate::xdr::sha256_hash(&bytes));
            assert_eq!(tx.fee(), 1000);
            assert_eq!(tx.num_ops(), 1);
        }
    }

    #[tokio::test]
    async fn incompressible_data_uses_original_frames_and_size_is_bounded() {
        use rand::{RngCore, SeedableRng};
        let codec = Codec::new();
        let mut raw = vec![0; MAX_BATCH_BYTES];
        rand::rngs::StdRng::seed_from_u64(42).fill_bytes(&mut raw);
        let result = codec.encode(raw.clone(), 1).await.unwrap();
        assert!(result.encoded.is_none());
        assert_eq!(result.raw, raw);
        assert!(codec.encode(vec![0; MAX_BATCH_BYTES + 1], 1).await.is_err());
        assert!(codec.encode(vec![], 0).await.is_err());
    }

    #[test]
    fn rejects_bad_frames_lengths_and_non_transaction_contents() {
        let (raw, _) = raw_batch(2);
        let frame = encoded(&raw);
        for end in 0..frame.len() {
            assert!(decode(&frame[..end]).is_err());
        }
        for length in [0, raw.len() - 1, raw.len() + 1, MAX_BATCH_BYTES + 1] {
            let mut changed = frame.clone();
            changed[..4].copy_from_slice(&(COMPRESSED | length as u32).to_be_bytes());
            assert!(decode(&changed).is_err());
        }
        let mut corrupt = frame.clone();
        corrupt[4] ^= 0xff;
        assert!(decode(&corrupt).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        let mut concatenated = frame.clone();
        concatenated.extend_from_slice(&frame[4..]);
        assert!(decode(&concatenated).is_err());
        let mut truncated_tx = raw.clone();
        truncated_tx.pop();
        assert!(decode(&encoded(&truncated_tx)).is_err());
        let mut bad_length = raw.clone();
        bad_length[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&encoded(&bad_length)).is_err());
        let request = crate::xdr::frame_get_scp_state(1);
        let mut mixed = raw.clone();
        mixed.extend_from_slice(&(request.len() as u32).to_be_bytes());
        mixed.extend_from_slice(&request);
        assert!(decode(&encoded(&mixed)).is_err());
        assert!(decode(&encoded(&frame)).is_err()); // No nested batches.
        assert!(decode(&encoded(&vec![0; MAX_BATCH_BYTES + 1])).is_err());
    }

    #[tokio::test]
    async fn maximum_batch_roundtrips_but_larger_valid_xdr_is_rejected() {
        use stellar_xdr::curr::{
            HostFunction, InvokeHostFunctionOp, Limits, Operation, OperationBody, ReadXdr,
            TransactionEnvelope, WriteXdr,
        };
        let mut envelope = TransactionEnvelope::from_xdr(
            crate::xdr::tests::valid_transaction_xdr(1000, 1, 1),
            Limits::none(),
        )
        .unwrap();
        let TransactionEnvelope::Tx(tx) = &mut envelope else {
            unreachable!()
        };
        tx.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(Default::default()),
                auth: Default::default(),
            }),
        }]
        .try_into()
        .unwrap();
        let overhead = envelope.to_xdr(Limits::none()).unwrap().len() + 8;
        for size in [MAX_BATCH_BYTES, MAX_BATCH_BYTES + 4] {
            let TransactionEnvelope::Tx(tx) = &mut envelope else {
                unreachable!()
            };
            tx.tx.operations = vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::UploadContractWasm(
                        vec![0; size - overhead].try_into().unwrap(),
                    ),
                    auth: Default::default(),
                }),
            }]
            .try_into()
            .unwrap();
            let bytes = envelope.to_xdr(Limits::none()).unwrap();
            let message = crate::xdr::frame_transaction(&bytes);
            // Both inputs are valid transaction XDR, including the over-limit one.
            assert!(TxStreamMessage::decode(&message).is_ok());
            let mut raw = (message.len() as u32).to_be_bytes().to_vec();
            raw.extend_from_slice(&message);
            assert_eq!(raw.len(), size);
            if size == MAX_BATCH_BYTES {
                let batch = Codec::new().encode(raw, 1).await.unwrap();
                let txs = decode(&batch.encoded.unwrap()).unwrap();
                assert_eq!(txs.len(), 1);
                assert_eq!(txs[0].bytes(), bytes);
            } else {
                assert!(decode(&encoded(&raw)).is_err());
            }
        }
    }

    #[tokio::test]
    async fn jobs_run_in_parallel_off_runtime_and_cancellation_retains_slot() {
        let codec = Arc::new(Codec {
            slots: Arc::new(Semaphore::new(2)),
            stats: Stats::default(),
        });
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        let a = Arc::clone(&codec);
        let started_a = started.clone();
        let first = tokio::spawn(async move {
            a.run(move || {
                started_a.send(1).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                Ok(())
            })
            .await
        });
        assert_eq!(starts.recv().await, Some(1));
        // On this single-thread runtime, a second blocking job and async
        // progress must both be possible while the first worker is held.
        let b = Arc::clone(&codec);
        let second = tokio::spawn(async move {
            b.run(move || {
                started.send(2).unwrap();
                Ok(())
            })
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(starts.recv().await, Some(2));
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(codec.slots.available_permits(), 1);
        let last = Arc::clone(&codec.slots).acquire_owned().await.unwrap();
        assert!(codec.slots.try_acquire().is_err());
        release.send(()).unwrap();
        let recovered =
            tokio::time::timeout(std::time::Duration::from_secs(2), codec.slots.acquire())
                .await
                .unwrap()
                .unwrap();
        drop((last, recovered));
        assert_eq!(codec.slots.available_permits(), 2);
    }
}
