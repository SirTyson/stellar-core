//! Reed–Solomon coding and wire format for eager TX-set dissemination.
//!
//! The nominator sends each encoded shred to a small number of branch roots.
//! With the fully-connected Tier-1 topology, those roots partition the remaining
//! validators and forward the shred once. Any `original_shards` distinct shreds
//! recover the canonical TX-set bytes.

use rayon::prelude::*;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::time::Instant;

pub(crate) const TXSET_SHARD_PROTOCOL_VERSION: u8 = 3;
pub(crate) const TXSET_TARGET_SHARD_SIZE: usize = 1024;
pub(crate) const TXSET_SHARD_RECOVERY_FACTOR_PERCENT: usize = 50;
pub(crate) const TXSET_SHARD_INITIAL_TTL: u8 = 1;
pub(crate) const TXSET_TARGET_SHARDS_PER_PEER: usize = 2;
pub(crate) const TXSET_MAX_TOTAL_SHARDS: usize = 255;
/// Branch roots per shred. Leader egress is `factor * (1 + recovery) * setSize`
/// and does not depend on peer count, while each relay's egress is about
/// `(1 + recovery) * setSize` regardless of the factor. At 1 those two are
/// equal, so no node is a hotspot; every value above 1 multiplies the leader's
/// share alone and rebuilds the bottleneck this scheme exists to remove. At 89
/// peers and a 5 MB set that is 7.50 MB from the leader against 7.42 MB from
/// each relay, versus 15.00 MB from the leader at factor 2.
///
/// A single dead root costs only the shreds it is root for, about
/// `total / peers` of them, against a recovery budget of `total / 3`: at that
/// scale roughly 30 roots can fail before reconstruction does, so the extra
/// root that factor 2 buys is redundant insurance at double the scarce cost.
pub(crate) const TXSET_SHARD_BRANCHING_FACTOR: usize = 1;
/// Largest factor peers accept on the wire. Must stay >= the value above: a
/// nominator that exceeded it would have every shred it sends rejected
/// network-wide, silently disabling dissemination.
pub(crate) const TXSET_MAX_SHARD_BRANCHING_FACTOR: usize = 2;
const _: () = assert!(TXSET_SHARD_BRANCHING_FACTOR >= 1);
const _: () = assert!(TXSET_SHARD_BRANCHING_FACTOR <= TXSET_MAX_SHARD_BRANCHING_FACTOR);
pub(crate) const TXSET_MAX_CODING_PARALLELISM: usize = 128;
// Core IPC caps an entire [hash:32][txSetXDR...] payload at 16 MiB.
pub(crate) const TXSET_MAX_WIRE_SIZE: usize = 16 * 1024 * 1024 - 32;
const TXSET_MAX_SHARD_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
const TXSET_MIN_PARALLEL_WORK_BYTES: usize = 512 * 1024;
const TXSET_ZSTD_COMPRESSION_LEVEL: i32 = 1;

// version + hash + original-count + recovery-count + index + shard-size +
// original-length + codec + ttl + branch-index + branch-count + payload-length.
pub(crate) const TXSET_SHARD_HEADER_LEN: usize = 1 + 32 + 2 + 2 + 2 + 4 + 8 + 1 + 1 + 1 + 1 + 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum TxSetCodec {
    Raw = 0,
    Zstd = 1,
}

impl TryFrom<u8> for TxSetCodec {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            value if value == Self::Raw as u8 => Ok(Self::Raw),
            value if value == Self::Zstd as u8 => Ok(Self::Zstd),
            value => Err(value),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TxSetShardDecodeError {
    UnsupportedCodec(u8),
    Invalid(String),
}

impl fmt::Display for TxSetShardDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCodec(codec) => write!(f, "unsupported TX-set codec {codec}"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum TxSetTransportDecodeError {
    UnknownDictionary(u32),
    Invalid(String),
}

impl fmt::Display for TxSetTransportDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDictionary(id) => {
                write!(f, "unsupported zstd dictionary ID {id}")
            }
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TxSetTransport {
    pub codec: TxSetCodec,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct TxSetTransportEncodeError {
    pub data: Vec<u8>,
    pub message: String,
}

/// Encode canonical TX-set bytes for transport. Compression is opportunistic:
/// a frame that does not reduce the payload falls back to raw bytes.
pub(crate) fn encode_txset_transport(
    data: Vec<u8>,
    compression_enabled: bool,
) -> Result<TxSetTransport, TxSetTransportEncodeError> {
    if data.is_empty() || data.len() > TXSET_MAX_WIRE_SIZE {
        return Err(TxSetTransportEncodeError {
            message: format!(
                "TX set length must be in 1..={TXSET_MAX_WIRE_SIZE}, got {}",
                data.len()
            ),
            data,
        });
    }
    if !compression_enabled {
        return Ok(TxSetTransport {
            codec: TxSetCodec::Raw,
            data,
        });
    }

    let compressed = match zstd::bulk::compress(&data, TXSET_ZSTD_COMPRESSION_LEVEL) {
        Ok(compressed) => compressed,
        Err(error) => {
            return Err(TxSetTransportEncodeError {
                data,
                message: format!("zstd compression failed: {error}"),
            });
        }
    };
    if compressed.len() >= data.len() || compressed.len() > TXSET_MAX_WIRE_SIZE {
        Ok(TxSetTransport {
            codec: TxSetCodec::Raw,
            data,
        })
    } else {
        Ok(TxSetTransport {
            codec: TxSetCodec::Zstd,
            data: compressed,
        })
    }
}

/// Decode one or more concatenated zstd frames into canonical TX-set bytes.
/// Every frame must declare its content size, the sum is capped before any
/// decompression, and the streaming read is separately bounded as defense in
/// depth against corrupt or malicious frame headers.
pub(crate) fn decode_txset_transport(
    codec: TxSetCodec,
    data: &[u8],
) -> Result<Vec<u8>, TxSetTransportDecodeError> {
    if data.is_empty() || data.len() > TXSET_MAX_WIRE_SIZE {
        return Err(TxSetTransportDecodeError::Invalid(format!(
            "transport payload length must be in 1..={TXSET_MAX_WIRE_SIZE}, got {}",
            data.len()
        )));
    }
    if codec == TxSetCodec::Raw {
        return Ok(data.to_vec());
    }

    let mut offset = 0usize;
    let mut declared_size = 0usize;
    while offset < data.len() {
        let remaining = &data[offset..];
        let frame_len = zstd::zstd_safe::find_frame_compressed_size(remaining).map_err(|e| {
            TxSetTransportDecodeError::Invalid(format!(
                "invalid zstd frame at byte {offset}: {}",
                zstd::zstd_safe::get_error_name(e)
            ))
        })?;
        if frame_len == 0 || frame_len > remaining.len() {
            return Err(TxSetTransportDecodeError::Invalid(format!(
                "invalid zstd frame length {frame_len} at byte {offset}"
            )));
        }
        let frame = &remaining[..frame_len];
        if let Some(id) = zstd::zstd_safe::get_dict_id_from_frame(frame) {
            return Err(TxSetTransportDecodeError::UnknownDictionary(id.get()));
        }
        let frame_size = zstd::zstd_safe::get_frame_content_size(frame)
            .map_err(|_| {
                TxSetTransportDecodeError::Invalid(format!(
                    "invalid zstd content size at byte {offset}"
                ))
            })?
            .ok_or_else(|| {
                TxSetTransportDecodeError::Invalid(format!(
                    "zstd frame at byte {offset} omits its content size"
                ))
            })?;
        let frame_size = usize::try_from(frame_size).map_err(|_| {
            TxSetTransportDecodeError::Invalid("zstd content size does not fit usize".to_string())
        })?;
        declared_size = declared_size.checked_add(frame_size).ok_or_else(|| {
            TxSetTransportDecodeError::Invalid("zstd content size overflow".to_string())
        })?;
        if declared_size > TXSET_MAX_WIRE_SIZE {
            return Err(TxSetTransportDecodeError::Invalid(format!(
                "decompressed TX set exceeds {TXSET_MAX_WIRE_SIZE} bytes"
            )));
        }
        offset = offset.checked_add(frame_len).ok_or_else(|| {
            TxSetTransportDecodeError::Invalid("zstd frame offset overflow".to_string())
        })?;
    }
    if declared_size == 0 {
        return Err(TxSetTransportDecodeError::Invalid(
            "decompressed TX set is empty".to_string(),
        ));
    }

    let decoder = zstd::stream::read::Decoder::new(data).map_err(|e| {
        TxSetTransportDecodeError::Invalid(format!("failed to create zstd decoder: {e}"))
    })?;
    let read_limit = u64::try_from(declared_size)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bounded = decoder.take(read_limit);
    let mut decoded = Vec::with_capacity(declared_size);
    bounded.read_to_end(&mut decoded).map_err(|e| {
        TxSetTransportDecodeError::Invalid(format!("zstd decompression failed: {e}"))
    })?;
    if decoded.len() != declared_size {
        return Err(TxSetTransportDecodeError::Invalid(format!(
            "zstd decoded {} bytes, frame headers declared {declared_size}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

/// A private Rayon pool prevents TX-set coding from consuming more workers
/// than the network's configured transaction-cluster parallelism.
pub(crate) struct TxSetCodingExecutor {
    max_parallelism: usize,
    pool: Option<rayon::ThreadPool>,
}

impl TxSetCodingExecutor {
    pub fn new(max_parallelism: usize) -> Result<Self, String> {
        if !(1..=TXSET_MAX_CODING_PARALLELISM).contains(&max_parallelism) {
            return Err(format!(
                "TX-set coding parallelism must be in 1..={TXSET_MAX_CODING_PARALLELISM}, got {max_parallelism}"
            ));
        }
        let pool = if max_parallelism == 1 {
            None
        } else {
            Some(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(max_parallelism)
                    .thread_name(|index| format!("txset-code-{index}"))
                    .build()
                    .map_err(|e| format!("failed to create TX-set coding pool: {e}"))?,
            )
        };
        Ok(Self {
            max_parallelism,
            pool,
        })
    }

    pub fn max_parallelism(&self) -> usize {
        self.max_parallelism
    }

    fn ranges(&self, shard_size: usize, original_shards: usize) -> Vec<(usize, usize)> {
        debug_assert!(shard_size > 0 && shard_size.is_multiple_of(2));
        let work_bytes = shard_size.saturating_mul(original_shards);
        let useful_workers = work_bytes.div_ceil(TXSET_MIN_PARALLEL_WORK_BYTES).max(1);
        let workers = self
            .max_parallelism
            .min(useful_workers)
            .min(shard_size / 2)
            .max(1);
        let pairs = shard_size / 2;
        (0..workers)
            .map(|worker| {
                let start = (worker * pairs / workers) * 2;
                let end = ((worker + 1) * pairs / workers) * 2;
                (start, end)
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TxSetShardConfig {
    pub target_shard_size: usize,
    pub recovery_factor_percent: usize,
    pub initial_ttl: u8,
}

impl Default for TxSetShardConfig {
    fn default() -> Self {
        Self {
            target_shard_size: TXSET_TARGET_SHARD_SIZE,
            recovery_factor_percent: TXSET_SHARD_RECOVERY_FACTOR_PERCENT,
            initial_ttl: TXSET_SHARD_INITIAL_TTL,
        }
    }
}

impl TxSetShardConfig {
    fn recovery_shards(self, original_shards: usize) -> Result<usize, String> {
        let scaled = original_shards
            .checked_mul(self.recovery_factor_percent)
            .ok_or_else(|| "recovery shard calculation overflow".to_string())?;
        Ok(scaled.div_ceil(100).max(1))
    }

    fn max_original_shards(self, total_shard_limit: usize) -> Result<Option<usize>, String> {
        let total_shard_limit = total_shard_limit.min(TXSET_MAX_TOTAL_SHARDS);
        for original_shards in (2..=total_shard_limit).rev() {
            if original_shards.is_multiple_of(2)
                && original_shards + self.recovery_shards(original_shards)? <= total_shard_limit
            {
                return Ok(Some(original_shards));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TxSetShardPlan {
    pub original_shards: usize,
    pub recovery_shards: usize,
    pub shard_size: usize,
}

impl TxSetShardPlan {
    pub fn total_shards(self) -> usize {
        self.original_shards + self.recovery_shards
    }
}

fn make_even(value: usize) -> Result<usize, String> {
    value
        .checked_add(value % 2)
        .ok_or_else(|| "shard size overflow".to_string())
}

pub(crate) fn plan_txset_shards(
    data_len: usize,
    peer_count: usize,
    config: TxSetShardConfig,
) -> Result<TxSetShardPlan, String> {
    if data_len == 0 || data_len > TXSET_MAX_WIRE_SIZE {
        return Err(format!(
            "TX set length must be in 1..={TXSET_MAX_WIRE_SIZE}, got {data_len}"
        ));
    }
    if peer_count == 0 {
        return Err("cannot plan TX-set shreds without peers".to_string());
    }
    if config.target_shard_size == 0 || config.target_shard_size > TXSET_MAX_WIRE_SIZE {
        return Err(format!(
            "configured target shard size must be in 1..={TXSET_MAX_WIRE_SIZE}"
        ));
    }
    if config.recovery_factor_percent == 0 {
        return Err("configured recovery factor must be non-zero".to_string());
    }
    // TTL=1 is the intended fully-connected Tier-1 topology. Permit zero for
    // focused tests; the branch partition is deliberately one forwarding hop.
    if config.initial_ttl > 1 {
        return Err("configured shred TTL must be at most 1".to_string());
    }

    let min_total_shards = 2usize
        .checked_add(config.recovery_shards(2)?)
        .ok_or_else(|| "minimum shard count overflow".to_string())?;
    let target_total_shards = peer_count
        .saturating_mul(TXSET_TARGET_SHARDS_PER_PEER)
        .max(min_total_shards)
        .min(TXSET_MAX_TOTAL_SHARDS);
    let max_original_shards = config
        .max_original_shards(target_total_shards)?
        .ok_or_else(|| {
            format!(
                "recovery factor {}% leaves no valid original shard count under {} total shards",
                config.recovery_factor_percent, target_total_shards
            )
        })?;

    let target_shard_size = make_even(config.target_shard_size)?;
    let size_limited_original_shards = make_even(data_len.div_ceil(target_shard_size))?.max(2);
    let original_shards = size_limited_original_shards.min(max_original_shards);
    // `target_shard_size` controls how many originals we create; do not pad a
    // tiny set all the way to that target. Large sets still land at roughly
    // the target (or grow above it when peer count is the limiting factor).
    let shard_size = make_even(data_len.div_ceil(original_shards))?.max(2);
    let recovery_shards = config.recovery_shards(original_shards)?;
    let total_shards = original_shards
        .checked_add(recovery_shards)
        .ok_or_else(|| "total shard count overflow".to_string())?;

    if total_shards > TXSET_MAX_TOTAL_SHARDS {
        return Err(format!(
            "planned shard count {total_shards} exceeds max {TXSET_MAX_TOTAL_SHARDS}"
        ));
    }
    if shard_size
        .checked_add(TXSET_SHARD_HEADER_LEN)
        .is_none_or(|wire_size| wire_size > TXSET_MAX_SHARD_MESSAGE_SIZE)
    {
        return Err("planned shred exceeds maximum wire message size".to_string());
    }

    Ok(TxSetShardPlan {
        original_shards,
        recovery_shards,
        shard_size,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TxSetShardMessage {
    pub hash: [u8; 32],
    pub original_shards: usize,
    pub recovery_shards: usize,
    pub shard_index: usize,
    pub shard_size: usize,
    pub original_len: usize,
    pub codec: TxSetCodec,
    pub ttl: u8,
    pub branch_index: usize,
    pub branch_count: usize,
    pub payload: Vec<u8>,
}

impl TxSetShardMessage {
    pub fn is_original(&self) -> bool {
        self.shard_index < self.original_shards
    }

    pub fn total_shards(&self) -> usize {
        self.original_shards + self.recovery_shards
    }

    pub fn with_ttl(&self, ttl: u8) -> Self {
        let mut next = self.clone();
        next.ttl = ttl;
        next
    }

    pub fn with_branch(&self, branch_index: usize, branch_count: usize) -> Self {
        let mut next = self.clone();
        next.branch_index = branch_index;
        next.branch_count = branch_count;
        next
    }

    fn validate(&self) -> Result<(), String> {
        if self.original_shards < 2 || !self.original_shards.is_multiple_of(2) {
            return Err("original shard count must be even and at least two".to_string());
        }
        if self.recovery_shards == 0 || self.total_shards() > TXSET_MAX_TOTAL_SHARDS {
            return Err("invalid recovery or total shard count".to_string());
        }
        if self.shard_index >= self.total_shards() {
            return Err("shard index out of range".to_string());
        }
        if self.shard_size == 0 || !self.shard_size.is_multiple_of(2) {
            return Err("shard size must be a non-zero even number".to_string());
        }
        if self.payload.len() != self.shard_size {
            return Err(format!(
                "payload length {} != shard size {}",
                self.payload.len(),
                self.shard_size
            ));
        }
        if self.original_len == 0 || self.original_len > TXSET_MAX_WIRE_SIZE {
            return Err("invalid original TX-set length".to_string());
        }
        if self.ttl > 1 {
            return Err("shred TTL exceeds maximum".to_string());
        }
        if self.branch_count == 0
            || self.branch_count > TXSET_MAX_SHARD_BRANCHING_FACTOR
            || self.branch_index >= self.branch_count
        {
            return Err("invalid shred branch parameters".to_string());
        }

        let padded_len = self
            .original_shards
            .checked_mul(self.shard_size)
            .ok_or_else(|| "padded TX-set length overflow".to_string())?;
        if padded_len < self.original_len {
            return Err("shreds cannot contain the declared TX-set length".to_string());
        }
        // Honest plans add at most target-size padding per original shred.
        // This also caps memory committed by a malicious first shred.
        let max_padded_len = TXSET_MAX_WIRE_SIZE
            .checked_add(
                self.original_shards
                    .checked_mul(TXSET_TARGET_SHARD_SIZE)
                    .ok_or_else(|| "padded TX-set bound overflow".to_string())?,
            )
            .ok_or_else(|| "padded TX-set bound overflow".to_string())?;
        if padded_len > max_padded_len {
            return Err("padded TX-set length exceeds maximum".to_string());
        }
        if self
            .shard_size
            .checked_add(TXSET_SHARD_HEADER_LEN)
            .is_none_or(|wire_size| wire_size > TXSET_MAX_SHARD_MESSAGE_SIZE)
        {
            return Err("shred exceeds maximum wire message size".to_string());
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let original_shards = u16::try_from(self.original_shards)
            .map_err(|_| "too many original shards".to_string())?;
        let recovery_shards = u16::try_from(self.recovery_shards)
            .map_err(|_| "too many recovery shards".to_string())?;
        let shard_index =
            u16::try_from(self.shard_index).map_err(|_| "shard index too large".to_string())?;
        let shard_size =
            u32::try_from(self.shard_size).map_err(|_| "shard size too large".to_string())?;
        let original_len = u64::try_from(self.original_len)
            .map_err(|_| "original length too large".to_string())?;
        let branch_index =
            u8::try_from(self.branch_index).map_err(|_| "branch index too large".to_string())?;
        let branch_count =
            u8::try_from(self.branch_count).map_err(|_| "branch count too large".to_string())?;
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| "payload too large".to_string())?;

        let mut out = Vec::with_capacity(TXSET_SHARD_HEADER_LEN + self.payload.len());
        out.push(TXSET_SHARD_PROTOCOL_VERSION);
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&original_shards.to_be_bytes());
        out.extend_from_slice(&recovery_shards.to_be_bytes());
        out.extend_from_slice(&shard_index.to_be_bytes());
        out.extend_from_slice(&shard_size.to_be_bytes());
        out.extend_from_slice(&original_len.to_be_bytes());
        out.push(self.codec as u8);
        out.push(self.ttl);
        out.push(branch_index);
        out.push(branch_count);
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, TxSetShardDecodeError> {
        if data.len() < TXSET_SHARD_HEADER_LEN {
            return Err(TxSetShardDecodeError::Invalid(format!(
                "shred message too short: {}",
                data.len()
            )));
        }
        if data[0] != TXSET_SHARD_PROTOCOL_VERSION {
            return Err(TxSetShardDecodeError::Invalid(format!(
                "unsupported shred version {}",
                data[0]
            )));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[1..33]);
        let original_shards = u16::from_be_bytes([data[33], data[34]]) as usize;
        let recovery_shards = u16::from_be_bytes([data[35], data[36]]) as usize;
        let shard_index = u16::from_be_bytes([data[37], data[38]]) as usize;
        let shard_size = u32::from_be_bytes([data[39], data[40], data[41], data[42]]) as usize;
        let original_len = u64::from_be_bytes([
            data[43], data[44], data[45], data[46], data[47], data[48], data[49], data[50],
        ]);
        let original_len = usize::try_from(original_len).map_err(|_| {
            TxSetShardDecodeError::Invalid("original length does not fit usize".to_string())
        })?;
        let codec =
            TxSetCodec::try_from(data[51]).map_err(TxSetShardDecodeError::UnsupportedCodec)?;
        let ttl = data[52];
        let branch_index = data[53] as usize;
        let branch_count = data[54] as usize;
        let payload_len = u32::from_be_bytes([data[55], data[56], data[57], data[58]]) as usize;
        let payload_end = TXSET_SHARD_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| TxSetShardDecodeError::Invalid("payload length overflow".to_string()))?;
        if payload_end != data.len() {
            return Err(TxSetShardDecodeError::Invalid(
                "shred payload length mismatch".to_string(),
            ));
        }

        let shard = Self {
            hash,
            original_shards,
            recovery_shards,
            shard_index,
            shard_size,
            original_len,
            codec,
            ttl,
            branch_index,
            branch_count,
            payload: data[TXSET_SHARD_HEADER_LEN..].to_vec(),
        };
        shard.validate().map_err(TxSetShardDecodeError::Invalid)?;
        Ok(shard)
    }
}

#[cfg(test)]
pub(crate) fn make_txset_shards(
    hash: [u8; 32],
    data: &[u8],
    peer_count: usize,
    config: TxSetShardConfig,
) -> Result<Vec<TxSetShardMessage>, String> {
    let executor = TxSetCodingExecutor::new(1)?;
    make_txset_shards_parallel(hash, data, peer_count, config, &executor)
}

#[cfg(test)]
pub(crate) fn make_txset_shards_parallel(
    hash: [u8; 32],
    data: &[u8],
    peer_count: usize,
    config: TxSetShardConfig,
    executor: &TxSetCodingExecutor,
) -> Result<Vec<TxSetShardMessage>, String> {
    make_txset_shards_parallel_with_codec(hash, data, TxSetCodec::Raw, peer_count, config, executor)
}

pub(crate) fn make_txset_shards_parallel_with_codec(
    hash: [u8; 32],
    data: &[u8],
    codec: TxSetCodec,
    peer_count: usize,
    config: TxSetShardConfig,
    executor: &TxSetCodingExecutor,
) -> Result<Vec<TxSetShardMessage>, String> {
    let plan = plan_txset_shards(data.len(), peer_count, config)?;
    let mut originals = Vec::with_capacity(plan.original_shards);
    for index in 0..plan.original_shards {
        let start = index * plan.shard_size;
        let end = (start + plan.shard_size).min(data.len());
        let mut shard = vec![0u8; plan.shard_size];
        if start < data.len() {
            shard[..end - start].copy_from_slice(&data[start..end]);
        }
        originals.push(shard);
    }

    let encode_range = |(start, end): (usize, usize)| {
        let width = end - start;
        let mut encoder =
            ReedSolomonEncoder::new(plan.original_shards, plan.recovery_shards, width)
                .map_err(|e| format!("failed to create Reed–Solomon encoder: {e}"))?;
        for shard in &originals {
            encoder
                .add_original_shard(&shard[start..end])
                .map_err(|e| format!("failed to add original shred: {e}"))?;
        }
        let result = encoder
            .encode()
            .map_err(|e| format!("failed to encode recovery shreds: {e}"))?;
        let recoveries: Vec<Vec<u8>> = result.recovery_iter().map(|shard| shard.to_vec()).collect();
        Ok::<_, String>((start, recoveries))
    };

    let ranges = executor.ranges(plan.shard_size, plan.original_shards);
    let encoded_ranges = if ranges.len() == 1 {
        vec![encode_range(ranges[0])?]
    } else {
        executor
            .pool
            .as_ref()
            .expect("multiple coding ranges require a worker pool")
            .install(|| {
                ranges
                    .into_par_iter()
                    .map(encode_range)
                    .collect::<Result<Vec<_>, String>>()
            })?
    };
    let mut recoveries = vec![vec![0u8; plan.shard_size]; plan.recovery_shards];
    for (start, recovery_ranges) in encoded_ranges {
        for (recovery, range) in recoveries.iter_mut().zip(recovery_ranges) {
            recovery[start..start + range.len()].copy_from_slice(&range);
        }
    }

    let mut messages = Vec::with_capacity(plan.total_shards());
    for (shard_index, payload) in originals.into_iter().enumerate() {
        messages.push(TxSetShardMessage {
            hash,
            original_shards: plan.original_shards,
            recovery_shards: plan.recovery_shards,
            shard_index,
            shard_size: plan.shard_size,
            original_len: data.len(),
            codec,
            ttl: config.initial_ttl,
            branch_index: 0,
            branch_count: 1,
            payload,
        });
    }
    for (recovery_index, payload) in recoveries.into_iter().enumerate() {
        messages.push(TxSetShardMessage {
            hash,
            original_shards: plan.original_shards,
            recovery_shards: plan.recovery_shards,
            shard_index: plan.original_shards + recovery_index,
            shard_size: plan.shard_size,
            original_len: data.len(),
            codec,
            ttl: config.initial_ttl,
            branch_index: 0,
            branch_count: 1,
            payload,
        });
    }
    Ok(messages)
}

#[cfg(test)]
pub(crate) fn assign_shards_to_peer_offsets(
    shard_count: usize,
    peer_count: usize,
) -> Vec<Vec<usize>> {
    let mut assignments = vec![Vec::new(); peer_count];
    if peer_count == 0 {
        return assignments;
    }
    for shard_offset in 0..shard_count {
        assignments[shard_offset % peer_count].push(shard_offset);
    }
    assignments
}

/// Assign each shred to `branch_count` distinct roots. Peer ordering must be
/// stable across the source and relays (the overlay sorts PeerIds).
pub(crate) fn assign_shard_branches_to_peer_offsets(
    shard_count: usize,
    peer_count: usize,
    requested_branch_count: usize,
) -> Vec<Vec<(usize, usize)>> {
    let mut assignments = vec![Vec::new(); peer_count];
    if peer_count == 0 || requested_branch_count == 0 {
        return assignments;
    }
    let branch_count = requested_branch_count.min(peer_count);
    for shard_index in 0..shard_count {
        for branch_index in 0..branch_count {
            let peer_offset = (shard_index * branch_count + branch_index) % peer_count;
            assignments[peer_offset].push((shard_index, branch_index));
        }
    }
    assignments
}

/// Return the non-root peer offsets covered by one branch of a shred. Across
/// all branches, every non-root is returned exactly once. Roots already receive
/// their copy directly from the leader.
pub(crate) fn relay_target_peer_offsets(
    peer_count: usize,
    shard_index: usize,
    branch_index: usize,
    branch_count: usize,
) -> Result<Vec<usize>, String> {
    if peer_count == 0
        || branch_count == 0
        || branch_count > peer_count
        || branch_index >= branch_count
    {
        return Err("invalid branch routing parameters".to_string());
    }
    let roots: HashSet<_> = (0..branch_count)
        .map(|branch| (shard_index * branch_count + branch) % peer_count)
        .collect();
    Ok((0..peer_count)
        .filter(|offset| {
            !roots.contains(offset) && (offset + shard_index) % branch_count == branch_index
        })
        .collect())
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TxSetReconstruction {
    pub data: Vec<u8>,
    pub used_recovery: bool,
}

pub(crate) struct TxSetShardAccumulator {
    original_shards: usize,
    recovery_shards: usize,
    shard_size: usize,
    original_len: usize,
    codec: TxSetCodec,
    originals: HashMap<usize, Vec<u8>>,
    recoveries: HashMap<usize, Vec<u8>>,
    pub created_at: Instant,
}

impl TxSetShardAccumulator {
    pub fn new(shard: &TxSetShardMessage) -> Self {
        Self {
            original_shards: shard.original_shards,
            recovery_shards: shard.recovery_shards,
            shard_size: shard.shard_size,
            original_len: shard.original_len,
            codec: shard.codec,
            originals: HashMap::new(),
            recoveries: HashMap::new(),
            created_at: Instant::now(),
        }
    }

    pub fn shard_count(&self) -> usize {
        self.originals.len() + self.recoveries.len()
    }

    pub fn is_ready(&self) -> bool {
        self.shard_count() >= self.original_shards
    }

    pub fn shard_indexes(&self) -> HashSet<usize> {
        self.originals
            .keys()
            .copied()
            .chain(
                self.recoveries
                    .keys()
                    .map(|index| self.original_shards + index),
            )
            .collect()
    }

    fn is_compatible(&self, shard: &TxSetShardMessage) -> bool {
        self.original_shards == shard.original_shards
            && self.recovery_shards == shard.recovery_shards
            && self.shard_size == shard.shard_size
            && self.original_len == shard.original_len
            && self.codec == shard.codec
    }

    pub fn insert(&mut self, shard: &TxSetShardMessage) -> Result<bool, String> {
        if !self.is_compatible(shard) {
            return Err("shred parameters differ from accumulator".to_string());
        }

        let (index, shards) = if shard.is_original() {
            (shard.shard_index, &mut self.originals)
        } else {
            (
                shard.shard_index - self.original_shards,
                &mut self.recoveries,
            )
        };
        match shards.entry(index) {
            Entry::Vacant(entry) => {
                entry.insert(shard.payload.clone());
                Ok(true)
            }
            Entry::Occupied(entry) if entry.get() == &shard.payload => Ok(false),
            Entry::Occupied(_) => Err("conflicting duplicate shred payload".to_string()),
        }
    }

    #[cfg(test)]
    pub fn reconstruct(&self) -> Result<Option<TxSetReconstruction>, String> {
        let executor = TxSetCodingExecutor::new(1)?;
        self.reconstruct_parallel(&executor)
    }

    pub fn reconstruct_parallel(
        &self,
        executor: &TxSetCodingExecutor,
    ) -> Result<Option<TxSetReconstruction>, String> {
        if !self.is_ready() {
            return Ok(None);
        }

        let used_recovery = self.originals.len() != self.original_shards;
        let mut pieces = Vec::with_capacity(self.original_shards * self.shard_size);
        if !used_recovery {
            for index in 0..self.original_shards {
                pieces.extend_from_slice(
                    self.originals
                        .get(&index)
                        .ok_or_else(|| format!("missing original shred {index}"))?,
                );
            }
        } else {
            let decode_range = |(start, end): (usize, usize)| {
                let width = end - start;
                let mut decoder =
                    ReedSolomonDecoder::new(self.original_shards, self.recovery_shards, width)
                        .map_err(|e| format!("failed to create Reed–Solomon decoder: {e}"))?;
                for (index, shard) in &self.originals {
                    decoder
                        .add_original_shard(*index, &shard[start..end])
                        .map_err(|e| format!("failed to add original shred {index}: {e}"))?;
                }
                for (index, shard) in &self.recoveries {
                    decoder
                        .add_recovery_shard(*index, &shard[start..end])
                        .map_err(|e| format!("failed to add recovery shred {index}: {e}"))?;
                }
                let result = decoder
                    .decode()
                    .map_err(|e| format!("failed to decode TX-set shreds: {e}"))?;
                let restored = result
                    .restored_original_iter()
                    .map(|(index, shard)| (index, shard.to_vec()))
                    .collect::<HashMap<_, _>>();
                Ok::<_, String>((start, restored))
            };
            let ranges = executor.ranges(self.shard_size, self.original_shards);
            let decoded_ranges = if ranges.len() == 1 {
                vec![decode_range(ranges[0])?]
            } else {
                executor
                    .pool
                    .as_ref()
                    .expect("multiple coding ranges require a worker pool")
                    .install(|| {
                        ranges
                            .into_par_iter()
                            .map(decode_range)
                            .collect::<Result<Vec<_>, String>>()
                    })?
            };
            let mut restored: HashMap<usize, Vec<u8>> = (0..self.original_shards)
                .filter(|index| !self.originals.contains_key(index))
                .map(|index| (index, vec![0u8; self.shard_size]))
                .collect();
            for (start, range_shards) in decoded_ranges {
                for (index, range) in range_shards {
                    let shard = restored
                        .get_mut(&index)
                        .ok_or_else(|| format!("decoder restored unexpected shred {index}"))?;
                    shard[start..start + range.len()].copy_from_slice(&range);
                }
            }
            for index in 0..self.original_shards {
                if let Some(shard) = self.originals.get(&index) {
                    pieces.extend_from_slice(shard);
                } else if let Some(shard) = restored.get(&index) {
                    pieces.extend_from_slice(shard);
                } else {
                    return Ok(None);
                }
            }
        }
        pieces.truncate(self.original_len);
        Ok(Some(TxSetReconstruction {
            data: pieces,
            used_recovery,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{Duration, Instant};

    fn data(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(31) & 0xff) as u8)
            .collect()
    }

    fn shards(len: usize, peers: usize) -> Vec<TxSetShardMessage> {
        make_txset_shards([0x42; 32], &data(len), peers, TxSetShardConfig::default()).unwrap()
    }

    #[test]
    fn protocol_v3_header_has_codec_byte() {
        assert_eq!(TXSET_SHARD_PROTOCOL_VERSION, 3);
        assert_eq!(TXSET_SHARD_HEADER_LEN, 59);

        let mut shard = shards(4096, 3)[0].clone();
        for codec in [TxSetCodec::Raw, TxSetCodec::Zstd] {
            shard.codec = codec;
            let encoded = shard.encode().unwrap();
            assert_eq!(encoded[51], codec as u8);
            assert_eq!(TxSetShardMessage::decode(&encoded).unwrap(), shard);
        }
    }

    #[test]
    fn compression_disabled_always_uses_raw_transport() {
        let expected = vec![0u8; 64 * 1024];
        let original_allocation = expected.as_ptr();
        let transport = encode_txset_transport(expected, false).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Raw);
        assert_eq!(transport.data.as_ptr(), original_allocation);
        let expected = vec![0u8; 64 * 1024];
        assert_eq!(transport.data, expected);
        assert_eq!(
            decode_txset_transport(transport.codec, &transport.data).unwrap(),
            expected
        );
    }

    #[test]
    fn compression_falls_back_when_zstd_would_expand() {
        let expected = [0x5a];
        let transport = encode_txset_transport(expected.to_vec(), true).unwrap();
        assert_eq!(
            transport,
            TxSetTransport {
                codec: TxSetCodec::Raw,
                data: expected.to_vec()
            }
        );
    }

    #[test]
    fn zstd_transport_round_trip_is_smaller_and_declares_size() {
        let expected: Vec<_> = (0..256 * 1024)
            .map(|index| ((index / 64) % 17) as u8)
            .collect();
        let transport = encode_txset_transport(expected.clone(), true).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Zstd);
        assert!(transport.data.len() < expected.len() / 10);
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&transport.data).unwrap(),
            Some(expected.len() as u64)
        );
        assert!(zstd::zstd_safe::get_dict_id_from_frame(&transport.data).is_none());
        assert_eq!(
            decode_txset_transport(transport.codec, &transport.data).unwrap(),
            expected
        );
    }

    #[test]
    fn concatenated_zstd_frames_decode_with_a_total_size_bound() {
        let first = vec![0x11; 32 * 1024];
        let second = data(48 * 1024 + 7);
        let mut encoded = zstd::bulk::compress(&first, 1).unwrap();
        encoded.extend_from_slice(&zstd::bulk::compress(&second, 1).unwrap());

        let mut expected = first;
        expected.extend_from_slice(&second);
        assert_eq!(
            decode_txset_transport(TxSetCodec::Zstd, &encoded).unwrap(),
            expected
        );
    }

    #[test]
    fn zstd_decoder_rejects_empty_truncated_garbage_and_trailing_data() {
        assert!(decode_txset_transport(TxSetCodec::Zstd, &[]).is_err());
        assert!(decode_txset_transport(TxSetCodec::Zstd, b"not zstd").is_err());

        let encoded = zstd::bulk::compress(&vec![0x33; 4096], 1).unwrap();
        assert!(decode_txset_transport(TxSetCodec::Zstd, &encoded[..encoded.len() - 1]).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_txset_transport(TxSetCodec::Zstd, &trailing).is_err());
    }

    #[test]
    fn zstd_decoder_requires_frame_content_size() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        encoder.include_contentsize(false).unwrap();
        encoder.write_all(&vec![0x44; 4096]).unwrap();
        let encoded = encoder.finish().unwrap();
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&encoded).unwrap(),
            None
        );
        assert!(matches!(
            decode_txset_transport(TxSetCodec::Zstd, &encoded),
            Err(TxSetTransportDecodeError::Invalid(message))
                if message.contains("omits its content size")
        ));
    }

    #[test]
    fn zstd_decoder_rejects_decompression_bomb_before_decoding() {
        let oversized = vec![0u8; TXSET_MAX_WIRE_SIZE + 1];
        let encoded = zstd::bulk::compress(&oversized, 1).unwrap();
        assert!(encoded.len() < TXSET_MAX_WIRE_SIZE);
        assert!(matches!(
            decode_txset_transport(TxSetCodec::Zstd, &encoded),
            Err(TxSetTransportDecodeError::Invalid(message))
                if message.contains("exceeds")
        ));
    }

    #[test]
    fn zstd_decoder_cleanly_rejects_unknown_dictionary_id() {
        let samples: Vec<Vec<u8>> = (0..128)
            .map(|sample| {
                (0..512)
                    .map(|index| ((sample * 13 + index / 8) % 251) as u8)
                    .collect()
            })
            .collect();
        let dictionary = zstd::dict::from_samples(&samples, 4096).unwrap();
        let expected = samples.concat();
        let mut compressor = zstd::bulk::Compressor::with_dictionary(1, &dictionary).unwrap();
        let encoded = compressor.compress(&expected).unwrap();
        let dictionary_id = zstd::zstd_safe::get_dict_id_from_frame(&encoded)
            .expect("trained dictionary must carry an ID")
            .get();

        assert_eq!(
            decode_txset_transport(TxSetCodec::Zstd, &encoded),
            Err(TxSetTransportDecodeError::UnknownDictionary(dictionary_id))
        );
    }

    #[test]
    fn transport_input_bounds_are_enforced_for_both_codecs() {
        assert!(encode_txset_transport(vec![], true).is_err());
        assert!(encode_txset_transport(vec![0; TXSET_MAX_WIRE_SIZE + 1], true).is_err());
        assert!(decode_txset_transport(TxSetCodec::Raw, &[]).is_err());
        assert!(
            decode_txset_transport(TxSetCodec::Raw, &vec![0; TXSET_MAX_WIRE_SIZE + 1]).is_err()
        );
    }

    /// The bound is inclusive: a set of exactly the maximum wire size is a
    /// legal TX set and must survive the round trip, or the largest sets the
    /// IPC layer can carry become undisseminatable.
    #[test]
    fn transport_accepts_a_payload_of_exactly_the_maximum_wire_size() {
        let at_limit = data(TXSET_MAX_WIRE_SIZE);
        let transport = encode_txset_transport(at_limit.clone(), true).unwrap();
        assert_eq!(
            decode_txset_transport(transport.codec, &transport.data).unwrap(),
            at_limit
        );

        // Raw transport at the limit too, since compression may decline it.
        let raw = encode_txset_transport(at_limit, false).unwrap();
        assert_eq!(raw.codec, TxSetCodec::Raw);
        assert_eq!(
            decode_txset_transport(raw.codec, &raw.data).unwrap().len(),
            TXSET_MAX_WIRE_SIZE
        );
    }

    /// The codec is part of accumulator compatibility, so shreds carrying two
    /// different transport encodings of the same content hash must be rejected
    /// as a conflict rather than blended into an undecodable payload — and the
    /// rejection must not poison the hash for the stream that follows.
    #[test]
    fn mixed_codec_shreds_for_one_hash_conflict_without_poisoning() {
        let plain = data(96 * 1024 + 11);
        let hash = [0x5c; 32];
        let config = TxSetShardConfig::default();
        let executor = TxSetCodingExecutor::new(1).unwrap();

        let compressed = encode_txset_transport(plain.clone(), true).unwrap();
        assert_eq!(compressed.codec, TxSetCodec::Zstd);
        let zstd_shreds = make_txset_shards_parallel_with_codec(
            hash,
            &compressed.data,
            TxSetCodec::Zstd,
            15,
            config,
            &executor,
        )
        .unwrap();
        let raw_shreds = make_txset_shards_parallel_with_codec(
            hash,
            &plain,
            TxSetCodec::Raw,
            15,
            config,
            &executor,
        )
        .unwrap();

        let mut accumulator = TxSetShardAccumulator::new(&zstd_shreds[0]);
        assert!(accumulator.insert(&zstd_shreds[0]).unwrap());
        // Same hash, same index, different transport encoding.
        assert!(accumulator.insert(&raw_shreds[0]).is_err());

        // A fresh accumulator for either encoding still completes cleanly.
        let mut recovered = TxSetShardAccumulator::new(&raw_shreds[0]);
        for shred in raw_shreds.iter().filter(|shred| shred.is_original()) {
            recovered.insert(shred).unwrap();
        }
        let reconstruction = recovered.reconstruct().unwrap().unwrap();
        assert_eq!(
            decode_txset_transport(TxSetCodec::Raw, &reconstruction.data).unwrap(),
            plain
        );
    }

    #[test]
    fn compressed_transport_survives_recovery_shards_before_decompression() {
        let expected: Vec<_> = (0..256 * 1024 + 17)
            .map(|index| ((index / 32) % 19) as u8)
            .collect();
        let transport = encode_txset_transport(expected.clone(), true).unwrap();
        assert_eq!(transport.codec, TxSetCodec::Zstd);
        let executor = TxSetCodingExecutor::new(4).unwrap();
        let all = make_txset_shards_parallel_with_codec(
            [0x90; 32],
            &transport.data,
            transport.codec,
            15,
            TxSetShardConfig::default(),
            &executor,
        )
        .unwrap();
        let original_count = all[0].original_shards;
        let mut accumulator = TxSetShardAccumulator::new(&all[0]);
        for shard in all
            .iter()
            .filter(|shard| shard.shard_index != 0)
            .take(original_count)
        {
            accumulator.insert(shard).unwrap();
        }
        let reconstructed = accumulator
            .reconstruct_parallel(&executor)
            .unwrap()
            .unwrap();
        assert!(reconstructed.used_recovery);
        assert_eq!(reconstructed.data, transport.data);
        assert_eq!(
            decode_txset_transport(transport.codec, &reconstructed.data).unwrap(),
            expected
        );
    }

    #[test]
    fn default_plan_targets_two_shreds_per_peer() {
        for peer_count in [1, 2, 3, 15, 64, 200] {
            let plan = plan_txset_shards(10 * 1024 * 1024, peer_count, TxSetShardConfig::default())
                .unwrap();
            assert_eq!(plan.original_shards % 2, 0);
            assert!(plan.total_shards() <= TXSET_MAX_TOTAL_SHARDS);
            assert!(
                plan.total_shards()
                    <= (peer_count * TXSET_TARGET_SHARDS_PER_PEER).clamp(3, TXSET_MAX_TOTAL_SHARDS)
            );
        }
    }

    #[test]
    fn tiny_txsets_are_not_padded_to_target_shred_size() {
        let data_len = 44;
        let peer_count = 15;
        let plan = plan_txset_shards(data_len, peer_count, TxSetShardConfig::default()).unwrap();
        assert_eq!(plan.original_shards, 2);
        assert_eq!(plan.recovery_shards, 1);
        assert_eq!(plan.shard_size, 22);

        let coded_wire = plan.total_shards() * (TXSET_SHARD_HEADER_LEN + plan.shard_size + 4);
        let eager_full_wire = peer_count * (data_len + 8);
        assert!(coded_wire < eager_full_wire);
    }

    #[test]
    fn plan_rejects_invalid_inputs() {
        let config = TxSetShardConfig::default();
        assert!(plan_txset_shards(0, 1, config).is_err());
        assert!(plan_txset_shards(TXSET_MAX_WIRE_SIZE + 1, 1, config).is_err());
        assert!(plan_txset_shards(1, 0, config).is_err());
        assert!(plan_txset_shards(
            1,
            1,
            TxSetShardConfig {
                target_shard_size: 0,
                ..config
            }
        )
        .is_err());
        assert!(plan_txset_shards(
            1,
            1,
            TxSetShardConfig {
                recovery_factor_percent: 0,
                ..config
            }
        )
        .is_err());
        assert!(plan_txset_shards(
            1,
            1,
            TxSetShardConfig {
                initial_ttl: 5,
                ..config
            }
        )
        .is_err());
        assert!(plan_txset_shards(
            1,
            1,
            TxSetShardConfig {
                target_shard_size: usize::MAX - 1,
                ..config
            }
        )
        .is_err());
    }

    #[test]
    fn wire_round_trip_preserves_every_field() {
        for shard in shards(8193, 7) {
            for branch in [
                shard.clone(),
                shard.with_branch(1, TXSET_MAX_SHARD_BRANCHING_FACTOR),
            ] {
                assert_eq!(
                    TxSetShardMessage::decode(&branch.encode().unwrap()).unwrap(),
                    branch
                );
            }
        }
    }

    #[test]
    fn wire_decoder_rejects_malformed_headers_and_lengths() {
        let encoded = shards(4096, 3)[0].encode().unwrap();
        assert!(TxSetShardMessage::decode(&encoded[..TXSET_SHARD_HEADER_LEN - 1]).is_err());

        let mut wrong_version = encoded.clone();
        wrong_version[0] += 1;
        assert!(TxSetShardMessage::decode(&wrong_version).is_err());

        let mut bad_index = encoded.clone();
        bad_index[37..39].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(TxSetShardMessage::decode(&bad_index).is_err());

        let mut bad_payload_len = encoded.clone();
        bad_payload_len[55..59].copy_from_slice(&1u32.to_be_bytes());
        assert!(TxSetShardMessage::decode(&bad_payload_len).is_err());

        let mut bad_branch = encoded.clone();
        bad_branch[53] = 2;
        bad_branch[54] = 2;
        assert!(TxSetShardMessage::decode(&bad_branch).is_err());

        let mut unknown_codec = encoded.clone();
        unknown_codec[51] = 0xff;
        assert_eq!(
            TxSetShardMessage::decode(&unknown_codec),
            Err(TxSetShardDecodeError::UnsupportedCodec(0xff))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(TxSetShardMessage::decode(&trailing).is_err());
    }

    #[test]
    fn all_original_shreds_reconstruct_exact_bytes() {
        for len in [1, 1023, 1024, 1025, 64 * 1024 + 3, 2 * 1024 * 1024] {
            let expected = data(len);
            let all =
                make_txset_shards([0x11; 32], &expected, 15, TxSetShardConfig::default()).unwrap();
            let mut accumulator = TxSetShardAccumulator::new(&all[0]);
            for shard in all.iter().filter(|shard| shard.is_original()) {
                assert!(accumulator.insert(shard).unwrap());
            }
            assert_eq!(
                accumulator.reconstruct().unwrap().unwrap(),
                TxSetReconstruction {
                    data: expected,
                    used_recovery: false
                }
            );
        }
    }

    #[test]
    fn recovery_shreds_replace_every_supported_loss_count() {
        let expected = data(128 * 1024 + 17);
        let all =
            make_txset_shards([0x22; 32], &expected, 15, TxSetShardConfig::default()).unwrap();
        let original_count = all[0].original_shards;
        let recovery_count = all[0].recovery_shards;

        for lost in 1..=recovery_count {
            let mut accumulator = TxSetShardAccumulator::new(&all[0]);
            for shard in all
                .iter()
                .filter(|shard| shard.shard_index >= lost)
                .take(original_count)
            {
                assert!(accumulator.insert(shard).unwrap());
            }
            assert_eq!(
                accumulator.reconstruct().unwrap().unwrap(),
                TxSetReconstruction {
                    data: expected.clone(),
                    used_recovery: true
                },
                "failed with {lost} missing originals"
            );
        }
    }

    #[test]
    fn insufficient_duplicate_and_conflicting_shreds_are_handled() {
        let all = shards(32 * 1024, 8);
        let original_count = all[0].original_shards;
        let mut accumulator = TxSetShardAccumulator::new(&all[0]);
        for shard in all.iter().take(original_count - 1) {
            assert!(accumulator.insert(shard).unwrap());
        }
        assert!(accumulator.reconstruct().unwrap().is_none());
        assert!(!accumulator.insert(&all[0]).unwrap());

        let mut conflicting = all[0].clone();
        conflicting.payload[0] ^= 1;
        assert!(accumulator.insert(&conflicting).is_err());

        let mut incompatible = all[original_count].clone();
        incompatible.original_len -= 1;
        assert!(accumulator.insert(&incompatible).is_err());

        let mut incompatible_codec = all[original_count].clone();
        incompatible_codec.codec = TxSetCodec::Zstd;
        assert!(accumulator.insert(&incompatible_codec).is_err());
    }

    #[test]
    fn assignments_are_complete_balanced_and_unique() {
        for (shred_count, peer_count) in [(1, 1), (3, 2), (10, 3), (30, 15), (255, 64)] {
            let assignments = assign_shards_to_peer_offsets(shred_count, peer_count);
            let mut assigned: Vec<_> = assignments.iter().flatten().copied().collect();
            assigned.sort_unstable();
            assert_eq!(assigned, (0..shred_count).collect::<Vec<_>>());
            let min = assignments.iter().map(Vec::len).min().unwrap();
            let max = assignments.iter().map(Vec::len).max().unwrap();
            assert!(max - min <= 1);
        }
        assert!(assign_shards_to_peer_offsets(10, 0).is_empty());
    }

    #[test]
    fn two_root_branching_is_balanced_and_has_no_duplicate_relay_edges() {
        for (shred_count, peer_count) in [(1, 1), (3, 2), (10, 3), (30, 15), (255, 64)] {
            let branch_count = TXSET_MAX_SHARD_BRANCHING_FACTOR.min(peer_count);
            let assignments = assign_shard_branches_to_peer_offsets(
                shred_count,
                peer_count,
                TXSET_MAX_SHARD_BRANCHING_FACTOR,
            );
            let min = assignments.iter().map(Vec::len).min().unwrap();
            let max = assignments.iter().map(Vec::len).max().unwrap();
            assert!(max - min <= 1);

            for shard_index in 0..shred_count {
                let roots: Vec<_> = assignments
                    .iter()
                    .enumerate()
                    .flat_map(|(peer, entries)| {
                        entries.iter().filter_map(move |(shard, branch)| {
                            (*shard == shard_index).then_some((peer, *branch))
                        })
                    })
                    .collect();
                assert_eq!(roots.len(), branch_count);
                assert_eq!(
                    roots
                        .iter()
                        .map(|(peer, _)| *peer)
                        .collect::<HashSet<_>>()
                        .len(),
                    branch_count
                );

                let mut deliveries: HashMap<usize, usize> =
                    roots.iter().map(|(peer, _)| (*peer, 1)).collect();
                for (_, branch) in roots {
                    for target in
                        relay_target_peer_offsets(peer_count, shard_index, branch, branch_count)
                            .unwrap()
                    {
                        *deliveries.entry(target).or_default() += 1;
                    }
                }
                assert_eq!(deliveries.len(), peer_count);
                assert!(deliveries.values().all(|count| *count == 1));
            }
        }
    }

    #[test]
    fn leader_bandwidth_is_bounded_with_two_roots() {
        let data_len = 10 * 1024 * 1024;
        for peer_count in [15, 64] {
            let all = shards(data_len, peer_count);
            let one_copy_wire_bytes: usize = all
                .iter()
                .map(|shard| TXSET_SHARD_HEADER_LEN + shard.payload.len() + 4)
                .sum();
            let shred_wire_bytes =
                one_copy_wire_bytes * TXSET_MAX_SHARD_BRANCHING_FACTOR.min(peer_count);
            let full_push_wire_bytes = peer_count * (data_len + 4 + 4);
            assert!(shred_wire_bytes < full_push_wire_bytes);
            // Two roots times 50% recovery data, plus small headers/padding.
            assert!(shred_wire_bytes < data_len * 16 / 5);
        }
    }

    #[test]
    fn fully_connected_forwarding_reaches_every_receiver() {
        let expected = data(2 * 1024 * 1024 + 9);
        let peer_count = 15;
        let all = make_txset_shards(
            [0x33; 32],
            &expected,
            peer_count,
            TxSetShardConfig::default(),
        )
        .unwrap();
        for branch_count in 1..=TXSET_MAX_SHARD_BRANCHING_FACTOR {
            let assignments =
                assign_shard_branches_to_peer_offsets(all.len(), peer_count, branch_count);

            // Lose one branch root completely. With one root, recovery covers
            // its balanced subset; with two, the other root retains every
            // shred.
            for receiver in 0..peer_count {
                let failed_root = (receiver + 1) % peer_count;
                let mut accumulator = TxSetShardAccumulator::new(&all[0]);
                for (root, entries) in assignments.iter().enumerate() {
                    if root == failed_root {
                        continue;
                    }
                    for (offset, _) in entries {
                        accumulator.insert(&all[*offset]).unwrap();
                    }
                }
                assert_eq!(accumulator.reconstruct().unwrap().unwrap().data, expected);
            }
        }
    }

    #[test]
    fn parallel_encode_and_recovery_decode_match_serial_bytes() {
        let expected = data(5 * 1024 * 1024 + 17);
        let config = TxSetShardConfig::default();
        let serial = make_txset_shards([0x44; 32], &expected, 15, config).unwrap();
        for parallelism in [2, 4, 8] {
            let executor = TxSetCodingExecutor::new(parallelism).unwrap();
            assert_eq!(executor.max_parallelism(), parallelism);
            assert!(
                executor
                    .ranges(serial[0].shard_size, serial[0].original_shards)
                    .len()
                    <= parallelism
            );
            let parallel =
                make_txset_shards_parallel([0x44; 32], &expected, 15, config, &executor).unwrap();
            assert_eq!(parallel, serial);

            let original_count = parallel[0].original_shards;
            let mut accumulator = TxSetShardAccumulator::new(&parallel[0]);
            for shred in parallel
                .iter()
                .filter(|shred| shred.shard_index != 0)
                .take(original_count)
            {
                accumulator.insert(shred).unwrap();
            }
            assert_eq!(
                accumulator
                    .reconstruct_parallel(&executor)
                    .unwrap()
                    .unwrap()
                    .data,
                expected
            );
        }
        assert!(TxSetCodingExecutor::new(0).is_err());
        assert!(TxSetCodingExecutor::new(TXSET_MAX_CODING_PARALLELISM + 1).is_err());
    }

    #[test]
    fn wire_validation_rejects_adversarial_parameter_combinations() {
        let template = shards(4096, 3)[0].clone();
        assert!(template.encode().is_ok());

        let mut odd_originals = template.clone();
        odd_originals.original_shards = 3;
        assert!(odd_originals.encode().is_err());

        let mut one_original = template.clone();
        one_original.original_shards = 1;
        assert!(one_original.encode().is_err());

        let mut no_recovery = template.clone();
        no_recovery.recovery_shards = 0;
        assert!(no_recovery.encode().is_err());

        let mut too_many_total = template.clone();
        too_many_total.recovery_shards = TXSET_MAX_TOTAL_SHARDS;
        assert!(too_many_total.encode().is_err());

        let mut odd_shard_size = template.clone();
        odd_shard_size.shard_size -= 1;
        odd_shard_size.payload.pop();
        assert!(odd_shard_size.encode().is_err());

        let mut payload_length_mismatch = template.clone();
        payload_length_mismatch.payload.pop();
        assert!(payload_length_mismatch.encode().is_err());

        let mut zero_original_len = template.clone();
        zero_original_len.original_len = 0;
        assert!(zero_original_len.encode().is_err());

        let mut oversized_original_len = template.clone();
        oversized_original_len.original_len = TXSET_MAX_WIRE_SIZE + 1;
        assert!(oversized_original_len.encode().is_err());

        // Declared TX-set length that the declared shreds cannot contain.
        let mut uncontainable = template.clone();
        uncontainable.original_len = uncontainable.original_shards * uncontainable.shard_size + 1;
        assert!(uncontainable.encode().is_err());

        // Padded size far beyond an honest plan: caps the memory a malicious
        // first shred can commit an accumulator to.
        let mut oversized_padding = template.clone();
        oversized_padding.original_shards = 254;
        oversized_padding.recovery_shards = 1;
        oversized_padding.shard_size = 128 * 1024;
        oversized_padding.payload = vec![0u8; 128 * 1024];
        oversized_padding.original_len = TXSET_MAX_WIRE_SIZE;
        assert!(oversized_padding.encode().is_err());

        let mut excessive_ttl = template.clone();
        excessive_ttl.ttl = 2;
        assert!(excessive_ttl.encode().is_err());
    }

    #[test]
    fn recovery_only_shreds_reconstruct_all_originals() {
        let expected = data(96 * 1024 + 5);
        let config = TxSetShardConfig {
            recovery_factor_percent: 100,
            ..TxSetShardConfig::default()
        };
        let all = make_txset_shards([0x77; 32], &expected, 15, config).unwrap();
        let original_count = all[0].original_shards;
        assert_eq!(all[0].recovery_shards, original_count);

        // The decoder must restore every original from recovery shreds alone.
        let mut accumulator = TxSetShardAccumulator::new(&all[0]);
        for shard in all.iter().filter(|shard| !shard.is_original()) {
            assert!(accumulator.insert(shard).unwrap());
        }
        assert!(accumulator.is_ready());
        assert_eq!(
            accumulator.reconstruct().unwrap().unwrap(),
            TxSetReconstruction {
                data: expected.clone(),
                used_recovery: true
            }
        );

        let executor = TxSetCodingExecutor::new(4).unwrap();
        assert_eq!(
            accumulator
                .reconstruct_parallel(&executor)
                .unwrap()
                .unwrap()
                .data,
            expected
        );
    }

    #[test]
    fn relay_target_offsets_reject_invalid_parameters() {
        assert!(relay_target_peer_offsets(0, 0, 0, 1).is_err());
        assert!(relay_target_peer_offsets(5, 1, 0, 0).is_err());
        assert!(relay_target_peer_offsets(5, 1, 2, 2).is_err());
        assert!(relay_target_peer_offsets(2, 1, 0, 3).is_err());
    }

    #[test]
    fn single_root_branching_covers_every_non_root_exactly_once() {
        for (shred_count, peer_count) in [(1, 1), (3, 2), (10, 3), (30, 15), (255, 64)] {
            let assignments = assign_shard_branches_to_peer_offsets(shred_count, peer_count, 1);
            for shard_index in 0..shred_count {
                let root = shard_index % peer_count;
                assert!(assignments[root].contains(&(shard_index, 0)));

                let mut deliveries: HashMap<usize, usize> = HashMap::from([(root, 1)]);
                for target in relay_target_peer_offsets(peer_count, shard_index, 0, 1).unwrap() {
                    *deliveries.entry(target).or_default() += 1;
                }
                assert_eq!(deliveries.len(), peer_count);
                assert!(deliveries.values().all(|count| *count == 1));
            }
        }
    }

    #[test]
    fn plan_invariants_hold_across_sizes_and_peer_counts() {
        let config = TxSetShardConfig::default();
        for data_len in [1, 100, 1024, 65_536, 1_048_576, TXSET_MAX_WIRE_SIZE] {
            for peer_count in [1, 2, 3, 7, 15, 64, 255, 1000] {
                let plan = plan_txset_shards(data_len, peer_count, config).unwrap();
                assert!(plan.original_shards >= 2);
                assert!(plan.original_shards.is_multiple_of(2));
                assert!(plan.recovery_shards >= 1);
                assert!(plan.total_shards() <= TXSET_MAX_TOTAL_SHARDS);
                assert!(plan.shard_size >= 2);
                assert!(plan.shard_size.is_multiple_of(2));
                assert!(plan.original_shards * plan.shard_size >= data_len);

                // Every planned shred passes wire validation end to end.
                let message = TxSetShardMessage {
                    hash: [0x88; 32],
                    original_shards: plan.original_shards,
                    recovery_shards: plan.recovery_shards,
                    shard_index: plan.total_shards() - 1,
                    shard_size: plan.shard_size,
                    original_len: data_len,
                    codec: TxSetCodec::Raw,
                    ttl: config.initial_ttl,
                    branch_index: 0,
                    branch_count: 1,
                    payload: vec![0u8; plan.shard_size],
                };
                assert_eq!(
                    TxSetShardMessage::decode(&message.encode().unwrap()).unwrap(),
                    message
                );
            }
        }
    }

    /// The production operating point: a large validator set on links where the
    /// nominator's uplink is the binding constraint. Pins the property that
    /// makes the branch factor 1: the nominator sends no more than any single
    /// relay does, so dissemination has no hotspot.
    #[test]
    fn deployment_scale_plan_leaves_no_bandwidth_hotspot() {
        let peer_count = 89;
        let set_len = 5_000_000;
        let plan = plan_txset_shards(set_len, peer_count, TxSetShardConfig::default()).unwrap();
        let coded_bytes = plan.total_shards() * plan.shard_size;

        // Coding overhead stays near the configured recovery factor.
        assert!(coded_bytes >= set_len);
        assert!(coded_bytes <= set_len * 8 / 5);

        // Shreds stay well clear of both hard caps.
        assert!(plan.total_shards() <= TXSET_MAX_TOTAL_SHARDS);
        assert!(plan.shard_size + TXSET_SHARD_HEADER_LEN < 16 * 1024 * 1024);

        let branches = TXSET_SHARD_BRANCHING_FACTOR.min(peer_count);
        let leader_egress = branches * coded_bytes;
        // Each peer roots total/peers shreds and relays each to peer_count-b
        // others, so its egress is coded_bytes*(peer_count-b)/peer_count.
        let relay_egress = coded_bytes * (peer_count - branches) / peer_count;
        assert!(
            leader_egress <= relay_egress * 11 / 10,
            "leader egress {leader_egress} exceeds a relay's {relay_egress} by more than 10%: \
             raising the branch factor rebuilds the nominator bottleneck"
        );

        // And it must beat sending the whole body to everyone by a wide margin.
        assert!(leader_egress * 50 < peer_count * set_len);

        // A dead root costs only the shreds it roots; recovery covers many.
        let shreds_per_root = plan.total_shards().div_ceil(peer_count);
        assert!(plan.recovery_shards / shreds_per_root >= 10);
    }

    #[test]
    fn coding_ranges_partition_shard_columns_evenly() {
        for parallelism in [1, 2, 3, 8] {
            let executor = TxSetCodingExecutor::new(parallelism).unwrap();
            for (shard_size, original_shards) in [(2, 2), (1024, 4), (4096, 254), (1_000_000, 2)] {
                let ranges = executor.ranges(shard_size, original_shards);
                assert!(!ranges.is_empty());
                assert!(ranges.len() <= parallelism);
                let mut cursor = 0;
                for (start, end) in ranges {
                    assert_eq!(start, cursor);
                    assert!(end > start);
                    assert!(start.is_multiple_of(2));
                    assert!(end.is_multiple_of(2));
                    cursor = end;
                }
                assert_eq!(cursor, shard_size);
            }
        }
    }

    #[test]
    #[ignore = "manual TX-set coding throughput baseline"]
    fn benchmark_txset_coding_throughput() {
        let expected = data(10 * 1024 * 1024);
        let config = TxSetShardConfig::default();
        let iterations = 10;

        for parallelism in [1, 2, 4, 8] {
            let executor = TxSetCodingExecutor::new(parallelism).unwrap();
            let encode_start = Instant::now();
            let mut last = Vec::new();
            for _ in 0..iterations {
                last = make_txset_shards_parallel([0x55; 32], &expected, 15, config, &executor)
                    .unwrap();
            }
            let encode_elapsed = encode_start.elapsed();

            let original_count = last[0].original_shards;
            let decode_start = Instant::now();
            for _ in 0..iterations {
                let mut accumulator = TxSetShardAccumulator::new(&last[0]);
                for shard in last
                    .iter()
                    .filter(|shard| shard.shard_index != 0)
                    .take(original_count)
                {
                    accumulator.insert(shard).unwrap();
                }
                assert_eq!(
                    accumulator
                        .reconstruct_parallel(&executor)
                        .unwrap()
                        .unwrap()
                        .data,
                    expected
                );
            }
            let decode_elapsed = decode_start.elapsed();

            let mib = (expected.len() * iterations) as f64 / (1024.0 * 1024.0);
            let one_root_bytes: usize = last
                .iter()
                .map(|shard| TXSET_SHARD_HEADER_LEN + shard.payload.len() + 4)
                .sum();
            let leader_bytes = one_root_bytes * TXSET_SHARD_BRANCHING_FACTOR;
            let full_source_bytes = 15 * (expected.len() + 8);
            eprintln!(
                "txset-shreds: clusters={parallelism}, encode={:.1} MiB/s ({:?}/set), recovery-decode={:.1} MiB/s ({:?}/set), leader-wire={} bytes vs eager-full={} bytes ({:.1}% reduction)",
                mib / encode_elapsed.as_secs_f64(),
                encode_elapsed / iterations as u32,
                mib / decode_elapsed.as_secs_f64(),
                decode_elapsed / iterations as u32,
                leader_bytes,
                full_source_bytes,
                100.0 * (1.0 - leader_bytes as f64 / full_source_bytes as f64)
            );
            assert!(encode_elapsed < Duration::from_secs(60));
            assert!(decode_elapsed < Duration::from_secs(60));
        }
    }
}
