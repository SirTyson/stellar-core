//! Reed-Solomon erasure coding for sharded TX set dispersion.
//!
//! Direct leader flooding (docs/direct-leader-flooding.md): instead of the
//! round-1 leader shipping the whole TX set body to every peer (O(N) upload on
//! one node), it erasure-codes the body into `data + parity` equal-length
//! shards and sends one *primary* shard to each peer. Every node then relays
//! its primary shard to the rest of the mesh (a deterministic depth-2 spanning
//! tree rooted at the leader), so each node ends up holding all shards while
//! uploading only ~one body's worth. Any `data` shards reconstruct the body, so
//! up to `parity` down / Byzantine / slow nodes are tolerated.
//!
//! Encoding is the compute-heavy, once-per-ledger, leader-side step; it is
//! parallelized across shard byte-columns with rayon (parity byte at column c
//! depends only on the data bytes at column c, so columns are independent).

use rayon::prelude::*;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Erasure-coding parameters: `data` shards carry the body, `parity` shards add
/// redundancy. Total shards = `data + parity`; any `data` of them reconstruct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShredParams {
    pub data: usize,
    pub parity: usize,
}

impl ShredParams {
    pub fn total(&self) -> usize {
        self.data + self.parity
    }
}

/// Choose shard parameters for an `num_nodes`-node dense mesh: one primary shard
/// per node (total = num_nodes), with `parity = f = floor((N-1)/3)` for BFT
/// redundancy and `data = total - parity`. Any `data` shards reconstruct, so up
/// to `f` nodes can be down / withholding / Byzantine.
///
/// Reed-Solomon over GF(2^8) requires `total <= 256`; larger meshes are clamped
/// (still correct, just proportionally less parity headroom per node).
pub fn params_for(num_nodes: usize) -> ShredParams {
    let total = num_nodes.clamp(2, 256);
    let parity = ((total - 1) / 3).max(1);
    ShredParams {
        data: total - parity,
        parity,
    }
}

/// Erasure-code `body` into `params.total()` equal-length shards
/// (`params.data` data shards followed by `params.parity` parity shards).
///
/// The caller must remember `body.len()` (the shards are zero-padded to an equal
/// length) and pass it to [`reconstruct`] to trim the padding.
///
/// Parity is computed in parallel across column ranges via rayon.
pub fn encode(body: &[u8], params: ShredParams) -> Result<Vec<Vec<u8>>, String> {
    let ShredParams { data, parity } = params;
    if data == 0 {
        return Err("erasure encode: zero data shards".to_string());
    }
    // Equal shard length = ceil(body / data), at least 1 byte.
    let shard_len = body.len().div_ceil(data).max(1);

    // Data shards: split the body into `data` contiguous, zero-padded chunks.
    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data + parity);
    for i in 0..data {
        let start = i * shard_len;
        let end = (start + shard_len).min(body.len());
        let mut s = vec![0u8; shard_len];
        if start < body.len() {
            s[..end - start].copy_from_slice(&body[start..end]);
        }
        shards.push(s);
    }

    let rs = ReedSolomon::new(data, parity).map_err(|e| format!("RS::new: {e}"))?;

    // Parallelize parity computation over disjoint column ranges. `rs` and the
    // data shards are shared immutably; each range owns small sub-buffers, so
    // there is no cross-thread aliasing.
    let threads = rayon::current_num_threads().max(1);
    let col_chunk = shard_len.div_ceil(threads).max(1);
    let starts: Vec<usize> = (0..shard_len).step_by(col_chunk).collect();

    let computed: Result<Vec<(usize, Vec<Vec<u8>>)>, String> = starts
        .into_par_iter()
        .map(|c0| {
            let c1 = (c0 + col_chunk).min(shard_len);
            let width = c1 - c0;
            let mut sub: Vec<Vec<u8>> = Vec::with_capacity(data + parity);
            for i in 0..data {
                sub.push(shards[i][c0..c1].to_vec());
            }
            for _ in 0..parity {
                sub.push(vec![0u8; width]);
            }
            rs.encode(&mut sub).map_err(|e| format!("RS encode: {e}"))?;
            // Keep only the parity rows for this column range.
            Ok((c0, sub.split_off(data)))
        })
        .collect();

    // Stitch parity column ranges back into full-length parity shards.
    let mut parity_shards: Vec<Vec<u8>> = (0..parity).map(|_| vec![0u8; shard_len]).collect();
    for (c0, chunk_parity) in computed? {
        let width = chunk_parity.first().map(|s| s.len()).unwrap_or(0);
        for (j, prow) in chunk_parity.into_iter().enumerate() {
            parity_shards[j][c0..c0 + width].copy_from_slice(&prow);
        }
    }

    shards.extend(parity_shards);
    Ok(shards)
}

/// Reconstruct the original body from a partial set of shards.
///
/// `received[i]` is `Some(bytes)` if shard `i` (0..total) arrived, else `None`.
/// Succeeds when at least `params.data` shards are present. `total_len` is the
/// original body length, used to trim the zero padding.
pub fn reconstruct(
    mut received: Vec<Option<Vec<u8>>>,
    params: ShredParams,
    total_len: usize,
) -> Result<Vec<u8>, String> {
    let ShredParams { data, parity } = params;
    if received.len() != data + parity {
        return Err(format!(
            "erasure reconstruct: expected {} slots, got {}",
            data + parity,
            received.len()
        ));
    }
    let present = received.iter().filter(|s| s.is_some()).count();
    if present < data {
        return Err(format!(
            "erasure reconstruct: only {present} of {data} required shards present"
        ));
    }

    let rs = ReedSolomon::new(data, parity).map_err(|e| format!("RS::new: {e}"))?;
    rs.reconstruct_data(&mut received)
        .map_err(|e| format!("RS reconstruct: {e}"))?;

    let mut body = Vec::with_capacity(total_len);
    for shard in received.iter().take(data) {
        let s = shard
            .as_ref()
            .ok_or_else(|| "erasure reconstruct: missing data shard after recovery".to_string())?;
        body.extend_from_slice(s);
    }
    body.truncate(total_len);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params_for_bft() {
        // f = floor((N-1)/3); data = N - f.
        assert_eq!(params_for(4), ShredParams { data: 3, parity: 1 });
        assert_eq!(params_for(7), ShredParams { data: 5, parity: 2 });
        assert_eq!(params_for(15), ShredParams { data: 11, parity: 4 });
        // Tiny/degenerate meshes still yield >=1 of each.
        assert_eq!(params_for(2), ShredParams { data: 1, parity: 1 });
        assert_eq!(params_for(0), ShredParams { data: 1, parity: 1 });
        // Clamp at the GF(2^8) limit.
        assert!(params_for(10_000).total() <= 256);
    }

    #[test]
    fn test_roundtrip_all_shards() {
        let params = params_for(15);
        let body: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let shards = encode(&body, params).unwrap();
        assert_eq!(shards.len(), params.total());
        // All shards equal length.
        let len = shards[0].len();
        assert!(shards.iter().all(|s| s.len() == len));

        let received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let out = reconstruct(received, params, body.len()).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn test_reconstruct_from_exactly_data_shards() {
        let params = params_for(15); // data=11, parity=4
        let body: Vec<u8> = (0..40_001u32).map(|i| (i ^ (i >> 3)) as u8).collect();
        let shards = encode(&body, params).unwrap();

        // Drop `parity` shards (the max tolerable): keep only `data` of them,
        // and drop a mix of data + parity indices to exercise real recovery.
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        // Erase indices 0, 5, 12, 14 (a mix of data and parity) = 4 = parity.
        for idx in [0usize, 5, 12, 14] {
            received[idx] = None;
        }
        assert_eq!(received.iter().filter(|s| s.is_some()).count(), params.data);
        let out = reconstruct(received, params, body.len()).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn test_reconstruct_fails_below_threshold() {
        let params = params_for(7); // data=5, parity=2
        let body: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let shards = encode(&body, params).unwrap();
        let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        // Erase parity+1 = 3 shards -> only data-1 remain -> must fail.
        for idx in [0usize, 1, 2] {
            received[idx] = None;
        }
        assert!(reconstruct(received, params, body.len()).is_err());
    }

    #[test]
    fn test_odd_sizes_and_small_bodies() {
        for &n in &[1usize, 2, 33, 257, 1000, 65_537] {
            let params = params_for(11);
            let body: Vec<u8> = (0..n as u32).map(|i| (i.wrapping_mul(2654435761)) as u8).collect();
            let shards = encode(&body, params).unwrap();
            let mut received: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            // Drop the maximum tolerable (parity) shards.
            for idx in 0..params.parity {
                received[idx] = None;
            }
            let out = reconstruct(received, params, body.len()).unwrap();
            assert_eq!(out, body, "roundtrip failed for body len {n}");
        }
    }
}
