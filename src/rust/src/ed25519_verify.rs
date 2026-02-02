// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

use ed25519_dalek::{Signature, VerifyingKey};

// Verifies an ed25519 signature using the dalek library.
// This function takes raw pointers to avoid copying data across the Rust/C++ boundary.
//
// # Safety
// The caller must ensure that:
// - `public_key_ptr` points to at least 32 bytes of readable memory
// - `signature_ptr` points to at least 64 bytes of readable memory
// - `message_ptr` points to at least `message_len` bytes of readable memory
// - All pointers remain valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn verify_ed25519_signature_dalek(
    public_key_ptr: *const u8,
    signature_ptr: *const u8,
    message_ptr: *const u8,
    message_len: usize,
) -> bool {
    let _span = tracy_span!("verify_ed25519_signature_dalek");

    // C++ caller must provide valid pointers
    let pk_bytes = &*(public_key_ptr as *const [u8; 32]);
    let sig_bytes = &*(signature_ptr as *const [u8; 64]);
    let message = std::slice::from_raw_parts(message_ptr, message_len);

    // Parse public key
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(key) => key,
        Err(_) => return false, // Invalid public key format
    };

    // Create signature (from_bytes returns the signature directly)
    let signature = Signature::from_bytes(sig_bytes);
    // Use verify_strict to reject small-order and mixed-order points, matching libsodium behavior
    verifying_key.verify_strict(message, &signature).is_ok()
}

// Batch-verifies multiple ed25519 signatures using the dalek library.
// Returns true only if ALL signatures are valid.
//
// This provides ~2x speedup over individual verification due to combined
// multi-scalar multiplication.
//
// Security: Uses verify_batch which doesn't check for weak keys. We pre-filter
// weak public keys to match verify_strict security guarantees.
//
// # Safety
// The caller must ensure that:
// - `count` is the number of signatures to verify
// - `public_keys_ptr` points to count * 32 bytes (array of 32-byte public keys)
// - `signatures_ptr` points to count * 64 bytes (array of 64-byte signatures)
// - `messages_ptr` points to an array of `count` pointers
// - `message_lens_ptr` points to an array of `count` lengths
// - Each messages_ptr[i] points to at least message_lens_ptr[i] bytes
// - All pointers remain valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn verify_ed25519_signature_batch_dalek(
    count: usize,
    public_keys_ptr: *const u8,
    signatures_ptr: *const u8,
    messages_ptr: *const *const u8,
    message_lens_ptr: *const usize,
) -> bool {
    let _span = tracy_span!("verify_ed25519_signature_batch_dalek");

    if count == 0 {
        return true;
    }

    let mut verifying_keys = Vec::with_capacity(count);
    let mut signatures = Vec::with_capacity(count);
    let mut messages: Vec<&[u8]> = Vec::with_capacity(count);

    for i in 0..count {
        let pk_bytes = &*(public_keys_ptr.add(i * 32) as *const [u8; 32]);
        let sig_bytes = &*(signatures_ptr.add(i * 64) as *const [u8; 64]);
        let msg_ptr = *messages_ptr.add(i);
        let msg_len = *message_lens_ptr.add(i);
        let message = std::slice::from_raw_parts(msg_ptr, msg_len);

        let verifying_key = match VerifyingKey::from_bytes(pk_bytes) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // Match verify_strict security: reject weak public keys
        if verifying_key.is_weak() {
            return false;
        }

        verifying_keys.push(verifying_key);
        signatures.push(Signature::from_bytes(sig_bytes));
        messages.push(message);
    }

    ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys).is_ok()
}
