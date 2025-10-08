// Copyright 2025 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

// SHA-256 hashing using sha2 crate
// Returns hash directly into output buffer to avoid copies
#[no_mangle]
pub unsafe extern "C" fn compute_sha256_rust(
    message_ptr: *const u8,
    message_len: usize,
    output_ptr: *mut u8,
) {
    let _span = tracy_span!("compute_sha256_rust");

    // Create slice from raw pointer
    let message = std::slice::from_raw_parts(message_ptr, message_len);

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();

    // Copy result directly to output buffer (32 bytes)
    std::ptr::copy_nonoverlapping(result.as_ptr(), output_ptr, 32);
}

// SHA-256 incremental hashing context
#[repr(C)]
pub struct Sha256Context {
    hasher: *mut Sha256,
}

#[no_mangle]
pub extern "C" fn sha256_init_rust() -> Sha256Context {
    let _span = tracy_span!("sha256_init_rust");
    let hasher = Box::new(Sha256::new());
    Sha256Context {
        hasher: Box::into_raw(hasher),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sha256_update_rust(
    ctx: *mut Sha256Context,
    data_ptr: *const u8,
    data_len: usize,
) {
    let _span = tracy_span!("sha256_update_rust");
    let ctx = &mut *ctx;
    let hasher = &mut *ctx.hasher;
    let data = std::slice::from_raw_parts(data_ptr, data_len);
    hasher.update(data);
}

#[no_mangle]
pub unsafe extern "C" fn sha256_final_rust(
    ctx: *mut Sha256Context,
    output_ptr: *mut u8,
) {
    let _span = tracy_span!("sha256_final_rust");
    let ctx = &mut *ctx;
    let hasher = Box::from_raw(ctx.hasher);
    let result = hasher.finalize();
    std::ptr::copy_nonoverlapping(result.as_ptr(), output_ptr, 32);
}

// HMAC-SHA256
#[no_mangle]
pub unsafe extern "C" fn compute_hmac_sha256_rust(
    key_ptr: *const u8,
    key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    output_ptr: *mut u8,
) -> bool {
    let _span = tracy_span!("compute_hmac_sha256_rust");

    let key = std::slice::from_raw_parts(key_ptr, key_len);
    let message = std::slice::from_raw_parts(message_ptr, message_len);

    // Create HMAC instance - return false if key is invalid
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(message);
    let result = mac.finalize();
    let code = result.into_bytes();

    std::ptr::copy_nonoverlapping(code.as_ptr(), output_ptr, 32);
    true
}

// HMAC-SHA256 verification
#[no_mangle]
pub unsafe extern "C" fn verify_hmac_sha256_rust(
    key_ptr: *const u8,
    key_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    mac_ptr: *const u8,
) -> bool {
    let _span = tracy_span!("verify_hmac_sha256_rust");

    let key = std::slice::from_raw_parts(key_ptr, key_len);
    let message = std::slice::from_raw_parts(message_ptr, message_len);
    let expected_mac = std::slice::from_raw_parts(mac_ptr, 32);

    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(message);
    mac.verify_slice(expected_mac).is_ok()
}

