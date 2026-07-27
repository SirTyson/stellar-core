//! End-to-end tests that spawn the actual stellar-overlay binary.
//!
//! These tests verify that the compiled binary works correctly,
//! catching issues that in-memory tests might miss (like main.rs wiring bugs).

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use stellar_xdr::curr::{Limits, ScpEnvelope, WriteXdr};

/// IPC message types (must match src/ipc/messages.rs)
mod ipc {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    pub const BROADCAST_SCP: u32 = 1;
    pub const SET_PEER_CONFIG: u32 = 8;
    pub const SHUTDOWN: u32 = 7;
    pub const SCP_RECEIVED: u32 = 100;
    pub const PEER_REQUESTS_SCP_STATE: u32 = 102;

    pub fn send_message(
        stream: &mut UnixStream,
        msg_type: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        let mut header = [0u8; 8];
        header[0..4].copy_from_slice(&msg_type.to_ne_bytes());
        header[4..8].copy_from_slice(&(payload.len() as u32).to_ne_bytes());
        stream.write_all(&header)?;
        if !payload.is_empty() {
            stream.write_all(payload)?;
        }
        Ok(())
    }

    pub fn recv_message(stream: &mut UnixStream) -> std::io::Result<(u32, Vec<u8>)> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;
        let msg_type = u32::from_ne_bytes(header[0..4].try_into().unwrap());
        let payload_len = u32::from_ne_bytes(header[4..8].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload)?;
        }
        Ok((msg_type, payload))
    }
}

/// Find the stellar-overlay binary
fn find_binary() -> PathBuf {
    if let Ok(path) = std::env::var("STELLAR_OVERLAY_BINARY") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }

    // The test runs from the overlay directory, so look in parent's target
    let debug = PathBuf::from("../target/debug/stellar-overlay");
    if debug.exists() {
        return debug;
    }
    let debug2 = PathBuf::from("target/debug/stellar-overlay");
    if debug2.exists() {
        return debug2;
    }
    let release = PathBuf::from("../target/release/stellar-overlay");
    if release.exists() {
        return release;
    }
    let release2 = PathBuf::from("target/release/stellar-overlay");
    if release2.exists() {
        return release2;
    }

    // Try manifest dir
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let debug = PathBuf::from(&manifest).join("../target/debug/stellar-overlay");
        if debug.exists() {
            return debug;
        }
        let release = PathBuf::from(&manifest).join("../target/release/stellar-overlay");
        if release.exists() {
            return release;
        }
    }

    panic!("stellar-overlay binary not found. Run `cargo build --release` first.");
}

/// Spawn an overlay process
fn spawn_overlay(socket_path: &str, peer_port: u16) -> Child {
    let binary = find_binary();
    let show_child_logs = std::env::var_os("STELLAR_OVERLAY_TEST_LOGS").is_some();

    if show_child_logs {
        eprintln!(
            "spawning stellar-overlay: {} --listen {} --peer-port {}",
            binary.display(),
            socket_path,
            peer_port
        );
    }

    let mut command = Command::new(binary);
    command
        .arg("--listen")
        .arg(socket_path)
        .arg("--peer-port")
        .arg(peer_port.to_string());

    if std::env::var_os("RUST_LOG").is_none() {
        command.env("RUST_LOG", "debug");
    }

    if show_child_logs {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    command.spawn().expect("Failed to spawn overlay process")
}

fn wait_for_child_exit(child: &mut Child, name: &str) -> ExitStatus {
    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if start.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{} did not exit within {:?}", name, timeout);
            }
            Err(e) => panic!("Failed waiting for {}: {}", name, e),
        }
    }
}

fn valid_scp_envelope_xdr(slot_index: u64) -> Vec<u8> {
    let mut envelope = ScpEnvelope::default();
    envelope.statement.slot_index = slot_index;
    envelope.to_xdr(Limits::none()).unwrap()
}

/// Wait for socket to be ready and return the connected stream
fn wait_for_socket(path: &str, timeout_ms: u64) -> Option<UnixStream> {
    let start = std::time::Instant::now();
    while start.elapsed().as_millis() < timeout_ms as u128 {
        if std::path::Path::new(path).exists() {
            // Try connecting
            if let Ok(stream) = UnixStream::connect(path) {
                return Some(stream);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn scp_socket_path(path: &str) -> String {
    format!("{path}.scp")
}

fn remove_ipc_sockets(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(scp_socket_path(path));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that the binary starts and accepts IPC connection
    #[test]
    fn test_binary_starts_and_accepts_connection() {
        let socket_path = format!("/tmp/e2e-test-{}.sock", std::process::id());

        // Clean up old sockets
        remove_ipc_sockets(&socket_path);

        // Spawn overlay
        let mut child = spawn_overlay(&socket_path, 11700);

        // The overlay accepts independent bulk and SCP connections.
        let mut stream = wait_for_socket(&socket_path, 5000).expect("Socket should be ready");
        let scp_stream = wait_for_socket(&scp_socket_path(&socket_path), 5000)
            .expect("SCP socket should be ready");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send shutdown
        ipc::send_message(&mut stream, ipc::SHUTDOWN, &[]).expect("Should send shutdown");
        drop(stream);
        drop(scp_stream);

        // Wait for process to exit
        let _status = wait_for_child_exit(&mut child, "overlay");
        // Process exits with 0 on shutdown

        // Cleanup
        remove_ipc_sockets(&socket_path);

        println!("✓ Binary starts and accepts IPC connection");
    }

    /// Test that SCP broadcast works through the actual binary
    #[test]
    fn test_binary_scp_broadcast() {
        let socket_path = format!("/tmp/e2e-scp-{}.sock", std::process::id());
        remove_ipc_sockets(&socket_path);

        // Spawn overlay
        let mut child = spawn_overlay(&socket_path, 11701);
        let mut stream = wait_for_socket(&socket_path, 5000).expect("Socket should be ready");
        let mut scp_stream = wait_for_socket(&scp_socket_path(&socket_path), 5000)
            .expect("SCP socket should be ready");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        scp_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send SCP broadcast (overlay should accept it even with no peers)
        let scp_envelope = valid_scp_envelope_xdr(1);
        ipc::send_message(&mut scp_stream, ipc::BROADCAST_SCP, &scp_envelope)
            .expect("Should send SCP");

        // Give it time to process
        thread::sleep(Duration::from_millis(100));

        // Shutdown
        ipc::send_message(&mut stream, ipc::SHUTDOWN, &[]).expect("Should send shutdown");
        drop(stream);
        drop(scp_stream);
        wait_for_child_exit(&mut child, "overlay");

        remove_ipc_sockets(&socket_path);

        println!("✓ Binary accepts SCP broadcast");
    }

    /// Test two overlay binaries can connect and relay SCP messages
    #[test]
    fn test_two_binaries_relay_scp() {
        let socket_a = format!("/tmp/e2e-relay-a-{}.sock", std::process::id());
        let socket_b = format!("/tmp/e2e-relay-b-{}.sock", std::process::id());
        remove_ipc_sockets(&socket_a);
        remove_ipc_sockets(&socket_b);

        // Spawn two overlays on different ports
        let mut child_a = spawn_overlay(&socket_a, 11710);
        let mut child_b = spawn_overlay(&socket_b, 11711);

        let mut stream_a = wait_for_socket(&socket_a, 5000).expect("Socket A should be ready");
        let mut stream_b = wait_for_socket(&socket_b, 5000).expect("Socket B should be ready");
        let mut scp_stream_a = wait_for_socket(&scp_socket_path(&socket_a), 5000)
            .expect("SCP socket A should be ready");
        let mut scp_stream_b = wait_for_socket(&scp_socket_path(&socket_b), 5000)
            .expect("SCP socket B should be ready");
        stream_a
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream_b
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        scp_stream_a
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        scp_stream_b
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Tell B to connect to A's peer port
        let peer_config =
            r#"{"known_peers":["127.0.0.1:11710"],"preferred_peers":[],"listen_port":11711}"#;
        ipc::send_message(&mut stream_b, ipc::SET_PEER_CONFIG, peer_config.as_bytes())
            .expect("Should send peer config");

        // Wait for connection to establish
        thread::sleep(Duration::from_millis(500));

        // When B connects to A, B asks Core for the current SCP state over the
        // bulk control channel.
        let (msg_type, _) =
            ipc::recv_message(&mut stream_b).expect("B should request SCP state from Core");
        assert_eq!(
            msg_type,
            ipc::PEER_REQUESTS_SCP_STATE,
            "B should request SCP state once when connecting to A"
        );

        // A broadcasts SCP
        let scp_envelope = valid_scp_envelope_xdr(2);

        ipc::send_message(&mut scp_stream_a, ipc::BROADCAST_SCP, &scp_envelope)
            .expect("Should send SCP from A");

        // B receives relayed envelopes over its dedicated SCP channel.
        let result = ipc::recv_message(&mut scp_stream_b)
            .map_err(|e| e.to_string())
            .and_then(|(msg_type, payload)| {
                if msg_type == ipc::SCP_RECEIVED {
                    Ok((msg_type, payload))
                } else {
                    Err(format!("unexpected message type {msg_type}"))
                }
            });

        // Shutdown both
        ipc::send_message(&mut stream_a, ipc::SHUTDOWN, &[]).ok();
        ipc::send_message(&mut stream_b, ipc::SHUTDOWN, &[]).ok();
        drop(stream_a);
        drop(stream_b);
        drop(scp_stream_a);
        drop(scp_stream_b);
        wait_for_child_exit(&mut child_a, "overlay A");
        wait_for_child_exit(&mut child_b, "overlay B");

        remove_ipc_sockets(&socket_a);
        remove_ipc_sockets(&socket_b);

        // Verify B received the SCP message
        match result {
            Ok((msg_type, payload)) => {
                assert_eq!(
                    msg_type,
                    ipc::SCP_RECEIVED,
                    "Should receive SCP_RECEIVED message"
                );
                assert_eq!(payload, scp_envelope, "Payload should match");
                println!("✓ Two binaries can relay SCP messages!");
            }
            Err(e) => {
                panic!("B did not receive SCP message from A: {}. This indicates peer connection or relay failed.", e);
            }
        }
    }
}
