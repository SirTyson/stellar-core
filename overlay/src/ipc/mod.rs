//! IPC module for Core ↔ Overlay communication.

mod messages;
pub mod payloads;
mod transport;

pub use messages::{Message, MessageCodec, MessageType};
pub use transport::CoreIpc;
