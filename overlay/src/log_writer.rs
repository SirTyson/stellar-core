//! Non-blocking, bounded log writer.
//!
//! Events are still formatted on the thread that emits them, but the write
//! to the output (stdout) happens on a dedicated thread, so a slow or blocked
//! output — e.g. a container log pipe — can never stall a tokio worker. When
//! the queue is full, lines are dropped and counted, and the writer thread
//! reports how many were lost.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing_subscriber::fmt::MakeWriter;

enum Msg {
    Line(Vec<u8>),
    Flush(mpsc::Sender<()>),
}

/// `MakeWriter` for tracing-subscriber that hands each formatted event to a
/// background writer thread without blocking.
pub struct NonBlockingWriter {
    tx: SyncSender<Msg>,
    dropped: Arc<AtomicU64>,
}

/// Flushes everything queued before it when dropped (bounded wait). Keep it
/// alive until the process is about to exit.
pub struct FlushGuard {
    tx: SyncSender<Msg>,
}

impl NonBlockingWriter {
    /// Spawn the writer thread for `out`, queueing at most `capacity` lines.
    pub fn new<W: Write + Send + 'static>(out: W, capacity: usize) -> (Self, FlushGuard) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let reader_dropped = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("log-writer".into())
            .spawn(move || write_loop(out, rx, reader_dropped))
            .expect("failed to spawn log writer thread");
        (
            Self {
                tx: tx.clone(),
                dropped,
            },
            FlushGuard { tx },
        )
    }

    /// Lines dropped so far because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn write_loop<W: Write>(mut out: W, rx: Receiver<Msg>, dropped: Arc<AtomicU64>) {
    let mut reported = 0u64;
    let mut report_drops = |out: &mut W| {
        let now = dropped.load(Ordering::Relaxed);
        if now != reported {
            let _ = writeln!(
                out,
                "LOG_DROPPED: {} log line(s) dropped because the log writer fell behind",
                now - reported
            );
            reported = now;
        }
    };
    while let Ok(msg) = rx.recv() {
        let mut pending = Some(msg);
        // Write everything already queued, then flush once.
        while let Some(msg) = pending.take() {
            match msg {
                Msg::Line(line) => {
                    let _ = out.write_all(&line);
                }
                Msg::Flush(ack) => {
                    report_drops(&mut out);
                    let _ = out.flush();
                    let _ = ack.send(());
                }
            }
            pending = rx.try_recv().ok();
        }
        report_drops(&mut out);
        let _ = out.flush();
    }
}

/// Longest a FlushGuard waits, in total, to queue its flush and have it done.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

impl Drop for FlushGuard {
    fn drop(&mut self) {
        // Both queueing the flush and waiting for it are bounded: a writer
        // stuck on a blocked stdout (with the queue full) must not keep the
        // process from exiting.
        let deadline = Instant::now() + FLUSH_TIMEOUT;
        let (ack_tx, ack_rx) = mpsc::channel();
        let mut flush = Msg::Flush(ack_tx);
        loop {
            match self.tx.try_send(flush) {
                Ok(()) => break,
                Err(TrySendError::Full(msg)) if Instant::now() < deadline => {
                    flush = msg;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
        match ack_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(()) | Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {}
        }
    }
}

/// Buffers one formatted event and queues it on drop.
pub struct QueuedLine<'a> {
    writer: &'a NonBlockingWriter,
    buf: Vec<u8>,
}

impl Write for QueuedLine<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for QueuedLine<'_> {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let line = std::mem::take(&mut self.buf);
        if let Err(TrySendError::Full(_)) = self.writer.tx.try_send(Msg::Line(line)) {
            self.writer.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<'a> MakeWriter<'a> for NonBlockingWriter {
    type Writer = QueuedLine<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        QueuedLine {
            writer: self,
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};

    /// Output that records writes and can be made to block.
    #[derive(Clone, Default)]
    struct Sink {
        data: Arc<Mutex<Vec<u8>>>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Sink {
        fn blocked() -> Self {
            let sink = Sink::default();
            *sink.gate.0.lock().unwrap() = true;
            sink
        }
        fn release(&self) {
            *self.gate.0.lock().unwrap() = false;
            self.gate.1.notify_all();
        }
        fn contents(&self) -> String {
            String::from_utf8(self.data.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let (lock, cvar) = &*self.gate;
            let mut blocked = lock.lock().unwrap();
            while *blocked {
                blocked = cvar.wait(blocked).unwrap();
            }
            self.data.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn emit(writer: &NonBlockingWriter, text: &str) {
        let mut line = writer.make_writer();
        line.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn lines_are_written_in_order_and_flushed_by_guard() {
        let sink = Sink::default();
        let (writer, guard) = NonBlockingWriter::new(sink.clone(), 16);
        for i in 0..10 {
            emit(&writer, &format!("line {}\n", i));
        }
        drop(guard);
        let expected: String = (0..10).map(|i| format!("line {}\n", i)).collect();
        assert_eq!(sink.contents(), expected);
        assert_eq!(writer.dropped(), 0);
    }

    #[test]
    fn blocked_output_drops_instead_of_blocking_and_reports() {
        let sink = Sink::blocked();
        let (writer, guard) = NonBlockingWriter::new(sink.clone(), 4);
        // The writer thread takes one line and blocks on it; at most
        // `capacity` more fit in the queue; everything else is dropped
        // without blocking this thread.
        for i in 0..100 {
            emit(&writer, &format!("line {}\n", i));
        }
        assert!(writer.dropped() >= 100 - 1 - 4);
        sink.release();
        drop(guard);
        let out = sink.contents();
        assert!(out.starts_with("line 0\n"));
        assert!(out.contains("LOG_DROPPED:"));
    }

    #[test]
    fn guard_gives_up_on_output_that_stays_blocked() {
        let sink = Sink::blocked();
        let (writer, guard) = NonBlockingWriter::new(sink.clone(), 4);
        // Leave the queue full behind a writer blocked on its first line.
        for i in 0..10 {
            emit(&writer, &format!("line {}\n", i));
        }
        let start = Instant::now();
        drop(guard);
        let waited = start.elapsed();
        assert!(waited >= FLUSH_TIMEOUT / 2, "gave up early: {:?}", waited);
        assert!(waited < FLUSH_TIMEOUT * 2, "blocked: {:?}", waited);
        sink.release();
    }
}
