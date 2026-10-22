//! Lets a writer hand the [`Bytes`] behind the buffer it passes to `AsyncWrite::poll_write` down
//! to the transport that ends up storing the data, so that the transport can keep a reference to
//! the shared buffer instead of copying it.
//!
//! gossipsub sends each message to many peers. It encodes a message once and writes the same
//! [`Bytes`] to every peer's stream, so QUIC's per-connection send buffers can all reference one
//! copy of the message instead of holding one copy each until the peer acknowledges it.
//!
//! The writer calls [`offer`] around its `poll_write` call, and the transport calls [`take`] in its
//! own `poll_write`, which runs synchronously inside that call. Layers in between need no changes
//! as long as they pass the buffer through. If a layer copies the data instead, [`take`] finds no
//! match and the transport copies it as usual.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

thread_local! {
    static OFFERED: RefCell<Option<Bytes>> = const { RefCell::new(None) };
}

static SHARED_BYTES: AtomicU64 = AtomicU64::new(0);
static COPIED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Calls `write`, which should pass a slice of `chunk` to `poll_write`, while offering `chunk` to
/// the transport.
pub fn offer<R>(chunk: &Bytes, write: impl FnOnce() -> R) -> R {
    let previous = OFFERED.with(|offered| offered.replace(Some(chunk.clone())));
    let result = write();
    OFFERED.with(|offered| *offered.borrow_mut() = previous);
    result
}

/// Returns a [`Bytes`] that shares the memory of `buf` if `buf` lies within the offered chunk.
pub fn take(buf: &[u8]) -> Option<Bytes> {
    if buf.is_empty() {
        return None;
    }
    OFFERED.with(|offered| {
        let offered = offered.borrow();
        let chunk = offered.as_ref()?;
        let chunk_start = chunk.as_ptr() as usize;
        let buf_start = buf.as_ptr() as usize;
        let within =
            buf_start >= chunk_start && buf_start + buf.len() <= chunk_start + chunk.len();
        within.then(|| chunk.slice_ref(buf))
    })
}

/// Records that a transport stored `len` written bytes, either by reference (`shared`) or by
/// copying them.
pub fn record(shared: bool, len: usize) {
    let counter = if shared { &SHARED_BYTES } else { &COPIED_BYTES };
    counter.fetch_add(len as u64, Ordering::Relaxed);
}

/// Bytes that transports in this process have stored by reference and by copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub shared_bytes: u64,
    pub copied_bytes: u64,
}

/// Returns the bytes that transports in this process have stored so far.
pub fn stats() -> Stats {
    Stats {
        shared_bytes: SHARED_BYTES.load(Ordering::Relaxed),
        copied_bytes: COPIED_BYTES.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_shares_slices_of_the_offered_chunk() {
        let chunk = Bytes::from(vec![7u8; 100]);
        let taken = offer(&chunk, || take(&chunk[10..40])).unwrap();
        assert_eq!(taken.as_ptr(), chunk[10..].as_ptr());
        assert_eq!(taken.len(), 30);
    }

    #[test]
    fn take_ignores_other_buffers() {
        let chunk = Bytes::from(vec![7u8; 100]);
        let other = vec![7u8; 100];
        assert!(offer(&chunk, || take(&other)).is_none());
        assert!(offer(&chunk, || take(&chunk[..0])).is_none());
        assert!(take(&chunk).is_none(), "nothing is offered outside of `offer`");
    }

    #[test]
    fn nested_offers_restore_the_outer_chunk() {
        let outer = Bytes::from(vec![1u8; 10]);
        let inner = Bytes::from(vec![2u8; 10]);
        offer(&outer, || {
            assert!(offer(&inner, || take(&inner)).is_some());
            assert!(take(&outer).is_some());
        });
    }
}
