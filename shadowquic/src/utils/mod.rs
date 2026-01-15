pub mod dual_socket;
pub mod dns;
pub mod route;
pub mod socket;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{self as tokio_io, AsyncRead, AsyncWrite};
use bytesize::ByteSize;

static BIDIRECTIONAL_COPY_BUFFER_SIZE: AtomicUsize = AtomicUsize::new(1 * 1024);

pub fn format_bytes(bytes: u64) -> String {
    ByteSize(bytes).to_string()
}

pub fn format_duration(duration: Duration) -> String {
    format!("{:.2?}", duration)
}

pub fn set_bidirectional_copy_buffer_size(size_kib: usize) {
    let size_kib = if size_kib == 0 { 1 } else { size_kib };
    let size_bytes = size_kib.saturating_mul(1024);
    BIDIRECTIONAL_COPY_BUFFER_SIZE.store(size_bytes, Ordering::Relaxed);
}

pub async fn bidirectional_copy<A, B>(
    a: &mut A,
    b: &mut B,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let buf_size = BIDIRECTIONAL_COPY_BUFFER_SIZE.load(Ordering::Relaxed);
    tokio_io::copy_bidirectional_with_sizes(a, b, buf_size, buf_size).await
}

#[cfg(target_os = "android")]
pub mod protect_socket;
