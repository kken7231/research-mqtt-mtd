use std::{io, path::Path};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpStream,
};

/// Enum that can hold either [TcpStream] or [UnixStream]
/// Implements [AsyncRead] and [AsyncWrite]
pub enum PlainStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl PlainStream {
    /// Splits the `PlainStream` into a `PlainReadHalf` and a `PlainWriteHalf`.
    /// This consumes the original `PlainStream`.
    pub fn split(self) -> (PlainReadHalf, PlainWriteHalf) {
        match self {
            PlainStream::Tcp(stream) => {
                let (read_half, write_half) = tokio::io::split(stream);
                (
                    PlainReadHalf::Tcp(read_half),
                    PlainWriteHalf::Tcp(write_half),
                )
            }
            #[cfg(unix)]
            PlainStream::Unix(stream) => {
                let (read_half, write_half) = tokio::io::split(stream);
                (
                    PlainReadHalf::Unix(read_half),
                    PlainWriteHalf::Unix(write_half),
                )
            }
        }
    }
}

impl AsyncRead for PlainStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            PlainStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PlainStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            PlainStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            PlainStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            PlainStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            PlainStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A read half of a [PlainStream].
/// Implements [AsyncRead].
pub enum PlainReadHalf {
    Tcp(ReadHalf<TcpStream>),
    #[cfg(unix)]
    Unix(ReadHalf<UnixStream>),
}

/// A write half of a [PlainStream].
/// Implements [AsyncWrite].
pub enum PlainWriteHalf {
    Tcp(WriteHalf<TcpStream>),
    #[cfg(unix)]
    Unix(WriteHalf<UnixStream>),
}

impl AsyncRead for PlainReadHalf {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainReadHalf::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            PlainReadHalf::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PlainWriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            PlainWriteHalf::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            PlainWriteHalf::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainWriteHalf::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            PlainWriteHalf::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            PlainWriteHalf::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            PlainWriteHalf::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Enum that can hold either [std::net::SocketAddr] (tcp) or [PathBuf] (unix)
/// Implements to_string().
pub enum PlainStreamAddress {
    Tcp(std::net::SocketAddr),
    #[cfg(unix)]
    Unix(std::os::unix::net::SocketAddr),
}

impl PlainStreamAddress {
    /// Returns either a Tcp address or a unix domain socket path.
    pub fn to_string(&self) -> String {
        match self {
            PlainStreamAddress::Tcp(tcp_addr) => tcp_addr.to_string(),
            #[cfg(unix)]
            PlainStreamAddress::Unix(unix_addr) => unix_addr
                .as_pathname()
                .unwrap_or(Path::new("ADDRESS_NONE"))
                .to_string_lossy()
                .to_string(),
        }
    }
}
