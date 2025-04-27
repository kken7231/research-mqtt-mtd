//! Util functions

use std::{io, time::Duration};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncRead;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;

pub async fn read(
    mut stream: ReaderStream<impl AsyncRead + Send + Sync + Unpin>,
    len: usize,
) -> Result<BytesMut, io::Error> {
    let mut ret_bytes = BytesMut::with_capacity(len);
    let mut bytes_read = 0;

    while bytes_read < len {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let remaining = len - bytes_read;
                let bytes_to_take = chunk.len().min(remaining);
                ret_bytes.extend_from_slice(&chunk[..bytes_to_take]);
                bytes_read += bytes_to_take;
                if bytes_read == len {
                    break;
                }
            }
            Some(Err(e)) => return Err(e),
            None => {
                // End of stream reached before reading 'len' bytes
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "End of stream reached before reading the specified length",
                ));
            }
        }
    }

    Ok(ret_bytes)
}
