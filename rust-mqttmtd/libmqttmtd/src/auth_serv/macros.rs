#[macro_export]
macro_rules! stream_read {
    ($stream: expr, $buf:expr) => {
        $stream
            .read_exact($buf)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
    };
}

#[macro_export]
macro_rules! stream_read_heap {
    ($stream:expr, $len:expr) => {{
        let mut buf = BytesMut::zeroed($len);
        stream_read!($stream, &mut buf[..]);
        buf.freeze()
    }};
}

#[macro_export]
macro_rules! stream_read_static {
    ($stream:expr, $len:expr) => {{
        let mut buf = [0u8; $len];
        stream_read!($stream, &mut buf[..]);
        std::io::Cursor::new(buf)
    }};
}

#[macro_export]
macro_rules! stream_read_topic {
    ($stream:expr, $len:expr) => {{
        let mut buf = vec![0u8; $len];
        stream_read!($stream, &mut buf[..]);
        String::from_utf8(buf.to_vec())?
    }};
}


#[macro_export]
macro_rules! auth_serv_write {
    ($stream: expr, $buf:expr) => {
        $stream
            .write_all($buf)
            .await
            .map(|_| $buf.len())
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?
    };
}

#[macro_export]
macro_rules! auth_serv_check_v2_header {
    ($byte: expr,  $packet_type:expr) => {
        match $byte {
            // v if ((v & crate::consts::MAGIC_NUM_MASK) == crate::consts::MAGIC_NUM)
            //     && ((v >> 4) & 0xF == 2)
            //     && (((v & 0xF) as u8) == $packet_type) =>
            v if ((v >> 4) & 0xF == 2) && (((v & 0xF) as u8) == $packet_type) => {
                (((v >> 4) & 0xF) as u8, (v & 0xF) as u8)
            }
            other => return Err(AuthServerParserError::InvalidHeaderError(other)),
        }
    };
}

#[macro_export]
macro_rules! auth_serv_v2_header {
    ($packet_type:expr) => {
        0x20u8 | $packet_type as u8
    };
}
