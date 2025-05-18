#[macro_export]
macro_rules! get_buf_checked {
    ($buf_candidate:expr, $min_buf_len:expr) => {
        match $buf_candidate {
            Some(b) if b.len() < $min_buf_len => {
                return Err(AuthServerParserError::BufferTooSmallError());
            }
            Some(b) => b,
            None => &mut [0u8; $min_buf_len][..],
        }
    };
}

#[macro_export]
macro_rules! auth_serv_read {
    ($stream: expr, $buf:expr) => {
        $stream
            .read_exact($buf)
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
    };
}

#[macro_export]
macro_rules! auth_serv_read_into_new_bytes {
    ($var_name:ident, $stream:expr, $len:expr) => {
        let mut $var_name = BytesMut::zeroed($len);
        $stream
            .read_exact(&mut $var_name[..])
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?;
        let $var_name = $var_name.freeze();
    };
}

#[macro_export]
macro_rules! auth_serv_write {
    ($stream: expr, $buf:expr) => {
        $stream
            .write_all($buf)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?;
    };
}
