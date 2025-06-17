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
macro_rules! auth_serv_read_into_new_mut_bytes {
    ($var_name:ident, $stream:expr, $len:expr) => {
        let mut $var_name = BytesMut::zeroed($len);
        auth_serv_read!($stream, &mut $var_name[..]);
        let mut $var_name = $var_name.freeze();
    };
}

#[macro_export]
macro_rules! auth_serv_read_into_new_bytes {
    ($var_name:ident, $stream:expr, $len:expr) => {
        let mut $var_name = BytesMut::zeroed($len);
        auth_serv_read!($stream, &mut $var_name[..]);
        let $var_name = $var_name.freeze();
    };
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
