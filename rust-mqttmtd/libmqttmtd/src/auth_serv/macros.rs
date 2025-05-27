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
macro_rules! auth_serv_read_u8 {
    ($stream: expr) => {
        $stream
            .read_u8()
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?
    };
}

#[macro_export]
macro_rules! auth_serv_read_u16 {
    ($stream: expr) => {
        $stream
            .read_u16()
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?
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
macro_rules! auth_serv_write_u8 {
    ($stream: expr, $value:expr) => {
        $stream
            .write_u8($value)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))
            .map(|_| 1usize)?
    };
}

#[macro_export]
macro_rules! auth_serv_write_u16 {
    ($stream: expr, $value:expr) => {
        $stream
            .write_u16($value)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))
            .map(|_| 2usize)?
    };
}

#[macro_export]
macro_rules! auth_serv_read_check_v2_header {
    ($stream: expr,  $packet_type:expr) => {
        match $stream
            // .read_u32()
            .read_u8()
            .await
            .map_err(|e| AuthServerParserError::SocketReadError(e))?
        {
            // v if ((v & crate::consts::MAGIC_NUM_MASK) == crate::consts::MAGIC_NUM)
            //     && ((v >> 4) & 0xF == 2)
            //     && (((v & 0xF) as u8) == $packet_type) =>
            v if ((v >> 4) & 0xF == 2) && (((v & 0xF) as u8) == $packet_type) =>
            {
                (
                    ((v >> 4) & 0xF) as u8,
                    (v & 0xF) as u8,
                )
            }
            other => return Err(AuthServerParserError::InvalidHeaderError(other)),
        }
    };
}

#[macro_export]
macro_rules! auth_serv_write_v2_header {
    ($stream: expr, $packet_type:expr) => {
        $stream
            // .write_u32(crate::consts::MAGIC_NUM | 0x20u32 | $packet_type as u32)
            .write_u8(0x20u8 | $packet_type as u8)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))
            // .map(|_| 4usize)?
            .map(|_| 1usize)?
    };
}
