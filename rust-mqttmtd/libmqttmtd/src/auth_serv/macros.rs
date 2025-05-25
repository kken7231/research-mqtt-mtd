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
macro_rules! auth_serv_check_magic_number {
    ($stream: expr, $buf:expr) => {
        auth_serv_read!($stream, &mut $buf[..4]);

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
#[macro_export]
macro_rules! auth_serv_write_u8 {
    ($stream: expr, $value:expr) => {
        $stream
            .write_u8($value)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?
    };
}

#[macro_export]
macro_rules! auth_serv_write_u16 {
    ($stream: expr, $value:expr) => {
        $stream
            .write_u16($value)
            .await
            .map_err(|e| AuthServerParserError::SocketWriteError(e))?
    };
}
