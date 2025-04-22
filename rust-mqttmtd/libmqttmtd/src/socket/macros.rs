#[macro_export]
macro_rules! sock_serv_println {
    ($($arg:tt)*) => {
        println!("sock_server| {}", format!($($arg)*));
    };
}

#[macro_export]
macro_rules! sock_cli_println {
    ($($arg:tt)*) => {
        println!("sock_client| {}", format!($($arg)*));
    };
}
