#[macro_export]
macro_rules! sock_cli_println {
    ($($arg:tt)*) => {
        println!("[sock_client] {}", format!($($arg)*));
    };
}
