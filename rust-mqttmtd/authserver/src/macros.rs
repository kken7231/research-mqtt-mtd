#[macro_export]
macro_rules! authserver_println {
    ($($arg:tt)*) => {
        // println!("auth_server| {}", format!($($arg)*))
        println!("{}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! authserver_issuer_println {
    ($addr:expr, $($arg:tt)*) => {
        // println!("auth_server(issuer)| [{}] {}", $addr, format!($($arg)*))
        println!("(issuer)| [{}] {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! authserver_verifier_println {
    ($addr:expr, $($arg:tt)*) => {
        // println!("auth_server(verifier)| [{}] {}", $addr, format!($($arg)*))
        println!("(verifier)| [{}] {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! authserver_eprintln {
    ($($arg:tt)*) => {
        // eprintln!("auth_server| {}", format!($($arg)*))
        eprintln!("{}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! authserver_issuer_eprintln {
    ($addr:expr, $($arg:tt)*) => {
        // eprintln!("auth_server(issuer)| [{}] {}", $addr, format!($($arg)*))
        eprintln!("(issuer)| [{}] {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! authserver_verifier_eprintln {
    ($addr:expr, $($arg:tt)*) => {
        // eprintln!("auth_server(verifier)| [{}] {}", $addr, format!($($arg)*))
        eprintln!("(verifier)| [{}] {}", $addr, format!($($arg)*))
    };
}
