#[macro_export]
macro_rules! proc_println {
    ($($arg:tt)*) => {
        println!("{}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! issuer_println {
    ($addr:expr, $($arg:tt)*) => {
        println!("[issuer]({}) {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! verifier_println {
    ($addr:expr, $($arg:tt)*) => {
        println!("[verifier]({}) {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! proc_eprintln {
    ($($arg:tt)*) => {
        eprintln!("{}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! issuer_eprintln {
    ($addr:expr, $($arg:tt)*) => {
        eprintln!("[issuer]({}) {}", $addr, format!($($arg)*))
    };
}

#[macro_export]
macro_rules! verifier_eprintln {
    ($addr:expr, $($arg:tt)*) => {
        eprintln!("[verifier]({}) {}", $addr, format!($($arg)*))
    };
}
