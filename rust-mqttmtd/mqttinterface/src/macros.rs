#[macro_export]
macro_rules! mqttinterface_println {
    ($($arg:tt)*) => {
        // println!("mqtt_interface| {}", format!($($arg)*))
        println!("{}", format!($($arg)*))
    };
}

#[macro_export]
macro_rules! mqttinterface_eprintln {
    ($($arg:tt)*) => {
        // eprintln!("mqtt_interface| {}", format!($($arg)*))
        println!("{}", format!($($arg)*))
    };
}
