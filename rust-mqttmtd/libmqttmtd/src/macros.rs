#[macro_export]
macro_rules! log_start_func {
    ($func_name:ident) => {
        let start = std::time::Instant::now();
    };
}

#[macro_export]
macro_rules! log_end_func {
    ($func_name:ident) => {
        let end = start.elapsed();
        println!(
            "[timecard][{}] started at {} for {} ns",
            tokio::task::try_id().unwrap_or(),
            $func_name,
            start,
            end.as_nanos()
        );
    };
}

#[macro_export]
macro_rules! localhost_v4 {
    ($port:expr) => {
        format!("127.0.0.1:{}", $port)
    };
}
