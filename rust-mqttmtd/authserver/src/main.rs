extern crate libmqttmtd;
use mqttmtd_authserver::{proc_eprintln, proc_println, run_server};

#[tokio::main]
async fn main() {
    match run_server().await {
        Err(e) => proc_eprintln!("Auth Server ended with error: {}", e),
        _ => proc_println!("Auth Server ended (unexpected reach)"),
    }
}
