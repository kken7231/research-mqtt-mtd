use mqttmtd_authserver::{authserver_eprintln, authserver_println, run_server};

extern crate libmqttmtd;

#[tokio::main]
async fn main() {
    if let Err(_) = run_server() {
        authserver_eprintln!("Auth Server ended with error");
    } else {
        authserver_println!("Auth Server ended (unexpected reach)");
    }
}
