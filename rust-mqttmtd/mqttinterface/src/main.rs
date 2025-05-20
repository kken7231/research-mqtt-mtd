use mqttinterface::run_server;

#[tokio::main]
async fn main() {
    if let Err(_) = run_server().await {
        eprintln!("MQTT Interface ended with error");
    } else {
        println!("MQTT Interface ended (unexpected reach)");
    }
}
