use mqttinterface::{mqttinterface_eprintln, mqttinterface_println, run_server};

#[tokio::main]
async fn main() {
    if let Err(_) = run_server().await {
        mqttinterface_eprintln!("MQTT Interface ended with error");
    } else {
        mqttinterface_println!("MQTT Interface ended (unexpected reach)");
    }
}
