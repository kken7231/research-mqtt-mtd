mod client;
mod config;
mod macros;
mod publish;
mod subscribe;

use crate::config::load_config;
use libmqttmtd::socket::plain::{PlainServer, ServerType::GLOBAL};
use std::error::Error;

pub async fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            return Err(Box::new(e));
        }
    };

    // Print configuration
    config
        .to_string_lines("MQTT Interface")
        .iter()
        .for_each(|line| mqttinterface_println!("{}", line));

    // open server
    let _server = PlainServer::new(config.port, None, GLOBAL)
        .spawn(move |s, addr| client::handler(config.broker_port, config.verifier_port, s, addr));
    mqttinterface_println!("launched mqtt interface at port {}", config.port);
    _server.await??;
    Ok(())
}
