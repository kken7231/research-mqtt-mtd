mod client;
mod config;
mod macros;
mod publish;

use crate::config::load_config;
use libmqttmtd::printer::display_config;
use libmqttmtd::socket::plain::PlainServer;
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
    for line in display_config("MQTT Interface", &config)?.iter() {
        mqttinterface_println!("{}", line);
    }

    // open server
    let _server = PlainServer::new(config.port, None)
        .spawn(move |s, addr| client::handler(config.broker_port, config.verifier_port, s, addr));
    mqttinterface_println!("launched mqtt interface at port {}", config.port);
    _server.await??;
    Ok(())
}
