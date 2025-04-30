pub mod client;
pub mod macros;
pub mod publish;

use clap::Parser;
use libmqttmtd::socket::plain::PlainServer;
use std::error::Error;
use std::io::Write;

#[derive(Parser, Debug)]
#[command(version)]
struct CliArgs {
    /// Port that accepts external clients (e.g., 8083)
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// MQTT Broker port
    #[arg(long, default_value_t = 3001)]
    broker_port: u16,

    /// Auth Server verifier port
    #[arg(long, default_value_t = 3002)]
    verifier_port: u16,
}

pub fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let args = CliArgs::parse();

    mqttinterface_println!("Starting MQTT Interface...");
    mqttinterface_println!("");
    mqttinterface_println!("--- MQTT Interface Configuration ---");
    mqttinterface_println!("Port:          {}", args.port);
    mqttinterface_println!("Broker Port:   {}", args.broker_port);
    mqttinterface_println!("Verifier Port: {}", args.verifier_port);
    mqttinterface_println!("--------------------------");
    mqttinterface_println!("");

    // open server
    let _server = PlainServer::new(args.port, None)
        .spawn(move |s, addr| client::handler(args.broker_port, args.verifier_port, s, addr));
    mqttinterface_println!("launched mqtt interface at port {}", args.port);

    loop {}
}
