pub mod client;
pub mod macros;
pub mod publish;

use clap::Parser;
use libmqttmtd::socket::plain::PlainServer;
use std::error::Error;
use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(version, long_about)]
struct CliArgs {
    /// Port that accepts external clients (e.g., 8083). Overrides config file.
    #[arg(long)]
    port: Option<u16>,

    /// MQTT Broker port. Overrides config file.
    #[arg(long)]
    broker_port: Option<u16>,

    /// Auth Server verifier port. Overrides config file.
    #[arg(long)]
    verifier_port: Option<u16>,

    /// Conf file that sets parameters
    #[arg(long, default_value = "")]
    conf: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub broker_port: u16,
    pub verifier_port: u16,
}

fn load_config() -> Result<AppConfig, ConfigError> {
    let cli_args:CliArgs = CliArgs::parse();

    let mut builder = Config::builder()
        .set_default("port", 3000)?
        .set_default("broker_port", 3001)?
        .set_default("verifier_port", 3002)?
        .add_source(File::with_name(&cli_args.conf).required(false));

    if let Some(port) = cli_args.port {
        builder = builder.set_override("port", port)?;
    }
    if let Some(broker_port) = cli_args.broker_port {
        builder = builder.set_override("broker_port", broker_port)?;
    }
    if let Some(verifier_port) = cli_args.verifier_port {
        builder = builder.set_override("verifier_port", verifier_port)?;
    }

    builder.build()?.try_deserialize()
}
pub async fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            return Err(Box::new(e));
        }
    };

    mqttinterface_println!("Starting MQTT Interface...");
    mqttinterface_println!("");
    mqttinterface_println!("--- MQTT Interface Configuration ---");
    mqttinterface_println!("  Port:          {}", config.port);
    mqttinterface_println!("  Broker Port:   {}", config.broker_port);
    mqttinterface_println!("  Verifier Port: {}", config.verifier_port);
    mqttinterface_println!("------------------------------------");
    mqttinterface_println!("");

    // open server
    let _server = PlainServer::new(config.port, None)
        .spawn(move |s, addr| client::handler(config.broker_port, config.verifier_port, s, addr));
    mqttinterface_println!("launched mqtt interface at port {}", config.port);
    _server.await??;
    Ok(())
}
