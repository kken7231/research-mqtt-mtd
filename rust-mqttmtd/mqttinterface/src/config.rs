use clap::Parser;
use config::{Config, ConfigError, File};
use libmqttmtd_macros::ToStringLines;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(version, about, long_about)]
pub(super) struct CliArgs {
    /// Port that accepts external clients (e.g., 8083). Overrides config file.
    #[arg(long)]
    port: Option<u16>,

    /// MQTT Broker port. Overrides config file.
    #[arg(long)]
    broker_port: Option<u16>,

    /// Auth Server verifier port. Overrides config file.
    #[arg(long)]
    verifier_port: Option<u16>,

    /// Enable unix sockets in both with Auth Server verifier interface and with
    /// broker. TCP sockets not supported when enabled.
    /// Socket path for Auth Server verifier is composed of `verifier_port`.
    /// Socket path for MQTT broker is `/tmp/mosquitto_plain`
    #[arg(long)]
    enable_unix_sock: Option<bool>,

    /// Conf file that sets parameters
    #[arg(long, default_value = "")]
    conf: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToStringLines)]
pub(super) struct AppConfig {
    pub port: u16,
    pub broker_port: u16,
    pub verifier_port: u16,
    pub enable_unix_sock: bool,
}

pub(super) fn load_config() -> Result<AppConfig, ConfigError> {
    let cli_args: CliArgs = CliArgs::parse();

    let mut builder = Config::builder()
        .set_default("port", 3000)?
        .set_default("broker_port", 3001)?
        .set_default("verifier_port", 3002)?
        .set_default("enable_unix_sock", true)?
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
    if let Some(verifier_port) = cli_args.enable_unix_sock {
        builder = builder.set_override("enable_unix_sock", verifier_port)?;
    }

    builder.build()?.try_deserialize()
}
