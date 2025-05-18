use clap::Parser;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};
use struct_display_macro::ToStringLines;

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

    /// Conf file that sets parameters
    #[arg(long, default_value = "")]
    conf: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToStringLines)]
pub(super) struct AppConfig {
    pub port: u16,
    pub broker_port: u16,
    pub verifier_port: u16,
}

pub(super) fn load_config() -> Result<AppConfig, ConfigError> {
    let cli_args: CliArgs = CliArgs::parse();

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
