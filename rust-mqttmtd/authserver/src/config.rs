use clap::Parser;
use config::{Config, File};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use to_string_lines_macro::ToStringLines;

#[derive(Parser, Debug)]
#[command(version, about, long_about)]
pub(super) struct CliArgs {
    /// Path to the server certificate PEM file. Default:
    /// "./certs/server/cert.crt". Overrides config file.
    #[arg(long)]
    server_cert_pem: Option<String>,

    /// Path to the server key PEM file. Default: "./certs/server/key.pem".
    /// Overrides config file.
    #[arg(long)]
    server_key_pem: Option<String>,

    /// Directory containing CA certificates for authentication. Default:
    /// "./certs/ca". Overrides config file.
    #[arg(long)]
    ca_certs_dir: Option<String>,

    /// Enable client certificate authentication. Default: true. Overrides
    /// config file.
    #[arg(long)]
    enable_client_auth: Option<bool>,

    /// Enable server key logging to SSLKEYLOGFILE. Default: true. Overrides
    /// config file.
    #[arg(long)]
    enable_server_key_log: Option<bool>,

    /// Port for the issuer server. Default: 3000. Overrides config file.
    #[arg(long)]
    issuer_port: Option<u16>,

    /// Port for the verifier server. Default: 3001. Overrides config file.
    #[arg(long)]
    verifier_port: Option<u16>,

    /// Path to the Access Control List (ACL) yaml file. Default: "./acl.yaml".
    /// Overrides config file.
    #[arg(long)]
    acl: Option<String>,

    /// conf file that sets parameters
    #[arg(long, default_value = "./conf/authserver.conf")]
    conf: String,
}

/// Expresses a collection of configurable values.
#[derive(Debug, Serialize, Deserialize, Clone, ToStringLines)]
pub(super) struct AppConfig {
    pub server_cert_pem: PathBuf,
    pub server_key_pem: PathBuf,
    pub ca_certs_dir: PathBuf,
    pub enable_client_auth: bool,
    pub enable_server_key_log: bool,
    pub issuer_port: u16,
    pub verifier_port: u16,
    pub acl: PathBuf,
}

/// Loads config variables from both CLI arguments and a config file.
pub(super) fn load_config() -> Result<AppConfig, config::ConfigError> {
    let args: CliArgs = CliArgs::parse();

    let mut builder = Config::builder()
        .set_default("server_cert_pem", "./certs/server/cert.crt")?
        .set_default("server_key_pem", "./certs/server/key.pem")?
        .set_default("ca_certs_dir", "./certs/ca")?
        .set_default("enable_client_auth", true)?
        .set_default("enable_server_key_log", false)?
        .set_default("issuer_port", 3000)?
        .set_default("verifier_port", 3001)?
        .set_default("acl", "./acl.yaml")?
        .add_source(File::with_name(&args.conf).required(false));

    if let Some(value) = args.server_cert_pem {
        builder = builder.set_override("server_cert_pem", value)?;
    }
    if let Some(value) = args.server_key_pem {
        builder = builder.set_override("server_key_pem", value)?;
    }
    if let Some(value) = args.ca_certs_dir {
        builder = builder.set_override("ca_certs_dir", value)?;
    }
    if let Some(value) = args.enable_client_auth {
        builder = builder.set_override("enable_client_auth", value)?;
    }
    if let Some(value) = args.enable_server_key_log {
        builder = builder.set_override("enable_server_key_log", value)?;
    }
    if let Some(value) = args.issuer_port {
        builder = builder.set_override("issuer_port", value)?;
    }
    if let Some(value) = args.verifier_port {
        builder = builder.set_override("verifier_port", value)?;
    }
    if let Some(value) = args.acl {
        builder = builder.set_override("acl", value)?;
    }

    builder.build()?.try_deserialize()
}
