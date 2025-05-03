use clap::Parser;
use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(super) struct CliArgs {
    /// Run server if true, otherwise run once. Overrides config file.
    #[arg(long)]
    run_server: Option<bool>,

    /// Auth Server issuer hostname. Overrides config file.
    #[arg(long)]
    issuer_host: Option<String>,

    /// Auth Server issuer port. Overrides config file.
    #[arg(long)]
    issuer_port: Option<u16>,

    /// Directory that token_set files are saved. Overrides config file.
    #[arg(long)]
    token_sets_dir: Option<String>,

    /// Client cert file. Overrides config file.
    #[arg(long)]
    cli_cert: Option<String>,

    /// Client key file. Overrides config file.
    #[arg(long)]
    cli_key: Option<String>,

    /// Directory containing CA certificates for authentication. Overrides config file.
    #[arg(long)]
    ca_certs_dir: Option<String>,

    /// Whether client authentication is disabled. Overrides config file.
    #[arg(long)]
    client_auth_disabled: Option<bool>,

    /// Port of the server. Valid when run_server=true. Overrides config file.
    #[arg(long)]
    server_port: Option<u16>,

    // Parameters to be kept as command-line arguments only
    /// Access type. Valid when run_server=true.
    #[arg(long, default_value_t = true)]
    pub is_pub: bool,

    /// Topic Name / Filters. Valid when run_server=true.
    #[arg(short, long, default_value = "topic")]
    pub topic: String,

    /// Number of tokens. Must be dividable by 4. Valid when run_server=true.
    #[arg(short, long, default_value_t = 4)]
    pub num_tokens: u16,

    /// AEAD algorithm. AES_128_GCM, AES_256_GCM or CHACHA20_POLY1305. Valid when run_server=true.
    #[arg(short, long, default_value = "AES_256_GCM")]
    pub algo: String,

    /// Conf file that sets parameters
    #[arg(long, default_value = "")]
    pub conf: String,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct AppConfig {
    pub run_server: bool,
    pub issuer_host: String,
    pub issuer_port: u16,
    pub token_sets_dir: String,
    pub cli_cert: String,
    pub cli_key: String,
    pub ca_certs_dir: String,
    pub client_auth_disabled: bool,
    pub server_port: u16,
}

pub(super) fn load_config(cli_args: &CliArgs) -> Result<AppConfig, ConfigError> {
    let mut builder = Config::builder()
        .set_default("run_server", false)?
        .set_default("issuer_host", "issuer")?
        .set_default("issuer_port", 3002)?
        .set_default("token_sets_dir", "./tokens")?
        .set_default("cli_cert", "./certs/client/cert.crt")?
        .set_default("cli_key", "./certs/client/key.pem")?
        .set_default("ca_certs_dir", "./certs/ca/")?
        .set_default("client_auth_disabled", false)?
        .set_default("server_port", 3000)?
        .add_source(File::with_name(&cli_args.conf).required(false));

    // Override with command-line arguments if provided
    if let Some(run_server) = cli_args.run_server {
        builder = builder.set_override("run_server", run_server)?;
    }
    if let Some(issuer_host) = &cli_args.issuer_host {
        builder = builder.set_override("issuer_host", issuer_host.as_str())?;
    }
    if let Some(issuer_port) = cli_args.issuer_port {
        builder = builder.set_override("issuer_port", issuer_port)?;
    }
    if let Some(token_sets_dir) = &cli_args.token_sets_dir {
        builder = builder.set_override("token_sets_dir", token_sets_dir.as_str())?;
    }
    if let Some(cli_cert) = &cli_args.cli_cert {
        builder = builder.set_override("cli_cert", cli_cert.as_str())?;
    }
    if let Some(cli_key) = &cli_args.cli_key {
        builder = builder.set_override("cli_key", cli_key.as_str())?;
    }
    if let Some(ca_certs_dir) = &cli_args.ca_certs_dir {
        builder = builder.set_override("ca_certs_dir", ca_certs_dir.as_str())?;
    }
    if let Some(client_auth_disabled) = cli_args.client_auth_disabled {
        builder = builder.set_override("client_auth_disabled", client_auth_disabled)?;
    }
    if let Some(server_port) = cli_args.server_port {
        builder = builder.set_override("server_port", server_port)?;
    }

    builder.build()?.try_deserialize()
}
