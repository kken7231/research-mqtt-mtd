use clap::Parser;
use std::{error::Error, sync::Arc};
use config::{Config, ConfigError, File};
use serde::Deserialize;

use atl::AccessTokenList;
use libmqttmtd::socket::{plain::PlainServer, tls::TlsServer, tls_config::TlsConfigLoader};

pub mod acl;
pub mod atl;
pub(crate) mod error;
pub mod issuer;
pub mod macros;
pub mod verifier;

#[derive(Parser, Debug)]
#[command(version, long_about)]
struct CliArgs {
    /// Path to the server certificate PEM file. Overrides config file.
    #[arg(long)]
    server_cert_pem: Option<String>,

    /// Path to the server key PEM file. Overrides config file.
    #[arg(long)]
    server_key_pem: Option<String>,

    /// Directory containing client certificates for authentication. Overrides config file.
    #[arg(long)]
    client_certs_dir: Option<String>,

    /// Disable client certificate authentication. Overrides config file.
    #[arg(long)]
    client_auth_disabled: Option<bool>,

    /// Port for the issuer server (e.g., 3000). Overrides config file.
    #[arg(long)]
    issuer_port: Option<u16>,

    /// Port for the verifier server (e.g., 3001). Overrides config file.
    #[arg(long)]
    verifier_port: Option<u16>,

    /// conf file that sets parameters
    #[arg(long, default_value = "./conf/authserver.conf")]
    conf: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_certs_dir: String,
    pub client_auth_disabled: bool,
    pub issuer_port: u16,
    pub verifier_port: u16,
}

fn load_config() -> Result<AppConfig, ConfigError> {
    let args: CliArgs = CliArgs::parse();

    let mut builder = Config::builder()
        .set_default("server_cert_pem", "./certs/server/cert.crt")?
        .set_default("server_key_pem", "./certs/server/key.pem")?
        .set_default("client_certs_dir", "./certs/clients")?
        .set_default("client_auth_disabled", false)?
        .set_default("issuer_port", 3000)?
        .set_default("verifier_port", 3001)?
        .add_source(File::with_name(&args.conf).required(false));

    if let Some(value) = args.server_cert_pem {
        builder = builder.set_override("server_cert_pem", value)?;
    }
    if let Some(value) = args.server_key_pem {
        builder = builder.set_override("server_key_pem", value)?;
    }
    if let Some(value) = args.client_certs_dir {
        builder = builder.set_override("client_certs_dir", value)?;
    }
    if let Some(value) = args.client_auth_disabled {
        builder = builder.set_override("client_auth_disabled", value)?;
    }
    if let Some(value) = args.issuer_port {
        builder = builder.set_override("issuer_port", value)?;
    }
    if let Some(value) = args.verifier_port {
        builder = builder.set_override("verifier_port", value)?;
    }

    builder.build()?.try_deserialize()
}

pub async fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let config = load_config()?;

    authserver_println!("Starting Auth Server...");
    authserver_println!("");
    authserver_println!("--- Auth Server Configuration ---");
    authserver_println!("  Server Cert PEM:      {}", config.server_cert_pem);
    authserver_println!("  Server Key PEM:       {}", config.server_key_pem);
    authserver_println!("  Client Certs Dir:     {}", config.client_certs_dir);
    authserver_println!("  Client Auth Disabled: {}", config.client_auth_disabled);
    authserver_println!("  Issuer Server Port:   {}", config.issuer_port);
    authserver_println!("  Verifier Server Port: {}", config.verifier_port);
    authserver_println!("---------------------------------");
    authserver_println!("");

    let atl = Arc::new(AccessTokenList::new());

    // server config
    let issuer_config = match TlsConfigLoader::load_server_config(
        config.server_cert_pem,
        config.server_key_pem,
        config.client_certs_dir,
        config.client_auth_disabled,
    ) {
        Err(e) => {
            authserver_eprintln!("found issue in loading Tls config: {}", e);
            return Err(Box::new(e));
        }
        Ok(config) => config,
    };

    // open verifier
    let atl_for_verifier = atl.clone();
    let verifier = PlainServer::new(config.verifier_port, None).spawn(move |s, addr| {
        let atl_for_this_connection = atl_for_verifier.clone();
        verifier::handler(atl_for_this_connection, s, addr)
    });
    authserver_println!("launched verifier interface at port {}", config.verifier_port);

    // issuer
    let atl_for_issuer = atl.clone();
    let issuer = TlsServer::new(config.issuer_port, None, issuer_config).spawn(move |s, addr| {
        let atl_for_this_connection = atl_for_issuer.clone();
        issuer::handler(atl_for_this_connection, s, addr)
    });
    authserver_println!("launched issuer interface at port {}", config.issuer_port);

    tokio::select! {
        _ = verifier => {
            eprintln!("verifier interface ended. stopping issuer as well...")
        },
        _ = issuer => {
            eprintln!("issuer interface ended. stopping verifier as well...")
        },
    };
    Ok(())
}
