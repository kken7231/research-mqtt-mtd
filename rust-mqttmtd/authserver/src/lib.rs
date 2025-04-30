use clap::Parser;
use std::{error::Error, sync::Arc};

use atl::AccessTokenList;
use libmqttmtd::socket::{plain::PlainServer, tls::TlsServer, tls_config::TlsConfigLoader};

pub mod acl;
pub mod atl;
pub(crate) mod error;
pub mod issuer;
pub mod macros;
pub mod verifier;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path to the server certificate PEM file
    #[arg(long, default_value = "./certs/server/cert.crt")]
    server_cert_pem: String,

    /// Path to the server key PEM file
    #[arg(long, default_value = "./certs/server/key.pem")]
    server_key_pem: String,

    /// Directory containing client certificates for authentication
    #[arg(long, default_value = "./certs/clients")]
    client_certs_dir: String,

    /// Disable client certificate authentication (false by default: --client-auth-disabled false)
    #[arg(long, default_value_t = false)]
    client_auth_disabled: bool,

    /// Port for the issuer server (e.g., 3000)
    #[arg(long, default_value_t = 3000)]
    issuer_port: u16,

    /// Port for the verifier server (e.g., 3001)
    #[arg(long, default_value_t = 3001)]
    verifier_port: u16,
}

pub fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let args = CliArgs::parse();

    // Use the parsed values and constructed addresses
    let p_server_cert_pem: &str = &args.server_cert_pem;
    let p_server_key_pem: &str = &args.server_key_pem;
    let p_client_certs_dir: &str = &args.client_certs_dir;
    let client_auth_disabled: bool = args.client_auth_disabled;

    authserver_println!("Starting Auth Server...");
    authserver_println!("");
    authserver_println!("--- Server Configuration ---");
    authserver_println!("Server Cert PEM:      {}", p_server_cert_pem);
    authserver_println!("Server Key PEM:       {}", p_server_key_pem);
    authserver_println!("Client Certs Dir:     {}", p_client_certs_dir);
    authserver_println!("Client Auth Disabled: {}", client_auth_disabled);
    authserver_println!("Issuer Server Port:   {}", args.issuer_port);
    authserver_println!("Verifier Server Port: {}", args.verifier_port);
    authserver_println!("--------------------------");

    let atl = Arc::new(AccessTokenList::new());

    // server config
    let issuer_config = match TlsConfigLoader::load_server_config(
        p_server_cert_pem,
        p_server_key_pem,
        p_client_certs_dir,
        client_auth_disabled,
    ) {
        Err(e) => {
            authserver_eprintln!("found issue in loading Tls config: {}", e);
            return Err(Box::new(e));
        }
        Ok(config) => config,
    };

    // open verifier
    let atl_for_verifier = atl.clone();
    let _verifier = PlainServer::new(args.verifier_port, None).spawn(move |s, addr| {
        let atl_for_this_connection = atl_for_verifier.clone();
        verifier::handler(atl_for_this_connection, s, addr)
    });
    authserver_println!("launched verifier interface at port {}", args.verifier_port);

    // issuer
    let atl_for_issuer = atl.clone();
    let _issuer = TlsServer::new(args.issuer_port, None, issuer_config).spawn(move |s, addr| {
        let atl_for_this_connection = atl_for_issuer.clone();
        issuer::handler(atl_for_this_connection, s, addr)
    });
    authserver_println!("launched issuer interface at port {}", args.issuer_port);
    loop {}
}
