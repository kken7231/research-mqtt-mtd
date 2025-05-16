use std::{error::Error, sync::Arc};

use acl::AccessControlList;
use atl::AccessTokenList;
use config::load_config;
use libmqttmtd::{
    config_helper::display_config,
    socket::{
        plain::{
            PlainServer,
            ServerType::{GLOBAL, LOCAL},
        },
        tls::TlsServer,
        tls_config::TlsConfigLoader,
    },
};

mod acl;
mod atl;
mod config;
mod error;
mod issuer;
mod macros;
mod verifier;

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
    for line in display_config("Auth Server", &config)?.iter() {
        authserver_println!("{}", line);
    }

    // Initialize ATL
    let atl = Arc::new(AccessTokenList::new());

    // Load ACL
    let acl = Arc::new(AccessControlList::from_yaml(config.acl)?);

    // server config
    let issuer_config = match TlsConfigLoader::load_server_config(
        config.server_cert_pem,
        config.server_key_pem,
        config.ca_certs_dir,
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
    let verifier = PlainServer::new(config.verifier_port, None, LOCAL).spawn(move |s, addr| {
        let atl_for_this_connection = atl_for_verifier.clone();
        verifier::handler(atl_for_this_connection, s, addr)
    });
    authserver_println!(
        "launched verifier interface at port {}",
        config.verifier_port
    );

    // open issuer
    let atl_for_issuer = atl.clone();
    let issuer =
        TlsServer::new(config.issuer_port, None, GLOBAL, issuer_config).spawn(move |s, addr| {
            let atl_for_this_connection = atl_for_issuer.clone();
            let acl_for_this_connection = acl.clone();
            issuer::handler(acl_for_this_connection, atl_for_this_connection, s, addr)
        });
    authserver_println!("launched issuer interface at port {}", config.issuer_port);

    // Wait till either one of two ends
    tokio::select! {
        result = verifier => {
            eprintln!("verifier interface ended. stopping issuer as well...");
            result
        },
        result = issuer => {
            eprintln!("issuer interface ended. stopping verifier as well...");
            result
        },
    }
    .unwrap()
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
