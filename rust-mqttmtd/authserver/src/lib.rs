use crate::garbage_collector::spawn_garbage_collector;
use acl::AccessControlList;
use atl::AccessTokenList;
use config::load_config;
use libmqttmtd::{
    consts::UNIX_SOCK_VERIFIER,
    socket::{
        plain::{
            server::PlainServer,
            tcp::TcpServerType::{GLOBAL, LOCAL},
        },
        tls::TlsServer,
        tls_config::TlsConfigLoader,
    },
};
use std::{error::Error, sync::Arc, time::Duration};

mod acl;
mod atl;
mod config;
mod error;
mod garbage_collector;
mod issuer;
mod macros;
mod verifier;

pub async fn run_server() -> Result<(), Box<dyn Error>> {
    // Parse command-line arguments
    let config = load_config().inspect_err(|e| proc_eprintln!("failed to load config: {}", e))?;

    // Print configuration
    config
        .to_string_lines("Auth Server")
        .iter()
        .for_each(|line| proc_println!("{}", line));

    #[cfg(not(unix))]
    if config.enable_unix_sock {
        return Box::new(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix domain sockets are not supported on this operating system",
        )));
    }

    // Initialize ATL
    let atl = Arc::new(AccessTokenList::new());
    // run garbage collector
    let _garbage_collector = spawn_garbage_collector(atl.clone(), Duration::from_secs(900));

    // Load ACL
    let acl = Arc::new(AccessControlList::from_yaml(config.acl)?);

    // server config
    let issuer_config = TlsConfigLoader::load_server_config(
        config.server_cert_pem,
        config.server_key_pem,
        config.ca_certs_dir,
        config.enable_client_auth,
        config.enable_server_key_log,
        config.enable_tlsv1_2,
    )
    .inspect_err(|e| proc_eprintln!("found issue in loading Tls config: {}", e))?;

    // open verifier
    let atl_for_verifier = atl.clone();
    let verifier = if config.enable_unix_sock {
        #[cfg(unix)]
        PlainServer::new_unix(UNIX_SOCK_VERIFIER, None).spawn(move |s, addr| {
            let atl_for_this_connection = atl_for_verifier.clone();
            verifier::handler(atl_for_this_connection, s, addr.to_string())
        })
    } else {
        PlainServer::new_tcp(config.verifier_port, None, LOCAL)?.spawn(move |s, addr| {
            let atl_for_this_connection = atl_for_verifier.clone();
            verifier::handler(atl_for_this_connection, s, addr.to_string())
        })
    };

    if config.enable_unix_sock {
        #[cfg(unix)]
        proc_println!("launched verifier interface at {}", UNIX_SOCK_VERIFIER);
    } else {
        proc_println!(
            "launched verifier interface at port {}",
            config.verifier_port
        );
    }

    // open issuer
    let atl_for_issuer = atl.clone();
    let issuer =
        TlsServer::new(config.issuer_port, None, GLOBAL, issuer_config)?.spawn(move |s, addr| {
            let atl_for_this_connection = atl_for_issuer.clone();
            let acl_for_this_connection = acl.clone();
            issuer::handler(acl_for_this_connection, atl_for_this_connection, s, addr)
        });
    proc_println!("launched issuer interface at port {}", config.issuer_port);

    // Wait till either one of two ends
    tokio::select! {
        result = verifier => {
            proc_eprintln!("verifier interface ended. stopping issuer as well...");
            result
        },
        result = issuer => {
            proc_eprintln!("issuer interface ended. stopping verifier as well...");
            result
        },
    }
    .unwrap()
    .map_err(|e| Box::new(e) as Box<dyn Error>)
}
