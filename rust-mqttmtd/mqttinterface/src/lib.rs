mod config;
mod v4;
mod v5;

use crate::config::load_config;
use libmqttmtd::{
    consts::UNIX_SOCK_VERIFIER,
    localhost_v4,
    socket::plain::{server::PlainServer, tcp::TcpServerType::GLOBAL},
};
use std::error::Error;

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
    config
        .to_string_lines("MQTT Interface")
        .iter()
        .for_each(|line| println!("{}", line));

    #[cfg(not(unix))]
    if config.enable_unix_sock {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix domain sockets are not supported on this operating system",
        ));
    }

    // open server
    let server = if config.is_v3_1_1 {
        PlainServer::new_tcp(config.port, None, GLOBAL)?.spawn(move |s, addr| {
            let verifier_addr = if config.enable_unix_sock {
                UNIX_SOCK_VERIFIER.to_string()
            } else {
                localhost_v4!(config.verifier_port)
            };
            println!("verifier_addr: {}", verifier_addr);
            v4::client::handler(
                config.broker_host.clone(),
                config.broker_port,
                verifier_addr,
                config.enable_unix_sock,
                s,
                addr.to_string(),
            )
        })
    } else {
        PlainServer::new_tcp(config.port, None, GLOBAL)?.spawn(move |s, addr| {
            let verifier_addr = if config.enable_unix_sock {
                UNIX_SOCK_VERIFIER.to_string()
            } else {
                localhost_v4!(config.verifier_port)
            };
            println!("verifier_addr: {}", verifier_addr);
            v5::client::handler(
                config.broker_host.clone(),
                config.broker_port,
                verifier_addr,
                config.enable_unix_sock,
                s,
                addr.to_string(),
            )
        })
    };

    println!("launched mqtt interface at port {}", config.port);
    server.await??;
    Ok(())
}
