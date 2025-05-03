pub mod config;
pub mod once;
pub mod server;
pub mod tokenset;

use crate::config::{CliArgs, load_config};
use clap::Parser;
use libmqttmtd::{
    aead::algo::SupportedAlgorithm, auth_serv::issuer, socket::tls_config::TlsConfigLoader,
};
use once::run_once;
use server::run_server;
use std::{net::ToSocketAddrs, path::Path, sync::Arc};

pub async fn process() {
    let cli_args: CliArgs = CliArgs::parse();

    // Load configuration from file, allowing overrides from command line
    let config = match load_config(&cli_args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            return;
        }
    };

    let tls_config = match TlsConfigLoader::load_client_config(
        &config.cli_cert,
        &config.cli_key,
        &config.ca_certs_dir,
        config.client_auth_disabled,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error when constructing tls client config: {}", e);
            return;
        }
    };

    let token_sets_dir = Arc::new(Path::new(&config.token_sets_dir).to_owned());
    let issuer_addr =
        match format!("{}:{}", config.issuer_host, config.issuer_port).to_socket_addrs() {
            Ok(mut addr) => match addr.next() {
                Some(addr) => addr,
                None => {
                    eprintln!("address not found when formatting issuer address");
                    return;
                }
            },
            Err(e) => {
                eprintln!("error when formatting issuer address: {}", e);
                return;
            }
        };

    if config.run_server {
        run_server(tls_config, token_sets_dir, issuer_addr, config.server_port);
    } else {
        let aead_algo = match cli_args.algo.as_str() {
            "AES_128_GCM" => SupportedAlgorithm::Aes128Gcm,
            "AES_256_GCM" => SupportedAlgorithm::Aes256Gcm,
            "CHACHA20_POLY1305" => SupportedAlgorithm::Chacha20Poly1305,
            _ => {
                eprintln!("invalid AEAD algorithm: {}", cli_args.algo);
                return;
            }
        };

        let request = issuer::Request::new(
            cli_args.is_pub,
            ((cli_args.num_tokens / 4) & 0x7F) as u8,
            aead_algo,
            cli_args.topic,
        );
        run_once(tls_config, token_sets_dir, issuer_addr, &request).await;
    }
}
