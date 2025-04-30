use std::{net::ToSocketAddrs, path::Path, sync::Arc};

use clap::Parser;
use libmqttmtd::{
    aead::algo::SupportedAlgorithm, auth_serv::issuer, socket::tls_config::TlsConfigLoader,
};
use once::run_once;
use server::run_server;

pub mod once;
pub mod server;
pub mod tokenset;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct CliArgs {
    /// run server if true, otherwise run once
    #[arg(long, default_value_t = false)]
    run_server: bool,

    /// Auth Server issuer hostname
    #[arg(long, default_value = "issuer")]
    issuer_host: String,

    /// Auth Server issuer port
    #[arg(long, default_value_t = 3002)]
    issuer_port: u16,

    /// token sets directory
    #[arg(long, default_value = "./tokens")]
    token_sets_dir: String,

    /// client cert file
    #[arg(long, default_value = "./certs/client/cert.crt")]
    cli_cert: String,

    /// client key file
    #[arg(long, default_value = "./certs/client/key.pem")]
    cli_key: String,

    /// ca certs directory
    #[arg(long, default_value = "./certs/ca/cert.crt")]
    ca_cert: String,

    /// ca certs directory
    #[arg(long, default_value_t = false)]
    client_auth_disabled: bool,

    // for run_server
    /// port of the server
    #[arg(long, default_value_t = 3000)]
    server_port: u16,

    // for run_once
    /// is access for publish or subscribe
    #[arg(long, default_value_t = true)]
    is_pub: bool,

    /// Topic Name / Filters
    #[arg(long)]
    topic: String,

    /// num_tokens divided by 4. must be dividable by 4
    #[arg(long, default_value_t = 4)]
    num_tokens: u16,

    /// aead algorithm. AES_128_GCM, AES_256_GCM or CHACHA20_POLY1305
    #[arg(long, default_value = "AES_256_GCM")]
    algo: String,
}

pub async fn process() {
    // Parse command-line arguments
    let args = CliArgs::parse();

    let aead_algo = match args.algo.as_str() {
        "AES_128_GCM" => SupportedAlgorithm::Aes128Gcm,
        "AES_256_GCM" => SupportedAlgorithm::Aes256Gcm,
        "CHACHA20_POLY1305" => SupportedAlgorithm::Chacha20Poly1305,
        _ => {
            eprintln!("invalid AEAD algorithm: {}", args.algo);
            return;
        }
    };

    let config = match TlsConfigLoader::load_client_config(
        &args.cli_cert,
        &args.cli_key,
        &args.ca_cert,
        args.client_auth_disabled,
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error when constructing tls client config: {}", e);
            return;
        }
    };

    let token_sets_dir = Arc::new(Path::new(&args.token_sets_dir).to_owned());
    let issuer_addr = match format!("{}:{}", args.issuer_host, args.issuer_port).to_socket_addrs() {
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

    if args.run_server {
        run_server(config, token_sets_dir, issuer_addr, args.server_port);
    } else {
        let request = issuer::Request::new(
            args.is_pub,
            ((args.num_tokens / 4) & 0x7F) as u8,
            aead_algo,
            args.topic,
        );
        run_once(config, token_sets_dir, issuer_addr, &request).await;
    }
}
