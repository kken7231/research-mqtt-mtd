use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use libmqttmtd::{auth_serv::issuer, socket::plain::PlainServer};
use rustls::ClientConfig;

use crate::tokenset_old::get_current_token_from_file;

pub fn run_server(
    tls_config: Arc<ClientConfig>,
    token_sets_dir: Arc<PathBuf>,
    issuer_addr: SocketAddr,
    server_port: u16,
) {
    let _server = PlainServer::new(server_port, None).spawn(move |mut s, addr| {
        let token_sets_dir_for_this_connection = token_sets_dir.clone();
        let issuer_addr_for_this_connection = issuer_addr.clone();
        let tls_config_for_this_connection = tls_config.clone();

        async move {
            let mut buf: [u8; 8] = [0u8; 8];
            let request = match issuer::Request::read_from(&mut s, &mut buf[..]).await {
                Err(e) => {
                    eprintln!(
                        "error found when reading issuer request from {}: {}",
                        addr, e
                    );
                    return;
                }
                Ok(req) => req,
            };

            let token_set = match get_current_token_from_file(
                token_sets_dir_for_this_connection,
                issuer_addr_for_this_connection,
                tls_config_for_this_connection,
                &request,
            )
                .await
            {
                Ok(token_set) => token_set,
                Err(e) => {
                    eprintln!("error when fetching token sets: {}", e);
                    return;
                }
            };

            if let Err(e) = token_set.write_current(&mut s).await {
                eprintln!("error when writing out token: {}", e);
                return;
            }
        }
    });
    loop {}
}
