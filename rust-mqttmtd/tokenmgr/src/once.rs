use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use libmqttmtd::auth_serv::issuer;
use rustls::ClientConfig;
use tokio::io::stdout;

use crate::tokenset::get_current_token_from_file;

pub async fn run_once(
    tls_config: Arc<ClientConfig>,
    token_sets_dir: Arc<PathBuf>,
    issuer_addr: SocketAddr,
    request: &issuer::Request,
) {
    let token_set = match get_current_token_from_file(
        token_sets_dir,
        issuer_addr,
        tls_config,
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

    if let Err(e) = token_set.write_current(&mut stdout()).await {
        eprintln!("error when writing out token: {}", e);
        return;
    }
}
