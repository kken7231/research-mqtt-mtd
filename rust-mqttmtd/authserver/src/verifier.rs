//! Verifier interface of auth server.

use std::{net::SocketAddr, sync::Arc};

use libmqttmtd::auth_serv::verifier;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{atl::AccessTokenList, verifier_eprintln, verifier_println};

macro_rules! send_verifier_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr) => { 
        match $result {
            Ok(v) => v,
            Err(e) => {
                verifier_eprintln!($addr, $err_str, e);
                if let Err(send_err) = verifier::ResponseWriter::write_error_to(&mut $stream).await {
                    verifier_eprintln!($addr, "Error sending out verifier (error) response: {}", send_err);
                };
                return;
            }
        }
    };
}

/// Handler function that handles a new connection with a client through
/// verifier interface.
pub(crate) async fn handler(
    atl: Arc<AccessTokenList>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    addr: SocketAddr,
) {
    // Parse request
    let req = send_verifier_err_resp_if_err!(
        verifier::Request::read_from(&mut stream).await,
        "error reading verifier request: {}",
        stream,
        addr
    );

    // Verify request
    let token_set = send_verifier_err_resp_if_err!(
        atl.verify(&req.token()).await,
        "error acquiring atl write lock: {}",
        stream,
        addr
    );

    // Send response
    let result = if let Some(resp_writer) = token_set {
        verifier_println!(addr, "Verification successful");
        resp_writer
            .write_success_to(&mut stream)
            .await
    } else {
        verifier_println!(addr, "Verification failed");
        verifier::ResponseWriter::write_failure_to(&mut stream).await
    };

    if let Err(e) = result {
        verifier_eprintln!(addr, "error sending out verifier response: {}", e);
    } else {
        verifier_println!(addr, "Verifier response sent out")
    }
}
