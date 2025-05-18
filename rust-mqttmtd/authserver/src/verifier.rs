//! Verifier interface of auth server.

use std::{net::SocketAddr, sync::Arc};

use libmqttmtd::auth_serv::verifier;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{atl::AccessTokenList, verifier_eprintln, verifier_println};

macro_rules! send_verifier_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr, $buf:expr) => { // Accept two expressions: the Result and the error string
        match $result {
            Ok(v) => v,
            Err(e) => {
                verifier_eprintln!($addr, $err_str, e); // Use the provided error string expression
                // Assuming ResponseWriter, stream, and buf are available in the scope where the macro is used
                if let Err(send_err) = verifier::ResponseWriter::write_error_to(&mut $stream, &mut $buf[..]).await {
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
    let mut buf = [0u8; verifier::REQ_RESP_MIN_BUF_LEN];

    // Parse request
    let req = send_verifier_err_resp_if_err!(
        verifier::Request::read_from(&mut stream).await,
        "error reading verifier request: {}",
        stream,
        addr,
        buf
    );

    // Verify request
    let token_set = send_verifier_err_resp_if_err!(
        atl.verify(&req.token()).await,
        "error acquiring atl write lock: {}",
        stream,
        addr,
        buf
    );

    // Send response
    let result = if let Some(resp_writer) = token_set {
        verifier_println!(addr, "Verification successful");
        resp_writer
            .write_success_to(&mut stream, &mut buf[..])
            .await
    } else {
        verifier_println!(addr, "Verification failed");
        verifier::ResponseWriter::write_failure_to(&mut stream, &mut buf[..]).await
    };

    if let Err(e) = result {
        verifier_eprintln!(addr, "error sending out verifier response: {}", e);
    } else {
        verifier_println!(addr, "Verifier response sent out")
    }
}
