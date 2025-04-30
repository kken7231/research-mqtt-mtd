//! Verifier interface of auth server.

use std::{net::SocketAddr, sync::Arc};

use libmqttmtd::auth_serv::verifier;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{atl::AccessTokenList, authserver_verifier_eprintln, authserver_verifier_println};

const REQ_RESP_MIN_BUFLEN: usize = if verifier::REQUEST_MIN_BUFLEN > verifier::RESPONSE_MIN_BUFLEN {
    verifier::RESPONSE_MIN_BUFLEN
} else {
    verifier::REQUEST_MIN_BUFLEN
};

macro_rules! send_verifier_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr, $buf:expr) => { // Accept two expressions: the Result and the error string
        match $result {
            Ok(v) => v,
            Err(e) => {
                authserver_verifier_eprintln!($addr, $err_str, e); // Use the provided error string expression
                // Assuming ResponseWriter, stream, and buf are available in the scope where the macro is used
                if let Err(send_err) = verifier::ResponseWriter::write_error_to(&mut $stream, &mut $buf[..]).await {
                    authserver_verifier_eprintln!($addr, "Error sending out verifier (error) response: {}", send_err);
                };
                return;
            }
        }
    };
}

pub async fn handler(
    atl: Arc<AccessTokenList>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    addr: SocketAddr,
) {
    let mut buf = [0u8; REQ_RESP_MIN_BUFLEN];

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
    let result = if let Some(token_set) = token_set {
        let token_set = token_set.read().await;
        verifier::ResponseWriter::new(
            token_set.is_pub(),
            token_set.aead_algo(),
            &token_set.current_nonce()[..],
            token_set.topic(),
            token_set.enc_key(),
        )
        .write_success_to(&mut stream, &mut buf[..])
        .await
    } else {
        verifier::ResponseWriter::write_failure_to(&mut stream, &mut buf[..]).await
    };

    if let Err(e) = result {
        authserver_verifier_eprintln!(addr, "error sending out verifier response: {}", e);
    } else {
        authserver_verifier_println!(addr, "Verifier response sent out")
    }
}
