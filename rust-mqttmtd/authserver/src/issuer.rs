//! Issuer interface of auth server.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use libmqttmtd::auth_serv::issuer;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::acl::AccessControlList;
use crate::{
    atl::{AccessTokenList, TokenSet},
    authserver_verifier_eprintln, authserver_verifier_println,
};

/// Minimum required buffer length for the buf for both request parsing and response parsing.
const REQ_RESP_MIN_BUFLEN: usize = if issuer::REQUEST_MIN_BUFLEN > issuer::RESPONSE_MIN_BUFLEN {
    issuer::RESPONSE_MIN_BUFLEN
} else {
    issuer::REQUEST_MIN_BUFLEN
};

macro_rules! send_issuer_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr, $buf:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                authserver_verifier_eprintln!($addr, $err_str, e);
                if let Err(send_err) =
                    issuer::ResponseWriter::write_error_to(&mut $stream, &mut $buf[..]).await
                {
                    authserver_verifier_eprintln!(
                        $addr,
                        "Error sending out issuer (error) response: {}",
                        send_err
                    );
                };
                return;
            }
        }
    };
}

/// Handler function that handles a new connection with a client through issuer interface.
pub(crate) async fn handler(
    acl: Arc<AccessControlList>,
    atl: Arc<AccessTokenList>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    addr: SocketAddr,
) {
    let mut buf = [0u8; REQ_RESP_MIN_BUFLEN];

    // Parse request
    let req = send_issuer_err_resp_if_err!(
        issuer::Request::read_from(&mut stream, &mut buf[..]).await,
        "error reading issuer request: {}",
        stream,
        addr,
        buf
    );

    // Check with ACL if access can be granted
    if !acl.check_if_allowed("localhost", req.topic(), req.is_pub()) {
        authserver_verifier_eprintln!(addr, "failed ACL verification");
        if let Err(send_err) =
            issuer::ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await
        {
            authserver_verifier_eprintln!(
                addr,
                "Error sending out issuer (error) response: {}",
                send_err
            );
        };
        return;
    }

    // Create a token set
    let token_set = send_issuer_err_resp_if_err!(
        TokenSet::create_without_rand_init(
            req.num_tokens_divided_by_4(),
            req.topic().to_string(),
            req.is_pub(),
            Duration::from_secs(300),
            req.aead_algo(),
        ),
        "error acquiring atl write lock: {}",
        stream,
        addr,
        buf
    );

    // File a token_set
    let (token_set, masked_timestamp) = send_issuer_err_resp_if_err!(
        atl.file(token_set).await,
        "error issuing a token set: {}",
        stream,
        addr,
        buf
    );

    // Acquire a read lock of the filed token_set
    let token_set = token_set.read().await;

    // Get parameters
    let enc_key = token_set.enc_key();
    let nonce_base = token_set.nonce_base();
    let mut timestamp = [0u8; 6];
    timestamp[..].copy_from_slice(&masked_timestamp.to_be_bytes()[2..8]);
    let all_randoms = token_set.all_randoms();

    // Send success response
    if let Err(e) = issuer::ResponseWriter::new(&enc_key, &nonce_base, timestamp, &all_randoms)
        .write_success_to(&mut stream, &mut buf[..])
        .await
    {
        authserver_verifier_eprintln!(addr, "error sending out issuer response: {}", e);
    } else {
        authserver_verifier_println!(addr, "Issuer response sent out");
    }
}
