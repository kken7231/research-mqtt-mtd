//! Issuer interface of auth server.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::acl::AccessControlList;
use crate::{
    atl::{AccessTokenList, TokenSet},
    authserver_issuer_eprintln, authserver_issuer_println,
};
use libmqttmtd::auth_serv::issuer;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use x509_parser::extensions::GeneralName;
use x509_parser::nom::AsBytes;
use x509_parser::parse_x509_certificate;

macro_rules! send_issuer_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr, $buf:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                authserver_issuer_eprintln!($addr, $err_str, e);
                if let Err(send_err) =
                    issuer::ResponseWriter::write_error_to(&mut $stream, &mut $buf[..]).await
                {
                    authserver_issuer_eprintln!(
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
pub(crate) async fn handler<IO: AsyncRead + AsyncWrite + Unpin>(
    acl: Arc<AccessControlList>,
    atl: Arc<AccessTokenList>,
    mut stream: TlsStream<IO>,
    addr: SocketAddr,
) {
    let mut buf = [0u8; issuer::REQ_RESP_MIN_BUFLEN];

    // Parse request
    let req = send_issuer_err_resp_if_err!(
        issuer::Request::read_from(&mut stream, &mut buf[..]).await,
        "error reading issuer request: {}",
        stream,
        addr,
        buf
    );

    // Get the peer certificates
    let user_hostname =
        stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| {
                certificates.get(0).and_then(|cert_der| {
                    parse_x509_certificate(cert_der.as_bytes())
                        .ok()
                        .and_then(|(_, certificate)| {
                            certificate.subject_alternative_name().ok().and_then(|opt| {
                                opt.and_then(|san_extension| {
                                    // Get the first DNS SAN
                                    san_extension.value.general_names.iter().find_map(
                                        |general_name| match general_name {
                                            GeneralName::DNSName(name) => Some(name.to_string()),
                                            _ => None,
                                        },
                                    )
                                })
                            })
                        })
                })
            });
    if user_hostname == None {
        authserver_issuer_eprintln!(addr, "failed to extract DNS name from SAN extension");
        if let Err(send_err) =
            issuer::ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await
        {
            authserver_issuer_eprintln!(
                addr,
                "Error sending out issuer (error) response: {}",
                send_err
            );
        };
        return;
    }
    let user_hostname = user_hostname.unwrap();

    // Check with ACL if access can be granted
    if !acl.check_if_allowed(user_hostname, req.topic(), req.is_pub()) {
        authserver_issuer_eprintln!(addr, "failed ACL verification");
        if let Err(send_err) =
            issuer::ResponseWriter::write_error_to(&mut stream, &mut buf[..]).await
        {
            authserver_issuer_eprintln!(
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
    timestamp[..].copy_from_slice(&masked_timestamp.to_be_bytes()[1..7]);
    let all_randoms = token_set.all_randoms();

    // Send success response
    if let Err(e) = issuer::ResponseWriter::new(&enc_key, &nonce_base, timestamp, &all_randoms)
        .write_success_to(&mut stream, &mut buf[..])
        .await
    {
        authserver_issuer_eprintln!(addr, "error sending out issuer response: {}", e);
    } else {
        authserver_issuer_println!(addr, "Issuer response sent out");
    }
}
