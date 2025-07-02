//! Issuer interface of auth server.

use crate::{
    acl::AccessControlList,
    atl::{AccessTokenList, TokenSet},
    issuer_eprintln, issuer_println,
};
use libmqttmtd::auth_serv::issuer;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use x509_parser::{extensions::GeneralName, nom::AsBytes, parse_x509_certificate};

macro_rules! send_issuer_err_resp_if_err {
    ($result:expr, $err_str:expr, $stream:expr, $addr:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                issuer_eprintln!($addr, $err_str, e);
                if let Err(send_err) = issuer::ResponseWriter::write_error_to(&mut $stream).await {
                    issuer_eprintln!(
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

/// Handler function that handles a new connection with a client through issuer
/// interface.
pub(crate) async fn handler<IO: AsyncRead + AsyncWrite + Unpin>(
    acl: Arc<AccessControlList>,
    atl: Arc<AccessTokenList>,
    mut stream: TlsStream<IO>,
    addr: SocketAddr,
) {
    // Parse request
    let req = send_issuer_err_resp_if_err!(
        issuer::Request::read_from(&mut stream).await,
        "error reading issuer request: {}",
        stream,
        addr
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
        issuer_eprintln!(addr, "failed to extract DNS name from SAN extension");
        if let Err(send_err) = issuer::ResponseWriter::write_error_to(&mut stream).await {
            issuer_eprintln!(
                addr,
                "Error sending out issuer (error) response: {}",
                send_err
            );
        };
        return;
    }
    let user_hostname = user_hostname.unwrap();

    // Check with ACL if access can be granted
    if !acl.check_if_allowed(&user_hostname, req.topic(), req.is_pub()) {
        issuer_eprintln!(addr, "failed ACL verification for {},{}", &user_hostname, req.topic()) ;
        if let Err(send_err) = issuer::ResponseWriter::write_error_to(&mut stream).await {
            issuer_eprintln!(
                addr,
                "Error sending out issuer (error) response: {}",
                send_err
            );
        };
        return;
    }

    // Create a token set
    let token_set = send_issuer_err_resp_if_err!(
        TokenSet::new(
            req.num_tokens_divided_by_4(),
            req.topic().to_string(),
            req.is_pub(),
            Duration::from_secs(300),
            req.algo(),
        ),
        "error acquiring atl write lock: {}",
        stream,
        addr
    );

    // File a token_set
    let (resp, _) = send_issuer_err_resp_if_err!(
        atl.file(token_set).await,
        "error issuing a token set: {}",
        stream,
        addr
    );

    // Send success response
    if let Err(e) = resp.write_success_to(&mut stream).await {
        issuer_eprintln!(addr, "error sending out issuer response: {}", e);
    } else {
        issuer_println!(addr, "Issuer response sent out");
    }
}
