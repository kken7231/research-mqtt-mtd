use crate::errors::TokenFetchError;
use libmqttmtd::{auth_serv::issuer, socket::tls::TlsClient};
use std::sync::Arc;
use tokio::net::ToSocketAddrs;

// pub mod config;
pub mod errors;
pub mod tokenset;

pub async fn fetch_tokens(
    issuer_addr: &str,
    tls_config: Arc<rustls::ClientConfig>,
    request: &issuer::Request,
) -> Result<issuer::ResponseReader, TokenFetchError> {
    // Connect to the issuer
    let mut issuer_stream = TlsClient::new(issuer_addr, None, tls_config)
        .map_err(|e| TokenFetchError::IssuerConnectError(e))?
        .connect("server")
        .await
        .map_err(|e| TokenFetchError::IssuerConnectError(e))?;

    // Write a request
    request
        .write_to(&mut issuer_stream)
        .await
        .map_err(|e| TokenFetchError::SocketWriteError(e))?;

    // Read the response
    if let Some(success_response) = issuer::ResponseReader::read_from(
        &mut issuer_stream,
        request.algo(),
        request.num_tokens_divided_by_4(),
    )
    .await
    .map_err(|e| TokenFetchError::SocketReadError(e))?
    {
        Ok(success_response)
    } else {
        eprintln!("issuing tokens failed on server side");
        Err(TokenFetchError::ErrorResponseFromIssuer)
    }
}
