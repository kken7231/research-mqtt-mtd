use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{ffi::OsStr, fs, path::Path, sync::Arc};

use super::error::LoadTLSConfigError;

pub struct TlsConfigLoader {}

impl TlsConfigLoader {
    pub fn load_server_config(
        serv_cert_pem: impl AsRef<Path>,
        serv_key_pem: impl AsRef<Path>,
        cli_certs_dir: impl AsRef<Path>,
        no_client_auth: bool,
    ) -> Result<Arc<rustls::ServerConfig>, LoadTLSConfigError> {
        // Load server certificate
        let serv_cert = CertificateDer::from_pem_file(&serv_cert_pem)?;
        println!(
            "Server certificate loaded from {:?}",
            serv_cert_pem.as_ref()
        );

        // Load server key
        let key = PrivateKeyDer::from_pem_file(&serv_key_pem)?;
        println!("Server key loaded from {:?}", serv_key_pem.as_ref());

        // Load client sertificates for mutual authentication
        let mut cli_roots = RootCertStore::empty();
        if !no_client_auth {
            for entry in fs::read_dir(cli_certs_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_file() && path.extension() == Some(OsStr::new("crt")) {
                    let cli_cert = CertificateDer::from_pem_file(&path)?;
                    cli_roots.add(cli_cert)?;
                    println!(
                        "Client cert loaded from {}",
                        path.to_str().unwrap_or("FILENAME_UNAVAILABLE")
                    );
                }
            }
        }

        // Create server config
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?;

        let config = if !no_client_auth {
            let cli_cert_verfier = WebPkiClientVerifier::builder(cli_roots.into()).build()?;
            /* (!important) Making one of these is cheap, though one of the inputs may be expensive:
            gathering trust roots from the operating system to add to the RootCertStore passed to a
            ClientCertVerifier builder may take on the order of a few hundred milliseconds.*/
            config.with_client_cert_verifier(cli_cert_verfier)
        } else {
            config.with_no_client_auth()
        };
        let config = config.with_single_cert(vec![serv_cert], key)?;

        Ok(config.into())
    }

    pub fn load_client_config(
        cli_cert_pem: impl AsRef<Path>,
        cli_key_pem: impl AsRef<Path>,
        ca_certs_dir: impl AsRef<Path>,
        no_client_auth: bool,
    ) -> Result<Arc<rustls::ClientConfig>, LoadTLSConfigError> {
        // Load client sertificate
        let cli_cert = CertificateDer::from_pem_file(&cli_cert_pem)?;
        println!("Client certificate loaded from {:?}", cli_cert_pem.as_ref());

        // Load client key
        let key = PrivateKeyDer::from_pem_file(&cli_key_pem)?;
        println!("Client key loaded from {:?}", cli_key_pem.as_ref());

        // Load CA certs
        let mut ca_roots = RootCertStore::empty();
        for entry in fs::read_dir(ca_certs_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension() == Some(OsStr::new("crt")) {
                let ca_cert = CertificateDer::from_pem_file(&path)?;
                ca_roots.add(ca_cert)?;
                println!(
                    "CA cert loaded from {}",
                    path.to_str().unwrap_or("FILENAME_UNAVAILABLE")
                );
            }
        }

        let config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(ca_roots);

        let config = if !no_client_auth {
            config.with_client_auth_cert(vec![cli_cert], key)?
        } else {
            config.with_no_client_auth()
        };

        Ok(config.into())
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::crypto::CryptoProvider;
    use std::{
        fs::{File, create_dir_all},
        io::Write,
    };
    use tempfile::tempdir;

    use super::*;

    fn install_provider() {
        if let None = CryptoProvider::get_default() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("failed to install default provider");
        };
    }

    fn create_cert_key_file(file_dir: impl AsRef<Path>) -> (File, File) {
        if !file_dir.as_ref().exists() {
            create_dir_all(&file_dir).expect("failed to create a parent directory");
        }

        // Paths
        let cert_path = file_dir.as_ref().join("cert.crt");
        let key_path = file_dir.as_ref().join("key.pem");

        // Generate cert
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("failed to generate a cert");

        // Save files
        let mut cert_file = File::create(&cert_path).expect("failed to create a cert file");
        cert_file
            .write_all(cert.pem().as_bytes())
            .expect("failed to write a cert file");
        let mut key_file = File::create(&key_path).expect("failed to create a key file");
        key_file
            .write_all(key_pair.serialize_pem().as_bytes())
            .expect("failed to write a key file");

        (cert_file, key_file)
    }

    #[test]
    fn serv_config_has_cli_auth_pass() {
        const NO_CLIENT_AUTH: bool = false;
        install_provider();

        let temp_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_serv_cert");
        let _ = create_cert_key_file(&temp_dir);

        let cli_certs_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_cli_certs");
        let _ = create_cert_key_file(&cli_certs_dir);

        let config = TlsConfigLoader::load_server_config(
            temp_dir.join("cert.crt"),
            temp_dir.join("key.pem"),
            cli_certs_dir,
            NO_CLIENT_AUTH,
        );

        assert!(config.is_ok());
    }

    #[test]
    fn serv_config_no_cli_auth_pass() {
        const NO_CLIENT_AUTH: bool = true;
        install_provider();

        let temp_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_serv_cert");
        let _ = create_cert_key_file(&temp_dir);

        let cli_certs_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_cli_certs");
        let _ = create_cert_key_file(&cli_certs_dir);

        let config = TlsConfigLoader::load_server_config(
            temp_dir.join("cert.crt"),
            temp_dir.join("key.pem"),
            cli_certs_dir,
            NO_CLIENT_AUTH,
        );

        assert!(config.is_ok());
    }

    #[test]
    fn cli_config_has_cli_auth_pass() {
        const NO_CLIENT_AUTH: bool = false;
        install_provider();

        let temp_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_cli_certs");
        let _ = create_cert_key_file(&temp_dir);

        let ca_certs_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_ca_certs");
        let _ = create_cert_key_file(&ca_certs_dir);

        let config = TlsConfigLoader::load_client_config(
            temp_dir.join("cert.crt"),
            temp_dir.join("key.pem"),
            ca_certs_dir,
            NO_CLIENT_AUTH,
        );

        assert!(config.is_ok());
    }

    #[test]
    fn cli_config_no_cli_auth_pass() {
        const NO_CLIENT_AUTH: bool = true;
        install_provider();

        let temp_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_cli_certs");
        let _ = create_cert_key_file(&temp_dir);

        let ca_certs_dir = tempdir()
            .expect("failed to create temp dir")
            .as_ref()
            .join("sample_ca_certs");
        let _ = create_cert_key_file(&ca_certs_dir);

        let config = TlsConfigLoader::load_client_config(
            temp_dir.join("cert.crt"),
            temp_dir.join("key.pem"),
            ca_certs_dir,
            NO_CLIENT_AUTH,
        );

        assert!(config.is_ok());
    }
}
