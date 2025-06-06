use clap::Args;
use config::{Config, ConfigError, File};
use libmqttmtd_macros::ToStringLines;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Formatter,
    fs,
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime};

#[derive(Args)]
pub struct CertgenArgs {
    /// Output directory for generated certificates and keys. Overrides config
    /// file.
    #[arg(short, long)]
    output_dir: Option<String>,

    /// Key algorithm to use (rsa, ed25519, ecdsa). Overrides config file.
    #[arg(short, long)]
    key_algo: Option<String>,

    /// Key size for RSA algorithm (e.g., 2048, 4096). Ignored for other
    /// algorithms. Overrides config file.
    #[arg(long)]
    rsa_key_size: Option<u64>,

    /// Curve for ECDSA (256 or 384). Ignored for other algorithms. Overrides
    /// config file.
    #[arg(long)]
    ecdsa_curve: Option<u64>,

    /// Common Name for the CA certificate. Overrides config file.
    #[arg(long)]
    ca_cn: Option<String>,

    /// Common Name for the server certificate. Overrides config file.
    #[arg(long)]
    server_cn: Option<String>,

    /// Common Names for client certificates (can be specified multiple times).
    /// Overrides config file.
    #[arg(short, long)]
    client_cn: Vec<String>,

    /// Validity period of certificates in days. Overrides config file.
    /// Overrides config file.
    #[arg(long)]
    validity_days: Option<i64>,

    /// conf file that sets parameters
    #[arg(long, default_value = "./conf/certgen.conf")]
    conf: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToStringLines)]
pub struct CertgenConfig {
    pub output_dir: PathBuf,
    pub key_algo: String,
    pub rsa_key_size: usize,
    pub ecdsa_curve: usize,
    pub ca_cn: String,
    pub server_cn: String,
    pub client_cn: Vec<String>,
    pub validity_days: i64,
}
fn load_config(args: CertgenArgs) -> Result<CertgenConfig, ConfigError> {
    let mut builder = Config::builder()
        .set_default("output_dir", "./")?
        .set_default("key_algo", "rsa")?
        .set_default("rsa_key_size", 2048)?
        .set_default("ecdsa_curve", 256)?
        .set_default("ca_cn", "ca")?
        .set_default("server_cn", "server")?
        .set_default("client_cn", Vec::<String>::new())?
        .set_default("validity_days", 365)?
        .add_source(File::with_name(&args.conf).required(false));

    if let Some(value) = args.output_dir {
        builder = builder.set_override("output_dir", value)?;
    }
    if let Some(value) = args.key_algo {
        builder = builder.set_override("key_algo", value)?;
    }
    if let Some(value) = args.rsa_key_size {
        builder = builder.set_override("rsa_key_size", value)?;
    }
    if let Some(value) = args.ecdsa_curve {
        builder = builder.set_override("ecdsa_curve", value)?;
    }
    if let Some(value) = args.ca_cn {
        builder = builder.set_override("ca_cn", value)?;
    }
    if let Some(value) = args.server_cn {
        builder = builder.set_override("server_cn", value)?;
    }
    if args.client_cn.len() > 0 {
        builder = builder.set_override("client_cn", args.client_cn)?;
    }
    if let Some(value) = args.validity_days {
        builder = builder.set_override("validity_days", value)?;
    }

    let mut config: CertgenConfig = builder.build()?.try_deserialize()?;

    // Replace ~ with homedir
    if let Some(resolved) = resolve_tilde(&config.output_dir) {
        config.output_dir = resolved;
    }

    Ok(config)
}

fn resolve_tilde(path: &Path) -> Option<PathBuf> {
    if path.starts_with("~") {
        let mut new_path = path
            .to_str()
            .expect("failed to convert PathBuf to string")
            .to_owned();
        new_path.replace_range(
            0..1,
            dirs::home_dir()
                .expect("failed to get home dir")
                .to_str()
                .expect("failed to convert home dir to str"),
        );
        Some(PathBuf::from(new_path))
    } else {
        None
    }
}

/// Generates a key pair based on the specified algorithm and RSA key size,
/// using the 'ring' crate.
fn generate_key_pair(
    algo: &str,
    rsa_key_size: usize,
    ecdsa_curve: usize,
) -> Result<KeyPair, CertgenError> {
    let sign_algo = match algo.to_lowercase().as_str() {
        "rsa" => match rsa_key_size {
            2048 => &PKCS_RSA_SHA256,
            3072 => &PKCS_RSA_SHA384,
            4096 => &PKCS_RSA_SHA512,
            _ => return Err(CertgenError::InvalidRSAKeySizeError(rsa_key_size)),
        },
        "ed25519" => &PKCS_ED25519,
        "ecdsa" => match ecdsa_curve {
            256 => &PKCS_ECDSA_P256_SHA256,
            384 => &PKCS_ECDSA_P384_SHA384,
            _ => return Err(CertgenError::InvalidECDSACurveError(ecdsa_curve)),
        },
        unknown => return Err(CertgenError::UnknownKeyAlgoError(unknown.to_owned())),
    };
    Ok(KeyPair::generate_for(sign_algo).map_err(|e| CertgenError::KeyGenerationFailedError(e))?)
}

/// Saves a PEM-encoded key pair and certificate to specified paths.
fn save_key_and_cert(
    key_pair: &KeyPair,
    cert: &Certificate,
    key_path: &Path,
    cert_path: &Path,
) -> Result<(), std::io::Error> {
    fs::write(key_path, key_pair.serialize_pem())?;
    fs::write(cert_path, cert.pem())?;
    Ok(())
}

pub fn certgen(args: CertgenArgs) -> Result<(), CertgenError> {
    // Parse command-line arguments
    let config = load_config(args).map_err(|e| CertgenError::LoadConfigFailedError(e))?;

    config
        .to_string_lines("certgen")
        .iter()
        .for_each(|line| println!("{}", line));

    // Create output directories
    if let Err(_) = fs::create_dir_all(&config.output_dir) {
        return Err(CertgenError::DirCreationFailedError(config.output_dir));
    }
    let ca_dir = config.output_dir.join("ca");
    if let Err(_) = fs::create_dir_all(&ca_dir) {
        return Err(CertgenError::DirCreationFailedError(ca_dir));
    }
    let server_dir = config.output_dir.join("server");
    if let Err(_) = fs::create_dir_all(&server_dir) {
        return Err(CertgenError::DirCreationFailedError(server_dir));
    }
    let clients_dir = config.output_dir.join("clients");
    if let Err(_) = fs::create_dir_all(&clients_dir) {
        return Err(CertgenError::DirCreationFailedError(clients_dir));
    }

    // Calculate validity dates
    let now = OffsetDateTime::now_utc();
    let not_before = now;
    let not_after = now + Duration::days(config.validity_days);

    // 1. Generate CA certificate and key
    println!("Generating CA certificate and key...");
    let ca_key_pair = generate_key_pair(&config.key_algo, config.rsa_key_size, config.ecdsa_curve)?;
    let mut ca_params = CertificateParams::new(vec![config.ca_cn.clone()])
        .expect("error on constructing ca certificate");
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, config.ca_cn.as_str());
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .map_err(|e| CertgenError::CertSigningFailedError(e))?;
    let ca_key_path = ca_dir.join("ca.pem");
    let ca_cert_path = ca_dir.join("ca.crt");
    save_key_and_cert(&ca_key_pair, &ca_cert, &ca_key_path, &ca_cert_path)
        .map_err(|e| CertgenError::SaveKeyCertFailedError(e))?;
    println!(
        "CA certificate and key saved to {:?} and {:?}",
        ca_cert_path, ca_key_path
    );

    // 2. Generate Server certificate and key, signed by CA
    println!("Generating Server certificate and key...");
    let server_key_pair =
        generate_key_pair(&config.key_algo, config.rsa_key_size, config.ecdsa_curve)?;
    let mut server_params = CertificateParams::new(vec![config.server_cn.clone()])
        .expect("error on constructing server certificate");
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, config.server_cn.as_str());
    server_params.distinguished_name = server_dn;
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.not_before = not_before;
    server_params.not_after = not_after;
    let server_cert = server_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .map_err(|e| CertgenError::CertSigningFailedError(e))?;
    let server_key_path = server_dir.join("server.pem");
    let server_cert_path = server_dir.join("server.crt");
    save_key_and_cert(
        &server_key_pair,
        &server_cert,
        &server_key_path,
        &server_cert_path,
    )
    .map_err(|e| CertgenError::SaveKeyCertFailedError(e))?;
    println!(
        "Server certificate and key saved to {:?} and {:?}",
        server_cert_path, server_key_path
    );

    // 3. Generate Client certificates and keys, signed by CA
    println!("Generating Client certificates and keys...");
    for client_cn in &config.client_cn {
        println!("  Generating client: {}", client_cn);
        let client_key_pair =
            generate_key_pair(&config.key_algo, config.rsa_key_size, config.ecdsa_curve)?;
        let mut client_params = CertificateParams::new(vec![client_cn.clone()])
            .expect("error on constructing server certificate");
        let mut client_dn = DistinguishedName::new();
        client_dn.push(DnType::CommonName, client_cn.as_str());
        client_params.distinguished_name = client_dn;
        client_params.is_ca = IsCa::NoCa;
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.not_before = not_before;
        client_params.not_after = not_after;
        let client_cert = client_params
            .signed_by(&client_key_pair, &ca_cert, &ca_key_pair)
            .map_err(|e| CertgenError::CertSigningFailedError(e))?;
        let client_key_path = clients_dir.join(format!("{}.pem", client_cn));
        let client_cert_path = clients_dir.join(format!("{}.crt", client_cn));
        save_key_and_cert(
            &client_key_pair,
            &client_cert,
            &client_key_path,
            &client_cert_path,
        )
        .map_err(|e| CertgenError::SaveKeyCertFailedError(e))?;
        println!(
            "  Client certificate and key saved to {:?} and {:?}",
            client_cert_path, client_key_path
        );
    }

    println!("Certificate generation complete!");
    Ok(())
}

#[derive(Debug)]
pub enum CertgenError {
    LoadConfigFailedError(ConfigError),
    DirCreationFailedError(PathBuf),
    UnknownKeyAlgoError(String),
    InvalidRSAKeySizeError(usize),
    InvalidECDSACurveError(usize),
    KeyGenerationFailedError(rcgen::Error),
    CertSigningFailedError(rcgen::Error),
    SaveKeyCertFailedError(std::io::Error),
}

impl std::error::Error for CertgenError {}

impl std::fmt::Display for CertgenError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CertgenError::LoadConfigFailedError(e) => {
                write!(f, "failed to load configuration {}", e)
            }
            CertgenError::DirCreationFailedError(path) => {
                write!(f, "failed to create a directory at {:?}", path)
            }
            CertgenError::UnknownKeyAlgoError(s) => {
                write!(f, "unknown key algo entered: {}", s)
            }
            CertgenError::InvalidRSAKeySizeError(u) => {
                write!(f, "invalid rsa key size entered: {}", u)
            }
            CertgenError::InvalidECDSACurveError(u) => {
                write!(f, "invalid ecdsa curve entered: {}", u)
            }
            CertgenError::KeyGenerationFailedError(e) => {
                write!(f, "generating keypair failed: {}", e)
            }
            CertgenError::CertSigningFailedError(e) => {
                write!(f, "signing certificate failed: {}", e)
            }
            CertgenError::SaveKeyCertFailedError(e) => {
                write!(f, "save key/cert failed: {}", e)
            }
        }
    }
}
