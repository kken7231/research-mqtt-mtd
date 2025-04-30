use clap::Parser;
use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyUsagePurpose, KeyPair, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512, PKCS_ED25519, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, IsCa};
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use time::{OffsetDateTime, Duration};

/// Command-line arguments for the certificate generator.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output directory for generated certificates and keys.
    #[arg(short, long)]
    output_dir: PathBuf,

    /// Key algorithm to use (rsa, ed25519, ecdsa).
    #[arg(short, long, default_value = "rsa")]
    key_algo: String,

    /// Key size for RSA algorithm (e.g., 2048, 4096). Ignored for other algorithms.
    #[arg(long, default_value = "2048")]
    rsa_key_size: usize,

    /// Curve for ECDSA (256 or 384). Ignored for other algorithms.
    #[arg(long, default_value = "256")]
    ecdsa_curve: usize,

    /// Common Name for the CA certificate.
    #[arg(long, default_value = "My Test CA")]
    ca_cn: String,

    /// Common Name for the server certificate.
    #[arg(long, default_value = "localhost")]
    server_cn: String,

    /// Common Names for client certificates (can be specified multiple times).
    #[arg(short, long)]
    client_cn: Vec<String>,

    /// Validity period of certificates in days.
    #[arg(long, default_value = "365")]
    validity_days: i64,
}

/// Generates a key pair based on the specified algorithm and RSA key size, using the 'ring' crate.
fn generate_key_pair(algo: &str, rsa_key_size: usize, ecdsa_curve: usize) -> Result<KeyPair> {
    let sign_algo = match algo.to_lowercase().as_str() {
        "rsa" => {
            match rsa_key_size {
                2048 => &PKCS_RSA_SHA256,
                3072 => &PKCS_RSA_SHA384,
                4096 => &PKCS_RSA_SHA512,
                _ => return Err(anyhow::anyhow!("Unsupported RSA key size: {}", rsa_key_size)),
            }
        },
        "ed25519" => {
            &PKCS_ED25519
        },
        "ecdsa" => {
            match ecdsa_curve {
                256 => &PKCS_ECDSA_P256_SHA256,
                384 => &PKCS_ECDSA_P384_SHA384,
                _ => return Err(anyhow::anyhow!("Unsupported ECDSA curve: {}", ecdsa_curve)),
            }
        },
        _ => return Err(anyhow::anyhow!("Unsupported key algorithm: {}", algo)),
    };
    Ok(KeyPair::generate_for(sign_algo)?)
}

/// Saves a PEM-encoded key pair and certificate to specified paths.
fn save_key_and_cert(key_pair: &KeyPair, cert: &Certificate, key_path: &Path, cert_path: &Path) -> Result<()> {
    // KeyPair::serialize_pem is the correct method to get the PEM-encoded private key from rcgen.
    fs::write(key_path, key_pair.serialize_pem())
        .context(format!("Failed to write key to {:?}", key_path))?;
    // Certificate::pem is the correct method to get the PEM-encoded certificate from rcgen.
    fs::write(cert_path, cert.pem())
        .context(format!("Failed to write certificate to {:?}", cert_path))?;
    Ok(())
}

fn main() -> Result<()> {
    let args:Args = Args::parse();

    // Create output directories
    fs::create_dir_all(&args.output_dir)
        .context(format!("Failed to create output directory {:?}", args.output_dir))?;
    let clients_dir = args.output_dir.join("clients");
    fs::create_dir_all(&clients_dir)
        .context(format!("Failed to create clients directory {:?}", clients_dir))?;

    // Calculate validity dates
    let now = OffsetDateTime::now_utc();
    let not_before = now;
    let not_after = now + Duration::days(args.validity_days);

    // 1. Generate CA certificate and key
    println!("Generating CA certificate and key...");
    let ca_key_pair = generate_key_pair(&args.key_algo, args.rsa_key_size, args.ecdsa_curve)?;
    let mut ca_params = CertificateParams::new(vec![args.ca_cn.clone()]).expect("error on constructing ca certificate");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;
    let ca_key_path = args.output_dir.join("ca.pem");
    let ca_cert_path = args.output_dir.join("ca.crt");
    save_key_and_cert(&ca_key_pair, &ca_cert, &ca_key_path, &ca_cert_path)?;
    println!("CA certificate and key saved to {:?} and {:?}", ca_cert_path, ca_key_path);

    // 2. Generate Server certificate and key, signed by CA
    println!("Generating Server certificate and key...");
    let server_key_pair = generate_key_pair(&args.key_algo, args.rsa_key_size, args.ecdsa_curve)?;
    let mut server_params = CertificateParams::new(vec![args.server_cn.clone()]).expect("error on constructing server certificate");
    server_params.is_ca = IsCa::NoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.not_before = not_before;
    server_params.not_after = not_after;
    let server_cert = server_params.signed_by(&server_key_pair, &ca_cert, &ca_key_pair)?;
    let server_key_path = args.output_dir.join("server.pem");
    let server_cert_path = args.output_dir.join("server.crt");
    save_key_and_cert(&server_key_pair, &server_cert, &server_key_path, &server_cert_path)?;
    println!("Server certificate and key saved to {:?} and {:?}", server_cert_path, server_key_path);

    // 3. Generate Client certificates and keys, signed by CA
    println!("Generating Client certificates and keys...");
    for client_cn in &args.client_cn {
        println!("  Generating client: {}", client_cn);
        let client_key_pair = generate_key_pair(&args.key_algo, args.rsa_key_size, args.ecdsa_curve)?;
        let mut client_params = CertificateParams::new(vec![client_cn.clone()]).expect("error on constructing server certificate");
        client_params.is_ca = IsCa::NoCa;
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.not_before = not_before;
        client_params.not_after = not_after;
        let client_cert = client_params.signed_by(&client_key_pair, &ca_cert, &ca_key_pair)?;
        let client_key_path = clients_dir.join(format!("{}.pem", client_cn));
        let client_cert_path = clients_dir.join(format!("{}.crt", client_cn));
        save_key_and_cert(&client_key_pair, &client_cert, &client_key_path, &client_cert_path)?;
        println!("  Client certificate and key saved to {:?} and {:?}", client_cert_path, client_key_path);
    }

    println!("Certificate generation complete!");

    Ok(())
}
