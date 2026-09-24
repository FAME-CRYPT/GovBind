use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use tlsn::{
    ProxyTranscript, Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, request::Request as AttestationRequest,
        signing::Secp256k1Signer,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    transcript::{ContentType, TlsTranscript, TranscriptCommitment},
    verifier::VerifierCommitStart,
    webpki::RootCertStore,
};
use tokio::{
    io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const EDEVLET_DOMAIN: &str = "www.turkiye.gov.tr";
const GIB_DOMAIN: &str = "dijital.gib.gov.tr";
const KEY_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_KEY_V1\n";
const PROVE_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_PROVE_V1\n";
const BENCHMARK_CAPTURE_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_BENCH_CAPTURE_V1\n";
const BENCHMARK_REPLAY_REQUEST_PREFIX: &[u8] = b"ZKDEVLET_NOTARY_BENCH_REPLAY_V1 ";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_CAPTURE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "External TLSNotary Proxy verifier for GovBind")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8000")]
    listen: SocketAddr,
    #[arg(long, default_value = ".runtime/notary.key")]
    key: PathBuf,
    #[arg(long, default_value = ".runtime/notary-benchmark-capture.bin")]
    benchmark_capture: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(error) = run().await {
        error!(error = %format!("{error:#}"), "Notary terminated");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() {
        bail!("the demo Notary must listen on a loopback address");
    }

    let signing_key = load_or_create_key(&args.key)?;
    let public_key = hex::encode(
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes(),
    );
    info!(notary_public_key = %public_key, "loaded secp256k1 Notary key");

    let listener = TcpListener::bind(args.listen).await?;
    info!(address = %args.listen, "Notary listening for approved targets");

    loop {
        let (mut socket, peer) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                error!(error = %error, "failed to accept Notary connection");
                sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            error!(%peer, "rejected non-loopback client");
            continue;
        }

        match accept_protocol(&mut socket, &public_key).await {
            Ok(Protocol::Key) => info!(%peer, "served Notary public key"),
            Ok(Protocol::Prove) => {
                if let Err(error) = notarize(socket, &signing_key).await {
                    error!(%peer, error = %format!("{error:#}"), "notarization failed");
                }
            }
            Ok(Protocol::BenchmarkCapture) => {
                if let Err(error) = capture_benchmark(socket, &args.benchmark_capture).await {
                    error!(%peer, error = %format!("{error:#}"), "benchmark capture failed");
                }
            }
            Ok(Protocol::BenchmarkReplay(capture_id)) => {
                if let Err(error) =
                    replay_benchmark(socket, &signing_key, &args.benchmark_capture, &capture_id)
                        .await
                {
                    error!(%peer, error = %format!("{error:#}"), "benchmark replay failed");
                }
            }
            Err(error) => error!(%peer, error = %format!("{error:#}"), "invalid client handshake"),
        }
    }
}

enum Protocol {
    Key,
    Prove,
    BenchmarkCapture,
    BenchmarkReplay(String),
}

async fn accept_protocol(socket: &mut TcpStream, public_key: &str) -> Result<Protocol> {
    let mut request = Vec::new();

    timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            ensure!(request.len() < 128, "Notary handshake is too long");
            let byte = TokioAsyncReadExt::read_u8(socket).await?;
            request.push(byte);
            if byte == b'\n' {
                return Ok::<(), anyhow::Error>(());
            }
        }
    })
    .await
    .context("Notary handshake timed out")??;

    let protocol = if request == KEY_REQUEST {
        Protocol::Key
    } else if request == PROVE_REQUEST {
        Protocol::Prove
    } else if request == BENCHMARK_CAPTURE_REQUEST {
        Protocol::BenchmarkCapture
    } else if let Some(capture_id) = request
        .strip_prefix(BENCHMARK_REPLAY_REQUEST_PREFIX)
        .and_then(|value| value.strip_suffix(b"\n"))
    {
        let capture_id =
            std::str::from_utf8(capture_id).context("benchmark capture identifier is not UTF-8")?;
        ensure!(
            capture_id.len() == 64 && capture_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "benchmark capture identifier is invalid"
        );
        Protocol::BenchmarkReplay(capture_id.to_ascii_lowercase())
    } else {
        bail!("unsupported Notary handshake")
    };

    TokioAsyncWriteExt::write_all(socket, format!("{public_key}\n").as_bytes()).await?;
    Ok(protocol)
}

fn load_or_create_key(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read Notary key {}", path.display()))?;
        ensure!(
            bytes.len() == 32,
            "Notary key {} must contain exactly 32 bytes",
            path.display()
        );
        return SigningKey::from_slice(&bytes).context("invalid secp256k1 Notary key");
    }

    let key = SigningKey::random(&mut OsRng);
    write_private(path, key.to_bytes().as_ref())?;
    Ok(key)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    write_private(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

fn allowed_upstream(server_name: &str) -> Result<&'static str> {
    match server_name {
        EDEVLET_DOMAIN => Ok(EDEVLET_DOMAIN),
        GIB_DOMAIN => Ok(GIB_DOMAIN),
        _ => bail!("unsupported server name"),
    }
}

fn capture_id(server_name: &str, capture: &ProxyTranscript) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zk-devlet:notary-benchmark-capture:v1\0");
    hasher.update((server_name.len() as u64).to_be_bytes());
    hasher.update(server_name.as_bytes());
    hasher.update((capture.sent().len() as u64).to_be_bytes());
    hasher.update(capture.sent());
    hasher.update((capture.received().len() as u64).to_be_bytes());
    hasher.update(capture.received());
    hex::encode(hasher.finalize())
}

fn load_benchmark_capture(path: &Path, expected_id: &str) -> Result<(String, ProxyTranscript)> {
    let bytes = std::fs::read(path).context("benchmark capture is unavailable")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CAPTURE_BYTES,
        "benchmark capture has an invalid size"
    );
    let (server_name, capture): (String, ProxyTranscript) =
        bincode::deserialize(&bytes).context("benchmark capture is invalid")?;
    allowed_upstream(&server_name)?;
    ensure!(
        capture_id(&server_name, &capture) == expected_id,
        "benchmark capture identifier mismatch"
    );
    Ok((server_name, capture))
}

async fn capture_benchmark(socket: TcpStream, path: &Path) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
        bail!("benchmark capture requires Proxy mode");
    };
    let target = allowed_upstream(verifier.config().server_name().as_str())?;
    let server_socket = TcpStream::connect((target, 443))
        .await
        .context("failed to connect to approved benchmark target")?;
    info!(target, "capturing benchmark Proxy-TLS session");
    let (verifier, capture) = verifier
        .accept()
        .await?
        .run_with_capture(server_socket.compat())
        .await
        .context("benchmark Proxy-TLS capture failed")?;
    verifier.close().await?;

    let bytes = bincode::serialize(&(target, &capture))?;
    ensure!(
        bytes.len() <= MAX_CAPTURE_BYTES,
        "benchmark capture is too large"
    );
    let id = capture_id(target, &capture);
    write_private_atomic(path, &bytes)?;

    handle.close();
    let mut socket = driver_task.await??;
    socket.write_all(format!("{id}\n").as_bytes()).await?;
    socket.close().await?;
    info!(capture_id = %id, "stored benchmark TLS capture");
    Ok(())
}

async fn replay_benchmark(
    socket: TcpStream,
    signing_key: &SigningKey,
    path: &Path,
    expected_id: &str,
) -> Result<()> {
    let (captured_server_name, capture) = load_benchmark_capture(path, expected_id)?;
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let mut driver_tasks = JoinSet::new();
    driver_tasks.spawn(driver);
    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let VerifierCommitStart::Proxy(verifier) = verifier.commit().await? else {
        bail!("benchmark replay requires Proxy mode");
    };
    let target = allowed_upstream(verifier.config().server_name().as_str())?;
    ensure!(
        target == captured_server_name,
        "benchmark capture server name mismatch"
    );
    let verifier = verifier.accept().await?.replay(capture).await?;
    finish_attestation(verifier, handle, &mut driver_tasks, signing_key).await?;
    info!(capture_id = %expected_id, "issued benchmark replay attestation");
    Ok(())
}

async fn notarize(socket: TcpStream, signing_key: &SigningKey) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let mut driver_tasks = JoinSet::new();
    driver_tasks.spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            verifier
                .reject(Some("this Notary accepts Proxy mode only"))
                .await?;
            bail!("prover requested MPC mode");
        }
        VerifierCommitStart::Proxy(verifier) => {
            let target = match allowed_upstream(verifier.config().server_name().as_str()) {
                Ok(target) => target,
                Err(error) => {
                    verifier.reject(Some("unsupported server name")).await?;
                    return Err(error);
                }
            };
            let server_socket = TcpStream::connect((target, 443))
                .await
                .context("failed to connect to approved upstream")?;
            info!(target, "connected Proxy-TLS upstream");
            verifier
                .accept()
                .await
                .context("failed to accept Proxy-TLS session")?
                .run(server_socket.compat())
                .await
                .context("Proxy-TLS traffic forwarding failed")?
        }
    };

    finish_attestation(verifier, handle, &mut driver_tasks, signing_key).await?;
    info!("issued TLS attestation");
    Ok(())
}

async fn finish_attestation(
    verifier: tlsn::verifier::Verifier<tlsn::verifier::state::Committed>,
    handle: tlsn::SessionHandle,
    driver_tasks: &mut JoinSet<tlsn::Result<Compat<TcpStream>>>,
    signing_key: &SigningKey,
) -> Result<()> {
    let (output, verifier) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let sent_len = application_data_len(tls_transcript.sent())?;
    let received_len = application_data_len(tls_transcript.recv())?;

    handle.close();
    let driver_result = driver_tasks
        .join_next()
        .await
        .context("Notary session driver ended unexpectedly")??;
    let mut socket = driver_result?;

    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest =
        bincode::deserialize(&request_bytes).context("invalid attestation request")?;

    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut config_builder = AttestationConfig::builder();
    config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let config = config_builder.build()?;

    let attestation = issue_attestation(
        request,
        output.transcript_commitments,
        &tls_transcript,
        sent_len,
        received_len,
        &config,
        &provider,
    )?;
    let response = bincode::serialize(&attestation)?;
    socket.write_all(&response).await?;
    socket.close().await?;
    Ok(())
}

fn issue_attestation(
    request: AttestationRequest,
    transcript_commitments: Vec<TranscriptCommitment>,
    tls_transcript: &TlsTranscript,
    sent_len: u32,
    received_len: u32,
    config: &AttestationConfig,
    provider: &CryptoProvider,
) -> Result<Attestation> {
    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        bail!("TLSNotary produced a non-TLS-1.2 certificate binding");
    };

    let mut builder = Attestation::builder(config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len,
                received: received_len,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments);
    Ok(builder.build(provider)?)
}

fn application_data_len(records: &[tlsn::transcript::Record]) -> Result<u32> {
    let length: usize = records
        .iter()
        .filter(|record| matches!(record.typ, ContentType::ApplicationData))
        .map(|record| record.ciphertext.len())
        .sum();
    u32::try_from(length).context("TLS application-data transcript is too large")
}
