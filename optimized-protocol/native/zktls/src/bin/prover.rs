use std::{
    future::IntoFuture,
    net::SocketAddr,
    ops::Range,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode, Uri, body::Bytes, header};
use hyper_util::rt::TokioIo;
use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tlsn::{
    ProverProxyTranscript, ProxyTranscript, Session,
    attestation::{
        Attestation, CryptoProvider,
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::KeyAlgId,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, HandshakeData, ServerName},
    hash::HashAlgId,
    prover::ProverOutput,
    transcript::{
        Direction, Transcript, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind, TranscriptSecret,
    },
    webpki::RootCertStore,
};
use tlsn_formats::http::HttpTranscript;
use tokio::{
    io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;
use tracing_subscriber::EnvFilter;

use govbind_optimized_zktls::{
    CRIMINAL_RECORD_PROFILE, DRIVER_LICENSE_PROFILE, EDEVLET_DOMAIN, EDEVLET_PDF_TARGET,
    GIB_DOMAIN, GIB_REPORT_TARGET_PREFIX, MAX_PDF_BYTES, MILITARY_PROFILE, RESIDENCE_PROFILE,
    TAX_DEBT_PROFILE, is_pdf_content_type, parse_profile_pdf_private_ranges,
    parse_profile_pdf_redacted_ranges, reject_header_injection, residence_city_encoding,
    validate_criminal_record_font_encoding, validate_tax_debt_font_encoding,
};

const PROVE_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_PROVE_V1\n";
const BENCHMARK_CAPTURE_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_BENCH_CAPTURE_V1\n";
const BENCHMARK_REPLAY_REQUEST_PREFIX: &[u8] = b"ZKDEVLET_NOTARY_BENCH_REPLAY_V1 ";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BENCHMARK_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "Create and verify a TLSNotary presentation for an e-Devlet PDF")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8000")]
    notary: SocketAddr,
    /// Capture one authenticated download for later benchmark replay.
    #[arg(long, conflicts_with = "benchmark_replay")]
    benchmark_capture: bool,
    /// Generate a proof from benchmark capture data supplied on stdin.
    #[arg(long, conflicts_with = "benchmark_capture")]
    benchmark_replay: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationInput {
    profile: String,
    city: Option<String>,
    identity_number: Option<String>,
    cookie: String,
    referer: String,
    notary_public_key_hex: String,
    benchmark_capture_base64: Option<String>,
    request_target: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateRangeOutput {
    kind: &'static str,
    offset: usize,
    length: usize,
    commitment_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationOutput {
    version: &'static str,
    profile: String,
    response_body_bytes: usize,
    city_encoding_hex: Option<String>,
    content_stream_base64: String,
    content_blinder_hex: String,
    private_ranges: Vec<PrivateRangeOutput>,
    presentation_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    benchmark_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkCaptureOutput {
    version: &'static str,
    capture_id_hex: String,
    prover_capture_base64: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum NativeOutput {
    Verification(VerificationOutput),
    BenchmarkCapture(BenchmarkCaptureOutput),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    ensure!(
        args.notary.ip().is_loopback(),
        "the demo prover only connects to a loopback Notary"
    );
    let input = read_verification_input(args.benchmark_replay).await?;
    let trusted_key = validate_input(&input)?;
    ensure!(
        args.benchmark_replay == input.benchmark_capture_base64.is_some(),
        "benchmark replay input and mode must be used together"
    );
    let output = prove(input, args.notary, &trusted_key, &args).await?;
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn read_verification_input(benchmark_replay: bool) -> Result<VerificationInput> {
    let mut bytes = Vec::new();
    tokio::io::stdin().read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len()
            <= if benchmark_replay {
                MAX_BENCHMARK_CAPTURE_BYTES * 4 / 3 + 64 * 1024
            } else {
                64 * 1024
            },
        "verification input is unexpectedly large"
    );
    serde_json::from_slice(&bytes).context("invalid verification input on stdin")
}

fn validate_input(input: &VerificationInput) -> Result<Vec<u8>> {
    ensure!(
        matches!(
            input.profile.as_str(),
            MILITARY_PROFILE
                | RESIDENCE_PROFILE
                | CRIMINAL_RECORD_PROFILE
                | DRIVER_LICENSE_PROFILE
                | TAX_DEBT_PROFILE
        ),
        "unsupported PDF profile"
    );
    if input.profile == RESIDENCE_PROFILE {
        let city = input
            .city
            .as_deref()
            .context("residence city is required")?;
        ensure!(
            city.chars().all(|character| character.is_alphabetic()) && city == city.to_uppercase(),
            "residence city is invalid"
        );
        ensure!(
            input.identity_number.is_none(),
            "residence profile has unexpected identity data"
        );
    } else if matches!(
        input.profile.as_str(),
        CRIMINAL_RECORD_PROFILE | TAX_DEBT_PROFILE
    ) {
        ensure!(
            input.city.is_none(),
            "identity-bearing profile has unexpected city data"
        );
        govbind_optimized_zktls::validate_criminal_record_identity_number(
            input
                .identity_number
                .as_deref()
                .context("public identity number is required")?,
        )?;
    } else {
        ensure!(
            input.city.is_none() && input.identity_number.is_none(),
            "PDF profile has unexpected public claim data"
        );
    }
    ensure!(!input.cookie.is_empty(), "cookie is empty");
    reject_header_injection("cookie", &input.cookie)?;
    reject_header_injection("referer", &input.referer)?;
    let expected_domain = profile_domain(&input.profile);
    let referer: Uri = input
        .referer
        .parse()
        .context("referer is not a valid URI")?;
    ensure!(
        referer.scheme_str() == Some("https"),
        "referer must use HTTPS"
    );
    ensure!(
        referer.host() == Some(expected_domain),
        "referer must use the selected issuer"
    );
    if input.profile == TAX_DEBT_PROFILE {
        validate_gib_report_target(
            input
                .request_target
                .as_deref()
                .context("GIB report target is required")?,
        )?;
    } else {
        ensure!(
            input.request_target.is_none(),
            "e-Devlet profile has an unexpected target"
        );
    }

    let trusted_key = hex::decode(&input.notary_public_key_hex)
        .context("Notary public key is not valid hexadecimal")?;
    ensure!(
        trusted_key.len() == 33 && matches!(trusted_key[0], 0x02 | 0x03),
        "Notary public key is not a compressed secp256k1 key"
    );
    Ok(trusted_key)
}

async fn connect_notary(
    notary_addr: SocketAddr,
    expected_public_key: &[u8],
    request: &[u8],
) -> Result<TcpStream> {
    let mut socket = TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("failed to connect to Notary at {notary_addr}"))?;
    TokioAsyncWriteExt::write_all(&mut socket, request).await?;

    let mut response = Vec::new();
    timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            ensure!(response.len() < 68, "Notary key response is too long");
            let byte = TokioAsyncReadExt::read_u8(&mut socket).await?;
            if byte == b'\n' {
                return Ok::<(), anyhow::Error>(());
            }
            response.push(byte);
        }
    })
    .await
    .context("Notary key response timed out")??;

    let received_key = hex::decode(&response).context("Notary returned an invalid public key")?;
    ensure!(
        received_key == expected_public_key,
        "Notary public key does not match the trusted key"
    );
    Ok(socket)
}

fn profile_domain(profile: &str) -> &'static str {
    if profile == TAX_DEBT_PROFILE {
        GIB_DOMAIN
    } else {
        EDEVLET_DOMAIN
    }
}

fn request_target(input: &VerificationInput) -> &str {
    input
        .request_target
        .as_deref()
        .unwrap_or(EDEVLET_PDF_TARGET)
}

fn validate_gib_report_target(target: &str) -> Result<()> {
    let uuid = target
        .strip_prefix(GIB_REPORT_TARGET_PREFIX)
        .context("GIB report target has the wrong path")?;
    ensure!(
        uuid.len() == 36
            && uuid.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "GIB report target has an invalid UUID"
    );
    Ok(())
}

fn capture_identifier(server_name: &str, capture: &ProxyTranscript) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"zk-devlet:notary-benchmark-capture:v1\0");
    hasher.update((server_name.len() as u64).to_be_bytes());
    hasher.update(server_name.as_bytes());
    hasher.update((capture.sent().len() as u64).to_be_bytes());
    hasher.update(capture.sent());
    hasher.update((capture.received().len() as u64).to_be_bytes());
    hasher.update(capture.received());
    Ok(hex::encode(hasher.finalize()))
}

async fn prove(
    input: VerificationInput,
    notary_addr: SocketAddr,
    trusted_key: &[u8],
    args: &Args,
) -> Result<NativeOutput> {
    let server_name = profile_domain(&input.profile);
    let replay_capture = input
        .benchmark_capture_base64
        .as_deref()
        .map(|encoded| {
            ensure!(
                encoded.len() <= MAX_BENCHMARK_CAPTURE_BYTES * 4 / 3 + 4,
                "benchmark prover capture is too large"
            );
            let bytes = BASE64
                .decode(encoded)
                .context("benchmark prover capture is not valid base64")?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_BENCHMARK_CAPTURE_BYTES,
                "benchmark prover capture has an invalid size"
            );
            bincode::deserialize::<ProverProxyTranscript>(&bytes)
                .context("benchmark prover capture is invalid")
        })
        .transpose()?;
    let capture_id = replay_capture
        .as_ref()
        .map(|capture| capture_identifier(server_name, capture.wire()))
        .transpose()?;
    let protocol = if args.benchmark_capture {
        BENCHMARK_CAPTURE_REQUEST.to_vec()
    } else if let Some(capture_id) = &capture_id {
        format!(
            "{}{}\n",
            std::str::from_utf8(BENCHMARK_REPLAY_REQUEST_PREFIX)?,
            capture_id
        )
        .into_bytes()
    } else {
        PROVE_REQUEST.to_vec()
    };
    let benchmark_started_at = args.benchmark_replay.then(Instant::now);
    let notary_socket = connect_notary(notary_addr, trusted_key, &protocol).await?;
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server_name)?)
                .build()?,
        )
        .await?;

    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(server_name.try_into()?))
        .root_store(RootCertStore::mozilla())
        .build()?;
    let request = Request::builder()
        .method("GET")
        .uri(request_target(&input))
        .header(header::HOST, server_name)
        .header(header::ACCEPT, "application/pdf")
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::ACCEPT_LANGUAGE, "tr-TR,tr;q=0.9")
        .header(header::CONNECTION, "close")
        .header(header::COOKIE, &input.cookie)
        .header(header::REFERER, &input.referer)
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (compatible; GovBind/1.0)",
        )
        .body(Empty::<Bytes>::new())?;

    let (mut prover, live_pdf) = if let Some(capture) = replay_capture {
        (
            prover
                .replay(ServerName::Dns(server_name.try_into()?), capture)
                .await?,
            None,
        )
    } else {
        let (tls_connection, prover) = if args.benchmark_capture {
            prover.connect_with_capture(tls_config)?
        } else {
            prover.connect(tls_config)?
        };
        let tls_connection = TokioIo::new(tls_connection.compat());
        let prover_task = tokio::spawn(prover.into_future());
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(tls_connection).await?;
        let connection_task = tokio::spawn(connection);
        info!("requesting authenticated PDF through TLSNotary Proxy mode");
        let mut response = sender.send_request(request).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "PDF request returned HTTP {}",
            response.status()
        );
        validate_response_headers(&input.profile, response.headers())?;
        let mut pdf_bytes = Vec::new();
        while let Some(frame) = response.frame().await {
            let frame = frame.context("failed while receiving PDF response")?;
            if let Ok(data) = frame.into_data() {
                ensure!(
                    pdf_bytes.len() + data.len() <= MAX_PDF_BYTES,
                    "PDF response exceeds the 4 MiB limit"
                );
                pdf_bytes.extend_from_slice(&data);
            }
        }
        ensure!(
            pdf_bytes.starts_with(b"%PDF-"),
            "response body is not a PDF"
        );
        drop(sender);
        connection_task.await??;
        (prover_task.await??, Some(pdf_bytes))
    };

    let http =
        HttpTranscript::parse(prover.transcript()).context("failed to parse HTTP transcript")?;
    ensure!(
        http.requests.len() == 1 && http.responses.len() == 1,
        "expected exactly one HTTP request and response"
    );
    let parsed_response = &http.responses[0];
    ensure!(
        parsed_response.status.code.as_str() == "200",
        "authenticated response status is not 200"
    );
    let body = parsed_response
        .body
        .as_ref()
        .context("authenticated response has no body")?;
    let authenticated_pdf = body.content_data();
    if let Some(live_pdf) = &live_pdf {
        ensure!(
            authenticated_pdf.as_ref() == live_pdf.as_slice(),
            "received PDF differs from the authenticated HTTP entity body"
        );
    }
    let pdf_bytes = authenticated_pdf.to_vec();

    let private_ranges = parse_profile_pdf_private_ranges(&input.profile, &pdf_bytes)?;
    if input.profile == CRIMINAL_RECORD_PROFILE {
        validate_criminal_record_font_encoding(
            &pdf_bytes,
            input
                .identity_number
                .as_deref()
                .context("public identity number is required")?,
        )?;
    } else if input.profile == TAX_DEBT_PROFILE {
        validate_tax_debt_font_encoding(&pdf_bytes)?;
    }
    let city_encoding = if input.profile == RESIDENCE_PROFILE {
        Some(residence_city_encoding(
            &pdf_bytes,
            input
                .city
                .as_deref()
                .context("residence city is required")?,
        )?)
    } else {
        None
    };
    if args.benchmark_capture {
        let capture = prover
            .proxy_transcript()
            .cloned()
            .context("Proxy-TLS did not produce benchmark replay data")?;
        let expected_id = capture_identifier(server_name, capture.wire())?;
        let capture_bytes = bincode::serialize(&capture)?;
        ensure!(
            capture_bytes.len() <= MAX_BENCHMARK_CAPTURE_BYTES,
            "benchmark prover capture is too large"
        );
        prover.close().await?;
        handle.close();
        let mut notary_socket = driver_task.await??;
        let mut response = Vec::new();
        notary_socket.read_to_end(&mut response).await?;
        ensure!(
            response.len() == 65 && response[64] == b'\n',
            "invalid capture response"
        );
        let received_id = std::str::from_utf8(&response[..64])?;
        ensure!(
            received_id == expected_id,
            "Notary stored a different TLS capture"
        );
        return Ok(NativeOutput::BenchmarkCapture(BenchmarkCaptureOutput {
            version: "zk-devlet-zktls-benchmark-capture-v1",
            capture_id_hex: expected_id,
            prover_capture_base64: BASE64.encode(capture_bytes),
        }));
    }
    let body_idx = entity_body_indices(body);
    let private_indices = private_ranges
        .ordered()
        .into_iter()
        .map(|range| body_local_range_indices(body, range.clone()))
        .collect::<Result<Vec<_>>>()?;
    let mut hidden_idx = RangeSet::default();
    for indices in &private_indices {
        hidden_idx.union_mut(indices);
    }
    ensure!(
        hidden_idx.len()
            == private_ranges
                .ordered()
                .into_iter()
                .map(|range| range.len())
                .sum::<usize>(),
        "private PDF transcript ranges overlap"
    );
    let safe_body_idx = body_idx.difference(&hidden_idx).into_set();
    let (presentation_sent_idx, presentation_recv_idx) =
        presentation_indices(&http, &input.profile);

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    commit_builder.commit_sent(presentation_sent_idx)?;
    commit_builder.commit_recv(presentation_recv_idx)?;
    commit_builder.commit_recv(safe_body_idx.clone())?;
    for indices in &private_indices {
        commit_builder.commit_recv(indices.clone())?;
    }
    let transcript_commit = commit_builder.build()?;

    let mut request_config_builder = RequestConfig::builder();
    request_config_builder.transcript_commit(transcript_commit);
    let request_config = request_config_builder.build()?;

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    prove_builder.transcript_commit(
        request_config
            .transcript_commit()
            .expect("commit config exists")
            .clone(),
    );
    let prove_config = prove_builder.build()?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    let started_at = benchmark_started_at.unwrap_or_else(Instant::now);
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
    } = prover.prove(&prove_config).await?;

    let openings = private_indices
        .iter()
        .map(|indices| find_hash_opening(&transcript_commitments, &transcript_secrets, indices))
        .collect::<Result<Vec<_>>>()?;
    for ((kind, range), (commitment, blinder)) in
        private_ranges.labeled().into_iter().zip(&openings)
    {
        let mut hasher = Sha256::new();
        hasher.update(&pdf_bytes[range.clone()]);
        hasher.update(blinder);
        ensure!(
            hasher.finalize().as_slice() == commitment,
            "{kind} TLSNotary commitment failed local consistency check"
        );
    }

    let mut request_builder = AttestationRequest::builder(&request_config);
    request_builder
        .server_name(ServerName::Dns(server_name.try_into()?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("server certificate chain is absent")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("server signature is absent")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (request, secrets) = request_builder.build(&CryptoProvider::default())?;
    let mut benchmark_ms = started_at.elapsed().as_secs_f64() * 1_000.0;
    prover.close().await?;

    handle.close();
    let mut notary_socket = driver_task.await??;
    let request_bytes = bincode::serialize(&request)?;
    let attestation_started_at = Instant::now();
    notary_socket.write_all(&request_bytes).await?;
    notary_socket.close().await?;

    let mut attestation_bytes = Vec::new();
    notary_socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)
        .context("Notary returned an invalid attestation")?;
    benchmark_ms += attestation_started_at.elapsed().as_secs_f64() * 1_000.0;

    let content_range = private_ranges.content_stream.clone();
    let presentation_started_at = Instant::now();
    request.validate(&attestation, &CryptoProvider::default())?;
    let presentation = build_presentation(
        &attestation,
        &secrets,
        safe_body_idx.clone(),
        &input.profile,
    )?;
    ensure!(
        presentation.verifying_key().alg == KeyAlgId::K256
            && presentation.verifying_key().data == trusted_key,
        "presentation was signed by an untrusted Notary"
    );
    verify_presentation(
        presentation.clone(),
        &input.profile,
        &private_indices,
        &safe_body_idx,
        &openings
            .iter()
            .map(|(commitment, _)| commitment.clone())
            .collect::<Vec<_>>(),
        input.identity_number.as_deref(),
    )?;
    let presentation_bytes = bincode::serialize(&presentation)?;
    benchmark_ms += presentation_started_at.elapsed().as_secs_f64() * 1_000.0;

    let private_range_output = private_ranges
        .labeled()
        .into_iter()
        .zip(&openings)
        .map(|((kind, range), (commitment, _))| PrivateRangeOutput {
            kind,
            offset: range.start,
            length: range.len(),
            commitment_hex: hex::encode(commitment),
        })
        .collect();
    let (_, content_blinder) = private_ranges
        .labeled()
        .into_iter()
        .zip(&openings)
        .find_map(|((kind, _), opening)| (kind == "content-stream").then_some(opening))
        .context("PDF profile has no content-stream range")?;

    Ok(NativeOutput::Verification(VerificationOutput {
        version: "zk-devlet-zktls-verification-v2",
        profile: input.profile,
        response_body_bytes: pdf_bytes.len(),
        city_encoding_hex: city_encoding.as_ref().map(hex::encode),
        content_stream_base64: BASE64.encode(&pdf_bytes[content_range]),
        content_blinder_hex: hex::encode(content_blinder),
        private_ranges: private_range_output,
        presentation_base64: BASE64.encode(presentation_bytes),
        benchmark_ms: args.benchmark_replay.then_some(benchmark_ms),
    }))
}

fn validate_response_headers(profile: &str, headers: &hyper::HeaderMap) -> Result<()> {
    let content_types = headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    ensure!(
        content_types.len() == 1
            && (is_pdf_content_type(content_types[0].as_bytes())
                || (profile == TAX_DEBT_PROFILE && content_types[0].as_bytes() == b"*/*")),
        "PDF response has an invalid Content-Type"
    );
    let content_encodings = headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    ensure!(
        content_encodings.len() <= 1,
        "PDF response has duplicate Content-Encoding headers"
    );
    if let Some(encoding) = content_encodings.first() {
        let encoding = encoding.to_str()?;
        ensure!(
            encoding.eq_ignore_ascii_case("identity"),
            "compressed PDF responses are unsupported: {encoding}"
        );
    }
    Ok(())
}

fn find_hash_opening(
    commitments: &[TranscriptCommitment],
    secrets: &[TranscriptSecret],
    expected_idx: &RangeSet<usize>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let commitment = commitments
        .iter()
        .find_map(|item| match item {
            TranscriptCommitment::Hash(hash)
                if hash.direction == Direction::Received
                    && &hash.idx == expected_idx
                    && hash.hash.alg == HashAlgId::SHA256 =>
            {
                Some(hash.hash.value.as_bytes().to_vec())
            }
            _ => None,
        })
        .context("expected private-range SHA-256 commitment was not produced")?;

    let blinder = secrets
        .iter()
        .find_map(|item| match item {
            TranscriptSecret::Hash(hash)
                if hash.direction == Direction::Received
                    && &hash.idx == expected_idx
                    && hash.alg == HashAlgId::SHA256 =>
            {
                Some(hash.blinder.as_bytes().to_vec())
            }
            _ => None,
        })
        .context("expected private-range commitment blinder was not produced")?;

    Ok((commitment, blinder))
}

fn build_presentation(
    attestation: &Attestation,
    secrets: &tlsn::attestation::Secrets,
    safe_body_idx: RangeSet<usize>,
    profile: &str,
) -> Result<Presentation> {
    let http = HttpTranscript::parse(secrets.transcript())?;
    let (presentation_sent_idx, presentation_recv_idx) = presentation_indices(&http, profile);
    let mut proof_builder = secrets.transcript_proof_builder();

    proof_builder.reveal_sent(presentation_sent_idx)?;
    proof_builder.reveal_recv(presentation_recv_idx)?;
    proof_builder.reveal_recv(safe_body_idx)?;

    let transcript_proof = proof_builder.build()?;
    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(builder.build()?)
}

fn presentation_indices(
    http: &HttpTranscript,
    profile: &str,
) -> (RangeSet<usize>, RangeSet<usize>) {
    let request = &http.requests[0];
    let response = &http.responses[0];

    let mut sent = RangeSet::default();
    sent.union_mut(request.without_data());
    if profile == TAX_DEBT_PROFILE {
        for range in request.request.target.indices().iter() {
            sent.union_mut(range.start..range.end - 36);
        }
    } else {
        sent.union_mut(&request.request.target);
    }
    for field in &request.headers {
        if ["host", "accept", "accept-encoding", "connection"]
            .iter()
            .any(|name| field.name.as_str().eq_ignore_ascii_case(name))
        {
            sent.union_mut(field);
        } else {
            sent.union_mut(field.without_value());
        }
    }

    let mut received = RangeSet::default();
    received.union_mut(response.without_data());
    for field in &response.headers {
        if [
            "content-type",
            "content-encoding",
            "content-length",
            "transfer-encoding",
        ]
        .iter()
        .any(|name| field.name.as_str().eq_ignore_ascii_case(name))
        {
            received.union_mut(field);
        } else {
            received.union_mut(field.without_value());
        }
    }
    if let Some(body) = &response.body {
        let entity_idx = entity_body_indices(body);
        let framing_idx = body.indices().difference(&entity_idx).into_set();
        if !framing_idx.is_empty() {
            received.union_mut(framing_idx);
        }
    }

    (sent, received)
}

fn verify_presentation(
    presentation: Presentation,
    profile: &str,
    expected_private_indices: &[RangeSet<usize>],
    expected_safe_body_idx: &RangeSet<usize>,
    expected_commitments: &[Vec<u8>],
    identity_number: Option<&str>,
) -> Result<()> {
    let PresentationOutput {
        attestation,
        server_name,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;
    ensure!(
        server_name == Some(ServerName::Dns(profile_domain(profile).try_into()?)),
        "presentation has the wrong server identity"
    );
    let mut transcript = transcript.context("presentation has no authenticated HTTP metadata")?;
    let authenticated_received = transcript.received_authed().clone();

    ensure!(
        expected_private_indices.len() == expected_commitments.len(),
        "PDF profile has the wrong private commitment count"
    );
    for (indices, expected_commitment) in expected_private_indices.iter().zip(expected_commitments)
    {
        let matches = attestation
            .body
            .transcript_commitments()
            .filter(|commitment| {
                matches!(
                    commitment,
                    TranscriptCommitment::Hash(hash)
                        if hash.direction == Direction::Received
                            && &hash.idx == indices
                            && hash.hash.alg == HashAlgId::SHA256
                            && hash.hash.value.as_bytes() == expected_commitment
                )
            })
            .count();
        ensure!(
            matches == 1,
            "presentation has a missing or duplicate private commitment"
        );
    }

    transcript.set_unauthed(b'X');
    let transcript = Transcript::new(
        transcript.sent_unsafe().to_vec(),
        transcript.received_unsafe().to_vec(),
    );
    let http = HttpTranscript::parse(&transcript)?;
    ensure!(
        http.requests.len() == 1 && http.responses.len() == 1,
        "presentation has an unexpected HTTP shape"
    );
    ensure!(
        http.requests[0].request.method.as_str() == "GET",
        "presentation request is not GET"
    );
    ensure!(
        if profile == TAX_DEBT_PROFILE {
            http.requests[0].request.target.as_str()
                == format!("{GIB_REPORT_TARGET_PREFIX}{}", "X".repeat(36))
        } else {
            http.requests[0].request.target.as_str() == EDEVLET_PDF_TARGET
        },
        "presentation has the wrong request target"
    );
    let accept_encoding = http.requests[0]
        .headers_with_name("accept-encoding")
        .next()
        .context("presentation has no authenticated Accept-Encoding")?;
    ensure!(
        accept_encoding
            .value
            .as_bytes()
            .eq_ignore_ascii_case(b"identity"),
        "presentation did not request an identity-encoded response"
    );
    ensure!(
        http.responses[0].status.code.as_str() == "200",
        "presentation response is not HTTP 200"
    );
    let content_type = http.responses[0]
        .headers_with_name("content-type")
        .next()
        .context("presentation has no authenticated Content-Type")?;
    ensure!(
        content_type
            .value
            .as_bytes()
            .starts_with(b"application/pdf")
            || (profile == TAX_DEBT_PROFILE && content_type.value.as_bytes().as_ref() == b"*/*"),
        "presentation response is not a PDF"
    );
    if let Some(content_encoding) = http.responses[0]
        .headers_with_name("content-encoding")
        .next()
    {
        ensure!(
            content_encoding
                .value
                .as_bytes()
                .eq_ignore_ascii_case(b"identity"),
            "presentation response uses content encoding"
        );
    }

    let body = http.responses[0]
        .body
        .as_ref()
        .context("presentation response has no body")?;
    let body_idx = entity_body_indices(body);
    let authenticated_body = authenticated_received.intersection(&body_idx).into_set();
    ensure!(
        &authenticated_body == expected_safe_body_idx,
        "presentation does not reveal exactly the safe PDF ranges"
    );
    let redacted_pdf = body.content_data();
    let derived_ranges = parse_profile_pdf_redacted_ranges(profile, redacted_pdf.as_ref())?;
    if profile == CRIMINAL_RECORD_PROFILE {
        validate_criminal_record_font_encoding(
            redacted_pdf.as_ref(),
            identity_number.context("public identity number is required")?,
        )?;
    } else if profile == TAX_DEBT_PROFILE {
        validate_tax_debt_font_encoding(redacted_pdf.as_ref())?;
        govbind_optimized_zktls::validate_criminal_record_identity_number(
            identity_number.context("public identity number is required")?,
        )?;
    } else {
        ensure!(
            identity_number.is_none(),
            "non-criminal profile has unexpected identity data"
        );
    }
    let derived_private_indices = derived_ranges
        .ordered()
        .into_iter()
        .map(|range| body_local_range_indices(body, range.clone()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        derived_private_indices == expected_private_indices,
        "presentation private ranges do not match the selected PDF profile"
    );
    Ok(())
}

fn entity_body_indices(body: &tlsn_formats::http::Body) -> RangeSet<usize> {
    match &body.chunks {
        Some(chunks) => chunks
            .iter()
            .flat_map(|chunk| chunk.indices().iter())
            .collect(),
        None => body.indices().clone(),
    }
}

fn body_local_range_indices(
    body: &tlsn_formats::http::Body,
    local: Range<usize>,
) -> Result<RangeSet<usize>> {
    ensure!(
        local.start < local.end && local.end <= body.content_data().len(),
        "local PDF range is outside the authenticated entity body"
    );
    let mut logical_offset = 0usize;
    let mut result = RangeSet::default();
    for absolute in entity_body_indices(body).iter() {
        let segment_length = absolute.len();
        let overlap_start = local.start.max(logical_offset);
        let overlap_end = local.end.min(logical_offset + segment_length);
        if overlap_start < overlap_end {
            let absolute_start = absolute.start + overlap_start - logical_offset;
            let absolute_end = absolute.start + overlap_end - logical_offset;
            result.union_mut(absolute_start..absolute_end);
        }
        logical_offset += segment_length;
    }
    ensure!(
        result.len() == local.len(),
        "could not map PDF range into the authenticated transcript"
    );
    Ok(result)
}
