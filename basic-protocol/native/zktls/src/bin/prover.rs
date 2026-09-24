use std::{future::IntoFuture, net::SocketAddr, path::PathBuf, time::Duration};

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
    Session,
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

use govbind_basic_zktls::{
    EDEVLET_DOMAIN, EDEVLET_PDF_TARGET, MAX_PDF_BYTES, reject_header_injection, write_private,
};

const PROVE_REQUEST: &[u8] = b"ZKDEVLET_NOTARY_PROVE_V1\n";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(about = "Create and verify a TLSNotary presentation for an e-Devlet PDF")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8000")]
    notary: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationInput {
    cookie: String,
    referer: String,
    output_path: PathBuf,
    notary_public_key_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationOutput {
    version: &'static str,
    commitment_hex: String,
    blinder_hex: String,
    pdf_sha256_hex: String,
    attestation_base64: String,
    presentation_base64: String,
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

    let input = read_verification_input().await?;
    let trusted_key = validate_input(&input)?;
    let output = prove(input, args.notary, &trusted_key).await?;
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn read_verification_input() -> Result<VerificationInput> {
    let mut bytes = Vec::new();
    tokio::io::stdin().read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() <= 64 * 1024,
        "verification input is unexpectedly large"
    );
    serde_json::from_slice(&bytes).context("invalid verification input on stdin")
}

fn validate_input(input: &VerificationInput) -> Result<Vec<u8>> {
    ensure!(!input.cookie.is_empty(), "cookie is empty");
    reject_header_injection("cookie", &input.cookie)?;
    reject_header_injection("referer", &input.referer)?;
    let referer: Uri = input
        .referer
        .parse()
        .context("referer is not a valid URI")?;
    ensure!(
        referer.scheme_str() == Some("https"),
        "referer must use HTTPS"
    );
    ensure!(
        referer.host() == Some(EDEVLET_DOMAIN),
        "referer must be an e-Devlet URL"
    );

    let trusted_key = hex::decode(&input.notary_public_key_hex)
        .context("Notary public key is not valid hexadecimal")?;
    ensure!(
        trusted_key.len() == 33 && matches!(trusted_key[0], 0x02 | 0x03),
        "Notary public key is not a compressed secp256k1 key"
    );
    Ok(trusted_key)
}

async fn connect_notary(notary_addr: SocketAddr, expected_public_key: &[u8]) -> Result<TcpStream> {
    let mut socket = TcpStream::connect(notary_addr)
        .await
        .with_context(|| format!("failed to connect to Notary at {notary_addr}"))?;
    TokioAsyncWriteExt::write_all(&mut socket, PROVE_REQUEST).await?;

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

async fn prove(
    input: VerificationInput,
    notary_addr: SocketAddr,
    trusted_key: &[u8],
) -> Result<VerificationOutput> {
    let notary_socket = connect_notary(notary_addr, trusted_key).await?;
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(EDEVLET_DOMAIN)?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(EDEVLET_DOMAIN.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut sender, connection) = hyper::client::conn::http1::handshake(tls_connection).await?;
    let connection_task = tokio::spawn(connection);

    let request = Request::builder()
        .method("GET")
        .uri(EDEVLET_PDF_TARGET)
        .header(header::HOST, EDEVLET_DOMAIN)
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

    info!("requesting authenticated PDF through TLSNotary Proxy mode");
    let mut response = sender.send_request(request).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "PDF request returned HTTP {}",
        response.status()
    );
    validate_response_headers(response.headers())?;

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
        "response body does not have a PDF signature"
    );

    drop(sender);
    connection_task.await??;
    let mut prover = prover_task.await??;

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
    ensure!(
        authenticated_pdf.as_ref() == pdf_bytes.as_slice(),
        "saved PDF differs from the authenticated HTTP entity body"
    );

    let body_idx = entity_body_indices(body);
    let (presentation_sent_idx, presentation_recv_idx) = presentation_indices(&http);

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    commit_builder.commit_sent(presentation_sent_idx)?;
    commit_builder.commit_recv(presentation_recv_idx)?;
    commit_builder.commit_recv(body_idx.clone())?;
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

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
    } = prover.prove(&prove_config).await?;
    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let (commitment, blinder) =
        find_body_commitment(&transcript_commitments, &transcript_secrets, &body_idx)?;
    let mut commitment_hasher = Sha256::new();
    commitment_hasher.update(authenticated_pdf.as_ref());
    commitment_hasher.update(&blinder);
    ensure!(
        commitment_hasher.finalize().as_slice() == commitment,
        "TLSNotary body commitment failed local consistency check"
    );

    let mut attestation_request_builder = AttestationRequest::builder(&request_config);
    attestation_request_builder
        .server_name(ServerName::Dns(EDEVLET_DOMAIN.try_into()?))
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
    let (attestation_request, secrets) =
        attestation_request_builder.build(&CryptoProvider::default())?;

    handle.close();
    let mut notary_socket = driver_task.await??;
    notary_socket
        .write_all(&bincode::serialize(&attestation_request)?)
        .await?;
    notary_socket.close().await?;

    let mut attestation_bytes = Vec::new();
    notary_socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)
        .context("Notary returned an invalid attestation")?;
    attestation_request.validate(&attestation, &CryptoProvider::default())?;

    let presentation = build_presentation(&attestation, &secrets)?;
    ensure!(
        presentation.verifying_key().alg == KeyAlgId::K256
            && presentation.verifying_key().data == trusted_key,
        "presentation was signed by an untrusted Notary"
    );
    verify_presentation(presentation.clone())?;

    write_private(&input.output_path, &pdf_bytes)?;
    let presentation_bytes = bincode::serialize(&presentation)?;

    Ok(VerificationOutput {
        version: "zk-devlet-zktls-verification-v1",
        commitment_hex: hex::encode(commitment),
        blinder_hex: hex::encode(blinder),
        pdf_sha256_hex: hex::encode(Sha256::digest(&pdf_bytes)),
        attestation_base64: BASE64.encode(attestation_bytes),
        presentation_base64: BASE64.encode(presentation_bytes),
    })
}

fn validate_response_headers(headers: &hyper::HeaderMap) -> Result<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .context("PDF response has no Content-Type")?
        .to_str()?;
    ensure!(
        content_type
            .to_ascii_lowercase()
            .starts_with("application/pdf"),
        "unexpected Content-Type: {content_type}"
    );
    if let Some(encoding) = headers.get(header::CONTENT_ENCODING) {
        let encoding = encoding.to_str()?;
        ensure!(
            encoding.eq_ignore_ascii_case("identity"),
            "compressed PDF responses are unsupported: {encoding}"
        );
    }
    Ok(())
}

fn find_body_commitment(
    commitments: &[TranscriptCommitment],
    secrets: &[TranscriptSecret],
    body_idx: &RangeSet<usize>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let commitment = commitments
        .iter()
        .find_map(|item| match item {
            TranscriptCommitment::Hash(hash)
                if hash.direction == Direction::Received
                    && &hash.idx == body_idx
                    && hash.hash.alg == HashAlgId::SHA256 =>
            {
                Some(hash.hash.value.as_bytes().to_vec())
            }
            _ => None,
        })
        .context("complete PDF-body SHA-256 commitment was not produced")?;

    let blinder = secrets
        .iter()
        .find_map(|item| match item {
            TranscriptSecret::Hash(hash)
                if hash.direction == Direction::Received
                    && &hash.idx == body_idx
                    && hash.alg == HashAlgId::SHA256 =>
            {
                Some(hash.blinder.as_bytes().to_vec())
            }
            _ => None,
        })
        .context("complete PDF-body commitment blinder was not produced")?;

    Ok((commitment, blinder))
}

fn build_presentation(
    attestation: &Attestation,
    secrets: &tlsn::attestation::Secrets,
) -> Result<Presentation> {
    let http = HttpTranscript::parse(secrets.transcript())?;
    let (presentation_sent_idx, presentation_recv_idx) = presentation_indices(&http);
    let mut proof_builder = secrets.transcript_proof_builder();

    proof_builder.reveal_sent(presentation_sent_idx)?;
    proof_builder.reveal_recv(presentation_recv_idx)?;

    let transcript_proof = proof_builder.build()?;
    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(builder.build()?)
}

fn presentation_indices(http: &HttpTranscript) -> (RangeSet<usize>, RangeSet<usize>) {
    let request = &http.requests[0];
    let response = &http.responses[0];

    let mut sent = RangeSet::default();
    sent.union_mut(request.without_data());
    sent.union_mut(&request.request.target);
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

fn verify_presentation(presentation: Presentation) -> Result<()> {
    let PresentationOutput {
        server_name,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;
    ensure!(
        server_name == Some(ServerName::Dns(EDEVLET_DOMAIN.try_into()?)),
        "presentation has the wrong server identity"
    );
    let mut transcript = transcript.context("presentation has no authenticated HTTP metadata")?;
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
        http.requests[0].request.target.as_str() == EDEVLET_PDF_TARGET,
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
            .starts_with(b"application/pdf"),
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
