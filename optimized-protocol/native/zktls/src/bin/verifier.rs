use std::ops::Range;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rangeset::{iter::RangeIterator, ops::Set, set::RangeSet};
use serde::{Deserialize, Serialize};
use tlsn::{
    attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
        signing::KeyAlgId,
    },
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, Transcript, TranscriptCommitment},
};
use tlsn_formats::http::HttpTranscript;
use govbind_optimized_zktls::{
    CRIMINAL_RECORD_PROFILE, DRIVER_LICENSE_PROFILE, EDEVLET_DOMAIN, EDEVLET_PDF_TARGET,
    GIB_DOMAIN, GIB_REPORT_TARGET_PREFIX, MILITARY_PROFILE, RESIDENCE_PROFILE, TAX_DEBT_PROFILE,
    is_pdf_content_type, parse_profile_pdf_redacted_ranges, validate_criminal_record_font_encoding,
    validate_residence_city_encoding, validate_tax_debt_font_encoding,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationInput {
    profile: String,
    city: Option<String>,
    city_encoding_hex: Option<String>,
    identity_number: Option<String>,
    notary_public_key_hex: String,
    presentation_base64: String,
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
    private_ranges: Vec<PrivateRangeOutput>,
}

fn main() -> Result<()> {
    let input: VerificationInput =
        serde_json::from_reader(std::io::stdin()).context("invalid verifier input")?;
    let trusted_key =
        hex::decode(&input.notary_public_key_hex).context("invalid Notary key encoding")?;
    ensure!(
        trusted_key.len() == 33 && matches!(trusted_key[0], 0x02 | 0x03),
        "Notary key is not compressed secp256k1"
    );
    let presentation_bytes = BASE64
        .decode(&input.presentation_base64)
        .context("invalid presentation encoding")?;
    ensure!(
        !presentation_bytes.is_empty() && presentation_bytes.len() <= 4 * 1024 * 1024,
        "presentation size is invalid"
    );
    let presentation: Presentation =
        bincode::deserialize(&presentation_bytes).context("invalid TLSNotary presentation")?;
    ensure!(
        presentation.verifying_key().alg == KeyAlgId::K256
            && presentation.verifying_key().data == trusted_key,
        "presentation was signed by an untrusted Notary"
    );
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
    let ranges = verify_presentation(
        presentation,
        &input.profile,
        input.city.as_deref(),
        input.city_encoding_hex.as_deref(),
        input.identity_number.as_deref(),
    )?;
    println!(
        "{}",
        serde_json::to_string(&VerificationOutput {
            version: "zk-devlet-zktls-presentation-verification-v2",
            profile: input.profile,
            private_ranges: ranges,
        })?
    );
    Ok(())
}

fn verify_presentation(
    presentation: Presentation,
    profile: &str,
    city: Option<&str>,
    city_encoding_hex: Option<&str>,
    identity_number: Option<&str>,
) -> Result<Vec<PrivateRangeOutput>> {
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
    let mut partial = transcript.context("presentation has no authenticated transcript")?;
    let authenticated_received = partial.received_authed().clone();
    partial.set_unauthed(b'X');
    let transcript = Transcript::new(
        partial.sent_unsafe().to_vec(),
        partial.received_unsafe().to_vec(),
    );
    let http = HttpTranscript::parse(&transcript)?;
    validate_http(&http, profile)?;

    let body = http.responses[0]
        .body
        .as_ref()
        .context("presentation response has no body")?;
    let redacted_pdf = body.content_data();
    let local_ranges = parse_profile_pdf_redacted_ranges(profile, redacted_pdf.as_ref())?;
    if profile == RESIDENCE_PROFILE {
        let encoded = hex::decode(city_encoding_hex.context("residence city encoding is missing")?)
            .context("residence city encoding is invalid")?;
        validate_residence_city_encoding(
            redacted_pdf.as_ref(),
            city.context("residence city is missing")?,
            &encoded,
        )?;
        ensure!(
            identity_number.is_none(),
            "residence verification has unexpected identity data"
        );
    } else if profile == CRIMINAL_RECORD_PROFILE {
        ensure!(
            city.is_none() && city_encoding_hex.is_none(),
            "criminal-record verification has unexpected city data"
        );
        validate_criminal_record_font_encoding(
            redacted_pdf.as_ref(),
            identity_number.context("public identity number is missing")?,
        )?;
    } else if profile == TAX_DEBT_PROFILE {
        ensure!(
            city.is_none() && city_encoding_hex.is_none(),
            "tax-debt verification has unexpected city data"
        );
        validate_tax_debt_font_encoding(redacted_pdf.as_ref())?;
        govbind_optimized_zktls::validate_criminal_record_identity_number(
            identity_number.context("public identity number is missing")?,
        )?;
    } else {
        ensure!(
            city.is_none() && city_encoding_hex.is_none() && identity_number.is_none(),
            "verification has unexpected public claim data"
        );
    }
    let private_indices = local_ranges
        .ordered()
        .into_iter()
        .map(|range| body_local_range_indices(body, range.clone()))
        .collect::<Result<Vec<_>>>()?;
    let body_idx = entity_body_indices(body);
    let mut hidden_idx = RangeSet::default();
    for indices in &private_indices {
        hidden_idx.union_mut(indices);
    }
    let safe_idx = body_idx.difference(&hidden_idx).into_set();
    let authenticated_body = authenticated_received.intersection(&body_idx).into_set();
    ensure!(
        authenticated_body == safe_idx,
        "presentation does not authenticate exactly the safe PDF ranges"
    );

    let commitments = attestation
        .body
        .transcript_commitments()
        .collect::<Vec<_>>();
    ensure!(
        matching_hashes(&commitments, &safe_idx).len() == 1,
        "presentation has no unique safe-range commitment"
    );
    let mut output = Vec::new();
    for ((kind, local), indices) in local_ranges.labeled().into_iter().zip(&private_indices) {
        let matches = matching_hashes(&commitments, indices);
        ensure!(
            matches.len() == 1,
            "presentation has no unique {kind} commitment"
        );
        output.push(PrivateRangeOutput {
            kind,
            offset: local.start,
            length: local.len(),
            commitment_hex: hex::encode(matches[0]),
        });
    }

    for commitment in commitments {
        if let TranscriptCommitment::Hash(hash) = commitment
            && hash.direction == Direction::Received
            && !hash.idx.intersection(&body_idx).into_set().is_empty()
        {
            let expected = &hash.idx == &safe_idx
                || private_indices.iter().any(|indices| &hash.idx == indices);
            ensure!(
                expected,
                "presentation has an unexpected PDF-body commitment"
            );
        }
    }
    Ok(output)
}

fn matching_hashes<'a>(
    commitments: &'a [&TranscriptCommitment],
    indices: &RangeSet<usize>,
) -> Vec<&'a [u8]> {
    commitments
        .iter()
        .filter_map(|commitment| match commitment {
            TranscriptCommitment::Hash(hash)
                if hash.direction == Direction::Received
                    && &hash.idx == indices
                    && hash.hash.alg == HashAlgId::SHA256 =>
            {
                Some(hash.hash.value.as_bytes())
            }
            _ => None,
        })
        .collect()
}

fn profile_domain(profile: &str) -> &'static str {
    if profile == TAX_DEBT_PROFILE {
        GIB_DOMAIN
    } else {
        EDEVLET_DOMAIN
    }
}

fn validate_http(http: &HttpTranscript, profile: &str) -> Result<()> {
    ensure!(
        http.requests.len() == 1 && http.responses.len() == 1,
        "presentation has an unexpected HTTP shape"
    );
    let request = &http.requests[0];
    let response = &http.responses[0];
    ensure!(
        request.request.method.as_str() == "GET"
            && if profile == TAX_DEBT_PROFILE {
                request.request.target.as_str()
                    == format!("{GIB_REPORT_TARGET_PREFIX}{}", "X".repeat(36))
            } else {
                request.request.target.as_str() == EDEVLET_PDF_TARGET
            },
        "presentation has the wrong request"
    );
    let hosts = request.headers_with_name("host").collect::<Vec<_>>();
    ensure!(
        hosts.len() == 1
            && hosts[0]
                .value
                .as_bytes()
                .eq_ignore_ascii_case(profile_domain(profile).as_bytes()),
        "presentation has the wrong authenticated Host"
    );
    let accepts = request.headers_with_name("accept").collect::<Vec<_>>();
    ensure!(
        accepts.len() == 1
            && accepts[0]
                .value
                .as_bytes()
                .eq_ignore_ascii_case(b"application/pdf"),
        "presentation has the wrong authenticated Accept header"
    );
    let accept_encodings = request
        .headers_with_name("accept-encoding")
        .collect::<Vec<_>>();
    ensure!(
        accept_encodings.len() == 1
            && accept_encodings[0]
                .value
                .as_bytes()
                .eq_ignore_ascii_case(b"identity"),
        "presentation did not request identity encoding"
    );
    ensure!(
        response.status.code.as_str() == "200",
        "presentation response is not HTTP 200"
    );
    let content_types = response
        .headers_with_name("content-type")
        .collect::<Vec<_>>();
    ensure!(
        content_types.len() == 1
            && (is_pdf_content_type(&content_types[0].value.as_bytes())
                || (profile == TAX_DEBT_PROFILE
                    && content_types[0].value.as_bytes().as_ref() == b"*/*")),
        "presentation response is not a PDF"
    );
    let content_encodings = response
        .headers_with_name("content-encoding")
        .collect::<Vec<_>>();
    ensure!(
        content_encodings.len() <= 1,
        "presentation has duplicate Content-Encoding headers"
    );
    if let Some(encoding) = content_encodings.first() {
        ensure!(
            encoding.value.as_bytes().eq_ignore_ascii_case(b"identity"),
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
            result.union_mut(
                absolute.start + overlap_start - logical_offset
                    ..absolute.start + overlap_end - logical_offset,
            );
        }
        logical_offset += segment_length;
    }
    ensure!(
        result.len() == local.len(),
        "could not map PDF range into authenticated transcript"
    );
    Ok(result)
}
