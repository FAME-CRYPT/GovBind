#![no_main]

use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

// zkPDF omits unsupported Turkish glyphs from this PDF's embedded font. Matching
// this degraded text is sufficient for the demo, but weakens the claim's soundness
// and must be revisited before supporting arbitrary documents or fonts.
const MILITARY_SERVICE_SUFFIX: &[u8] = b" TARHNE KADARASKERLK LE L YOKTUR";

fn parse_date(date: &[u8; 10]) -> (u64, u64, u64) {
    // The verifier validates public date syntax and policy. The private date is
    // authenticated by its exact PDF match, so the guest only decodes positions.
    let digit = |index: usize| u64::from(date[index].wrapping_sub(b'0'));
    let day = digit(0) * 10 + digit(1);
    let month = digit(3) * 10 + digit(4);
    let year = digit(6) * 1000 + digit(7) * 100 + digit(8) * 10 + digit(9);
    (year, month, day)
}

fn add_months((year, month, day): (u64, u64, u64), months: u32) -> (u64, u64, u64) {
    // Public-input policy belongs to the verifier. For valid calendar inputs this
    // deliberately preserves the day, so 31/01 + one month becomes 31/02.
    let month_index = month.saturating_sub(1);
    let total_months = year * 12 + month_index + u64::from(months);
    (total_months / 12, total_months % 12 + 1, day)
}

pub fn main() {
    let expected_body_commitment = sp1_zkvm::io::read::<[u8; 32]>();
    let today = sp1_zkvm::io::read::<[u8; 10]>();
    let assertion_months = sp1_zkvm::io::read::<u32>();

    let pdf_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let blinder = sp1_zkvm::io::read::<[u8; 16]>();
    let document_date = sp1_zkvm::io::read::<[u8; 10]>();
    let page_number = sp1_zkvm::io::read::<u8>();
    let offset = sp1_zkvm::io::read::<u32>();

    let mut body_hasher = Sha256::new();
    body_hasher.update(&pdf_bytes);
    body_hasher.update(blinder);
    let actual_body_commitment: [u8; 32] = body_hasher.finalize().into();
    assert_eq!(
        actual_body_commitment, expected_body_commitment,
        "TLSNotary PDF body commitment mismatch"
    );

    let mut statement = Vec::with_capacity(document_date.len() + MILITARY_SERVICE_SUFFIX.len());
    statement.extend_from_slice(&document_date);
    statement.extend_from_slice(MILITARY_SERVICE_SUFFIX);

    let pages = extractor::extract_text(pdf_bytes).expect("could not extract PDF text");
    let statement_matches = pages
        .get(page_number as usize)
        .and_then(|page| page.as_bytes().get(offset as usize..))
        .map(|text| text.starts_with(&statement))
        .unwrap_or(false);
    assert!(
        statement_matches,
        "military-service statement does not match at the private PDF position"
    );

    let document_date_components = parse_date(&document_date);
    let threshold = add_months(parse_date(&today), assertion_months);
    assert!(
        document_date_components > threshold,
        "military-service date must be strictly later than the asserted threshold"
    );

    sp1_zkvm::io::commit_slice(&expected_body_commitment);
    sp1_zkvm::io::commit_slice(&today);
    sp1_zkvm::io::commit_slice(&assertion_months.to_be_bytes());
}
