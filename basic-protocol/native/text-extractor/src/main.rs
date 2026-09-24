use std::{env, fs, process::ExitCode};

use sha2::{Digest, Sha256};

const FORMAT_TAG: &[u8] = b"ZKPDF-TEXT-V1\0";

fn canonical_text_hash(pages: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FORMAT_TAG);
    hasher.update((pages.len() as u64).to_be_bytes());

    for page in pages {
        let bytes = page.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    hasher.finalize().into()
}

fn run() -> Result<(), String> {
    let input = env::args_os()
        .nth(1)
        .ok_or_else(|| "usage: zkpdf-text-hash <input.pdf>".to_owned())?;
    let pdf = fs::read(&input).map_err(|error| format!("could not read {input:?}: {error}"))?;
    let pages = extractor::extract_text(pdf)
        .map_err(|error| format!("zkPDF could not extract text: {error:?}"))?;

    println!("{}", hex::encode(canonical_text_hash(&pages)));
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_text_hash;

    #[test]
    fn page_boundaries_are_unambiguous() {
        assert_ne!(
            canonical_text_hash(&["ab".into(), "c".into()]),
            canonical_text_hash(&["a".into(), "bc".into()]),
        );
    }
}
