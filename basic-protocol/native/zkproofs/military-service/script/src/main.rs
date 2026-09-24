use std::{fs, io::Read as _, path::PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    blocking::{Prover as _, ProverClient},
    include_elf, Elf, SP1Stdin,
};

const MILITARY_SERVICE_ELF: Elf = include_elf!("military-service-program");
const MILITARY_SERVICE_SUFFIX: &str = " TARHNE KADARASKERLK LE L YOKTUR";
const MAX_INPUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionInput {
    pdf_path: PathBuf,
    commitment_hex: String,
    blinder_hex: String,
    document_date: String,
    today: String,
    assertion_months: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionOutput {
    version: &'static str,
    public_values_hex: String,
    total_instruction_count: u64,
    prover_gas: u64,
}

fn parse_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N]> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{name} must be hexadecimal"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly {N} bytes"))
}

fn parse_date(value: &str, name: &str) -> Result<[u8; 10]> {
    let date: [u8; 10] = value
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must contain exactly 10 ASCII bytes"))?;
    if date[2] != b'/'
        || date[5] != b'/'
        || [0, 1, 3, 4, 6, 7, 8, 9]
            .into_iter()
            .any(|index| !date[index].is_ascii_digit())
    {
        bail!("{name} must use DD/MM/YYYY format");
    }
    Ok(date)
}

fn find_statement_position(pages: &[String], statement: &str) -> Result<(u8, u32)> {
    for (page_index, page) in pages.iter().enumerate() {
        let Some(offset) = page.find(statement) else {
            continue;
        };
        return Ok((
            u8::try_from(page_index).context("statement page does not fit in u8")?,
            u32::try_from(offset).context("statement offset does not fit in u32")?,
        ));
    }
    bail!("military-service statement not found in zkPDF-extracted text")
}

fn read_input() -> Result<ExecutionInput> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INPUT_BYTES {
        bail!("military-service execution input is too large");
    }
    serde_json::from_slice(&bytes).context("invalid military-service input on stdin")
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let input = read_input()?;
    let commitment = parse_hex::<32>(&input.commitment_hex, "TLS body commitment")?;
    let blinder = parse_hex::<16>(&input.blinder_hex, "TLS body blinder")?;
    let document_date = parse_date(&input.document_date, "document date")?;
    let today = parse_date(&input.today, "today")?;
    let pdf_bytes = fs::read(&input.pdf_path)
        .with_context(|| format!("could not read {}", input.pdf_path.display()))?;

    let statement = format!("{}{}", input.document_date, MILITARY_SERVICE_SUFFIX);
    let pages = extractor::extract_text(pdf_bytes.clone())
        .map_err(|error| anyhow::anyhow!("could not extract PDF text: {error:?}"))?;
    let (page_number, offset) = find_statement_position(&pages, &statement)?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&commitment);
    stdin.write(&today);
    stdin.write(&input.assertion_months);
    stdin.write(&pdf_bytes);
    stdin.write(&blinder);
    stdin.write(&document_date);
    stdin.write(&page_number);
    stdin.write(&offset);

    let client = ProverClient::from_env();
    let (public_values, report) = client
        .execute(MILITARY_SERVICE_ELF, stdin)
        .run()
        .context("military-service SP1 execution failed")?;
    let assertion_months_bytes = input.assertion_months.to_be_bytes();
    let expected_public_values = [
        commitment.as_slice(),
        today.as_slice(),
        assertion_months_bytes.as_slice(),
    ]
    .concat();
    if public_values.as_slice() != expected_public_values {
        bail!("military-service program committed unexpected public values");
    }
    let prover_gas = report
        .gas()
        .context("military-service SP1 execution did not report prover gas")?;

    println!(
        "{}",
        serde_json::to_string(&ExecutionOutput {
            version: "zk-devlet-military-service-execution-v2",
            public_values_hex: hex::encode(expected_public_values),
            total_instruction_count: report.total_instruction_count(),
            prover_gas,
        })?
    );
    Ok(())
}
