use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Write},
    ops::Range,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use flate2::read::ZlibDecoder;

pub const EDEVLET_DOMAIN: &str = "www.turkiye.gov.tr";
pub const EDEVLET_PDF_TARGET: &str = "/belge-dogrulama?belge=goster&goster=1&display=display";
pub const GIB_DOMAIN: &str = "dijital.gib.gov.tr";
pub const GIB_REPORT_TARGET_PREFIX: &str = "/apigateway/verification/report/download?uuid=";
pub const MAX_PDF_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CONTENT_STREAM_BYTES: usize = 1536;
pub const MAX_RESIDENCE_CONTENT_STREAM_BYTES: usize = 5504;
pub const MAX_CRIMINAL_RECORD_CONTENT_STREAM_BYTES: usize = 1024;
pub const MAX_DRIVER_LICENSE_CONTENT_STREAM_BYTES: usize = 4096;
pub const MAX_TAX_DEBT_CONTENT_STREAM_BYTES: usize = 2304;

pub const MILITARY_PROFILE: &str = "edevlet-military-service-pdf-v1";
pub const RESIDENCE_PROFILE: &str = "edevlet-residence-pdf-v1";
pub const CRIMINAL_RECORD_PROFILE: &str = "edevlet-criminal-record-pdf-v1";
pub const DRIVER_LICENSE_PROFILE: &str = "edevlet-driver-license-traffic-penalties-pdf-v1";
pub const TAX_DEBT_PROFILE: &str = "gib-tax-debt-status-pdf-v1";

/// Exact private byte ranges for a supported e-Devlet PDF profile.
///
/// Stream ranges contain only the encoded stream data, not the surrounding PDF
/// dictionary or `stream`/`endstream` delimiters. `document_id` contains the
/// complete `[<id><id>]` trailer value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdfPrivateRanges {
    pub barcode_stream: Option<Range<usize>>,
    pub qr_image_stream: Option<Range<usize>>,
    pub content_stream: Range<usize>,
    pub creation_date: Option<Range<usize>>,
    pub modification_date: Option<Range<usize>>,
    pub document_id: Option<Range<usize>>,
}

impl PdfPrivateRanges {
    pub fn labeled(&self) -> Vec<(&'static str, &Range<usize>)> {
        let mut ranges = Vec::new();
        if let Some(range) = &self.barcode_stream {
            ranges.push(("barcode", range));
        }
        if let Some(range) = &self.qr_image_stream {
            ranges.push(("qr-image", range));
        }
        ranges.push(("content-stream", &self.content_stream));
        if let Some(range) = &self.creation_date {
            ranges.push(("creation-date", range));
        }
        if let Some(range) = &self.modification_date {
            ranges.push(("modification-date", range));
        }
        if let Some(range) = &self.document_id {
            ranges.push(("document-id", range));
        }
        ranges
    }

    pub fn ordered(&self) -> Vec<&Range<usize>> {
        self.labeled().into_iter().map(|(_, range)| range).collect()
    }
}

pub type MilitaryPdfPrivateRanges = PdfPrivateRanges;

pub fn parse_military_pdf_private_ranges(pdf: &[u8]) -> Result<MilitaryPdfPrivateRanges> {
    let ranges = parse_military_pdf_redacted_ranges(pdf)?;
    ensure!(
        pdf.get(ranges.content_stream.start..ranges.content_stream.start + 2)
            == Some(&[0x78, 0x9c]),
        "page content stream does not use the military profile zlib header"
    );
    validate_document_id(
        &pdf[ranges
            .document_id
            .clone()
            .context("military document ID is missing")?],
    )?;
    Ok(ranges)
}

/// Derives the expected hidden ranges using only the public PDF structure.
///
/// This accepts arbitrary bytes inside the military profile's four private ranges so that a final
/// verifier can run it over a TLSNotary partial transcript filled with a
/// placeholder byte.
pub fn parse_military_pdf_redacted_ranges(pdf: &[u8]) -> Result<MilitaryPdfPrivateRanges> {
    parse_pdf_redacted_ranges(pdf, PdfRangeProfile::Military)
}

pub fn parse_residence_pdf_private_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    let ranges = parse_residence_pdf_redacted_ranges(pdf)?;
    ensure!(
        pdf.get(ranges.content_stream.start..ranges.content_stream.start + 2)
            == Some(&[0x58, 0x09]),
        "page content stream does not use the residence profile zlib header"
    );
    validate_residence_document_id(
        &pdf[ranges
            .document_id
            .clone()
            .context("residence document ID is missing")?],
    )?;
    Ok(ranges)
}

pub fn parse_residence_pdf_redacted_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    parse_pdf_redacted_ranges(pdf, PdfRangeProfile::Residence)
}

pub fn parse_criminal_record_pdf_private_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    let ranges = parse_criminal_record_pdf_redacted_ranges(pdf)?;
    ensure!(
        pdf.get(ranges.content_stream.start..ranges.content_stream.start + 2)
            == Some(&[0x78, 0x9c]),
        "criminal-record content stream does not use the expected zlib header"
    );
    validate_document_id(
        &pdf[ranges
            .document_id
            .clone()
            .context("criminal-record document ID is missing")?],
    )?;
    Ok(ranges)
}

pub fn parse_criminal_record_pdf_redacted_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    parse_pdf_redacted_ranges(pdf, PdfRangeProfile::CriminalRecord)
}

pub fn parse_driver_license_pdf_private_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    let ranges = parse_driver_license_pdf_redacted_ranges(pdf)?;
    ensure!(
        pdf.get(ranges.content_stream.start..ranges.content_stream.start + 2)
            == Some(&[0x58, 0x09]),
        "driver-license content stream does not use the expected zlib header"
    );
    Ok(ranges)
}

pub fn parse_driver_license_pdf_redacted_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    parse_pdf_redacted_ranges(pdf, PdfRangeProfile::DriverLicense)
}

pub fn parse_tax_debt_pdf_private_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    let ranges = parse_tax_debt_pdf_redacted_ranges(pdf)?;
    ensure!(
        pdf.get(ranges.content_stream.start..ranges.content_stream.start + 2)
            == Some(&[0x78, 0x9c]),
        "tax-debt content stream does not use the expected zlib header"
    );
    validate_tax_debt_document_id(
        &pdf[ranges
            .document_id
            .clone()
            .context("tax-debt document ID is missing")?],
    )?;
    Ok(ranges)
}

pub fn parse_tax_debt_pdf_redacted_ranges(pdf: &[u8]) -> Result<PdfPrivateRanges> {
    parse_pdf_redacted_ranges(pdf, PdfRangeProfile::TaxDebt)
}

pub fn parse_profile_pdf_private_ranges(profile: &str, pdf: &[u8]) -> Result<PdfPrivateRanges> {
    match profile {
        MILITARY_PROFILE => parse_military_pdf_private_ranges(pdf),
        RESIDENCE_PROFILE => parse_residence_pdf_private_ranges(pdf),
        CRIMINAL_RECORD_PROFILE => parse_criminal_record_pdf_private_ranges(pdf),
        DRIVER_LICENSE_PROFILE => parse_driver_license_pdf_private_ranges(pdf),
        TAX_DEBT_PROFILE => parse_tax_debt_pdf_private_ranges(pdf),
        _ => bail!("unsupported PDF profile"),
    }
}

pub fn parse_profile_pdf_redacted_ranges(profile: &str, pdf: &[u8]) -> Result<PdfPrivateRanges> {
    match profile {
        MILITARY_PROFILE => parse_military_pdf_redacted_ranges(pdf),
        RESIDENCE_PROFILE => parse_residence_pdf_redacted_ranges(pdf),
        CRIMINAL_RECORD_PROFILE => parse_criminal_record_pdf_redacted_ranges(pdf),
        DRIVER_LICENSE_PROFILE => parse_driver_license_pdf_redacted_ranges(pdf),
        TAX_DEBT_PROFILE => parse_tax_debt_pdf_redacted_ranges(pdf),
        _ => bail!("unsupported PDF profile"),
    }
}

#[derive(Clone, Copy)]
enum PdfRangeProfile {
    Military,
    Residence,
    CriminalRecord,
    DriverLicense,
    TaxDebt,
}

fn parse_pdf_redacted_ranges(pdf: &[u8], profile: PdfRangeProfile) -> Result<PdfPrivateRanges> {
    ensure_pdf_shape(pdf)?;
    let objects = indirect_objects(pdf)?;
    let barcode_stream = if matches!(
        profile,
        PdfRangeProfile::Military | PdfRangeProfile::CriminalRecord
    ) {
        Some(find_unique_stream(
            pdf,
            &objects,
            "barcode Form XObject",
            &[
                (b"/Type".as_slice(), b"/XObject".as_slice()),
                (b"/Subtype".as_slice(), b"/Form".as_slice()),
                (b"/Filter".as_slice(), b"/FlateDecode".as_slice()),
            ],
        )?)
    } else if matches!(profile, PdfRangeProfile::DriverLicense) {
        Some(find_unique_sized_flate_image(
            pdf,
            &objects,
            "driver-license barcode",
            200,
            50,
        )?)
    } else {
        None
    };
    let qr_image_stream = if matches!(profile, PdfRangeProfile::Military) {
        Some(find_unique_stream(
            pdf,
            &objects,
            "QR JPEG Image XObject",
            &[
                (b"/Type".as_slice(), b"/XObject".as_slice()),
                (b"/Subtype".as_slice(), b"/Image".as_slice()),
                (b"/Filter".as_slice(), b"/DCTDecode".as_slice()),
            ],
        )?)
    } else if matches!(profile, PdfRangeProfile::CriminalRecord) {
        Some(find_unique_criminal_qr_stream(pdf, &objects)?)
    } else if matches!(profile, PdfRangeProfile::DriverLicense) {
        Some(find_unique_sized_flate_image(
            pdf,
            &objects,
            "driver-license QR image",
            181,
            181,
        )?)
    } else if matches!(profile, PdfRangeProfile::TaxDebt) {
        Some(find_unique_sized_flate_image(
            pdf,
            &objects,
            "tax-debt QR image",
            49,
            49,
        )?)
    } else {
        None
    };
    let content_object = if matches!(profile, PdfRangeProfile::CriminalRecord) {
        find_criminal_record_content_object(pdf, &objects)?
    } else {
        find_page_content_object(pdf, &objects)?
    };
    let content_stream = if matches!(profile, PdfRangeProfile::DriverLicense) {
        stream_for_driver_license_content(pdf, &objects, content_object)?
    } else {
        stream_for_object(pdf, &objects, content_object)?
    };
    let maximum_content_stream_bytes = match profile {
        PdfRangeProfile::Military => MAX_CONTENT_STREAM_BYTES,
        PdfRangeProfile::Residence => MAX_RESIDENCE_CONTENT_STREAM_BYTES,
        PdfRangeProfile::CriminalRecord => MAX_CRIMINAL_RECORD_CONTENT_STREAM_BYTES,
        PdfRangeProfile::DriverLicense => MAX_DRIVER_LICENSE_CONTENT_STREAM_BYTES,
        PdfRangeProfile::TaxDebt => MAX_TAX_DEBT_CONTENT_STREAM_BYTES,
    };
    ensure!(
        content_stream.len() <= maximum_content_stream_bytes,
        "page content stream exceeds the Noir profile bound"
    );
    let document_id = match profile {
        PdfRangeProfile::Military => Some(find_document_id_range(pdf)?),
        PdfRangeProfile::Residence => Some(find_residence_document_id_range(pdf)?),
        PdfRangeProfile::CriminalRecord => Some(find_criminal_record_document_id_range(pdf)?),
        PdfRangeProfile::DriverLicense => {
            ensure!(
                occurrences(pdf, b"/ID") == 0,
                "driver-license PDF has an unexpected document ID"
            );
            None
        }
        PdfRangeProfile::TaxDebt => Some(find_tax_debt_document_id_range(pdf)?),
    };
    let (creation_date, modification_date) = if matches!(profile, PdfRangeProfile::CriminalRecord) {
        (
            Some(find_info_literal_range(pdf, &objects, b"/CreationDate")?),
            Some(find_info_literal_range(pdf, &objects, b"/ModDate")?),
        )
    } else if matches!(profile, PdfRangeProfile::DriverLicense) {
        ensure!(
            occurrences(pdf, b"/ModDate") == 0,
            "driver-license PDF has an unexpected modification date"
        );
        (
            Some(find_info_literal_range(pdf, &objects, b"/CreationDate")?),
            None,
        )
    } else if matches!(profile, PdfRangeProfile::TaxDebt) {
        (
            Some(find_info_literal_range(pdf, &objects, b"/CreationDate")?),
            Some(find_info_literal_range(pdf, &objects, b"/ModDate")?),
        )
    } else {
        (None, None)
    };

    let ranges = PdfPrivateRanges {
        barcode_stream,
        qr_image_stream,
        content_stream,
        creation_date,
        modification_date,
        document_id,
    };
    for range in ranges.ordered() {
        ensure!(
            range.end <= pdf.len() && !range.is_empty(),
            "private PDF range is outside the document"
        );
    }
    let ordered = ranges.ordered();
    for left in 0..ordered.len() {
        for right in left + 1..ordered.len() {
            ensure!(
                ordered[left].end <= ordered[right].start
                    || ordered[right].end <= ordered[left].start,
                "private PDF ranges overlap"
            );
        }
    }
    Ok(ranges)
}

pub fn residence_city_encoding(pdf: &[u8], city: &str) -> Result<Vec<u8>> {
    ensure!(
        city.chars().count() >= 2 && city.chars().count() <= 16,
        "city length is invalid"
    );
    let ranges = parse_residence_pdf_private_ranges(pdf)?;
    let mut decoder = ZlibDecoder::new(&pdf[ranges.content_stream]);
    let mut content = Vec::new();
    decoder
        .read_to_end(&mut content)
        .context("could not inflate residence page content")?;
    ensure!(
        content.len() <= 24_576,
        "residence page content exceeds its profile bound"
    );
    let operations = hex_text_operations(&content)?;
    let address_operations = residence_address_operations(&content, &operations)?;
    let encoded_address = decode_pdf_hex(
        &content[operations[*address_operations.last().expect("non-empty checked")].clone()],
    )?;
    let encoded_city_length = city.chars().count() * 2;
    ensure!(
        encoded_address.len() >= encoded_city_length,
        "residence address is shorter than the selected city"
    );
    let encoded_city = encoded_address[encoded_address.len() - encoded_city_length..].to_vec();
    validate_residence_city_encoding(pdf, city, &encoded_city)?;
    Ok(encoded_city)
}

fn residence_address_operations(content: &[u8], operations: &[Range<usize>]) -> Result<Vec<usize>> {
    const ADDRESS_BLOCK_PREFIX: &[u8] = b"BT\n/Font_1 -10 Tf\n";
    let mut candidates = Vec::new();
    let mut cursor = 0;
    while let Some(start) = find_from(content, ADDRESS_BLOCK_PREFIX, cursor) {
        let end = find_from(content, b"\nET", start + ADDRESS_BLOCK_PREFIX.len())
            .map(|position| position + 3)
            .context("residence Font_1 text block is not closed")?;
        let indexes = operations
            .iter()
            .enumerate()
            .filter(|(_, operation)| operation.start >= start && operation.end <= end)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if indexes.len() >= 2 {
            candidates.push(indexes);
        }
        cursor = end;
    }
    ensure!(
        candidates.len() == 1,
        "residence page does not have one address text block"
    );
    let indexes = candidates.pop().expect("candidate count checked");
    ensure!(
        indexes.len() <= 6,
        "residence address has too many text lines"
    );
    Ok(indexes)
}

pub fn validate_residence_city_encoding(pdf: &[u8], city: &str, encoded: &[u8]) -> Result<()> {
    ensure!(
        encoded.len() >= 4 && encoded.len() <= 32 && encoded.len() % 2 == 0,
        "city encoding length is invalid"
    );
    let cmap = residence_font_cmap(pdf)?;
    let mut decoded = String::new();
    for pair in encoded.chunks_exact(2) {
        let source = u16::from_be_bytes([pair[0], pair[1]]);
        let character = cmap
            .get(&source)
            .context("city encoding is absent from the authenticated font map")?;
        decoded.push(*character);
    }
    ensure!(
        decoded == city,
        "authenticated residence city does not match the selected city"
    );
    Ok(())
}

pub fn validate_criminal_record_identity_number(value: &str) -> Result<()> {
    ensure!(
        value.len() == 11
            && value.as_bytes()[0] != b'0'
            && value.bytes().all(|byte| byte.is_ascii_digit()),
        "criminal-record identity number must contain 11 digits and may not start with zero"
    );
    let digits = value
        .bytes()
        .map(|byte| (byte - b'0') as u32)
        .collect::<Vec<_>>();
    let odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
    let even = digits[1] + digits[3] + digits[5] + digits[7];
    ensure!(
        (odd * 7 + 10 - even % 10) % 10 == digits[9]
            && digits[..10].iter().sum::<u32>() % 10 == digits[10],
        "criminal-record identity number checksum is invalid"
    );
    Ok(())
}

pub fn validate_criminal_record_font_encoding(pdf: &[u8], identity_number: &str) -> Result<()> {
    validate_criminal_record_identity_number(identity_number)?;
    let regular = page_font_cmap(pdf, b"/F1")?;
    let bold = page_font_cmap(pdf, b"/F2")?;
    validate_criminal_cmap_text(&regular, "KİMLİK NUMARASI : ")?;
    validate_criminal_cmap_text(&regular, identity_number)?;
    validate_criminal_cmap_text(
        &bold,
        "YUKARIDA KİMLİK BİLGİLERİ BULUNAN KİŞİNİN ADLİ SİCİL KAYDI YOKTUR",
    )?;
    Ok(())
}

pub fn validate_tax_debt_font_encoding(pdf: &[u8]) -> Result<()> {
    let bold = page_font_cmap(pdf, b"/F2")?;
    const CODES: [u16; 20] = [
        0x45, 0x52, 0x55, 0x46, 0x58, 0x51, 0x58, 0x51, 0x03, 0x45, 0x58, 0x4f, 0x58, 0x51, 0x50,
        0x44, 0x47, 0xd5, 0xf7, 0xd5,
    ];
    for (code, character) in CODES.into_iter().zip("borcunun bulunmadığı".chars()) {
        ensure!(
            bold.get(&code) == Some(&character),
            "tax-debt claim encoding is absent from the authenticated font map"
        );
    }
    for digit in 0..10_u16 {
        ensure!(
            bold.get(&(0x13 + digit)) == char::from_digit(digit as u32, 10).as_ref(),
            "tax-debt digit encoding is absent from the authenticated font map"
        );
    }
    ensure!(
        bold.get(&0x12) == Some(&'/'),
        "tax-debt date separator encoding is absent from the authenticated font map"
    );
    Ok(())
}

fn validate_criminal_cmap_text(cmap: &HashMap<u16, char>, text: &str) -> Result<()> {
    for character in text.chars() {
        let source = criminal_record_glyph_code(character)
            .context("criminal-record text contains an unsupported profile character")?;
        ensure!(
            cmap.get(&source) == Some(&character),
            "criminal-record text encoding is absent from the authenticated font map"
        );
    }
    Ok(())
}

fn criminal_record_glyph_code(character: char) -> Option<u16> {
    match character {
        ' ' => Some(0x0003),
        ':' => Some(0x001d),
        '0'..='9' => Some(0x0013 + character as u16 - '0' as u16),
        'A' => Some(0x0024),
        'B' => Some(0x0025),
        'C' => Some(0x0026),
        'D' => Some(0x0027),
        'E' => Some(0x0028),
        'G' => Some(0x002a),
        'H' => Some(0x002b),
        'I' => Some(0x002c),
        'K' => Some(0x002e),
        'L' => Some(0x002f),
        'M' => Some(0x0030),
        'N' => Some(0x0031),
        'O' => Some(0x0032),
        'P' => Some(0x0033),
        'R' => Some(0x0035),
        'S' => Some(0x0036),
        'T' => Some(0x0037),
        'U' => Some(0x0038),
        'V' => Some(0x0039),
        'Y' => Some(0x003c),
        'Ç' => Some(0x0064),
        'Ö' => Some(0x0067),
        'Ü' => Some(0x0068),
        'Ğ' => Some(0x00f6),
        'İ' => Some(0x00f8),
        'Ş' => Some(0x00f9),
        _ => None,
    }
}

fn hex_text_operations(content: &[u8]) -> Result<Vec<Range<usize>>> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while let Some(open) = find_from(content, b"<", cursor) {
        let close = find_from(content, b">", open + 1).context("unterminated PDF hex string")?;
        let mut operator = close + 1;
        while operator < content.len() && matches!(content[operator], 0 | 9 | 10 | 12 | 13 | 32) {
            operator += 1;
        }
        if content.get(operator..operator + 2) == Some(b"Tj") {
            ensure!(
                content[open + 1..close]
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() || byte.is_ascii_whitespace()),
                "invalid PDF hex text operation"
            );
            result.push(open + 1..close);
        }
        cursor = close + 1;
    }
    Ok(result)
}

fn decode_pdf_hex(value: &[u8]) -> Result<Vec<u8>> {
    let digits = value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    ensure!(digits.len() % 2 == 0, "PDF hex string has odd length");
    hex::decode(digits).context("PDF text operation contains invalid hexadecimal")
}

fn residence_font_cmap(pdf: &[u8]) -> Result<HashMap<u16, char>> {
    page_font_cmap(pdf, b"/Font_1")
}

fn page_font_cmap(pdf: &[u8], font_marker: &[u8]) -> Result<HashMap<u16, char>> {
    let objects = indirect_objects(pdf)?;
    let pages = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object)
                .is_ok_and(|dictionary| has_name_entry(dictionary, b"/Type", b"/Page"))
        })
        .collect::<Vec<_>>();
    ensure!(
        pages.len() == 1,
        "PDF does not have one page font resource dictionary"
    );
    let page_dictionary = object_dictionary(pdf, pages[0])?;
    let resource_dictionary = dictionary_for_entry(
        pdf,
        &objects,
        page_dictionary,
        b"/Resources",
        "page resource dictionary",
    )?;
    let font_dictionary = dictionary_for_entry(
        pdf,
        &objects,
        resource_dictionary,
        b"/Font",
        "page font resource dictionary",
    )?;
    let at =
        find_unique_name(font_dictionary, font_marker, "page font resource")? + font_marker.len();
    let font_number = parse_reference_at(font_dictionary, at)?;
    let font = objects
        .iter()
        .find(|object| object.number == font_number)
        .context("page font object is missing")?;
    let dictionary = object_dictionary(pdf, font)?;
    let marker = find_from(dictionary, b"/ToUnicode", 0).context("Font_1 has no ToUnicode map")?
        + b"/ToUnicode".len();
    let cmap_number = parse_reference_at(dictionary, marker)?;
    let range = stream_for_object(pdf, &objects, cmap_number)?;
    let cmap_object = objects
        .iter()
        .find(|object| object.number == cmap_number)
        .context("ToUnicode object is missing")?;
    let cmap_dictionary = object_dictionary(pdf, cmap_object)?;
    let cmap_bytes = if find_from(cmap_dictionary, b"/FlateDecode", 0).is_some() {
        let mut decoder = ZlibDecoder::new(&pdf[range]);
        let mut decoded = Vec::new();
        decoder
            .read_to_end(&mut decoded)
            .context("could not inflate authenticated font map")?;
        decoded
    } else {
        pdf[range].to_vec()
    };
    parse_cmap(&cmap_bytes)
}

fn dictionary_for_entry<'a>(
    pdf: &'a [u8],
    objects: &[IndirectObject],
    dictionary: &'a [u8],
    key: &[u8],
    description: &str,
) -> Result<&'a [u8]> {
    let at = find_unique_name(dictionary, key, description)? + key.len();
    let mut cursor = at;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if !dictionary.get(cursor).is_some_and(u8::is_ascii_digit) {
        return Ok(dictionary);
    }
    let object_number = parse_reference_at(dictionary, cursor)?;
    let object = objects
        .iter()
        .find(|object| object.number == object_number)
        .with_context(|| format!("{description} object is missing"))?;
    object_dictionary(pdf, object)
}

fn find_unique_name(dictionary: &[u8], name: &[u8], description: &str) -> Result<usize> {
    let mut matches = Vec::new();
    let mut search_from = 0;
    while let Some(position) = find_from(dictionary, name, search_from) {
        let end = position + name.len();
        if dictionary
            .get(end)
            .is_none_or(|byte| is_pdf_name_delimiter(*byte))
        {
            matches.push(position);
        }
        search_from = end;
    }
    ensure!(matches.len() == 1, "{description} is not unique");
    Ok(matches[0])
}

fn is_pdf_name_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

fn parse_reference_at(bytes: &[u8], mut cursor: usize) -> Result<u32> {
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    let start = cursor;
    while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
        cursor += 1;
    }
    ensure!(cursor > start, "PDF reference has no object number");
    let number = std::str::from_utf8(&bytes[start..cursor])?.parse()?;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    ensure!(
        bytes.get(cursor..cursor + 3) == Some(b"0 R"),
        "PDF reference is not generation zero"
    );
    Ok(number)
}

fn parse_cmap(bytes: &[u8]) -> Result<HashMap<u16, char>> {
    let text = std::str::from_utf8(bytes).context("ToUnicode map is not UTF-8 ASCII")?;
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut tokens = Vec::new();
        let mut cursor = 0;
        while let Some(relative_open) = line[cursor..].find('<') {
            let open = cursor + relative_open;
            if line.as_bytes().get(open + 1) == Some(&b'<') {
                cursor = open + 2;
                continue;
            }
            let close = line[open + 1..]
                .find('>')
                .map(|relative| open + 1 + relative)
                .context("ToUnicode hex token is not closed")?;
            tokens.push(&line[open + 1..close]);
            cursor = close + 1;
        }
        if tokens.len() != 3 {
            continue;
        }
        let parse = |token: &str| u32::from_str_radix(token, 16);
        let (start, end, unicode_start) = (parse(tokens[0])?, parse(tokens[1])?, parse(tokens[2])?);
        ensure!(
            start <= end && end <= u16::MAX as u32,
            "ToUnicode range is invalid"
        );
        for source in start..=end {
            let character = char::from_u32(unicode_start + source - start)
                .context("ToUnicode character is invalid")?;
            map.insert(source as u16, character);
        }
    }
    ensure!(!map.is_empty(), "ToUnicode map has no supported ranges");
    Ok(map)
}

fn ensure_pdf_shape(pdf: &[u8]) -> Result<()> {
    ensure!(
        pdf.starts_with(b"%PDF-1."),
        "response body is not a supported PDF"
    );
    ensure!(
        occurrences(pdf, b"startxref") == 1 && occurrences(pdf, b"%%EOF") == 1,
        "PDF must contain exactly one cross-reference trailer"
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct IndirectObject {
    number: u32,
    start: usize,
    end: usize,
}

fn indirect_objects(pdf: &[u8]) -> Result<Vec<IndirectObject>> {
    let marker = b" 0 obj";
    let mut objects = Vec::new();
    let mut search_from = 0;
    while let Some(marker_start) = find_from(pdf, marker, search_from) {
        search_from = marker_start + marker.len();
        let mut digit_start = marker_start;
        while digit_start > 0 && pdf[digit_start - 1].is_ascii_digit() {
            digit_start -= 1;
        }
        if digit_start == marker_start
            || (digit_start > 0 && !matches!(pdf[digit_start - 1], b'\n' | b'\r'))
        {
            continue;
        }
        let number = std::str::from_utf8(&pdf[digit_start..marker_start])?.parse()?;
        let body_start = marker_start + marker.len();
        let end_marker =
            find_from(pdf, b"endobj", body_start).context("PDF indirect object has no endobj")?;
        objects.push(IndirectObject {
            number,
            start: digit_start,
            end: end_marker + b"endobj".len(),
        });
    }
    ensure!(!objects.is_empty(), "PDF has no indirect objects");
    for (index, object) in objects.iter().enumerate() {
        ensure!(
            objects.iter().enumerate().all(|(other_index, other)| {
                index == other_index || object.number != other.number
            }),
            "PDF indirect object {} occurs more than once",
            object.number
        );
    }
    Ok(objects)
}

fn object_dictionary<'a>(pdf: &'a [u8], object: &IndirectObject) -> Result<&'a [u8]> {
    let dictionary_end = find_from(pdf, b"stream", object.start)
        .filter(|position| *position < object.end)
        .unwrap_or(object.end);
    Ok(&pdf[object.start..dictionary_end])
}

fn find_unique_stream(
    pdf: &[u8],
    objects: &[IndirectObject],
    description: &str,
    required_names: &[(&[u8], &[u8])],
) -> Result<Range<usize>> {
    let matches = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object).is_ok_and(|dictionary| {
                required_names
                    .iter()
                    .all(|(key, value)| has_name_entry(dictionary, key, value))
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "PDF must contain exactly one {description}, found {}",
        matches.len()
    );
    stream_for_object(pdf, objects, matches[0].number)
}

fn stream_for_object(
    pdf: &[u8],
    objects: &[IndirectObject],
    object_number: u32,
) -> Result<Range<usize>> {
    let object = objects
        .iter()
        .find(|object| object.number == object_number)
        .context("referenced PDF stream object is absent")?;
    let stream_marker = find_from(pdf, b"stream", object.start)
        .filter(|position| *position < object.end)
        .context("referenced PDF object has no stream")?;
    let dictionary = &pdf[object.start..stream_marker];
    let length = direct_stream_length(dictionary)
        .with_context(|| format!("PDF object {object_number} has an invalid /Length"))?;
    let mut data_start = stream_marker + b"stream".len();
    match pdf.get(data_start..data_start + 2) {
        Some(b"\r\n") => data_start += 2,
        _ if pdf.get(data_start) == Some(&b'\n') => data_start += 1,
        _ => bail!("PDF object {object_number} has invalid stream framing"),
    }
    let data_end = data_start
        .checked_add(length)
        .context("PDF stream length overflow")?;
    ensure!(
        data_end <= pdf.len(),
        "PDF object {object_number} stream is truncated"
    );
    let suffix = pdf
        .get(data_end..)
        .context("PDF object stream ends outside the document")?;
    ensure!(
        suffix.starts_with(b"\nendstream") || suffix.starts_with(b"\r\nendstream"),
        "PDF object {object_number} stream length does not match its framing"
    );
    Ok(data_start..data_end)
}

fn stream_for_driver_license_content(
    pdf: &[u8],
    objects: &[IndirectObject],
    object_number: u32,
) -> Result<Range<usize>> {
    let object = objects
        .iter()
        .find(|object| object.number == object_number)
        .context("referenced driver-license stream object is absent")?;
    let stream_marker = find_from(pdf, b"stream", object.start)
        .filter(|position| *position < object.end)
        .context("referenced driver-license object has no stream")?;
    let dictionary = &pdf[object.start..stream_marker];
    let length = direct_stream_length(dictionary)
        .with_context(|| format!("PDF object {object_number} has an invalid /Length"))?;
    let data_start = stream_marker + b"stream".len() + 3;
    ensure!(
        pdf.get(stream_marker + b"stream".len()..data_start) == Some(b" \r\n"),
        "driver-license content stream has invalid framing"
    );
    let data_end = data_start
        .checked_add(length)
        .context("PDF stream length overflow")?;
    ensure!(
        data_end <= pdf.len(),
        "driver-license content stream is truncated"
    );
    let suffix = pdf
        .get(data_end..)
        .context("PDF stream ends outside the document")?;
    ensure!(
        suffix.starts_with(b"\r\nendstream") || suffix.starts_with(b"\nendstream"),
        "driver-license content stream length does not match its framing"
    );
    Ok(data_start..data_end)
}

fn find_page_content_object(pdf: &[u8], objects: &[IndirectObject]) -> Result<u32> {
    let pages = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object)
                .is_ok_and(|dictionary| has_name_entry(dictionary, b"/Type", b"/Page"))
        })
        .collect::<Vec<_>>();
    ensure!(
        pages.len() == 1,
        "PDF must contain exactly one page, found {}",
        pages.len()
    );
    let dictionary = object_dictionary(pdf, pages[0])?;
    parse_indirect_reference(dictionary, b"/Contents")
        .context("PDF page must have one direct /Contents reference")
}

fn find_criminal_record_content_object(pdf: &[u8], objects: &[IndirectObject]) -> Result<u32> {
    let pages = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object)
                .is_ok_and(|dictionary| has_name_entry(dictionary, b"/Type", b"/Page"))
        })
        .collect::<Vec<_>>();
    ensure!(
        pages.len() == 1,
        "criminal-record PDF must contain exactly one page"
    );
    let dictionary = object_dictionary(pdf, pages[0])?;
    ensure!(
        occurrences(dictionary, b"/Contents") == 1,
        "criminal-record page must have exactly one /Contents entry"
    );
    let mut cursor =
        find_from(dictionary, b"/Contents", 0).expect("occurrence checked") + b"/Contents".len();
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        dictionary.get(cursor) == Some(&b'['),
        "criminal-record /Contents is not an array"
    );
    cursor += 1;
    let mut references = Vec::new();
    loop {
        while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if dictionary.get(cursor) == Some(&b']') {
            break;
        }
        let (reference, end) = parse_reference_with_end(dictionary, cursor)?;
        references.push(reference);
        cursor = end;
    }
    ensure!(
        references.len() == 5
            && references
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == 5,
        "criminal-record /Contents must contain five unique stream references"
    );
    let expected_safe_lengths = [(0usize, 10usize), (1, 10), (3, 58), (4, 345)];
    for (index, expected_length) in expected_safe_lengths {
        let range = stream_for_object(pdf, objects, references[index])?;
        ensure!(
            range.len() == expected_length,
            "criminal-record static content stream has the wrong length"
        );
    }
    Ok(references[2])
}

fn parse_reference_with_end(bytes: &[u8], mut cursor: usize) -> Result<(u32, usize)> {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let start = cursor;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    ensure!(cursor > start, "PDF reference has no object number");
    let number = std::str::from_utf8(&bytes[start..cursor])?.parse()?;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        bytes.get(cursor) == Some(&b'0'),
        "PDF reference generation is not zero"
    );
    cursor += 1;
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        bytes.get(cursor) == Some(&b'R'),
        "PDF reference has no R marker"
    );
    Ok((number, cursor + 1))
}

fn has_integer_entry(dictionary: &[u8], key: &[u8], expected: usize) -> bool {
    let Some(position) = find_from(dictionary, key, 0) else {
        return false;
    };
    if occurrences(dictionary, key) != 1 {
        return false;
    }
    let mut cursor = position + key.len();
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let start = cursor;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    cursor > start
        && std::str::from_utf8(&dictionary[start..cursor])
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            == Some(expected)
}

fn find_unique_criminal_qr_stream(pdf: &[u8], objects: &[IndirectObject]) -> Result<Range<usize>> {
    let matches = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object).is_ok_and(|dictionary| {
                has_name_entry(dictionary, b"/Type", b"/XObject")
                    && has_name_entry(dictionary, b"/Subtype", b"/Image")
                    && has_name_entry(dictionary, b"/Filter", b"/CCITTFaxDecode")
                    && has_integer_entry(dictionary, b"/Width", 90)
                    && has_integer_entry(dictionary, b"/Height", 90)
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "criminal-record PDF must contain one 90x90 CCITT QR image"
    );
    stream_for_object(pdf, objects, matches[0].number)
}

fn find_unique_sized_flate_image(
    pdf: &[u8],
    objects: &[IndirectObject],
    description: &str,
    width: usize,
    height: usize,
) -> Result<Range<usize>> {
    let matches = objects
        .iter()
        .filter(|object| {
            object_dictionary(pdf, object).is_ok_and(|dictionary| {
                has_name_entry(dictionary, b"/Type", b"/XObject")
                    && has_name_entry(dictionary, b"/Subtype", b"/Image")
                    && has_name_entry(dictionary, b"/Filter", b"/FlateDecode")
                    && has_integer_entry(dictionary, b"/Width", width)
                    && has_integer_entry(dictionary, b"/Height", height)
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "PDF must contain exactly one {description}"
    );
    stream_for_object(pdf, objects, matches[0].number)
}

fn find_info_literal_range(
    pdf: &[u8],
    objects: &[IndirectObject],
    key: &[u8],
) -> Result<Range<usize>> {
    ensure!(
        occurrences(pdf, b"/Info") == 1,
        "PDF must contain exactly one /Info reference"
    );
    let info_marker = find_from(pdf, b"/Info", 0).expect("occurrence checked") + b"/Info".len();
    let info_number = parse_reference_at(pdf, info_marker)?;
    let info = objects
        .iter()
        .find(|object| object.number == info_number)
        .context("PDF Info object is missing")?;
    let dictionary = object_dictionary(pdf, info)?;
    ensure!(
        occurrences(dictionary, key) == 1,
        "PDF Info date key is not unique"
    );
    let mut cursor = find_from(dictionary, key, 0).expect("occurrence checked") + key.len();
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        dictionary.get(cursor) == Some(&b'('),
        "PDF Info date is not a literal string"
    );
    let value_start = info.start + cursor + 1;
    let mut value_end = value_start;
    while value_end < info.end {
        if pdf[value_end] == b'\\' {
            value_end += 2;
            continue;
        }
        if pdf[value_end] == b')' {
            break;
        }
        value_end += 1;
    }
    ensure!(
        value_end < info.end && (16..=64).contains(&(value_end - value_start)),
        "PDF Info date has an invalid length"
    );
    Ok(value_start..value_end)
}

fn has_name_entry(dictionary: &[u8], key: &[u8], value: &[u8]) -> bool {
    let mut search_from = 0;
    while let Some(position) = find_from(dictionary, key, search_from) {
        let mut cursor = position + key.len();
        while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if dictionary.get(cursor..cursor + value.len()) == Some(value)
            && dictionary
                .get(cursor + value.len())
                .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        {
            return true;
        }
        search_from = position + key.len();
    }
    false
}

fn parse_indirect_reference(dictionary: &[u8], key: &[u8]) -> Result<u32> {
    ensure!(
        occurrences(dictionary, key) == 1,
        "expected exactly one reference key"
    );
    let mut cursor = find_from(dictionary, key, 0).expect("occurrence checked") + key.len();
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let number_start = cursor;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    ensure!(cursor > number_start, "reference has no object number");
    let number = std::str::from_utf8(&dictionary[number_start..cursor])?.parse()?;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        dictionary.get(cursor) == Some(&b'0'),
        "reference generation is not zero"
    );
    cursor += 1;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    ensure!(
        dictionary.get(cursor) == Some(&b'R'),
        "reference has no R marker"
    );
    Ok(number)
}

fn direct_stream_length(dictionary: &[u8]) -> Result<usize> {
    ensure!(
        occurrences(dictionary, b"/Length") == 1,
        "expected one direct /Length"
    );
    let start =
        find_from(dictionary, b"/Length", 0).expect("occurrence checked") + b"/Length".len();
    let mut cursor = start;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let digit_start = cursor;
    while dictionary.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    ensure!(cursor > digit_start, "/Length is not a decimal integer");
    let value = std::str::from_utf8(&dictionary[digit_start..cursor])?.parse()?;
    Ok(value)
}

fn find_document_id_range(pdf: &[u8]) -> Result<Range<usize>> {
    ensure!(
        occurrences(pdf, b"/ID") == 1,
        "PDF trailer must contain exactly one /ID"
    );
    let id = find_from(pdf, b"/ID", 0).expect("occurrence checked");
    let mut start = id + 3;
    while pdf.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let end = start.checked_add(70).context("PDF /ID range overflow")?;
    pdf.get(start..end).context("PDF /ID value is truncated")?;
    ensure!(
        pdf.get(end..end + 5) == Some(b"/Root"),
        "PDF /ID is not followed by the expected trailer root"
    );
    Ok(start..end)
}

fn find_criminal_record_document_id_range(pdf: &[u8]) -> Result<Range<usize>> {
    ensure!(
        occurrences(pdf, b"/ID") == 1,
        "criminal-record cross-reference stream must contain exactly one /ID"
    );
    let id = find_from(pdf, b"/ID", 0).expect("occurrence checked");
    let mut start = id + b"/ID".len();
    while pdf.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let end = start.checked_add(70).context("PDF /ID range overflow")?;
    pdf.get(start..end).context("PDF /ID value is truncated")?;
    let mut suffix = end;
    while pdf.get(suffix).is_some_and(u8::is_ascii_whitespace) {
        suffix += 1;
    }
    ensure!(
        pdf.get(suffix..suffix + 2) == Some(b">>"),
        "criminal-record /ID is not the final cross-reference dictionary entry"
    );
    Ok(start..end)
}

fn find_tax_debt_document_id_range(pdf: &[u8]) -> Result<Range<usize>> {
    ensure!(
        occurrences(pdf, b"/ID") == 1,
        "tax-debt PDF trailer must contain exactly one /ID"
    );
    let id = find_from(pdf, b"/ID", 0).expect("occurrence checked");
    let mut start = id + 3;
    while pdf.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let end = start
        .checked_add(262)
        .context("tax-debt PDF /ID range overflow")?;
    pdf.get(start..end)
        .context("tax-debt PDF /ID value is truncated")?;
    ensure!(
        pdf.get(end..end + 5) == Some(b"/Info"),
        "tax-debt PDF /ID is not followed by the expected trailer Info entry"
    );
    Ok(start..end)
}

fn find_residence_document_id_range(pdf: &[u8]) -> Result<Range<usize>> {
    let startxref = find_from(pdf, b"startxref", 0).context("PDF startxref is missing")?;
    let trailer = pdf[..startxref]
        .windows(b"trailer".len())
        .enumerate()
        .filter(|(position, token)| {
            *token == b"trailer"
                && (*position == 0 || pdf[*position - 1].is_ascii_whitespace())
                && pdf
                    .get(*position + b"trailer".len())
                    .is_some_and(u8::is_ascii_whitespace)
        })
        .map(|(position, _)| position)
        .last()
        .context("PDF classic trailer dictionary is missing")?;
    let dictionary_start = find_from(pdf, b"<<", trailer + b"trailer".len())
        .filter(|position| *position < startxref)
        .context("PDF trailer dictionary is missing")?;
    let dictionary_end = pdf[dictionary_start + 2..startxref]
        .windows(2)
        .enumerate()
        .filter(|(_, token)| *token == b">>")
        .map(|(position, _)| dictionary_start + 2 + position)
        .last()
        .context("PDF trailer dictionary is not closed")?;
    ensure!(
        pdf[dictionary_end + 2..startxref]
            .iter()
            .all(u8::is_ascii_whitespace),
        "PDF trailer has unexpected bytes before startxref"
    );

    let dictionary = &pdf[dictionary_start..dictionary_end];
    let id_entries = dictionary
        .windows(3)
        .enumerate()
        .filter(|(position, token)| {
            *token == b"/ID"
                && (*position == 0 || is_pdf_delimiter(dictionary[*position - 1]))
                && dictionary
                    .get(*position + 3)
                    .is_some_and(|byte| is_pdf_delimiter(*byte) || *byte == b'X')
        })
        .map(|(position, _)| dictionary_start + position)
        .collect::<Vec<_>>();
    ensure!(
        id_entries.len() == 1,
        "PDF trailer must contain exactly one direct /ID entry"
    );
    let mut start = id_entries[0] + 3;
    while pdf.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let mut end = dictionary_end;
    while end > start && pdf[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    ensure!(start < end, "PDF /ID value is empty");
    ensure!(end - start <= 140, "PDF /ID value is too long");
    Ok(start..end)
}

fn is_pdf_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(byte, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'/' | b'%')
}

fn validate_document_id(value: &[u8]) -> Result<()> {
    ensure!(
        value[0] == b'['
            && value[1] == b'<'
            && value[34] == b'>'
            && value[35] == b'<'
            && value[68] == b'>'
            && value[69] == b']',
        "PDF /ID has the wrong profile shape"
    );
    for &byte in &value[2..34] {
        ensure!(byte.is_ascii_hexdigit(), "PDF /ID is not hexadecimal");
    }
    for &byte in &value[36..68] {
        ensure!(byte.is_ascii_hexdigit(), "PDF /ID is not hexadecimal");
    }
    Ok(())
}

fn validate_tax_debt_document_id(value: &[u8]) -> Result<()> {
    ensure!(
        value.len() == 262
            && value[0] == b'['
            && value[1] == b'<'
            && value[130] == b'>'
            && value[131] == b'<'
            && value[260] == b'>'
            && value[261] == b']',
        "tax-debt PDF /ID has the wrong profile shape"
    );
    ensure!(
        value[2..130].iter().all(u8::is_ascii_hexdigit)
            && value[132..260].iter().all(u8::is_ascii_hexdigit),
        "tax-debt PDF /ID is not hexadecimal"
    );
    Ok(())
}

fn validate_residence_document_id(value: &[u8]) -> Result<()> {
    ensure!(
        value.first() == Some(&b'[') && value.last() == Some(&b']'),
        "PDF /ID has the wrong residence profile shape"
    );
    let compact = value
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let mut cursor = 1;
    for _ in 0..2 {
        ensure!(
            compact.get(cursor) == Some(&b'<'),
            "PDF /ID has the wrong residence profile shape"
        );
        cursor += 1;
        let end = compact[cursor..]
            .iter()
            .position(|byte| *byte == b'>')
            .map(|position| cursor + position)
            .context("PDF /ID hexadecimal string is not closed")?;
        ensure!(cursor < end, "PDF /ID hexadecimal string is empty");
        ensure!(
            compact[cursor..end].iter().all(u8::is_ascii_hexdigit),
            "PDF /ID is not hexadecimal"
        );
        cursor = end + 1;
    }
    ensure!(
        cursor + 1 == compact.len() && compact[cursor] == b']',
        "PDF /ID has the wrong residence profile shape"
    );
    Ok(())
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    let mut count = 0;
    let mut offset = 0;
    while let Some(position) = find_from(haystack, needle, offset) {
        count += 1;
        offset = position + needle.len();
    }
    count
}

fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}

pub fn reject_header_injection(name: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        bail!("{name} contains a forbidden line break");
    }
    Ok(())
}

pub fn is_pdf_content_type(value: &[u8]) -> bool {
    let media_type = value.split(|byte| *byte == b';').next().unwrap_or_default();
    let start = media_type
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(media_type.len());
    let end = media_type
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    media_type[start..end].eq_ignore_ascii_case(b"application/pdf")
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::{
        find_residence_document_id_range, hex_text_operations, is_pdf_content_type, page_font_cmap,
        parse_criminal_record_pdf_private_ranges, parse_criminal_record_pdf_redacted_ranges,
        parse_military_pdf_private_ranges, parse_military_pdf_redacted_ranges,
        parse_residence_pdf_private_ranges, parse_residence_pdf_redacted_ranges,
        parse_tax_debt_pdf_private_ranges, parse_tax_debt_pdf_redacted_ranges,
        residence_address_operations, residence_city_encoding,
        validate_criminal_record_font_encoding, validate_criminal_record_identity_number,
        validate_residence_city_encoding, validate_residence_document_id,
        validate_tax_debt_font_encoding,
    };

    fn fixture() -> Vec<u8> {
        let mut pdf = b"%PDF-1.7\n\
91 0 obj <</Contents 73 0 R/Type/Page>>\nendobj\n\
42 0 obj <</Type/XObject/Subtype/Image/Filter/DCTDecode/Length 2>>\nstream\ncd\nendstream\nendobj\n\
73 0 obj <</Filter/FlateDecode/Length 2>>\nstream\n"
            .to_vec();
        pdf.extend_from_slice(&[0x78, 0x9c]);
        pdf.extend_from_slice(
            b"\nendstream\nendobj\n\
18 0 obj <</Type/XObject/Subtype/Form/Filter/FlateDecode/Length 2>>\nstream\nab\nendstream\nendobj\n\
trailer <</ID [<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa><bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb>]/Root 1 0 R>>\n\
startxref\n0\n%%EOF\n",
        );
        pdf
    }

    fn criminal_record_fixture() -> Vec<u8> {
        let mut pdf = b"%PDF-1.5\n\
5 0 obj <</CreationDate (D:20260903000000+03'00')/ModDate (D:20260903000000+03'00')/Producer (fixture)>> endobj\n\
22 0 obj <</Type/Page/Contents [6 0 R 9 0 R 20 0 R 10 0 R 7 0 R]>> endobj\n\
1 0 obj <</Type/XObject/Subtype/Image/Filter/CCITTFaxDecode/Width 90/Height 90/Length 2>>\nstream\nqr\nendstream\nendobj\n\
3 0 obj <</Type/XObject/Subtype/Form/Filter/FlateDecode/Length 2>>\nstream\nbc\nendstream\nendobj\n\
6 0 obj <</Filter/FlateDecode/Length 10>>\nstream\n0123456789\nendstream\nendobj\n\
9 0 obj <</Filter/FlateDecode/Length 10>>\nstream\n0123456789\nendstream\nendobj\n\
20 0 obj <</Filter/FlateDecode/Length 2>>\nstream\n"
            .to_vec();
        pdf.extend_from_slice(&[0x78, 0x9c]);
        pdf.extend_from_slice(
            b"\nendstream\nendobj\n\
10 0 obj <</Filter/FlateDecode/Length 58>>\nstream\n0000000000000000000000000000000000000000000000000000000000\nendstream\nendobj\n\
7 0 obj <</Filter/FlateDecode/Length 345>>\nstream\n",
        );
        pdf.extend(std::iter::repeat_n(b'0', 345));
        pdf.extend_from_slice(
            b"\nendstream\nendobj\n\
23 0 obj <</Type/XRef/Info 5 0 R/ID [<aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa><bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb>]>>\nstream\nx\nendstream\nendobj\n\
startxref\n0\n%%EOF\n",
        );
        pdf
    }

    fn font_resource_fixture(page_resources: &str, resource_object: Option<&str>) -> Vec<u8> {
        let cmap = b"<0001> <0001> <0041>";
        let mut pdf =
            format!("%PDF-1.7\n1 0 obj <</Type/Page/Resources {page_resources}>> endobj\n")
                .into_bytes();
        if let Some(resource_object) = resource_object {
            pdf.extend_from_slice(resource_object.as_bytes());
        }
        pdf.extend_from_slice(
            b"3 0 obj <</ToUnicode 4 0 R>> endobj\n\
4 0 obj <</Length 20>>\nstream\n",
        );
        pdf.extend_from_slice(cmap);
        pdf.extend_from_slice(b"\nendstream\nendobj\nstartxref\n0\n%%EOF\n");
        pdf
    }

    #[test]
    fn derives_the_same_ranges_from_private_and_redacted_bytes() {
        let mut pdf = fixture();
        let private = parse_military_pdf_private_ranges(&pdf).unwrap();
        for range in private.ordered() {
            pdf[range.clone()].fill(b'X');
        }
        let redacted = parse_military_pdf_redacted_ranges(&pdf).unwrap();
        assert_eq!(private, redacted);
    }

    #[test]
    fn criminal_record_ranges_are_semantic_and_redaction_stable() {
        let mut pdf = criminal_record_fixture();
        let private = parse_criminal_record_pdf_private_ranges(&pdf).unwrap();
        assert_eq!(private.labeled().len(), 6);
        for range in private.ordered() {
            pdf[range.clone()].fill(b'X');
        }
        assert_eq!(
            private,
            parse_criminal_record_pdf_redacted_ranges(&pdf).unwrap()
        );
    }

    #[test]
    fn residence_document_id_is_trailer_scoped_and_redaction_stable() {
        let value = format!("[<{}> <{}>]", "a".repeat(60), "b".repeat(60));
        let prefix = b"%PDF-1.7\n7 0 obj <</Identity-H/ID [not-a-trailer-id]>>\nendobj\n\
trailer\n<< /Root 1 0 R\n/ID \n";
        let suffix = b"\n>>\nstartxref\n0\n%%EOF\n";
        let mut pdf = prefix.to_vec();
        pdf.extend_from_slice(value.as_bytes());
        pdf.extend_from_slice(suffix);

        let expected = prefix.len()..prefix.len() + value.len();
        assert_eq!(find_residence_document_id_range(&pdf).unwrap(), expected);
        pdf[expected.clone()].fill(b'X');
        assert_eq!(find_residence_document_id_range(&pdf).unwrap(), expected);
    }

    #[test]
    fn page_font_map_resolves_indirect_resource_dictionary() {
        let pdf = font_resource_fixture(
            "2 0 R",
            Some("2 0 obj <</Font <</Font_1 3 0 R>>>> endobj\n"),
        );
        assert_eq!(
            page_font_cmap(&pdf, b"/Font_1").unwrap().get(&1),
            Some(&'A')
        );
    }

    #[test]
    fn page_font_name_does_not_match_longer_font_name() {
        let pdf = font_resource_fixture("<</Font <</F10 9 0 R/F1 3 0 R>>>>", None);
        assert_eq!(page_font_cmap(&pdf, b"/F1").unwrap().get(&1), Some(&'A'));
    }

    #[test]
    fn residence_document_id_accepts_variable_length_hexadecimal_strings() {
        validate_residence_document_id(
            format!("[<{}> <{}>]", "a".repeat(60), "b".repeat(60)).as_bytes(),
        )
        .unwrap();
        validate_residence_document_id(
            format!("[<{}> <{}>]", "a".repeat(54), "b".repeat(54)).as_bytes(),
        )
        .unwrap();

        assert!(validate_residence_document_id(b"[<> <12>]").is_err());
        assert!(validate_residence_document_id(b"[<12> <not-hex>]").is_err());
        assert!(validate_residence_document_id(b"[<12>]").is_err());
        assert!(validate_residence_document_id(b"[<12> <34> <56>]").is_err());
    }

    #[test]
    fn residence_address_uses_the_variable_length_font_block() {
        for address in [
            "BT\n/Font_1 -10 Tf\n1 1 Td\n<0001> Tj\n1 1 Td\n<0002> Tj\nET",
            "BT\n/Font_1 -10 Tf\n1 1 Td\n<0001> Tj\n1 1 Td\n<0002> Tj\n1 1 Td\n<0003> Tj\nET",
        ] {
            let content = format!("{address}\nBT\n/Font_1 -10 Tf\n1 1 Td\n<0041> Tj\nET");
            let operations = hex_text_operations(content.as_bytes()).unwrap();
            let address_operations =
                residence_address_operations(content.as_bytes(), &operations).unwrap();
            assert_eq!(address_operations.last(), Some(&(operations.len() - 2)));
        }
    }

    #[test]
    fn validates_pdf_content_type_as_a_media_type() {
        assert!(is_pdf_content_type(b"application/pdf"));
        assert!(is_pdf_content_type(b" Application/PDF ; charset=binary"));
        assert!(!is_pdf_content_type(b"application/pdfx"));
        assert!(!is_pdf_content_type(b"text/plain"));
    }

    #[test]
    fn validates_optional_local_profile_fixtures() {
        let Ok(paths) = std::env::var("ZKDEVLET_PROFILE_FIXTURES") else {
            return;
        };
        for path in std::env::split_paths(&paths) {
            let pdf = std::fs::read(&path).unwrap();
            parse_military_pdf_private_ranges(&pdf).unwrap();
        }
    }

    #[test]
    fn validates_optional_local_residence_fixture() {
        let Ok(path) = std::env::var("ZKDEVLET_RESIDENCE_FIXTURE") else {
            return;
        };
        let pdf = std::fs::read(path).unwrap();
        let ranges = parse_residence_pdf_private_ranges(&pdf).unwrap();
        let mut redacted = pdf.clone();
        for range in ranges.ordered() {
            redacted[range.clone()].fill(b'X');
        }
        assert_eq!(
            ranges,
            parse_residence_pdf_redacted_ranges(&redacted).unwrap()
        );
        if let Ok(city) = std::env::var("ZKDEVLET_RESIDENCE_CITY") {
            let encoding = residence_city_encoding(&pdf, &city).unwrap();
            validate_residence_city_encoding(&redacted, &city, &encoding).unwrap();
        }
    }

    #[test]
    fn validates_optional_local_criminal_record_fixtures() {
        let Ok(paths) = std::env::var("ZKDEVLET_CRIMINAL_RECORD_FIXTURES") else {
            return;
        };
        for path in std::env::split_paths(&paths) {
            let pdf = std::fs::read(path).unwrap();
            let ranges = parse_criminal_record_pdf_private_ranges(&pdf).unwrap();
            let mut decoder = flate2::read::ZlibDecoder::new(&pdf[ranges.content_stream.clone()]);
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut decoder, &mut content).unwrap();
            let prefix = [0, 3, 0, 29, 0, 3];
            let identities = content
                .windows(28)
                .filter_map(|window| {
                    if window[..6] != prefix {
                        return None;
                    }
                    let mut identity = String::new();
                    for pair in window[6..].chunks_exact(2) {
                        if pair[0] != 0 || !(0x13..=0x1c).contains(&pair[1]) {
                            return None;
                        }
                        identity.push(char::from(b'0' + pair[1] - 0x13));
                    }
                    validate_criminal_record_identity_number(&identity)
                        .is_ok()
                        .then_some(identity)
                })
                .collect::<Vec<_>>();
            assert_eq!(identities.len(), 1);
            validate_criminal_record_font_encoding(&pdf, &identities[0]).unwrap();
            let mut redacted = pdf.clone();
            for range in ranges.ordered() {
                redacted[range.clone()].fill(b'X');
            }
            assert_eq!(
                ranges,
                parse_criminal_record_pdf_redacted_ranges(&redacted).unwrap()
            );
            validate_criminal_record_font_encoding(&redacted, &identities[0]).unwrap();
        }
    }

    #[test]
    fn validates_optional_local_tax_debt_fixtures() {
        let Ok(paths) = std::env::var("ZKDEVLET_TAX_DEBT_FIXTURES") else {
            return;
        };
        for path in std::env::split_paths(&paths) {
            let pdf = std::fs::read(path).unwrap();
            let ranges = parse_tax_debt_pdf_private_ranges(&pdf).unwrap();
            validate_tax_debt_font_encoding(&pdf).unwrap();
            assert_eq!(ranges.labeled().len(), 5);
            let mut redacted = pdf.clone();
            for range in ranges.ordered() {
                redacted[range.clone()].fill(b'X');
            }
            assert_eq!(
                ranges,
                parse_tax_debt_pdf_redacted_ranges(&redacted).unwrap()
            );
            validate_tax_debt_font_encoding(&redacted).unwrap();
        }
    }
}
