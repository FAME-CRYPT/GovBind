use crate::deflate::InflateOutput;

global PRIVATE_FIELD_COUNT: u32 = 12;
global STATIC_LENGTH: u32 = 5851;
global STATIC_SEGMENT_LENGTHS: [u32; 13] = [
    593, 3800, 118, 169, 264, 5, 5, 353, 130, 174, 170, 67, 3,
];
global EXPECTED_STATIC_HASH_A: [u8; 32] = [
    0x27, 0xa3, 0x69, 0x4c, 0xdd, 0xa2, 0x60, 0xf1,
    0x70, 0xfc, 0xdd, 0x64, 0x5d, 0xe8, 0xc4, 0x32,
    0x3a, 0x30, 0x90, 0x35, 0xcd, 0x5b, 0x82, 0xc3,
    0xea, 0xec, 0x47, 0x56, 0x24, 0xbe, 0x7b, 0xdf,
];
global EXPECTED_STATIC_HASH_B: [u8; 32] = [
    0x71, 0x04, 0x4f, 0x60, 0x6c, 0x55, 0xcc, 0xe2,
    0x34, 0xea, 0x08, 0x15, 0xdd, 0xb5, 0x76, 0x9f,
    0xa6, 0xdc, 0x76, 0x49, 0x07, 0x7d, 0xab, 0x15,
    0xd1, 0x6b, 0xdc, 0x8c, 0x10, 0xc7, 0xe5, 0x94,
];
global CLAIM_CODES: [u16; 20] = [
    0x45, 0x52, 0x55, 0x46, 0x58, 0x51, 0x58, 0x51, 0x03, 0x45,
    0x58, 0x4f, 0x58, 0x51, 0x50, 0x44, 0x47, 0xd5, 0xf7, 0xd5,
];

fn identity_digits(identity_number: u64) -> [u8; 11] {
    assert((identity_number >= 10_000_000_000) & (identity_number <= 99_999_999_999));
    let divisors: [u64; 11] = [
        10_000_000_000, 1_000_000_000, 100_000_000, 10_000_000, 1_000_000,
        100_000, 10_000, 1_000, 100, 10, 1,
    ];
    let mut digits = [0 as u8; 11];
    for index in 0..11 {
        digits[index] = ((identity_number / divisors[index]) % 10) as u8;
    }
    let odd = digits[0] as u32 + digits[2] as u32 + digits[4] as u32
        + digits[6] as u32 + digits[8] as u32;
    let even = digits[1] as u32 + digits[3] as u32 + digits[5] as u32
        + digits[7] as u32;
    assert(((odd * 7 + 10 - (even % 10)) % 10) == digits[9] as u32);
    let mut first_ten = 0 as u32;
    for index in 0..10 {
        first_ten = first_ten + digits[index] as u32;
    }
    assert((first_ten % 10) == digits[10] as u32);
    digits
}

fn ascii_hex_nibble(value: u8) -> u8 {
    if value < 10 { 48 + value } else { 55 + value }
}

fn is_ascii_hex_nibble(byte: u8, value: u8) -> bool {
    (byte == ascii_hex_nibble(value)) | ((value >= 10) & (byte == 87 + value))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    if (month == 2) {
        let leap = ((year % 4 == 0) & (year % 100 != 0)) | (year % 400 == 0);
        if leap { 29 } else { 28 }
    } else if (month == 4) | (month == 6) | (month == 9) | (month == 11) {
        30
    } else {
        31
    }
}

fn assert_hex_glyph(bytes: [u8; 9216], start: u32, code: u16) {
    assert(is_ascii_hex_nibble(bytes[start], ((code >> 12) & 15) as u8));
    assert(is_ascii_hex_nibble(bytes[start + 1], ((code >> 8) & 15) as u8));
    assert(is_ascii_hex_nibble(bytes[start + 2], ((code >> 4) & 15) as u8));
    assert(is_ascii_hex_nibble(bytes[start + 3], (code & 15) as u8));
}

fn assert_text_wrapper(bytes: [u8; 9216], start: u32, length: u32) {
    let prefix: [u8; 12] = [66, 84, 10, 47, 70, 50, 32, 57, 32, 84, 102, 10];
    let suffix: [u8; 6] = [62, 84, 106, 10, 69, 84];
    for index in 0..12 {
        assert(bytes[start + index] == prefix[index]);
    }
    assert(bytes[start + 26] == 84);
    assert(bytes[start + 27] == 100);
    assert(bytes[start + 28] == 10);
    assert(bytes[start + 29] == 60);
    for index in 0..6 {
        assert(bytes[start + length - 6 + index] == suffix[index]);
    }
}

pub fn validate(
    inflated: InflateOutput,
    private_lengths: [u32; PRIVATE_FIELD_COUNT],
    claim_glyph_fields: [u8; 20],
    claim_glyph_offsets: [u32; 20],
    claim_date_glyph_fields: [u8; 10],
    claim_date_glyph_offsets: [u32; 10],
    identity_number: u64,
    issuance_date_yyyymmdd: u32,
) {
    for field in 0..PRIVATE_FIELD_COUNT {
        assert((private_lengths[field] >= 56) & (private_lengths[field] <= 1280));
    }
    assert(private_lengths[1] == 76);
    assert(private_lengths[2] == 76);
    assert(private_lengths[3] == 92);
    assert(private_lengths[9] == 76);
    assert(private_lengths[10] == 80);

    let mut expected_length = STATIC_LENGTH;
    for field in 0..PRIVATE_FIELD_COUNT {
        expected_length = expected_length + private_lengths[field];
    }
    assert(inflated.length == expected_length);

    let mut private_starts = [0 as u32; PRIVATE_FIELD_COUNT];
    let mut normalized = [0 as u8; STATIC_LENGTH];
    let mut input_position = 0 as u32;
    let mut static_position = 0 as u32;
    for segment in 0..13 {
        let segment_length = STATIC_SEGMENT_LENGTHS[segment];
        for offset in 0..3800 {
            if offset < segment_length {
                normalized[static_position + offset] = inflated.bytes[input_position + offset];
            }
        }
        input_position = input_position + segment_length;
        static_position = static_position + segment_length;
        if segment < PRIVATE_FIELD_COUNT {
            private_starts[segment] = input_position;
            input_position = input_position + private_lengths[segment];
        }
    }
    assert(input_position == inflated.length);
    assert(static_position == STATIC_LENGTH);
    let digest = sha256::sha256_var(normalized, STATIC_LENGTH);
    assert((digest == EXPECTED_STATIC_HASH_A) | (digest == EXPECTED_STATIC_HASH_B));

    for index in 0..20 {
        let field = claim_glyph_fields[index];
        assert((field == 5) | (field == 6));
        let offset = claim_glyph_offsets[index];
        assert(offset + 4 <= private_lengths[field as u32]);
        if index > 0 {
            assert(field >= claim_glyph_fields[index - 1]);
            if field == claim_glyph_fields[index - 1] {
                assert(offset >= claim_glyph_offsets[index - 1] + 4);
            }
        }
        assert_hex_glyph(inflated.bytes, private_starts[field as u32] + offset, CLAIM_CODES[index]);
    }

    let identity_start = private_starts[10];
    assert_text_wrapper(inflated.bytes, identity_start, private_lengths[10]);
    let digits = identity_digits(identity_number);
    for index in 0..11 {
        assert_hex_glyph(inflated.bytes, identity_start + 30 + index * 4, (0x13 + digits[index]) as u16);
    }

    assert((issuance_date_yyyymmdd >= 20000101) & (issuance_date_yyyymmdd <= 99991231));
    let year = issuance_date_yyyymmdd / 10000;
    let month = (issuance_date_yyyymmdd / 100) % 100;
    let day = issuance_date_yyyymmdd % 100;
    assert((month >= 1) & (month <= 12));
    assert((day >= 1) & (day <= days_in_month(year, month)));
    let date_digits: [u8; 8] = [
        (day / 10) as u8, (day % 10) as u8,
        (month / 10) as u8, (month % 10) as u8,
        (year / 1000) as u8, ((year / 100) % 10) as u8,
        ((year / 10) % 10) as u8, (year % 10) as u8,
    ];
    let date_start = private_starts[2];
    assert_text_wrapper(inflated.bytes, date_start, private_lengths[2]);
    for glyph in 0..10 {
        let code = if (glyph == 2) | (glyph == 5) {
            0x12 as u16
        } else {
            let digit_index = if glyph < 2 { glyph } else if glyph < 5 { glyph - 1 } else { glyph - 2 };
            (0x13 + date_digits[digit_index]) as u16
        };
        assert_hex_glyph(inflated.bytes, date_start + 30 + glyph * 4, code);

        let claim_field = claim_date_glyph_fields[glyph];
        assert((claim_field >= 4) & (claim_field <= 6));
        let claim_offset = claim_date_glyph_offsets[glyph];
        assert(claim_offset + 4 <= private_lengths[claim_field as u32]);
        if glyph > 0 {
            assert(claim_field >= claim_date_glyph_fields[glyph - 1]);
            if claim_field == claim_date_glyph_fields[glyph - 1] {
                assert(claim_offset >= claim_date_glyph_offsets[glyph - 1] + 4);
            }
        }
        assert_hex_glyph(
            inflated.bytes,
            private_starts[claim_field as u32] + claim_offset,
            code,
        );
    }
}
