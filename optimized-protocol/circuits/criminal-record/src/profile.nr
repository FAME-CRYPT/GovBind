use crate::deflate::{InflateOutput, MAX_OUTPUT};

global PRIVATE_FIELD_COUNT: u32 = 8;
global STATIC_BUFFER_LENGTH: u32 = 2704;

global COMPACT_STATIC_HASH: [u8; 32] = [
    0x54, 0xd1, 0xdb, 0xfe, 0x23, 0xd6, 0xef, 0x99,
    0xd5, 0x0e, 0x95, 0xe8, 0xb7, 0x98, 0xae, 0xe0,
    0x65, 0x81, 0x4f, 0x8b, 0x13, 0x11, 0xbb, 0x0a,
    0xb1, 0x48, 0xb2, 0xa3, 0x4e, 0xdf, 0x72, 0xd6,
];
global EXTENDED_STATIC_HASH: [u8; 32] = [
    0x00, 0xca, 0xd7, 0xc1, 0x0e, 0x2b, 0x83, 0x8f,
    0x15, 0xe3, 0xff, 0xbf, 0x27, 0xab, 0x64, 0x11,
    0x47, 0x78, 0xdd, 0x52, 0xa1, 0x2f, 0x14, 0x4c,
    0x94, 0x2b, 0xcc, 0x7c, 0x81, 0xc0, 0x9e, 0x1a,
];

global NO_RECORD_STATEMENT_OFFSET: u32 = 443;
global NO_RECORD_STATEMENT: [u8; 131] = [
    0, 60, 0, 56, 0, 46, 0, 36, 0, 53, 0, 44, 0, 39, 0, 36, 0, 3, 0, 46,
    0, 248, 0, 48, 0, 47, 0, 248, 0, 46, 0, 3, 0, 37, 0, 248, 0, 47, 0, 42,
    0, 248, 0, 47, 0, 92, 40, 0, 53, 0, 248, 0, 3, 0, 37, 0, 56, 0, 47,
    0, 56, 0, 49, 0, 36, 0, 49, 0, 3, 0, 46, 0, 248, 0, 249, 0, 248, 0, 49,
    0, 248, 0, 49, 0, 3, 0, 36, 0, 39, 0, 47, 0, 248, 0, 3, 0, 54, 0, 248,
    0, 38, 0, 248, 0, 47, 0, 3, 0, 46, 0, 36, 0, 60, 0, 39, 0, 44, 0, 3,
    0, 60, 0, 50, 0, 46, 0, 55, 0, 56, 0, 53,
];
global IDENTITY_LABEL: [u8; 30] = [
    0, 46, 0, 248, 0, 48, 0, 47, 0, 248, 0, 46, 0, 3, 0, 49, 0, 56, 0, 48,
    0, 36, 0, 53, 0, 36, 0, 54, 0, 44,
];
global IDENTITY_VALUE_PREFIX: [u8; 6] = [0, 3, 0, 29, 0, 3];

fn is_encoded_digit(high: u8, low: u8) -> bool {
    (high == 0) & (low >= 0x13) & (low <= 0x1c)
}

fn assert_encoded_date_suffix(
    output: [u8; MAX_OUTPUT],
    start: u32,
    length: u32,
) {
    assert(length >= 20);
    let suffix = start + length - 20;
    for glyph in 0..10 {
        let high = output[suffix + glyph * 2];
        let low = output[suffix + glyph * 2 + 1];
        if (glyph == 2) | (glyph == 5) {
            assert((high == 0) & (low == 0x11));
        } else {
            assert(is_encoded_digit(high, low));
        }
    }
}

fn assert_encoded_glyph(output: [u8; MAX_OUTPUT], start: u32, glyph: u32, low: u8) {
    assert(output[start + glyph * 2] == 0);
    assert(output[start + glyph * 2 + 1] == low);
}

fn assert_encoded_document_number(output: [u8; MAX_OUTPUT], start: u32) {
    assert_encoded_glyph(output, start, 0, 0x03);
    assert_encoded_glyph(output, start, 1, 0x1d);
    assert_encoded_glyph(output, start, 2, 0x03);
    for glyph in 3..7 {
        assert(is_encoded_digit(output[start + glyph * 2], output[start + glyph * 2 + 1]));
    }
    assert_encoded_glyph(output, start, 7, 0x10);
    for glyph in 8..12 {
        assert(is_encoded_digit(output[start + glyph * 2], output[start + glyph * 2 + 1]));
    }
    assert_encoded_glyph(output, start, 12, 0x10);
    for glyph in 13..23 {
        assert(is_encoded_digit(output[start + glyph * 2], output[start + glyph * 2 + 1]));
    }
    assert_encoded_glyph(output, start, 23, 0x03);
    assert_encoded_glyph(output, start, 24, 0x12);
    assert_encoded_glyph(output, start, 25, 0x03);
    for glyph in 26..28 {
        assert(is_encoded_digit(output[start + glyph * 2], output[start + glyph * 2 + 1]));
    }
    assert_encoded_glyph(output, start, 28, 0x1d);
    for glyph in 29..31 {
        assert(is_encoded_digit(output[start + glyph * 2], output[start + glyph * 2 + 1]));
    }
}

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

pub fn validate(
    inflated: InflateOutput,
    layout_variant: u8,
    private_lengths: [u32; PRIVATE_FIELD_COUNT],
    identity_number: u64,
) {
    assert(layout_variant <= 1);
    assert(private_lengths[0] == 62);
    assert(private_lengths[1] == 94);
    assert((private_lengths[2] >= 8) & (private_lengths[2] <= 64));
    assert((private_lengths[3] >= 8) & (private_lengths[3] <= 128));
    assert(private_lengths[4] == 22);
    assert((private_lengths[5] >= 2) & (private_lengths[5] <= 160));
    assert((private_lengths[6] >= 2) & (private_lengths[6] <= 160));
    assert((private_lengths[7] >= 20) & (private_lengths[7] <= 160));

    let static_length = if layout_variant == 0 { 2496 } else { 2704 };
    let expected_hash = if layout_variant == 0 {
        COMPACT_STATIC_HASH
    } else {
        EXTENDED_STATIC_HASH
    };

    let mut expected_output_length = static_length;
    for field in 0..PRIVATE_FIELD_COUNT {
        expected_output_length = expected_output_length + private_lengths[field];
    }
    assert(inflated.length == expected_output_length);

    let mut private_starts = [0 as u32; PRIVATE_FIELD_COUNT];
    let mut normalized = [0 as u8; STATIC_BUFFER_LENGTH];
    let mut input_position = 0 as u32;
    if layout_variant == 0 {
        for offset in 0..1517 {
            normalized[offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 1517;
        private_starts[0] = input_position;
        input_position = input_position + private_lengths[0];
        for offset in 0..110 {
            normalized[1517 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 110;
        private_starts[1] = input_position;
        input_position = input_position + private_lengths[1];
        for offset in 0..107 {
            normalized[1627 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 107;
        private_starts[2] = input_position;
        input_position = input_position + private_lengths[2];
        for offset in 0..115 {
            normalized[1734 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 115;
        private_starts[3] = input_position;
        input_position = input_position + private_lengths[3];
        for offset in 0..267 {
            normalized[1849 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 267;
        private_starts[4] = input_position;
        input_position = input_position + private_lengths[4];
        for offset in 0..105 {
            normalized[2116 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 105;
        private_starts[5] = input_position;
        input_position = input_position + private_lengths[5];
        for offset in 0..126 {
            normalized[2221 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 126;
        private_starts[6] = input_position;
        input_position = input_position + private_lengths[6];
        for offset in 0..126 {
            normalized[2347 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 126;
        private_starts[7] = input_position;
        input_position = input_position + private_lengths[7];
        for offset in 0..23 {
            normalized[2473 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 23;
    } else {
        for offset in 0..1725 {
            normalized[offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 1725;
        private_starts[0] = input_position;
        input_position = input_position + private_lengths[0];
        for offset in 0..110 {
            normalized[1725 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 110;
        private_starts[1] = input_position;
        input_position = input_position + private_lengths[1];
        for offset in 0..107 {
            normalized[1835 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 107;
        private_starts[2] = input_position;
        input_position = input_position + private_lengths[2];
        for offset in 0..115 {
            normalized[1942 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 115;
        private_starts[3] = input_position;
        input_position = input_position + private_lengths[3];
        for offset in 0..267 {
            normalized[2057 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 267;
        private_starts[4] = input_position;
        input_position = input_position + private_lengths[4];
        for offset in 0..105 {
            normalized[2324 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 105;
        private_starts[5] = input_position;
        input_position = input_position + private_lengths[5];
        for offset in 0..126 {
            normalized[2429 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 126;
        private_starts[6] = input_position;
        input_position = input_position + private_lengths[6];
        for offset in 0..126 {
            normalized[2555 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 126;
        private_starts[7] = input_position;
        input_position = input_position + private_lengths[7];
        for offset in 0..23 {
            normalized[2681 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 23;
    }
    assert(input_position == inflated.length);
    assert(sha256::sha256_var(normalized, static_length) == expected_hash);

    for offset in 0..131 {
        assert(inflated.bytes[NO_RECORD_STATEMENT_OFFSET + offset] == NO_RECORD_STATEMENT[offset]);
    }

    let identity_start = private_starts[4];
    for offset in 0..30 {
        assert(inflated.bytes[identity_start - 81 + offset] == IDENTITY_LABEL[offset]);
    }
    for offset in 0..6 {
        assert(inflated.bytes[identity_start - 6 + offset] == IDENTITY_VALUE_PREFIX[offset]);
    }
    let digits = identity_digits(identity_number);
    for index in 0..11 {
        assert(inflated.bytes[identity_start + index * 2] == 0);
        assert(inflated.bytes[identity_start + index * 2 + 1] == 0x13 + digits[index]);
    }

    assert_encoded_document_number(inflated.bytes, private_starts[0]);
    assert_encoded_date_suffix(inflated.bytes, private_starts[1], private_lengths[1]);
    assert_encoded_date_suffix(inflated.bytes, private_starts[7], private_lengths[7]);
}
