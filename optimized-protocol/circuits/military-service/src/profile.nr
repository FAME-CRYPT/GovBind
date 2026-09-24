use crate::date;
use crate::deflate::{MAX_OUTPUT, InflateOutput};

global PRIVATE_FIELD_COUNT: u32 = 9;
global STATIC_LENGTH: u32 = 5147;

global EXPECTED_STATIC_HASH: [u8; 32] = [
    0xee, 0x49, 0x07, 0xbb, 0x44, 0x72, 0x47, 0x0e,
    0xf4, 0x3a, 0xdc, 0x98, 0xab, 0xfe, 0xf3, 0x0c,
    0x97, 0xaf, 0x70, 0x9a, 0xd7, 0x53, 0x93, 0xe5,
    0x2c, 0x9e, 0xd1, 0x0f, 0xf8, 0x53, 0xec, 0xfd,
];

fn is_digit(value: u8) -> bool {
    value >= 48 & value <= 57
}

fn validate_date_shape(value: [u8; 10]) {
    assert((value[2] == 47) & (value[5] == 47));
    for i in 0..10 {
        if (i != 2) & (i != 5) {
            assert(is_digit(value[i]));
        }
    }
}

fn read_private_byte(
    output: [u8; MAX_OUTPUT],
    private_starts: [u32; PRIVATE_FIELD_COUNT],
    field: u32,
    offset: u32,
) -> u8 {
    output[private_starts[field] + offset]
}

fn extract_date(
    output: [u8; MAX_OUTPUT],
    private_starts: [u32; PRIVATE_FIELD_COUNT],
    field: u32,
    offset: u32,
) -> [u8; 10] {
    let mut value = [0 as u8; 10];
    for i in 0..10 {
        value[i] = read_private_byte(output, private_starts, field, offset + i);
    }
    value
}

pub fn validate(
    inflated: InflateOutput,
    private_lengths: [u32; PRIVATE_FIELD_COUNT],
    comparison_date_yyyymmdd: u32,
    assertion_months: u32,
) {
    assert(private_lengths[0] == 15);
    assert(private_lengths[1] == 15);
    assert(private_lengths[2] == 17);
    assert(private_lengths[3] == 10);
    assert(private_lengths[4] == 11);
    assert((private_lengths[5] >= 1) & (private_lengths[5] <= 40));
    assert((private_lengths[6] >= 1) & (private_lengths[6] <= 50));
    assert((private_lengths[7] >= 13) & (private_lengths[7] <= 60));
    assert((private_lengths[8] >= 1) & (private_lengths[8] <= 50));

    let mut expected_output_length = STATIC_LENGTH;
    for i in 0..PRIVATE_FIELD_COUNT {
        expected_output_length = expected_output_length + private_lengths[i];
    }
    assert(inflated.length == expected_output_length);

    let mut private_starts = [0 as u32; PRIVATE_FIELD_COUNT];
    let mut normalized = [0 as u8; STATIC_LENGTH];

    let mut output_position = 0 as u32;
    for i in 0..509 {
        normalized[i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 509;
    private_starts[0] = output_position;
    output_position = output_position + private_lengths[0];

    for i in 0..643 {
        normalized[509 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 643;
    private_starts[1] = output_position;
    output_position = output_position + private_lengths[1];

    for i in 0..248 {
        normalized[1152 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 248;
    private_starts[2] = output_position;
    output_position = output_position + private_lengths[2];

    for i in 0..861 {
        normalized[1400 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 861;
    private_starts[3] = output_position;
    output_position = output_position + private_lengths[3];

    for i in 0..1797 {
        normalized[2261 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 1797;
    private_starts[4] = output_position;
    output_position = output_position + private_lengths[4];

    for i in 0..215 {
        normalized[4058 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 215;
    private_starts[5] = output_position;
    output_position = output_position + private_lengths[5];

    for i in 0..223 {
        normalized[4273 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 223;
    private_starts[6] = output_position;
    output_position = output_position + private_lengths[6];

    for i in 0..224 {
        normalized[4496 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 224;
    private_starts[7] = output_position;
    output_position = output_position + private_lengths[7];

    for i in 0..230 {
        normalized[4720 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 230;
    private_starts[8] = output_position;
    output_position = output_position + private_lengths[8];

    for i in 0..197 {
        normalized[4950 + i] = inflated.bytes[output_position + i];
    }
    output_position = output_position + 197;

    assert(output_position == inflated.length);
    assert(sha256::sha256_var(normalized, STATIC_LENGTH) == EXPECTED_STATIC_HASH);

    for i in 0..15 {
        let left = read_private_byte(inflated.bytes, private_starts, 0, i);
        let right = read_private_byte(inflated.bytes, private_starts, 1, i);
        assert(left == right);
        assert(
            ((left >= 48) & (left <= 57))
                | ((left >= 65) & (left <= 90))
                | ((left >= 97) & (left <= 122)),
        );
    }

    let issue_date = extract_date(inflated.bytes, private_starts, 2, 0);
    validate_date_shape(issue_date);
    assert(read_private_byte(inflated.bytes, private_starts, 2, 10) == 32);
    assert(read_private_byte(inflated.bytes, private_starts, 2, 11) == 32);
    assert(is_digit(read_private_byte(inflated.bytes, private_starts, 2, 12)));
    assert(is_digit(read_private_byte(inflated.bytes, private_starts, 2, 13)));
    assert(read_private_byte(inflated.bytes, private_starts, 2, 14) == 58);
    assert(is_digit(read_private_byte(inflated.bytes, private_starts, 2, 15)));
    assert(is_digit(read_private_byte(inflated.bytes, private_starts, 2, 16)));

    let valid_until_ascii = extract_date(inflated.bytes, private_starts, 3, 0);
    validate_date_shape(valid_until_ascii);
    let valid_until = date::from_ddmmyyyy_ascii(valid_until_ascii);
    let comparison = date::from_yyyymmdd(comparison_date_yyyymmdd);
    let cutoff = date::add_months_clamped(comparison, assertion_months);
    assert(date::is_strictly_after(valid_until, cutoff));

    for i in 0..11 {
        assert(is_digit(read_private_byte(inflated.bytes, private_starts, 4, i)));
    }

    let birth_field_length = private_lengths[7];
    let birth_date = extract_date(
        inflated.bytes,
        private_starts,
        7,
        birth_field_length - 10,
    );
    validate_date_shape(birth_date);
    let _birth_date = date::from_ddmmyyyy_ascii(birth_date);
}
