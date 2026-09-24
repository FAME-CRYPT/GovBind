use crate::deflate::InflateOutput;

global PRIVATE_FIELD_COUNT: u32 = 8;
global STATIC_LENGTH: u32 = 9110;

global EXPECTED_TWO_LINE_STATIC_HASH: [u8; 32] = [
    0xd7, 0xe9, 0x48, 0x6b, 0xf8, 0x77, 0x5a, 0xb7, 0xd5, 0x51, 0x9a, 0xdd, 0xb0, 0x10, 0xf1, 0x67,
    0x42, 0x40, 0x47, 0x1e, 0xff, 0xb1, 0xce, 0x5c, 0xf9, 0xc3, 0x46, 0xc6, 0xc8, 0x6d, 0x95, 0x0a,
];
global EXPECTED_THREE_LINE_STATIC_HASH: [u8; 32] = [
    0x22, 0x98, 0xcf, 0xca, 0x90, 0x18, 0xdc, 0x07, 0x33, 0x4b, 0x09, 0xa9, 0x53, 0x71, 0x6d, 0xeb,
    0x1f, 0x2b, 0xd1, 0x4a, 0x7d, 0x37, 0xa1, 0xcf, 0xb7, 0x12, 0x84, 0xf3, 0x9e, 0x41, 0x24, 0x32,
];
global ADDRESS_PREFIX: [u8; 18] = [
    66, 84, 10, 47, 70, 111, 110, 116, 95, 49, 32, 45, 49, 48, 32, 84, 102, 10,
];
global ADDRESS_SUFFIX: [u8; 7] = [
    62, 32, 84, 106, 10, 69, 84,
];

fn hex_ascii(nibble: u8) -> u8 {
    assert(nibble < 16);
    if nibble < 10 {
        48 + nibble
    } else {
        55 + nibble
    }
}

pub fn validate(
    inflated: InflateOutput,
    private_lengths: [u32; PRIVATE_FIELD_COUNT],
    city_code: u32,
    city_encoding_length: u32,
    city_encoding: [u8; 32],
) {
    assert((city_code >= 1) & (city_code <= 81));
    assert(
        (city_encoding_length >= 2)
            & (city_encoding_length <= 32)
            & (city_encoding_length % 2 == 0),
    );
    assert((private_lengths[0] >= 25 + city_encoding_length * 2) & (private_lengths[0] <= 1024));
    assert(private_lengths[1] == 40);
    assert((private_lengths[2] >= 4) & (private_lengths[2] <= 128));
    assert(private_lengths[3] == 44);
    assert((private_lengths[4] >= 4) & (private_lengths[4] <= 160));
    assert((private_lengths[5] >= 4) & (private_lengths[5] <= 200));
    assert((private_lengths[6] >= 500) & (private_lengths[6] <= 5000));
    assert((private_lengths[7] >= 5000) & (private_lengths[7] <= 15000));

    let mut expected_output_length = STATIC_LENGTH;
    for i in 0..PRIVATE_FIELD_COUNT {
        expected_output_length = expected_output_length + private_lengths[i];
    }
    assert(inflated.length == expected_output_length);

    let mut private_starts = [0 as u32; PRIVATE_FIELD_COUNT];
    let mut normalized = [0 as u8; STATIC_LENGTH];
    let mut input_position = 0 as u32;
    for i in 0..1733 {
        normalized[i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 1733;
    private_starts[0] = input_position;
    input_position = input_position + private_lengths[0];
    for i in 0..332 {
        normalized[1733 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 332;
    private_starts[1] = input_position;
    input_position = input_position + private_lengths[1];
    for i in 0..338 {
        normalized[2065 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 338;
    private_starts[2] = input_position;
    input_position = input_position + private_lengths[2];
    for i in 0..1634 {
        normalized[2403 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 1634;
    private_starts[3] = input_position;
    input_position = input_position + private_lengths[3];
    for i in 0..18 {
        normalized[4037 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 18;
    private_starts[4] = input_position;
    input_position = input_position + private_lengths[4];
    for i in 0..91 {
        normalized[4055 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 91;
    private_starts[5] = input_position;
    input_position = input_position + private_lengths[5];
    for i in 0..417 {
        normalized[4146 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 417;
    private_starts[6] = input_position;
    input_position = input_position + private_lengths[6];
    private_starts[7] = input_position;
    input_position = input_position + private_lengths[7];
    for i in 0..4547 {
        normalized[4563 + i] = inflated.bytes[input_position + i];
    }
    input_position = input_position + 4547;
    assert(input_position == inflated.length);
    let static_hash = sha256::sha256_var(normalized, STATIC_LENGTH);
    assert(
        (static_hash == EXPECTED_TWO_LINE_STATIC_HASH)
            | (static_hash == EXPECTED_THREE_LINE_STATIC_HASH),
    );

    for i in 0..18 {
        assert(inflated.bytes[private_starts[0] + i] == ADDRESS_PREFIX[i]);
    }
    for i in 0..7 {
        assert(
            inflated.bytes[private_starts[0] + private_lengths[0] - 7 + i] == ADDRESS_SUFFIX[i],
        );
    }

    for index in 0..32 {
        if index >= city_encoding_length {
            assert(city_encoding[index] == 0);
        }
    }
    let city_hex_length = city_encoding_length * 2;
    let mut matched_city_digits = 0 as u32;
    for reverse_offset in 0..384 {
        if (reverse_offset < private_lengths[0] - 25) & (matched_city_digits < city_hex_length) {
            let value = inflated.bytes[private_starts[0] + private_lengths[0] - 8 - reverse_offset];
            let whitespace =
                (value == 9) | (value == 10) | (value == 12) | (value == 13) | (value == 32);
            let hexadecimal = ((value >= 48) & (value <= 57))
                | ((value >= 65) & (value <= 70))
                | ((value >= 97) & (value <= 102));
            assert(whitespace | hexadecimal);
            if !whitespace {
                let forward_nibble = city_hex_length - 1 - matched_city_digits;
                let encoded = city_encoding[forward_nibble / 2];
                let nibble = if forward_nibble % 2 == 0 {
                    encoded >> 4
                } else {
                    encoded & 15
                };
                let expected = hex_ascii(nibble);
                let alternate = if nibble >= 10 {
                    expected + 32
                } else {
                    expected
                };
                assert((value == expected) | (value == alternate));
                matched_city_digits = matched_city_digits + 1;
            }
        }
    }
    assert(matched_city_digits == city_hex_length);
}
