use crate::deflate::InflateOutput;

global PRIVATE_FIELD_COUNT: u32 = 15;
global STATIC_BUFFER_LENGTH: u32 = 13150;
global ORIGINAL_STATIC_HASH: [u8; 32] = [
    0x79, 0xd2, 0x9d, 0xb8, 0x54, 0xce, 0x24, 0xc0,
    0x43, 0xf5, 0x95, 0x33, 0x38, 0xb8, 0x41, 0xa4,
    0xad, 0x90, 0xcb, 0xfc, 0xee, 0xef, 0xb6, 0x8e,
    0x8e, 0x62, 0x47, 0xa1, 0x92, 0x6f, 0x83, 0x6d,
];
global VERIFICATION_STATIC_HASH: [u8; 32] = [
    0xa2, 0xc8, 0x41, 0x65, 0x19, 0x6e, 0x7a, 0xb5,
    0x3f, 0x34, 0xde, 0xf3, 0xc8, 0x4d, 0xe8, 0xf2,
    0x27, 0x7d, 0xcf, 0x11, 0x06, 0x9e, 0xab, 0x2f,
    0x36, 0xec, 0x28, 0x17, 0x4f, 0x90, 0x36, 0x31,
];
global TARGET_FIELDS: [u32; 3] = [6, 8, 10];
global TARGET_PREFIXES: [[u8; 53]; 3] = [
    [66, 84, 32, 47, 70, 52, 32, 49, 48, 32, 84, 102, 32, 48, 32, 48, 32, 48, 32, 114, 103, 32, 52, 53, 50, 46, 55, 49, 56, 32, 84, 76, 32, 52, 52, 56, 46, 53, 49, 55, 32, 53, 52, 57, 46, 50, 49, 57, 32, 84, 100, 32, 40],
    [66, 84, 32, 47, 70, 52, 32, 49, 48, 32, 84, 102, 32, 48, 32, 48, 32, 48, 32, 114, 103, 32, 52, 53, 50, 46, 55, 49, 56, 32, 84, 76, 32, 52, 52, 56, 46, 53, 49, 55, 32, 53, 51, 49, 46, 51, 54, 52, 32, 84, 100, 32, 40],
    [66, 84, 32, 47, 70, 52, 32, 49, 48, 32, 84, 102, 32, 48, 32, 48, 32, 48, 32, 114, 103, 32, 52, 53, 50, 46, 55, 49, 56, 32, 84, 76, 32, 52, 52, 56, 46, 53, 49, 55, 32, 53, 49, 51, 46, 53, 55, 57, 32, 84, 100, 32, 40],
];
global TARGET_SUFFIX: [u8; 10] = [41, 32, 84, 106, 32, 84, 42, 32, 69, 84];

fn parse_target(
    bytes: [u8; 16384],
    start: u32,
    length: u32,
    target: u32,
    layout_variant: u8,
) -> u32 {
    assert((length >= 64) & (length <= 73));
    for i in 0..53 {
        let expected = if (layout_variant == 1) & (target == 1) & (i == 47) {
            51
        } else {
            TARGET_PREFIXES[target][i]
        };
        assert(bytes[start + i] == expected);
    }
    let digit_length = length - 63;
    let mut value = 0 as u64;
    for i in 0..10 {
        if i < digit_length {
            let byte = bytes[start + 53 + i];
            assert((byte >= 48) & (byte <= 57));
            if (i == 0) & (digit_length > 1) {
                assert(byte != 48);
            }
            value = value * 10 + (byte - 48) as u64;
        }
    }
    for i in 0..10 {
        assert(bytes[start + 53 + digit_length + i] == TARGET_SUFFIX[i]);
    }
    assert(value <= 4294967295);
    value as u32
}

pub fn validate(
    inflated: InflateOutput,
    layout_variant: u8,
    private_lengths: [u32; PRIVATE_FIELD_COUNT],
    maximum_traffic_tickets: u32,
    maximum_total_penalty_points: u32,
    maximum_active_penalty_points: u32,
) {
    assert(layout_variant <= 1);
    assert(private_lengths[0] == 73);
    assert((private_lengths[1] >= 64) & (private_lengths[1] <= 512));
    assert((private_lengths[2] >= 64) & (private_lengths[2] <= 512));
    assert((private_lengths[3] >= 64) & (private_lengths[3] <= 512));
    assert(private_lengths[4] == 72);
    assert((private_lengths[5] >= 64) & (private_lengths[5] <= 512));
    assert((private_lengths[6] >= 64) & (private_lengths[6] <= 73));
    assert((private_lengths[7] >= 64) & (private_lengths[7] <= 512));
    assert((private_lengths[8] >= 64) & (private_lengths[8] <= 73));
    assert(private_lengths[9] == 73);
    assert((private_lengths[10] >= 64) & (private_lengths[10] <= 73));
    assert((private_lengths[11] >= 64) & (private_lengths[11] <= 512));
    assert((private_lengths[12] >= 64) & (private_lengths[12] <= 512));
    assert(private_lengths[13] == 87);
    assert(private_lengths[14] == 79);

    let static_length = if layout_variant == 0 { 13150 } else { 13144 };
    let expected_hash = if layout_variant == 0 {
        ORIGINAL_STATIC_HASH
    } else {
        VERIFICATION_STATIC_HASH
    };
    let mut expected_length = static_length;
    for i in 0..PRIVATE_FIELD_COUNT {
        expected_length = expected_length + private_lengths[i];
    }
    assert(inflated.length == expected_length);

    let mut private_starts = [0 as u32; PRIVATE_FIELD_COUNT];
    let mut normalized = [0 as u8; STATIC_BUFFER_LENGTH];
    let mut input_position = 0 as u32;
    for offset in 0..269 {
        normalized[0 + offset] = inflated.bytes[input_position + offset];
    }
    input_position = input_position + 269;
    private_starts[0] = input_position;
    input_position = input_position + private_lengths[0];
    for offset in 0..192 {
        normalized[269 + offset] = inflated.bytes[input_position + offset];
    }
    input_position = input_position + 192;
    private_starts[1] = input_position;
    input_position = input_position + private_lengths[1];
    for offset in 0..200 {
        normalized[461 + offset] = inflated.bytes[input_position + offset];
    }
    input_position = input_position + 200;
    private_starts[2] = input_position;
    input_position = input_position + private_lengths[2];
    for offset in 0..192 {
        normalized[661 + offset] = inflated.bytes[input_position + offset];
    }
    input_position = input_position + 192;
    private_starts[3] = input_position;
    input_position = input_position + private_lengths[3];
    for offset in 0..200 {
        normalized[853 + offset] = inflated.bytes[input_position + offset];
    }
    input_position = input_position + 200;
    private_starts[4] = input_position;
    input_position = input_position + private_lengths[4];
    if layout_variant == 0 {
        for offset in 0..3760 {
            normalized[1053 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 3760;
        private_starts[5] = input_position;
        input_position = input_position + private_lengths[5];
        for offset in 0..168 {
            normalized[4813 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 168;
        private_starts[6] = input_position;
        input_position = input_position + private_lengths[6];
        for offset in 0..183 {
            normalized[4981 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 183;
        private_starts[7] = input_position;
        input_position = input_position + private_lengths[7];
        for offset in 0..219 {
            normalized[5164 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 219;
        private_starts[8] = input_position;
        input_position = input_position + private_lengths[8];
        for offset in 0..157 {
            normalized[5383 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 157;
        private_starts[9] = input_position;
        input_position = input_position + private_lengths[9];
        for offset in 0..259 {
            normalized[5540 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 259;
        private_starts[10] = input_position;
        input_position = input_position + private_lengths[10];
        for offset in 0..173 {
            normalized[5799 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 173;
        private_starts[11] = input_position;
        input_position = input_position + private_lengths[11];
        for offset in 0..2 {
            normalized[5972 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 2;
        private_starts[12] = input_position;
        input_position = input_position + private_lengths[12];
        for offset in 0..6832 {
            normalized[5974 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 6832;
        private_starts[13] = input_position;
        input_position = input_position + private_lengths[13];
        for offset in 0..136 {
            normalized[12806 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 136;
        private_starts[14] = input_position;
        input_position = input_position + private_lengths[14];
        for offset in 0..208 {
            normalized[12942 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 208;
    } else {
        for offset in 0..3758 {
            normalized[1053 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 3758;
        private_starts[5] = input_position;
        input_position = input_position + private_lengths[5];
        for offset in 0..168 {
            normalized[4811 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 168;
        private_starts[6] = input_position;
        input_position = input_position + private_lengths[6];
        for offset in 0..183 {
            normalized[4979 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 183;
        private_starts[7] = input_position;
        input_position = input_position + private_lengths[7];
        for offset in 0..219 {
            normalized[5162 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 219;
        private_starts[8] = input_position;
        input_position = input_position + private_lengths[8];
        for offset in 0..157 {
            normalized[5381 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 157;
        private_starts[9] = input_position;
        input_position = input_position + private_lengths[9];
        for offset in 0..259 {
            normalized[5538 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 259;
        private_starts[10] = input_position;
        input_position = input_position + private_lengths[10];
        for offset in 0..173 {
            normalized[5797 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 173;
        private_starts[11] = input_position;
        input_position = input_position + private_lengths[11];
        for offset in 0..2 {
            normalized[5970 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 2;
        private_starts[12] = input_position;
        input_position = input_position + private_lengths[12];
        for offset in 0..6828 {
            normalized[5972 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 6828;
        private_starts[13] = input_position;
        input_position = input_position + private_lengths[13];
        for offset in 0..136 {
            normalized[12800 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 136;
        private_starts[14] = input_position;
        input_position = input_position + private_lengths[14];
        for offset in 0..208 {
            normalized[12936 + offset] = inflated.bytes[input_position + offset];
        }
        input_position = input_position + 208;
    }
    assert(input_position == inflated.length);
    assert(sha256::sha256_var(normalized, static_length) == expected_hash);

    let traffic_tickets = parse_target(
        inflated.bytes, private_starts[TARGET_FIELDS[0]], private_lengths[TARGET_FIELDS[0]], 0,
        layout_variant,
    );
    let total_points = parse_target(
        inflated.bytes, private_starts[TARGET_FIELDS[1]], private_lengths[TARGET_FIELDS[1]], 1,
        layout_variant,
    );
    let active_points = parse_target(
        inflated.bytes, private_starts[TARGET_FIELDS[2]], private_lengths[TARGET_FIELDS[2]], 2,
        layout_variant,
    );
    assert(traffic_tickets < maximum_traffic_tickets);
    assert(total_points < maximum_total_penalty_points);
    assert(active_points < maximum_active_penalty_points);
}
