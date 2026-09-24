pub global MAX_COMMITMENT_PREIMAGE: u32 = 1552;
pub global MAX_COMPRESSED: u32 = 1536;
pub global MAX_COMPRESSED_BITS: u32 = MAX_COMPRESSED * 8;
pub global MAX_OUTPUT: u32 = 5504;

global LITLEN_SYMBOLS: u32 = 288;
global DISTANCE_SYMBOLS: u32 = 32;
global CODE_LENGTH_SYMBOLS: u32 = 19;
global MAX_CODE_BITS: u32 = 15;
global MAX_HEADER_TOKENS: u32 = 160;
global MAX_DATA_TOKENS: u32 = 1200;

pub struct DeflateTrace {
    pub bits: [u8; MAX_COMPRESSED_BITS],
    pub code_lengths: [u8; 303],
    pub header_symbols: [u8; MAX_HEADER_TOKENS],
    pub header_symbol_count: u32,
    pub header_token_index: [u8; 303],
    pub data_symbols: [u16; MAX_DATA_TOKENS],
    pub distance_symbols: [u8; MAX_DATA_TOKENS],
    pub data_symbol_count: u32,
    pub output: [u8; MAX_OUTPUT],
    pub output_token_index: [u16; MAX_OUTPUT],
}

pub struct InflateOutput {
    pub bytes: [u8; MAX_OUTPUT],
    pub length: u32,
}

fn reverse_low_bits(value: u16, length: u8) -> u16 {
    let mut reversed = 0 as u16;
    for i in 0..MAX_CODE_BITS {
        if i < length as u32 {
            let bit = (value >> (i as u16)) & 1;
            reversed = reversed | bit << (length as u16 - 1 - i as u16);
        }
    }
    reversed
}

fn read_bits(bits: [u8; MAX_COMPRESSED_BITS], position: u32, length: u8) -> u16 {
    let mut value = 0 as u16;
    for i in 0..MAX_CODE_BITS {
        if i < length as u32 {
            value = value | (bits[position + i] as u16) << (i as u16);
        }
    }
    value
}

fn code_length_codes(lengths: [u8; CODE_LENGTH_SYMBOLS]) -> [u16; CODE_LENGTH_SYMBOLS] {
    let mut counts = [0 as u16; 16];
    for symbol in 0..CODE_LENGTH_SYMBOLS {
        let length = lengths[symbol];
        assert(length <= 7);
        if length > 0 {
            counts[length as u32] = counts[length as u32] + 1;
        }
    }

    let mut next = [0 as u16; 16];
    let mut code = 0 as u16;
    for bit_length in 1..16 {
        code = (code + counts[bit_length - 1]) << 1;
        next[bit_length] = code;
    }

    let mut result = [0 as u16; CODE_LENGTH_SYMBOLS];
    for symbol in 0..CODE_LENGTH_SYMBOLS {
        let length = lengths[symbol];
        if length > 0 {
            let canonical = next[length as u32];
            result[symbol] = reverse_low_bits(canonical, length);
            next[length as u32] = canonical + 1;
        }
    }
    result
}

fn litlen_codes(lengths: [u8; LITLEN_SYMBOLS]) -> [u16; LITLEN_SYMBOLS] {
    let mut counts = [0 as u16; 16];
    for symbol in 0..LITLEN_SYMBOLS {
        let length = lengths[symbol];
        assert(length <= 15);
        if length > 0 {
            counts[length as u32] = counts[length as u32] + 1;
        }
    }

    let mut next = [0 as u16; 16];
    let mut code = 0 as u16;
    for bit_length in 1..16 {
        code = (code + counts[bit_length - 1]) << 1;
        next[bit_length] = code;
    }

    let mut result = [0 as u16; LITLEN_SYMBOLS];
    for symbol in 0..LITLEN_SYMBOLS {
        let length = lengths[symbol];
        if length > 0 {
            let canonical = next[length as u32];
            result[symbol] = reverse_low_bits(canonical, length);
            next[length as u32] = canonical + 1;
        }
    }
    result
}

fn distance_codes(lengths: [u8; DISTANCE_SYMBOLS]) -> [u16; DISTANCE_SYMBOLS] {
    let mut counts = [0 as u16; 16];
    for symbol in 0..DISTANCE_SYMBOLS {
        let length = lengths[symbol];
        assert(length <= 15);
        if length > 0 {
            counts[length as u32] = counts[length as u32] + 1;
        }
    }

    let mut next = [0 as u16; 16];
    let mut code = 0 as u16;
    for bit_length in 1..16 {
        code = (code + counts[bit_length - 1]) << 1;
        next[bit_length] = code;
    }

    let mut result = [0 as u16; DISTANCE_SYMBOLS];
    for symbol in 0..DISTANCE_SYMBOLS {
        let length = lengths[symbol];
        if length > 0 {
            let canonical = next[length as u32];
            result[symbol] = reverse_low_bits(canonical, length);
            next[length as u32] = canonical + 1;
        }
    }
    result
}

fn length_base(symbol: u16) -> u16 {
    let table = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
        115, 131, 163, 195, 227, 258,
    ];
    assert((symbol >= 257) & (symbol <= 285));
    table[(symbol - 257) as u32]
}

fn length_extra_bits(symbol: u16) -> u8 {
    let table = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5,
        5, 0,
    ];
    table[(symbol - 257) as u32]
}

fn distance_base(symbol: u8) -> u32 {
    let table = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    assert(symbol <= 29);
    table[symbol as u32]
}

fn distance_extra_bits(symbol: u8) -> u8 {
    let table = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11,
        11, 12, 12, 13, 13,
    ];
    table[symbol as u32]
}

fn verify_adler32(
    compressed: [u8; MAX_COMMITMENT_PREIMAGE],
    compressed_length: u32,
    output: [u8; MAX_OUTPUT],
    output_length: u32,
) {
    let mut first = 1 as u32;
    let mut second = 0 as u32;
    for i in 0..MAX_OUTPUT {
        if i < output_length {
            first = (first + output[i] as u32) % 65521;
            second = (second + first) % 65521;
        }
    }
    let expected = (second << 16) | first;
    let offset = compressed_length - 4;
    let actual = (compressed[offset] as u32) << 24
        | (compressed[offset + 1] as u32) << 16
        | (compressed[offset + 2] as u32) << 8
        | compressed[offset + 3] as u32;
    assert(actual == expected);
}

pub fn inflate(
    compressed: [u8; MAX_COMMITMENT_PREIMAGE],
    compressed_length: u32,
    trace: DeflateTrace,
) -> InflateOutput {
    assert((compressed_length >= 6) & (compressed_length <= MAX_COMPRESSED));
    assert(compressed[0] == 0x78);
    assert(compressed[1] == 0x9c);

    for position in 0..MAX_COMPRESSED_BITS {
        let bit = trace.bits[position];
        assert(bit <= 1);
        if position < compressed_length * 8 {
            let expected =
                (compressed[position / 8] >> ((position % 8) as u8)) & 1;
            assert(bit == expected);
        }
    }

    let mut bit_position = 16 as u32;
    assert(read_bits(trace.bits, bit_position, 1) == 1);
    bit_position = bit_position + 1;
    assert(read_bits(trace.bits, bit_position, 2) == 2);
    bit_position = bit_position + 2;

    let literal_count = read_bits(trace.bits, bit_position, 5) as u32 + 257;
    bit_position = bit_position + 5;
    let distance_count = read_bits(trace.bits, bit_position, 5) as u32 + 1;
    bit_position = bit_position + 5;
    let code_length_count = read_bits(trace.bits, bit_position, 4) as u32 + 4;
    bit_position = bit_position + 4;
    assert(literal_count == 278);
    assert(distance_count == 25);
    assert(code_length_count == 14);

    let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let mut header_lengths = [0 as u8; CODE_LENGTH_SYMBOLS];
    for i in 0..CODE_LENGTH_SYMBOLS {
        if i < code_length_count {
            header_lengths[order[i] as u32] =
                read_bits(trace.bits, bit_position, 3) as u8;
            bit_position = bit_position + 3;
        }
    }
    let header_codes = code_length_codes(header_lengths);

    assert(trace.header_symbol_count <= MAX_HEADER_TOKENS);
    let mut header_starts = [0 as u32; MAX_HEADER_TOKENS];
    let mut header_repeats = [0 as u32; MAX_HEADER_TOKENS];
    let mut header_values = [0 as u8; MAX_HEADER_TOKENS];
    let mut length_position = 0 as u32;
    for token in 0..MAX_HEADER_TOKENS {
        if token < trace.header_symbol_count {
            let symbol = trace.header_symbols[token];
            assert(symbol <= 18);
            let code_bits = header_lengths[symbol as u32];
            assert(code_bits > 0);
            assert(
                read_bits(trace.bits, bit_position, code_bits)
                    == header_codes[symbol as u32],
            );
            bit_position = bit_position + code_bits as u32;
            header_starts[token] = length_position;

            if symbol <= 15 {
                assert(length_position < 303);
                header_repeats[token] = 1;
                header_values[token] = symbol;
                length_position = length_position + 1;
            } else {
                let mut repeat = 0 as u32;
                let mut repeated_length = 0 as u8;
                if symbol == 16 {
                    assert(length_position > 0);
                    repeat = read_bits(trace.bits, bit_position, 2) as u32 + 3;
                    bit_position = bit_position + 2;
                    repeated_length = trace.code_lengths[length_position - 1];
                } else if symbol == 17 {
                    repeat = read_bits(trace.bits, bit_position, 3) as u32 + 3;
                    bit_position = bit_position + 3;
                } else {
                    repeat = read_bits(trace.bits, bit_position, 7) as u32 + 11;
                    bit_position = bit_position + 7;
                }
                assert(length_position + repeat <= 303);
                header_repeats[token] = repeat;
                header_values[token] = repeated_length;
                length_position = length_position + repeat;
            }
        }
    }
    assert(length_position == 303);
    for position in 0..303 {
        let token = trace.header_token_index[position] as u32;
        assert(token < trace.header_symbol_count);
        let start = header_starts[token];
        let repeat = header_repeats[token];
        assert((position >= start) & (position < start + repeat));
        assert(trace.code_lengths[position] == header_values[token]);
    }

    let mut literal_lengths = [0 as u8; LITLEN_SYMBOLS];
    for symbol in 0..LITLEN_SYMBOLS {
        if symbol < literal_count {
            literal_lengths[symbol] = trace.code_lengths[symbol];
        }
    }
    assert(literal_lengths[256] > 0);

    let mut distance_lengths = [0 as u8; DISTANCE_SYMBOLS];
    for symbol in 0..DISTANCE_SYMBOLS {
        if symbol < distance_count {
            distance_lengths[symbol] = trace.code_lengths[literal_count + symbol];
        }
    }
    let literal_codes = litlen_codes(literal_lengths);
    let distance_code_values = distance_codes(distance_lengths);

    assert(
        (trace.data_symbol_count > 0)
            & (trace.data_symbol_count <= MAX_DATA_TOKENS),
    );
    let mut token_starts = [0 as u32; MAX_DATA_TOKENS];
    let mut token_lengths = [0 as u32; MAX_DATA_TOKENS];
    let mut token_distances = [0 as u32; MAX_DATA_TOKENS];
    let mut output_position = 0 as u32;
    let mut finished = false;

    for token in 0..MAX_DATA_TOKENS {
        if token < trace.data_symbol_count {
            assert(!finished);
            let symbol = trace.data_symbols[token];
            assert(symbol < literal_count as u16);
            let code_bits = literal_lengths[symbol as u32];
            assert(code_bits > 0);
            assert(
                read_bits(trace.bits, bit_position, code_bits)
                    == literal_codes[symbol as u32],
            );
            bit_position = bit_position + code_bits as u32;
            token_starts[token] = output_position;

            if symbol < 256 {
                token_lengths[token] = 1;
                output_position = output_position + 1;
            } else if symbol == 256 {
                assert(token + 1 == trace.data_symbol_count);
                finished = true;
            } else {
                assert(symbol <= 285);
                let extra_length_bits = length_extra_bits(symbol);
                let match_length = length_base(symbol) as u32
                    + read_bits(trace.bits, bit_position, extra_length_bits) as u32;
                bit_position = bit_position + extra_length_bits as u32;

                let distance_symbol = trace.distance_symbols[token];
                assert(distance_symbol < distance_count as u8);
                let distance_code_bits = distance_lengths[distance_symbol as u32];
                assert(distance_code_bits > 0);
                assert(
                    read_bits(trace.bits, bit_position, distance_code_bits)
                        == distance_code_values[distance_symbol as u32],
                );
                bit_position = bit_position + distance_code_bits as u32;
                let extra_distance_bits = distance_extra_bits(distance_symbol);
                let distance = distance_base(distance_symbol)
                    + read_bits(trace.bits, bit_position, extra_distance_bits) as u32;
                bit_position = bit_position + extra_distance_bits as u32;

                assert((distance > 0) & (distance <= output_position));
                assert(output_position + match_length <= MAX_OUTPUT);
                token_lengths[token] = match_length;
                token_distances[token] = distance;
                output_position = output_position + match_length;
            }
        }
    }
    assert(finished);
    assert((output_position >= 5200) & (output_position <= MAX_OUTPUT));

    for position in 0..MAX_OUTPUT {
        if position < output_position {
            let token = trace.output_token_index[position] as u32;
            assert(token < trace.data_symbol_count);
            let token_start = token_starts[token];
            let token_length = token_lengths[token];
            assert(
                (position >= token_start)
                    & (position < token_start + token_length),
            );
            let symbol = trace.data_symbols[token];
            if symbol < 256 {
                assert(trace.output[position] == symbol as u8);
            } else {
                let distance = token_distances[token];
                assert(distance > 0);
                assert(trace.output[position] == trace.output[position - distance]);
            }
        }
    }

    let payload_end = compressed_length - 4;
    assert((bit_position + 7) / 8 == payload_end);
    let padding = payload_end * 8 - bit_position;
    assert(read_bits(trace.bits, bit_position, padding as u8) == 0);
    verify_adler32(
        compressed,
        compressed_length,
        trace.output,
        output_position,
    );

    InflateOutput { bytes: trace.output, length: output_position }
}
