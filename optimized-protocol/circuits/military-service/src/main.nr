mod date;
mod deflate;
mod profile;

use deflate::{MAX_COMMITMENT_PREIMAGE, MAX_COMPRESSED};

fn digest_limbs(digest: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0 as u64; 4];
    for limb in 0..4 {
        let mut value = 0 as u64;
        for byte in 0..8 {
            value = (value << 8) | digest[limb * 8 + byte] as u64;
        }
        limbs[limb] = value;
    }
    limbs
}

fn main(
    commitment: pub [u64; 4],
    compressed_length: pub u32,
    comparison_date_yyyymmdd: pub u32,
    assertion_months: pub u32,
    commitment_preimage: [u8; MAX_COMMITMENT_PREIMAGE],
    private_field_lengths: [u32; 9],
    deflate_trace: deflate::DeflateTrace,
) {
    assert(compressed_length <= MAX_COMPRESSED);
    let digest = sha256::sha256_var(commitment_preimage, compressed_length + 16);
    assert(digest_limbs(digest) == commitment);

    let inflated =
        deflate::inflate(commitment_preimage, compressed_length, deflate_trace);
    profile::validate(
        inflated,
        private_field_lengths,
        comparison_date_yyyymmdd,
        assertion_months,
    );
}
