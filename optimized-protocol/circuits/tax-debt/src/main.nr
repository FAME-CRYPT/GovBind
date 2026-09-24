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
    identity_number: pub u64,
    issuance_date_yyyymmdd: pub u32,
    commitment_preimage: [u8; MAX_COMMITMENT_PREIMAGE],
    private_field_lengths: [u32; 12],
    claim_glyph_fields: [u8; 20],
    claim_glyph_offsets: [u32; 20],
    claim_date_glyph_fields: [u8; 10],
    claim_date_glyph_offsets: [u32; 10],
    deflate_trace: deflate::DeflateTrace,
) {
    assert(compressed_length <= MAX_COMPRESSED);
    let digest = sha256::sha256_var(commitment_preimage, compressed_length + 16);
    assert(digest_limbs(digest) == commitment);
    let inflated = deflate::inflate(commitment_preimage, compressed_length, deflate_trace);
    profile::validate(
        inflated,
        private_field_lengths,
        claim_glyph_fields,
        claim_glyph_offsets,
        claim_date_glyph_fields,
        claim_date_glyph_offsets,
        identity_number,
        issuance_date_yyyymmdd,
    );
}
