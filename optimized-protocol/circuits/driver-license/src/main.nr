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
    maximum_traffic_tickets: pub u32,
    maximum_total_penalty_points: pub u32,
    maximum_active_penalty_points: pub u32,
    commitment_preimage: [u8; MAX_COMMITMENT_PREIMAGE],
    layout_variant: u8,
    private_field_lengths: [u32; 15],
    deflate_trace: deflate::DeflateTrace,
) {
    assert(compressed_length <= MAX_COMPRESSED);
    assert(maximum_traffic_tickets > 0);
    assert(maximum_total_penalty_points > 0);
    assert(maximum_active_penalty_points > 0);
    let digest = sha256::sha256_var(commitment_preimage, compressed_length + 16);
    assert(digest_limbs(digest) == commitment);
    let inflated = deflate::inflate(commitment_preimage, compressed_length, deflate_trace);
    profile::validate(
        inflated,
        layout_variant,
        private_field_lengths,
        maximum_traffic_tickets,
        maximum_total_penalty_points,
        maximum_active_penalty_points,
    );
}
