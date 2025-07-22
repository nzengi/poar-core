// Common WOTS+ logic for sign and verify
use super::params::WotsParams;

pub fn message_to_base_w(message_hash: &[u8], params: &WotsParams) -> Vec<u32> {
    let _w = params.w();
    let len1 = params.len1() as usize;
    let mut coefficients = Vec::with_capacity(params.len as usize);
    // Convert message to base-w (len1 coefficients)
    let mut current_byte_idx = 0;
    let mut bit_buffer = 0u32;
    let mut bits_in_buffer = 0;
    for _ in 0..len1 {
        // Ensure we have enough bits in buffer
        while bits_in_buffer < params.log_w && current_byte_idx < message_hash.len() {
            bit_buffer = (bit_buffer << 8) | (message_hash[current_byte_idx] as u32);
            bits_in_buffer += 8;
            current_byte_idx += 1;
        }
        if bits_in_buffer >= params.log_w {
            // Extract coefficient from buffer
            let coeff = (bit_buffer >> (bits_in_buffer - params.log_w)) & ((1u32 << params.log_w) - 1);
            coefficients.push(coeff);
            bits_in_buffer -= params.log_w;
        } else {
            // Not enough bits, pad with zeros
            coefficients.push(0);
        }
    }
    // Calculate checksum for remaining coefficients
    let checksum = calculate_checksum(&coefficients, params);
    let checksum_coeffs = checksum_to_base_w(checksum, params);
    coefficients.extend_from_slice(&checksum_coeffs);
    coefficients
}

pub fn calculate_checksum(coefficients: &[u32], params: &WotsParams) -> u32 {
    let w = params.w();
    let mut checksum = 0u32;
    for &coeff in coefficients.iter().take(params.len1() as usize) {
        checksum += w - 1 - coeff;
    }
    checksum
}

pub fn checksum_to_base_w(mut checksum: u32, params: &WotsParams) -> Vec<u32> {
    let len2 = params.len2() as usize;
    let mut coeffs = vec![0u32; len2];
    for i in 0..len2 {
        coeffs[len2 - 1 - i] = checksum & ((1u32 << params.log_w) - 1);
        checksum >>= params.log_w;
    }
    coeffs
} 