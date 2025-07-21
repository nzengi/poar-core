//! WOTS+ signature creation module

use crate::crypto::hash::poseidon_hash;
use super::params::WotsParams;

/// WOTS+ signature type
pub type WotsSignature = Vec<u8>;

/// WOTS+ signer interface
pub struct WotsSigner;

impl WotsSigner {
    /// Create new signer instance
    pub fn new() -> Self {
        Self
    }
}

/// Sign message with WOTS+ private key
pub fn sign_message(message: &[u8], private_key: &[u8], params: &WotsParams) -> WotsSignature {
    // Hash message to fixed length
    let message_hash = poseidon_hash(message);
    
    // Convert hash to base-w representation
    let coefficients = message_to_base_w(&message_hash, params);
    
    // Generate signature by hashing private key chains
    generate_signature_chains(&coefficients, private_key, params)
}

/// Convert message hash to base-w representation
fn message_to_base_w(message_hash: &[u8], params: &WotsParams) -> Vec<u32> {
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

/// Calculate checksum for WOTS+ signature
fn calculate_checksum(coefficients: &[u32], params: &WotsParams) -> u32 {
    let w = params.w();
    let mut checksum = 0u32;
    
    for &coeff in coefficients.iter().take(params.len1() as usize) {
        checksum += w - 1 - coeff;
    }
    
    checksum
}

/// Convert checksum to base-w representation
fn checksum_to_base_w(mut checksum: u32, params: &WotsParams) -> Vec<u32> {
    let len2 = params.len2() as usize;
    let mut coeffs = vec![0u32; len2];
    
    for i in 0..len2 {
        coeffs[len2 - 1 - i] = checksum & ((1u32 << params.log_w) - 1);
        checksum >>= params.log_w;
    }
    
    coeffs
}

/// Generate signature chains from coefficients
fn generate_signature_chains(coefficients: &[u32], private_key: &[u8], params: &WotsParams) -> WotsSignature {
    let mut signature = Vec::with_capacity((params.len * params.n) as usize);
    
    for (i, &coeff) in coefficients.iter().enumerate() {
        let start = (i as u32 * params.n) as usize;
        let end = start + params.n as usize;
        let mut chain_value = private_key[start..end].to_vec();
        
        // Hash chain coeff times
        for _ in 0..coeff {
            chain_value = poseidon_hash(&chain_value);
        }
        
        signature.extend_from_slice(&chain_value);
    }
    
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wots::keygen::generate_keypair;

    #[test]
    fn test_message_to_base_w() {
        let params = WotsParams::default();
        let message = b"test message";
        let message_hash = poseidon_hash(message);
        let coeffs = message_to_base_w(&message_hash, &params);
        
        assert_eq!(coeffs.len(), params.len as usize);
        
        // All coefficients should be < w
        for &coeff in &coeffs {
            assert!(coeff < params.w());
        }
    }

    #[test]
    fn test_checksum_calculation() {
        let coeffs = vec![1, 2, 3, 4, 5];
        let params = WotsParams::new(4, 32, 32); // w = 16
        let checksum = calculate_checksum(&coeffs, &params);
        
        // checksum = (16-1-1) + (16-1-2) + ... = 14+13+12+11+10 = 60
        assert_eq!(checksum, 60);
    }

    #[test]
    fn test_sign_message() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"Hello Beam Chain!";
        
        let signature = sign_message(message, &keypair.private_key, &params);
        
        // Signature should have correct length
        assert_eq!(signature.len(), (params.len * params.n) as usize);
    }

    #[test]
    fn test_deterministic_signing() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"test message";
        
        let sig1 = sign_message(message, &keypair.private_key, &params);
        let sig2 = sign_message(message, &keypair.private_key, &params);
        
        assert_eq!(sig1, sig2);
    }
}
