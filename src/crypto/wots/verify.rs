//! WOTS+ signature verification module

use crate::crypto::hash::poseidon_hash;
use super::params::WotsParams;
use super::sign::{WotsSignature};

/// WOTS+ verifier interface
pub struct WotsVerifier;

impl WotsVerifier {
    /// Create new verifier instance
    pub fn new() -> Self {
        Self
    }
}

/// Verify WOTS+ signature
pub fn verify_signature(
    message: &[u8], 
    signature: &WotsSignature, 
    public_key: &[u8], 
    params: &WotsParams
) -> bool {
    // Hash message to fixed length
    let message_hash = poseidon_hash(message);
    println!("[DEBUG] message_hash: {:02x?}", message_hash);
    // Convert hash to base-w representation (same as signing)
    let coefficients = message_to_base_w(&message_hash, params);
    println!("[DEBUG] coefficients: {:?}", coefficients);
    // Derive public key from signature
    let derived_pk = derive_public_key_from_signature(signature, &coefficients, params);
    println!("[DEBUG] derived_pk: {:02x?}", derived_pk);
    println!("[DEBUG] provided_pk: {:02x?}", public_key);
    // Compare with provided public key
    derived_pk == public_key
}

/// Convert message hash to base-w representation (same as in sign.rs)
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

/// Derive public key from signature using coefficients
fn derive_public_key_from_signature(
    signature: &[u8], 
    coefficients: &[u32], 
    params: &WotsParams
) -> Vec<u8> {
    let mut derived_pk = Vec::with_capacity((params.len * params.n) as usize);
    let w = params.w();
    
    for (i, &coeff) in coefficients.iter().enumerate() {
        let start = (i as u32 * params.n) as usize;
        let end = start + params.n as usize;
        
        if end > signature.len() {
            // Invalid signature length - return empty to signal failure
            return Vec::new();
        }
        
        let mut chain_value = signature[start..end].to_vec();
        
        // Hash chain (w - 1 - coeff) times to get public key element
        if coeff >= w {
            // Invalid coefficient - return empty to signal failure
            return Vec::new();
        }
        
        let remaining_hashes = w - 1 - coeff;
        for _ in 0..remaining_hashes {
            chain_value = poseidon_hash(&chain_value);
        }
        
        derived_pk.extend_from_slice(&chain_value);
    }
    
    derived_pk
}

/// Fast verification for known valid signatures (optimization)
pub fn fast_verify(
    message_hash: &[u8],
    signature: &WotsSignature,
    public_key: &[u8],
    params: &WotsParams
) -> bool {
    // Skip message hashing if hash is already provided
    let coefficients = message_to_base_w(message_hash, params);
    let derived_pk = derive_public_key_from_signature(signature, &coefficients, params);
    derived_pk == public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wots::keygen::generate_keypair;
    use crate::crypto::wots::sign::sign_message;

    #[test]
    fn test_valid_signature_verification() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"Hello Beam Chain!";
        
        let signature = sign_message(message, &keypair.private_key, &params);
        let is_valid = verify_signature(message, &signature, &keypair.public_key, &params);
        
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_message_verification() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"Hello Beam Chain!";
        let wrong_message = b"Wrong message!";
        
        let signature = sign_message(message, &keypair.private_key, &params);
        let is_valid = verify_signature(wrong_message, &signature, &keypair.public_key, &params);
        
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_signature_verification() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"Hello Beam Chain!";
        
        let mut signature = sign_message(message, &keypair.private_key, &params);
        signature[0] ^= 1; // Corrupt signature
        
        let is_valid = verify_signature(message, &signature, &keypair.public_key, &params);
        
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_public_key_verification() {
        let params = WotsParams::default();
        let keypair1 = generate_keypair(&params);
        let keypair2 = generate_keypair(&params);
        let message = b"Hello Beam Chain!";
        
        let signature = sign_message(message, &keypair1.private_key, &params);
        let is_valid = verify_signature(message, &signature, &keypair2.public_key, &params);
        
        assert!(!is_valid);
    }

    #[test]
    fn test_fast_verify() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let message = b"test message";
        let message_hash = poseidon_hash(message);
        
        let signature = sign_message(message, &keypair.private_key, &params);
        let is_valid = fast_verify(&message_hash, &signature, &keypair.public_key, &params);
        
        assert!(is_valid);
    }
}
