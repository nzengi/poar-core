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

pub use super::common::{message_to_base_w, calculate_checksum, checksum_to_base_w};

/// Sign message with WOTS+ private key
pub fn sign_message(message: &[u8], private_key: &[u8], params: &WotsParams) -> WotsSignature {
    // Hash message to fixed length
    let message_hash = poseidon_hash(message);
    
    // Convert hash to base-w representation
    let coefficients = message_to_base_w(&message_hash, params);
    
    // Generate signature by hashing private key chains
    generate_signature_chains(&coefficients, private_key, params)
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
