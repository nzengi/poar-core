//! WOTS+ key generation module

use crate::crypto::hash::poseidon_hash;
use super::params::WotsParams;
use serde::{Deserialize, Serialize};

/// WOTS+ keypair structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WotsKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Generate WOTS+ keypair
pub fn generate_keypair(params: &WotsParams) -> WotsKeyPair {
    let mut rng = rand::thread_rng();
    
    // Generate private key - len chains of n bytes each
    let mut private_key = Vec::with_capacity((params.len * params.n) as usize);
    for _ in 0..params.len {
        let mut chain_seed = vec![0u8; params.n as usize];
        rand::RngCore::fill_bytes(&mut rng, &mut chain_seed);
        private_key.extend_from_slice(&chain_seed);
    }
    
    // Generate public key by hashing private key chains w-1 times
    let public_key = derive_public_key(&private_key, params);
    
    WotsKeyPair {
        public_key,
        private_key,
    }
}

/// Derive public key from private key
pub fn derive_public_key(private_key: &[u8], params: &WotsParams) -> Vec<u8> {
    let mut public_key = Vec::with_capacity((params.len * params.n) as usize);
    let w = params.w();
    
    for i in 0..params.len {
        let start = (i * params.n) as usize;
        let end = start + params.n as usize;
        let mut chain_value = private_key[start..end].to_vec();
        
        // Hash chain w-1 times to get public key element
        for _ in 1..w {
            chain_value = poseidon_hash(&chain_value);
        }
        
        public_key.extend_from_slice(&chain_value);
    }
    
    public_key
}

/// Generate address for WOTS instance
pub fn generate_address(keypair_addr: u32, chain_addr: u32, hash_addr: u32) -> Vec<u8> {
    let mut address = Vec::with_capacity(12);
    address.extend_from_slice(&keypair_addr.to_be_bytes());
    address.extend_from_slice(&chain_addr.to_be_bytes());
    address.extend_from_slice(&hash_addr.to_be_bytes());
    address
}

use rand;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        
        // Check private key length
        assert_eq!(keypair.private_key.len(), (params.len * params.n) as usize);
        
        // Check public key length
        assert_eq!(keypair.public_key.len(), (params.len * params.n) as usize);
        
        // Keys should be different
        assert_ne!(keypair.private_key, keypair.public_key);
    }

    #[test]
    fn test_public_key_derivation() {
        let params = WotsParams::default();
        let keypair = generate_keypair(&params);
        let derived_pk = derive_public_key(&keypair.private_key, &params);
        
        assert_eq!(keypair.public_key, derived_pk);
    }

    #[test]
    fn test_address_generation() {
        let addr = generate_address(1, 2, 3);
        assert_eq!(addr.len(), 12);
        
        // Check big-endian encoding
        assert_eq!(&addr[0..4], &1u32.to_be_bytes());
        assert_eq!(&addr[4..8], &2u32.to_be_bytes());
        assert_eq!(&addr[8..12], &3u32.to_be_bytes());
    }

    #[test]
    fn test_deterministic_public_key() {
        let params = WotsParams::default();
        let private_key = vec![42u8; (params.len * params.n) as usize];
        
        let pk1 = derive_public_key(&private_key, &params);
        let pk2 = derive_public_key(&private_key, &params);
        
        assert_eq!(pk1, pk2);
    }
}
