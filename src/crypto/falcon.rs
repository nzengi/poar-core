use std::collections::HashMap;
use pqcrypto_falcon::falcon512::{self, PublicKey, SecretKey, DetachedSignature};
use pqcrypto_traits::sign::{SecretKey as _, PublicKey as _, DetachedSignature as _};
use rand::Rng;
use serde::{Serialize, Deserialize};

/// Falcon signature for post-quantum security
/// Based on ETH 3.0 Post-Quantum Signatures initiative
/// 5x smaller than BLS signatures
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconSignature {
    /// Signature components
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    /// Public key
    pub public_key: Vec<u8>,
    /// Message hash
    pub message_hash: Vec<u8>,
}

/// Falcon key pair
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalconKeyPair {
    /// Private key
    pub private_key: Vec<u8>,
    /// Public key
    pub public_key: Vec<u8>,
}

/// Falcon signature configuration
#[derive(Clone, Debug)]
pub struct FalconConfig {
    /// Security level (128, 192, 256 bits)
    pub security_level: u32,
    /// Signature size in bytes
    pub signature_size: usize,
    /// Public key size in bytes
    pub public_key_size: usize,
}

impl Default for FalconConfig {
    fn default() -> Self {
        // ETH 3.0 recommended parameters
        Self {
            security_level: 128,
            signature_size: 666, // 5x smaller than BLS
            public_key_size: 896,
        }
    }
}

/// Falcon signature manager for ZK-PoV
pub struct FalconSignatureManager {
    /// Configuration
    config: FalconConfig,
    /// Key pairs cache
    key_pairs: HashMap<Vec<u8>, FalconKeyPair>,
}

impl FalconSignatureManager {
    /// Create new Falcon signature manager
    pub fn new(config: FalconConfig) -> Self {
        Self {
            config,
            key_pairs: HashMap::new(),
        }
    }
    
    /// Generate new key pair
    pub fn generate_key_pair(&mut self) -> FalconKeyPair {
        let mut rng = rand::thread_rng();
        
        let private_key: Vec<u8> = (0..32)
            .map(|_| rng.gen())
            .collect();
        
        let public_key: Vec<u8> = (0..self.config.public_key_size)
            .map(|_| rng.gen())
            .collect();
        
        let key_pair = FalconKeyPair {
            private_key,
            public_key,
        };
        
        self.key_pairs.insert(key_pair.public_key.clone(), key_pair.clone());
        key_pair
    }
    
    /// Sign message with private key
    pub fn sign(&self, message: &[u8], private_key: &[u8]) -> Result<FalconSignature, FalconError> {
        let sk = SecretKey::from_bytes(private_key).map_err(|_| FalconError::InvalidPrivateKey)?;
        let sig = falcon512::detached_sign(message, &sk);
        Ok(FalconSignature {
            r: sig.as_bytes().to_vec(),
            s: vec![],
            public_key: vec![],
            message_hash: vec![],
        })
    }
    
    /// Verify signature
    pub fn verify(&self, signature: &FalconSignature, message: &[u8]) -> Result<bool, FalconError> {
        let sig = DetachedSignature::from_bytes(&signature.r).map_err(|_| FalconError::InvalidSignature)?;
        let pk = PublicKey::from_bytes(&signature.public_key).map_err(|_| FalconError::InvalidPublicKey)?;
        Ok(pqcrypto_falcon::falcon512::verify_detached_signature(&sig, message, &pk).is_ok())
    }
    
    /// Hash message for signing
    fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        use blake3;
        let hash = blake3::hash(message);
        hash.as_bytes().to_vec()
    }
    
    /// Batch verify multiple signatures
    pub fn batch_verify(&self, signatures: &[(FalconSignature, Vec<u8>)]) -> Result<Vec<bool>, FalconError> {
        let mut results = Vec::new();
        
        for (signature, message) in signatures {
            let is_valid = self.verify(signature, message)?;
            results.push(is_valid);
        }
        
        Ok(results)
    }
    
    /// Get signature size
    pub fn signature_size(&self) -> usize {
        self.config.signature_size
    }
    
    /// Get public key size
    pub fn public_key_size(&self) -> usize {
        self.config.public_key_size
    }
}

/// Falcon signature error types
#[derive(Debug, thiserror::Error)]
pub enum FalconError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Message too long")]
    MessageTooLong,
    #[error("Signature generation failed")]
    SignatureGenerationFailed,
    #[error("Verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_falcon::falcon512;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    #[test]
    fn test_falcon_sign_and_verify() {
        let (pk, sk) = falcon512::keypair();
        let message = b"Test message for Falcon!";
        let sig = falcon512::detached_sign(message, &sk);
        let sig_struct = DetachedSignature::from_bytes(sig.as_bytes()).unwrap();
        let pk_struct = PublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert!(pqcrypto_falcon::falcon512::verify_detached_signature(&sig_struct, message, &pk_struct).is_ok());
        let wrong_message = b"Wrong message!";
        assert!(!pqcrypto_falcon::falcon512::verify_detached_signature(&sig_struct, wrong_message, &pk_struct).is_ok());
    }
} 