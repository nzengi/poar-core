// POAR Signature Types
// Digital signature implementation using Ed25519

use crate::types::{Hash, POARError, POARResult};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey, Signer};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash as StdHash;

/// Signature size in bytes (64 bytes for Ed25519)
pub const SIGNATURE_SIZE: usize = 64;

/// Public key size in bytes (32 bytes for Ed25519)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Private key size in bytes (32 bytes for Ed25519)
pub const PRIVATE_KEY_SIZE: usize = 32;

/// POAR digital signature
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "serde_big_array::BigArray")] [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create signature from bytes
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }
    
    /// Create signature from slice
    pub fn from_slice(slice: &[u8]) -> POARResult<Self> {
        if slice.len() != SIGNATURE_SIZE {
            return Err(POARError::CryptographicError(
                format!("Invalid signature length: expected {}, got {}", SIGNATURE_SIZE, slice.len())
            ));
        }
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Signature(bytes))
    }
    
    /// Get signature as bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
    
    /// Get signature as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Verify signature
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> POARResult<bool> {
        let ed25519_sig = Ed25519Signature::from_bytes(&self.0);
        let ed25519_pk = VerifyingKey::from_bytes(public_key.as_bytes())
            .map_err(|e| POARError::CryptographicError(format!("Invalid public key: {}", e)))?;
        
        match ed25519_pk.verify_strict(message, &ed25519_sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// POAR public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create public key from bytes
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }
    
    /// Create public key from slice
    pub fn from_slice(slice: &[u8]) -> POARResult<Self> {
        if slice.len() != PUBLIC_KEY_SIZE {
            return Err(POARError::CryptographicError(
                format!("Invalid public key length: expected {}, got {}", PUBLIC_KEY_SIZE, slice.len())
            ));
        }
        let mut bytes = [0u8; PUBLIC_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(PublicKey(bytes))
    }
    
    /// Get public key as bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
    
    /// Get public key as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Derive address from public key
    pub fn to_address(&self) -> crate::types::Address {
        let hash = Hash::hash(self.as_slice());
        crate::types::Address::from_public_key_hash(hash)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// POAR private key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey([u8; PRIVATE_KEY_SIZE]);

impl PrivateKey {
    /// Generate a new random private key
    pub fn generate() -> Self {
        let mut csprng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        for i in 0..32 {
            secret_bytes[i] = rand::random();
        }
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        PrivateKey(signing_key.to_bytes())
    }
    
    /// Create private key from bytes
    pub fn from_bytes(bytes: [u8; PRIVATE_KEY_SIZE]) -> Self {
        PrivateKey(bytes)
    }
    
    /// Create private key from slice
    pub fn from_slice(slice: &[u8]) -> POARResult<Self> {
        if slice.len() != PRIVATE_KEY_SIZE {
            return Err(POARError::CryptographicError(
                format!("Invalid private key length: expected {}, got {}", PRIVATE_KEY_SIZE, slice.len())
            ));
        }
        let mut bytes = [0u8; PRIVATE_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(PrivateKey(bytes))
    }
    
    /// Get private key as bytes
    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY_SIZE] {
        &self.0
    }
    
    /// Get private key as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Get corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        let verifying_key = signing_key.verifying_key();
        PublicKey::from_bytes(verifying_key.to_bytes())
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signing_key = SigningKey::from_bytes(&self.0);
        let signature = signing_key.sign(message);
        Signature::from_bytes(signature.to_bytes())
    }
    
    /// Convert to hex string (be careful with this!)
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrivateKey(***)")
    }
}

/// Key pair containing both private and public keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate() -> Self {
        let private_key = PrivateKey::generate();
        let public_key = private_key.public_key();
        KeyPair {
            private_key,
            public_key,
        }
    }
    
    /// Create key pair from private key
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        let public_key = private_key.public_key();
        KeyPair {
            private_key,
            public_key,
        }
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message)
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> POARResult<bool> {
        signature.verify(message, &self.public_key)
    }
    
    /// Get address for this key pair
    pub fn address(&self) -> crate::types::Address {
        self.public_key.to_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key_pair = KeyPair::generate();
        assert_eq!(key_pair.private_key.public_key(), key_pair.public_key);
    }
    
    #[test]
    fn test_signature_verification() {
        let key_pair = KeyPair::generate();
        let message = b"Hello, POAR!";
        
        let signature = key_pair.sign(message);
        assert!(key_pair.verify(message, &signature).unwrap());
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(!key_pair.verify(wrong_message, &signature).unwrap());
    }
    
    #[test]
    fn test_address_derivation() {
        let key_pair = KeyPair::generate();
        let address1 = key_pair.address();
        let address2 = key_pair.public_key.to_address();
        assert_eq!(address1, address2);
    }
    
    #[test]
    fn test_signature_serialization() {
        let key_pair = KeyPair::generate();
        let message = b"Test message";
        let signature = key_pair.sign(message);
        
        let hex = signature.to_hex();
        assert_eq!(hex.len(), SIGNATURE_SIZE * 2);
        
        let bytes = hex::decode(hex).unwrap();
        let restored_signature = Signature::from_slice(&bytes).unwrap();
        assert_eq!(signature, restored_signature);
    }
} 