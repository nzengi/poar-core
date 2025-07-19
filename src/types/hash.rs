use blake3;
use serde::{Deserialize, Serialize};
use std::fmt;

/// BLAKE3 256-bit hash type for POAR blockchain
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Create a new hash from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create hash from slice (must be 32 bytes)
    pub fn from_slice(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("Hash must be 32 bytes");
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(bytes);
        Ok(Hash(hash))
    }

    /// Hash arbitrary data using BLAKE3
    pub fn hash(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Hash(*hash.as_bytes())
    }

    /// Hash multiple pieces of data
    pub fn hash_multiple(data: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for item in data {
            hasher.update(item);
        }
        let hash = hasher.finalize();
        Hash(*hash.as_bytes())
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        let bytes = hex::decode(hex_str).map_err(|_| "Invalid hex string")?;
        Self::from_slice(&bytes)
    }

    /// Zero hash (all zeros)
    pub fn zero() -> Self {
        Hash([0u8; 32])
    }

    /// Check if hash is zero
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..8])
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::zero()
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_creation() {
        let data = b"hello world";
        let hash = Hash::hash(data);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_hash_hex() {
        let hash = Hash::zero();
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0".repeat(64));
    }

    #[test]
    fn test_hash_multiple() {
        let data1 = b"hello";
        let data2 = b"world";
        let hash = Hash::hash_multiple(&[data1, data2]);
        assert!(!hash.is_zero());
    }
} 