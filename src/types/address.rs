// POAR Address Types
// Blockchain address implementation

use crate::types::{Hash, POARError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::hash::Hash as StdHash;

/// Address size in bytes (20 bytes like Ethereum)
pub const ADDRESS_SIZE: usize = 20;

/// POAR blockchain address
#[derive(Debug, Clone, Copy, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub struct Address([u8; ADDRESS_SIZE]);

impl Address {
    /// Create address from bytes
    pub fn from_bytes(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Address(bytes)
    }
    
    /// Create address from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, POARError> {
        if slice.len() != ADDRESS_SIZE {
            return Err(POARError::CryptographicError(
                format!("Invalid address length: expected {}, got {}", ADDRESS_SIZE, slice.len())
            ));
        }
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }
    
    /// Create address from public key hash
    pub fn from_public_key_hash(hash: Hash) -> Self {
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash.as_slice()[..ADDRESS_SIZE]);
        Address(bytes)
    }
    
    /// Get address as bytes
    pub fn as_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }
    
    /// Get address as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Create zero address
    pub fn zero() -> Self {
        Address([0u8; ADDRESS_SIZE])
    }
    
    /// Check if address is zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
    
    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
    
    /// Convert to checksum address (EIP-55 style)
    pub fn to_checksum(&self) -> String {
        let hex = hex::encode(self.0);
        let hash = Hash::hash(hex.as_bytes());
        let hash_hex = hash.to_hex();
        
        let mut checksum = String::from("0x");
        for (i, c) in hex.chars().enumerate() {
            if c.is_ascii_digit() {
                checksum.push(c);
            } else {
                let hash_char = hash_hex.chars().nth(i).unwrap();
                if hash_char >= '8' {
                    checksum.push(c.to_ascii_uppercase());
                } else {
                    checksum.push(c);
                }
            }
        }
        checksum
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum())
    }
}

impl FromStr for Address {
    type Err = POARError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        
        if s.len() != ADDRESS_SIZE * 2 {
            return Err(POARError::CryptographicError(
                format!("Invalid address hex length: expected {}, got {}", ADDRESS_SIZE * 2, s.len())
            ));
        }
        
        let bytes = hex::decode(s).map_err(|e| {
            POARError::CryptographicError(format!("Invalid hex: {}", e))
        })?;
        
        Address::from_slice(&bytes)
    }
}

impl From<Hash> for Address {
    fn from(hash: Hash) -> Self {
        Address::from_public_key_hash(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_creation() {
        let bytes = [1u8; ADDRESS_SIZE];
        let addr = Address::from_bytes(bytes);
        assert_eq!(addr.as_bytes(), &bytes);
        assert!(!addr.is_zero());
        
        let zero_addr = Address::zero();
        assert!(zero_addr.is_zero());
    }
    
    #[test]
    fn test_address_hex() {
        let addr = Address::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]);
        let hex = addr.to_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + ADDRESS_SIZE * 2);
        
        let parsed = Address::from_str(&hex).unwrap();
        assert_eq!(addr, parsed);
    }
    
    #[test]
    fn test_checksum_address() {
        let addr = Address::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]);
        let checksum = addr.to_checksum();
        assert!(checksum.starts_with("0x"));
        assert_eq!(checksum.len(), 2 + ADDRESS_SIZE * 2);
    }
} 