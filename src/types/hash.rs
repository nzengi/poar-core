// POAR Hash Types
// Cryptographic hash types for Zero-Knowledge Proof of Validity blockchain

use blake3;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// POAR uses BLAKE3 as the primary hash function for superior performance
/// and security compared to SHA-256 used by Bitcoin
pub const HASH_SIZE: usize = 32; // 256 bits

/// Generic hash type for POAR blockchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Create a new hash from bytes
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Hash(bytes)
    }
    
    /// Create hash from slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::types::POARError> {
        if slice.len() != HASH_SIZE {
            return Err(crate::types::POARError::CryptographicError(
                format!("Invalid hash length: expected {}, got {}", HASH_SIZE, slice.len())
            ));
        }
        let mut bytes = [0u8; HASH_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Hash(bytes))
    }
    
    /// Get hash as bytes
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
    
    /// Get hash as slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Create zero hash (used for genesis)
    pub fn zero() -> Self {
        Hash([0u8; HASH_SIZE])
    }
    
    /// Check if hash is zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    
    /// Hash arbitrary data using BLAKE3
    pub fn hash(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Hash(*hash.as_bytes())
    }
    
    /// Hash multiple pieces of data
    pub fn hash_multiple(data: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        for piece in data {
            hasher.update(piece);
        }
        let hash = hasher.finalize();
        Hash(*hash.as_bytes())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Hash {
    type Err = crate::types::POARError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != HASH_SIZE * 2 {
            return Err(crate::types::POARError::CryptographicError(
                format!("Invalid hash hex length: expected {}, got {}", HASH_SIZE * 2, s.len())
            ));
        }
        
        let bytes = hex::decode(s).map_err(|e| {
            crate::types::POARError::CryptographicError(format!("Invalid hex: {}", e))
        })?;
        
        Hash::from_slice(&bytes)
    }
}

/// Block hash type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHash(Hash);

impl BlockHash {
    pub fn new(hash: Hash) -> Self {
        BlockHash(hash)
    }
    
    pub fn hash(&self) -> Hash {
        self.0
    }
    
    pub fn zero() -> Self {
        BlockHash(Hash::zero())
    }
    
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash> for BlockHash {
    fn from(hash: Hash) -> Self {
        BlockHash(hash)
    }
}

impl From<BlockHash> for Hash {
    fn from(block_hash: BlockHash) -> Self {
        block_hash.0
    }
}

/// Transaction hash type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionHash(Hash);

impl TransactionHash {
    pub fn new(hash: Hash) -> Self {
        TransactionHash(hash)
    }
    
    pub fn hash(&self) -> Hash {
        self.0
    }
    
    pub fn zero() -> Self {
        TransactionHash(Hash::zero())
    }
}

impl fmt::Display for TransactionHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash> for TransactionHash {
    fn from(hash: Hash) -> Self {
        TransactionHash(hash)
    }
}

impl From<TransactionHash> for Hash {
    fn from(tx_hash: TransactionHash) -> Self {
        tx_hash.0
    }
}

/// Merkle root hash type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleRoot(Hash);

impl MerkleRoot {
    pub fn new(hash: Hash) -> Self {
        MerkleRoot(hash)
    }
    
    pub fn hash(&self) -> Hash {
        self.0
    }
    
    pub fn zero() -> Self {
        MerkleRoot(Hash::zero())
    }
    
    /// Calculate Merkle root from transaction hashes
    pub fn from_transactions(tx_hashes: &[TransactionHash]) -> Self {
        if tx_hashes.is_empty() {
            return MerkleRoot::zero();
        }
        
        let mut hashes: Vec<Hash> = tx_hashes.iter().map(|&tx| tx.into()).collect();
        
        // Build Merkle tree
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let hash = if chunk.len() == 2 {
                    // Hash pair
                    Hash::hash_multiple(&[chunk[0].as_slice(), chunk[1].as_slice()])
                } else {
                    // Odd number, hash with itself
                    Hash::hash_multiple(&[chunk[0].as_slice(), chunk[0].as_slice()])
                };
                next_level.push(hash);
            }
            
            hashes = next_level;
        }
        
        MerkleRoot(hashes[0])
    }
}

impl fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash> for MerkleRoot {
    fn from(hash: Hash) -> Self {
        MerkleRoot(hash)
    }
}

impl From<MerkleRoot> for Hash {
    fn from(merkle_root: MerkleRoot) -> Self {
        merkle_root.0
    }
}

/// State root hash type for account states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateRoot(Hash);

impl StateRoot {
    pub fn new(hash: Hash) -> Self {
        StateRoot(hash)
    }
    
    pub fn hash(&self) -> Hash {
        self.0
    }
    
    pub fn zero() -> Self {
        StateRoot(Hash::zero())
    }
}

impl fmt::Display for StateRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash> for StateRoot {
    fn from(hash: Hash) -> Self {
        StateRoot(hash)
    }
}

impl From<StateRoot> for Hash {
    fn from(state_root: StateRoot) -> Self {
        state_root.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_creation() {
        let data = b"POAR ZK-PoV Blockchain";
        let hash = Hash::hash(data);
        assert!(!hash.is_zero());
        
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        
        let parsed = Hash::from_str(&hex).unwrap();
        assert_eq!(hash, parsed);
    }
    
    #[test]
    fn test_merkle_root() {
        let tx_hashes = vec![
            TransactionHash::new(Hash::hash(b"tx1")),
            TransactionHash::new(Hash::hash(b"tx2")),
            TransactionHash::new(Hash::hash(b"tx3")),
        ];
        
        let merkle_root = MerkleRoot::from_transactions(&tx_hashes);
        assert!(!merkle_root.hash().is_zero());
        
        // Empty transactions should give zero root
        let empty_root = MerkleRoot::from_transactions(&[]);
        assert!(empty_root.hash().is_zero());
    }
    
    #[test]
    fn test_hash_consistency() {
        let data = b"test data";
        let hash1 = Hash::hash(data);
        let hash2 = Hash::hash(data);
        assert_eq!(hash1, hash2);
        
        let different_data = b"different data";
        let hash3 = Hash::hash(different_data);
        assert_ne!(hash1, hash3);
    }
} 