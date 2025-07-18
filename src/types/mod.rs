// POAR ZK-PoV Core Types
// Revolutionary blockchain types for Zero-Knowledge Proof of Validity consensus

pub mod block;
pub mod transaction;
pub mod validator;
pub mod proof;
pub mod address;
pub mod hash;
pub mod signature;

// Re-export core types
pub use block::*;
pub use transaction::*;
pub use validator::*;
pub use proof::*;
pub use address::*;
pub use hash::*;
pub use signature::*;

use serde::{Deserialize, Serialize};
use std::fmt;

/// POAR blockchain configuration constants
pub const POAR_CHAIN_ID: u64 = 2025;
pub const POAR_GENESIS_TIMESTAMP: u64 = 1737403200; // 2025-01-20 20:00:00 UTC
pub const POAR_BLOCK_TIME: u64 = 12; // 12 seconds
pub const POAR_FINALITY_TIME: u64 = 2; // 2.4 seconds average
pub const POAR_MAX_BLOCK_SIZE: usize = 1024 * 1024; // 1MB
pub const POAR_MAX_TRANSACTIONS_PER_BLOCK: usize = 10000;
pub const POAR_MIN_VALIDATOR_STAKE: u64 = 10000; // 10,000 POAR
pub const POAR_ZK_PROOF_SIZE: usize = 288; // 288 bytes constant

/// POAR native token unit (1 POAR = 10^18 units)
pub const POAR_DECIMALS: u8 = 18;
pub const POAR_UNIT: u64 = 1_000_000_000_000_000_000; // 10^18

/// Network identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkId {
    Mainnet,
    Testnet,
    Devnet,
    Local,
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkId::Mainnet => write!(f, "mainnet"),
            NetworkId::Testnet => write!(f, "testnet"),
            NetworkId::Devnet => write!(f, "devnet"),
            NetworkId::Local => write!(f, "local"),
        }
    }
}

/// POAR blockchain errors
#[derive(Debug, thiserror::Error)]
pub enum POARError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    
    #[error("Invalid ZK proof: {0}")]
    InvalidZKProof(String),
    
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

pub type POARResult<T> = Result<T, POARError>;

/// Blockchain height type
pub type BlockHeight = u64;

/// Blockchain timestamp type (Unix timestamp in seconds)
pub type Timestamp = u64;

/// Amount type for POAR tokens
pub type Amount = u64;

/// Gas type for transaction fees
pub type Gas = u64;

/// Nonce type for transaction ordering
pub type Nonce = u64;

/// Difficulty type for consensus
pub type Difficulty = u64;

/// Epoch type for validator management
pub type Epoch = u64;

/// Slot type for consensus rounds
pub type Slot = u64; 