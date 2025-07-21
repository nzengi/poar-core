use thiserror::Error;

#[derive(Debug, Error)]
pub enum POARError {
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Invalid ZK proof: {0}")]
    InvalidZKProof(String),
    // Add more error variants as needed
}

pub type POARResult<T> = Result<T, POARError>;

pub mod address;
pub mod block;
pub mod hash;
pub mod proof;
pub mod signature;
pub mod token;
pub mod transaction;
pub mod validator;

pub use address::Address;
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub const POAR_ZK_PROOF_SIZE: usize = 288;
pub use proof::ZKProof;
pub use signature::{Signature, PublicKey, PrivateKey};
pub use token::{Poar, Proof, Valid, Zero, TokenUnit, TokenAmount, TokenUtils, PROOF_PER_POAR, VALID_PER_PROOF, ZERO_PER_VALID, ZERO_PER_POAR};
pub use transaction::{Transaction, TransactionInput, TransactionOutput};
pub use validator::Validator; 