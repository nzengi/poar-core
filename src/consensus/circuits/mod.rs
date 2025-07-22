pub use crate::consensus::circuits::BlockValidityCircuit;
pub use crate::consensus::circuits::TransactionValidityCircuit;
// ZK-PoV Circuit implementations
// Original circuits
pub mod circuits;
// Optimized circuits for performance
pub mod optimized;

pub use circuits::*;
pub use optimized::*; 