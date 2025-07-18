// POAR Virtual Machine Module
// Smart contract execution environment

pub mod zkvm;
pub mod runtime;
pub mod opcodes;

// Re-export VM types
pub use zkvm::*;
pub use runtime::*;
pub use opcodes::*; 