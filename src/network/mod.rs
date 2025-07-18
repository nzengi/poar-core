// POAR Network Module
// P2P networking layer for blockchain communication

pub mod p2p;
pub mod protocol;
pub mod discovery;

// Re-export network types
pub use p2p::*;
pub use protocol::*;
pub use discovery::*; 