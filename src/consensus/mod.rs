// POAR ZK-PoV Consensus Module
// Revolutionary Zero-Knowledge Proof of Validity consensus implementation

pub mod circuits;
pub mod zksnark;
pub mod engine;
pub mod finality;
pub mod validator;
pub mod optimization;

pub use circuits::{CircuitType, CircuitManager, BlockValidityCircuit, TransactionValidityCircuit, StateTransitionCircuit, ValidatorEligibilityCircuit, MerkleInclusionCircuit, SignatureVerificationCircuit};
pub use zksnark::{PoarProver, PoarVerifier, TrustedSetup, TrustedSetupManager, ProverMetrics, VerifierMetrics};
pub use engine::{ConsensusEngine, ConsensusState, ValidatorRegistry, ValidatorInfo, ValidatorStatus, ConsensusConfig, ConsensusEvent, ConsensusMetrics};
pub use finality::FinalityGadget;
pub use validator::ValidatorManager;
pub use optimization::{ProofOptimizer, OptimizationConfig, OptimizationMetrics, BatchVerificationResult, ParallelProofResult}; 