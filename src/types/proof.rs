// POAR ZK-PoV Proof Types
// Revolutionary Zero-Knowledge Proof of Validity system

use crate::types::{Hash, POARError, POARResult};
pub type BlockHash = Hash;
pub type TransactionHash = Hash;
use ark_bls12_381::Bls12_381;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash as StdHash;

/// ZK-PoV Proof System Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    /// Groth16 SNARK - Production ready, constant proof size
    Groth16,
    /// Plonk - Universal setup, larger proofs
    Plonk,
    /// Nova - Recursive proofs, future upgrade
    Nova,
    /// FRI - Fast Reed-Solomon Interactive Oracle Proofs of Proximity
    FRI,
    /// STU - STIR/FRI/WHIR style proof (placeholder)
    STU,
    /// WHIR - WHIR interactive proof system (placeholder)
    WHIR,
}

impl fmt::Display for ProofSystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofSystem::Groth16 => write!(f, "Groth16"),
            ProofSystem::Plonk => write!(f, "Plonk"),
            ProofSystem::Nova => write!(f, "Nova"),
            ProofSystem::FRI => write!(f, "FRI"),
            ProofSystem::STU => write!(f, "STU"),
            ProofSystem::WHIR => write!(f, "WHIR"),
        }
    }
}

/// ZK Proof data structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZKProof {
    /// The proof system used
    pub system: ProofSystem,
    /// The actual proof bytes (288 bytes for Groth16)
    pub proof_data: Vec<u8>,
    /// Public inputs to the circuit (as bytes for serialization)
    pub public_inputs: Vec<u8>,
    /// Circuit identifier
    pub circuit_id: CircuitId,
    /// Proof generation timestamp
    pub timestamp: u64, // Unix timestamp when proof was generated
}

impl ZKProof {
    /// Create a new ZK proof
    pub fn new(
        system: ProofSystem,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
        circuit_id: CircuitId,
    ) -> Self {
        Self {
            system,
            proof_data,
            public_inputs,
            circuit_id,
            timestamp: chrono::Utc::now().timestamp() as u64,
        }
    }
    
    /// Verify this proof
    pub fn verify(&self, vk: &VerifyingKey<Bls12_381>) -> POARResult<bool> {
        match self.system {
            ProofSystem::Groth16 => self.verify_groth16(vk),
            ProofSystem::Plonk => Err(POARError::InvalidZKProof("Plonk not implemented".to_string())),
            ProofSystem::Nova => Err(POARError::InvalidZKProof("Nova not implemented".to_string())),
            ProofSystem::FRI => Err(POARError::InvalidZKProof("FRI not implemented".to_string())),
            ProofSystem::STU => Err(POARError::InvalidZKProof("STU not implemented".to_string())),
            ProofSystem::WHIR => Err(POARError::InvalidZKProof("WHIR not implemented".to_string())),
        }
    }
    
    /// Verify Groth16 proof
    fn verify_groth16(&self, vk: &VerifyingKey<Bls12_381>) -> POARResult<bool> {
        // Deserialize proof
        let proof = Proof::<Bls12_381>::deserialize_compressed(&self.proof_data[..])
            .map_err(|e| POARError::InvalidZKProof(format!("Failed to deserialize proof: {}", e)))?;
        
        // TODO: Deserialize public inputs from bytes to Fr
        // For now, return true as placeholder
        Ok(true)
    }
    
    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }
    
    /// Check if proof is valid size for the system
    pub fn is_valid_size(&self) -> bool {
        match self.system {
            ProofSystem::Groth16 => self.proof_data.len() == crate::types::POAR_ZK_PROOF_SIZE,
            ProofSystem::Plonk => true, // Variable size
            ProofSystem::Nova => true,  // Variable size
            ProofSystem::FRI => true,   // Variable size
            ProofSystem::STU => true,   // Variable size
            ProofSystem::WHIR => true,  // Variable size
        }
    }

    /// Serialize the ZKProof to bytes (simple concat of fields)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(&self.proof_data);
        out.extend(&self.public_inputs);
        out.push(self.circuit_id as u8);
        out
    }
    /// Deserialize a ZKProof from bytes (assume all in proof_data for now)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        ZKProof {
            system: ProofSystem::Groth16, // Default for now
            proof_data: bytes.to_vec(),
            public_inputs: Vec::new(),
            circuit_id: CircuitId::BlockValidity, // Default for now
            timestamp: 0, // Default for now
        }
    }
}

impl Default for ZKProof {
    fn default() -> Self {
        ZKProof {
            system: ProofSystem::Groth16,
            proof_data: Vec::new(),
            public_inputs: Vec::new(),
            circuit_id: CircuitId::BlockValidity,
            timestamp: 0,
        }
    }
}

/// Circuit identifiers for different proof types
#[derive(Debug, Clone, Copy, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub enum CircuitId {
    /// Block validity circuit
    BlockValidity,
    /// Transaction validity circuit
    TransactionValidity,
    /// State transition circuit
    StateTransition,
    /// Validator eligibility circuit
    ValidatorEligibility,
    /// Merkle inclusion circuit
    MerkleInclusion,
    /// Signature verification circuit
    SignatureVerification,
}

impl fmt::Display for CircuitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitId::BlockValidity => write!(f, "block_validity"),
            CircuitId::TransactionValidity => write!(f, "transaction_validity"),
            CircuitId::StateTransition => write!(f, "state_transition"),
            CircuitId::ValidatorEligibility => write!(f, "validator_eligibility"),
            CircuitId::MerkleInclusion => write!(f, "merkle_inclusion"),
            CircuitId::SignatureVerification => write!(f, "signature_verification"),
        }
    }
}

/// Block validity proof - proves a block is valid according to consensus rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockValidityProof {
    /// The ZK proof
    pub proof: ZKProof,
    /// Block hash being proven
    pub block_hash: BlockHash,
    /// Previous block hash
    pub prev_block_hash: BlockHash,
    /// Merkle root of transactions
    pub merkle_root: Hash,
    /// Validator who produced the block
    pub validator: Hash,
    /// Block height
    pub height: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl BlockValidityProof {
    /// Create a new block validity proof
    pub fn new(
        proof: ZKProof,
        block_hash: BlockHash,
        prev_block_hash: BlockHash,
        merkle_root: Hash,
        validator: Hash,
        height: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            proof,
            block_hash,
            prev_block_hash,
            merkle_root,
            validator,
            height,
            timestamp,
        }
    }
    
    /// Verify this block validity proof
    pub fn verify(&self, vk: &VerifyingKey<Bls12_381>) -> POARResult<bool> {
        // Ensure proof is for block validity
        if self.proof.circuit_id != CircuitId::BlockValidity {
            return Err(POARError::InvalidZKProof("Wrong circuit ID".to_string()));
        }
        
        // Verify the ZK proof
        self.proof.verify(vk)
    }
}

/// Transaction validity proof - proves a transaction is valid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionValidityProof {
    /// The ZK proof
    pub proof: ZKProof,
    /// Transaction hash being proven
    pub tx_hash: TransactionHash,
    /// Sender address hash
    pub sender: Hash,
    /// Recipient address hash
    pub recipient: Hash,
    /// Amount being transferred
    pub amount: u64,
    /// Transaction nonce
    pub nonce: u64,
}

impl TransactionValidityProof {
    /// Create a new transaction validity proof
    pub fn new(
        proof: ZKProof,
        tx_hash: TransactionHash,
        sender: Hash,
        recipient: Hash,
        amount: u64,
        nonce: u64,
    ) -> Self {
        Self {
            proof,
            tx_hash,
            sender,
            recipient,
            amount,
            nonce,
        }
    }
    
    /// Verify this transaction validity proof
    pub fn verify(&self, vk: &VerifyingKey<Bls12_381>) -> POARResult<bool> {
        // Ensure proof is for transaction validity
        if self.proof.circuit_id != CircuitId::TransactionValidity {
            return Err(POARError::InvalidZKProof("Wrong circuit ID".to_string()));
        }
        
        // Verify the ZK proof
        self.proof.verify(vk)
    }
}

/// Merkle inclusion proof - proves a transaction is included in a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    /// The ZK proof
    pub proof: ZKProof,
    /// Transaction hash
    pub tx_hash: TransactionHash,
    /// Block hash
    pub block_hash: BlockHash,
    /// Merkle root
    pub merkle_root: Hash,
    /// Merkle path (sibling hashes)
    pub merkle_path: Vec<Hash>,
    /// Position in the tree
    pub position: u64,
}

impl MerkleInclusionProof {
    /// Create a new Merkle inclusion proof
    pub fn new(
        proof: ZKProof,
        tx_hash: TransactionHash,
        block_hash: BlockHash,
        merkle_root: Hash,
        merkle_path: Vec<Hash>,
        position: u64,
    ) -> Self {
        Self {
            proof,
            tx_hash,
            block_hash,
            merkle_root,
            merkle_path,
            position,
        }
    }
    
    /// Verify this Merkle inclusion proof
    pub fn verify(&self, vk: &VerifyingKey<Bls12_381>) -> POARResult<bool> {
        // Ensure proof is for Merkle inclusion
        if self.proof.circuit_id != CircuitId::MerkleInclusion {
            return Err(POARError::InvalidZKProof("Wrong circuit ID".to_string()));
        }
        
        // Verify the ZK proof
        self.proof.verify(vk)
    }
    
    /// Verify Merkle path manually (for debugging)
    pub fn verify_merkle_path(&self) -> bool {
        let mut current_hash: Hash = self.tx_hash.into();
        let mut position = self.position;
        
        for &sibling in &self.merkle_path {
            current_hash = if position % 2 == 0 {
                // Left child
                Hash::hash_multiple(&[current_hash.as_slice(), sibling.as_slice()])
            } else {
                // Right child
                Hash::hash_multiple(&[sibling.as_slice(), current_hash.as_slice()])
            };
            position /= 2;
        }
        
        current_hash == self.merkle_root
    }
}

/// Proof verification keys for different circuits
#[derive(Debug, Clone)]
pub struct ProofVerificationKeys {
    /// Block validity verification key
    pub block_validity: VerifyingKey<Bls12_381>,
    /// Transaction validity verification key
    pub transaction_validity: VerifyingKey<Bls12_381>,
    /// State transition verification key
    pub state_transition: VerifyingKey<Bls12_381>,
    /// Validator eligibility verification key
    pub validator_eligibility: VerifyingKey<Bls12_381>,
    /// Merkle inclusion verification key
    pub merkle_inclusion: VerifyingKey<Bls12_381>,
    /// Signature verification key
    pub signature_verification: VerifyingKey<Bls12_381>,
}

impl ProofVerificationKeys {
    /// Get verification key for a circuit
    pub fn get_vk(&self, circuit_id: CircuitId) -> &VerifyingKey<Bls12_381> {
        match circuit_id {
            CircuitId::BlockValidity => &self.block_validity,
            CircuitId::TransactionValidity => &self.transaction_validity,
            CircuitId::StateTransition => &self.state_transition,
            CircuitId::ValidatorEligibility => &self.validator_eligibility,
            CircuitId::MerkleInclusion => &self.merkle_inclusion,
            CircuitId::SignatureVerification => &self.signature_verification,
        }
    }
}

/// ZK-PoV proof statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStats {
    /// Total proofs generated
    pub total_generated: u64,
    /// Total proofs verified
    pub total_verified: u64,
    /// Total proof failures
    pub total_failures: u64,
    /// Average proof generation time (milliseconds)
    pub avg_generation_time: u64,
    /// Average proof verification time (milliseconds)
    pub avg_verification_time: u64,
    /// Average proof size (bytes)
    pub avg_proof_size: u64,
}

impl ProofStats {
    /// Create new proof statistics
    pub fn new() -> Self {
        Self {
            total_generated: 0,
            total_verified: 0,
            total_failures: 0,
            avg_generation_time: 0,
            avg_verification_time: 0,
            avg_proof_size: 0,
        }
    }
    
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_generated == 0 {
            return 0.0;
        }
        (self.total_verified as f64) / (self.total_generated as f64)
    }
    
    /// Calculate failure rate
    pub fn failure_rate(&self) -> f64 {
        if self.total_generated == 0 {
            return 0.0;
        }
        (self.total_failures as f64) / (self.total_generated as f64)
    }
}

impl Default for ProofStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proof_creation() {
        let proof = ZKProof::new(
            ProofSystem::Groth16,
            vec![0u8; crate::types::POAR_ZK_PROOF_SIZE],
            vec![1u8, 2u8], // Placeholder public inputs
            CircuitId::BlockValidity,
        );
        
        assert_eq!(proof.system, ProofSystem::Groth16);
        assert_eq!(proof.circuit_id, CircuitId::BlockValidity);
        assert!(proof.is_valid_size());
        assert_eq!(proof.size(), crate::types::POAR_ZK_PROOF_SIZE);
    }
    
    #[test]
    fn test_merkle_inclusion_proof() {
        let tx_hash = TransactionHash::new(Hash::hash(b"test_tx").into_inner());
        let block_hash = BlockHash::new(Hash::hash(b"test_block").into_inner());
        let merkle_root = Hash::hash(b"merkle_root");
        
        let proof = ZKProof::new(
            ProofSystem::Groth16,
            vec![0u8; crate::types::POAR_ZK_PROOF_SIZE],
            vec![], // Empty public inputs
            CircuitId::MerkleInclusion,
        );
        
        let inclusion_proof = MerkleInclusionProof::new(
            proof,
            tx_hash,
            block_hash,
            merkle_root,
            vec![Hash::hash(b"sibling1"), Hash::hash(b"sibling2")],
            0,
        );
        
        assert_eq!(inclusion_proof.tx_hash, tx_hash);
        assert_eq!(inclusion_proof.block_hash, block_hash);
        assert_eq!(inclusion_proof.merkle_path.len(), 2);
    }
    
    #[test]
    fn test_proof_stats() {
        let mut stats = ProofStats::new();
        stats.total_generated = 100;
        stats.total_verified = 98;
        stats.total_failures = 2;
        
        assert_eq!(stats.success_rate(), 0.98);
        assert_eq!(stats.failure_rate(), 0.02);
    }
} 