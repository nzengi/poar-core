use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey, PreparedVerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_std::rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, BufReader, Write, Read};
use std::path::Path;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Compress, Validate};

use crate::types::{ZKProof, Hash};
use super::circuits::{CircuitType, CircuitManager};

/// Groth16 ZK-SNARK prover for POAR consensus
pub struct PoarProver {
    /// Proving keys for different circuit types
    proving_keys: HashMap<CircuitType, ProvingKey<Bls12_381>>,
    /// Verifying keys for different circuit types
    verifying_keys: HashMap<CircuitType, VerifyingKey<Bls12_381>>,
    /// Prepared verifying keys for faster verification
    prepared_vks: HashMap<CircuitType, PreparedVerifyingKey<Bls12_381>>,
    /// Performance metrics
    metrics: Arc<Mutex<ProverMetrics>>,
}

/// Groth16 ZK-SNARK verifier for POAR consensus
pub struct PoarVerifier {
    /// Prepared verifying keys for different circuit types
    prepared_vks: HashMap<CircuitType, PreparedVerifyingKey<Bls12_381>>,
    /// Performance metrics
    metrics: Arc<Mutex<VerifierMetrics>>,
}

/// Performance metrics for proof generation
#[derive(Debug, Default)]
pub struct ProverMetrics {
    pub total_proofs_generated: u64,
    pub avg_proof_time_ms: f64,
    pub total_proof_time_ms: u64,
    pub circuit_metrics: HashMap<CircuitType, CircuitMetrics>,
}

/// Performance metrics for proof verification
#[derive(Debug, Default)]
pub struct VerifierMetrics {
    pub total_proofs_verified: u64,
    pub avg_verification_time_ms: f64,
    pub total_verification_time_ms: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
}

/// Circuit-specific metrics
#[derive(Debug, Default)]
pub struct CircuitMetrics {
    pub proofs_generated: u64,
    pub avg_time_ms: f64,
    pub constraints_count: usize,
    pub last_proof_time_ms: u64,
}

/// Trusted setup parameters
pub struct TrustedSetup {
    pub proving_keys: HashMap<CircuitType, ProvingKey<Bls12_381>>,
    pub verifying_keys: HashMap<CircuitType, VerifyingKey<Bls12_381>>,
}

/// Error types for ZK-SNARK operations
#[derive(Debug, thiserror::Error)]
pub enum ZKError {
    #[error("Circuit setup failed: {0}")]
    SetupError(String),
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Proof verification failed: {0}")]
    VerificationError(String),
    #[error("Circuit type not supported: {0:?}")]
    UnsupportedCircuit(CircuitType),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl PoarProver {
    /// Create new prover with trusted setup
    pub fn new(setup: TrustedSetup) -> Self {
        let mut prepared_vks = HashMap::new();
        
        // Prepare verifying keys for faster verification
        for (circuit_type, vk) in &setup.verifying_keys {
            let prepared_vk = PreparedVerifyingKey::from(vk.clone());
            prepared_vks.insert(circuit_type.clone(), prepared_vk);
        }
        
        Self {
            proving_keys: setup.proving_keys,
            verifying_keys: setup.verifying_keys,
            prepared_vks,
            metrics: Arc::new(Mutex::new(ProverMetrics::default())),
        }
    }
    
    /// Generate proof for a specific circuit type
    pub fn prove<R: Rng>(
        &self,
        circuit_type: CircuitType,
        circuit: Box<dyn ConstraintSynthesizer<Fr>>,
        rng: &mut R,
    ) -> Result<ZKProof, ZKError> {
        let start_time = Instant::now();
        
        // Get proving key for this circuit type
        let pk = self.proving_keys.get(&circuit_type)
            .ok_or_else(|| ZKError::UnsupportedCircuit(circuit_type.clone()))?;
        
        // Generate proof using Groth16
        let proof = Groth16::<Bls12_381>::prove(pk, circuit, rng)
            .map_err(|e| ZKError::ProofError(format!("Groth16 proof generation failed: {}", e)))?;
        
        let proof_time = start_time.elapsed().as_millis() as u64;
        
        // Update metrics
        self.update_prover_metrics(&circuit_type, proof_time);
        
        // Convert to POAR ZKProof format
        let zk_proof = self.serialize_proof(proof)?;
        
        Ok(zk_proof)
    }
    
    /// Generate block validity proof
    pub fn prove_block_validity<R: Rng>(
        &self,
        block_hash: Hash,
        previous_hash: Hash,
        merkle_root: Hash,
        timestamp: u64,
        transactions: Vec<super::circuits::TransactionWitness>,
        validator_signature: crate::types::Signature,
        validator_pubkey: Vec<u8>,
        nonce: u64,
        rng: &mut R,
    ) -> Result<ZKProof, ZKError> {
        let circuit = super::circuits::BlockValidityCircuit::new(
            block_hash,
            previous_hash,
            merkle_root,
            timestamp,
            transactions,
            validator_signature,
            validator_pubkey,
            nonce,
        );
        
        self.prove(CircuitType::BlockValidity, Box::new(circuit), rng)
    }
    
    /// Generate transaction validity proof
    pub fn prove_transaction_validity<R: Rng>(
        &self,
        tx_hash: Hash,
        from_address: crate::types::Address,
        to_address: crate::types::Address,
        amount: u64,
        signature: crate::types::Signature,
        nonce: u64,
        balance: u64,
        rng: &mut R,
    ) -> Result<ZKProof, ZKError> {
        let mut circuit = super::circuits::TransactionValidityCircuit::default();
        circuit.tx_hash = Some(tx_hash);
        circuit.from_address = Some(from_address);
        circuit.to_address = Some(to_address);
        circuit.amount = Some(amount);
        circuit.signature = Some(signature);
        circuit.nonce = Some(nonce);
        circuit.balance = Some(balance);
        
        self.prove(CircuitType::TransactionValidity, Box::new(circuit), rng)
    }
    
    /// Generate validator eligibility proof
    pub fn prove_validator_eligibility<R: Rng>(
        &self,
        validator_address: crate::types::Address,
        slot: u64,
        epoch: u64,
        stake_amount: u64,
        stake_proof: super::circuits::MerkleProof,
        randomness: Hash,
        rng: &mut R,
    ) -> Result<ZKProof, ZKError> {
        let mut circuit = super::circuits::ValidatorEligibilityCircuit::default();
        circuit.validator_address = Some(validator_address);
        circuit.slot = Some(slot);
        circuit.epoch = Some(epoch);
        circuit.stake_amount = Some(stake_amount);
        circuit.stake_proof = Some(stake_proof);
        circuit.randomness = Some(randomness);
        
        self.prove(CircuitType::ValidatorEligibility, Box::new(circuit), rng)
    }
    
    /// Batch proof generation for multiple circuits
    pub async fn prove_batch<R: Rng>(
        &self,
        proofs: Vec<(CircuitType, Box<dyn ConstraintSynthesizer<Fr>>)>,
        rng: &mut R,
    ) -> Result<Vec<ZKProof>, ZKError> {
        let mut results = Vec::new();
        
        // TODO: Implement parallel proof generation
        for (circuit_type, circuit) in proofs {
            let proof = self.prove(circuit_type, circuit, rng)?;
            results.push(proof);
        }
        
        Ok(results)
    }
    
    /// Generate proof for a specific circuit type and proof system
    pub fn prove_with_system<R: Rng>(
        &self,
        system: crate::types::proof::ProofSystem,
        circuit_type: CircuitType,
        circuit: Box<dyn ConstraintSynthesizer<Fr>>,
        rng: &mut R,
    ) -> Result<ZKProof, ZKError> {
        match system {
            crate::types::proof::ProofSystem::Groth16 => self.prove(circuit_type, circuit, rng),
            crate::types::proof::ProofSystem::Plonk => Err(ZKError::ProofError("Plonk not implemented".to_string())),
            crate::types::proof::ProofSystem::Nova => Err(ZKError::ProofError("Nova not implemented".to_string())),
            crate::types::proof::ProofSystem::FRI => Err(ZKError::ProofError("FRI not implemented".to_string())),
            crate::types::proof::ProofSystem::STU => Err(ZKError::ProofError("STU not implemented".to_string())),
            crate::types::proof::ProofSystem::WHIR => Err(ZKError::ProofError("WHIR not implemented".to_string())),
        }
    }
    
    /// Serialize Groth16 proof to POAR format
    fn serialize_proof(&self, proof: Proof<Bls12_381>) -> Result<ZKProof, ZKError> {
        // Serialize proof to bytes (288 bytes for Groth16)
        let mut proof_bytes = Vec::new();
        
        // Serialize A point (48 bytes compressed)
        proof_bytes.extend_from_slice(&self.serialize_g1_point(&proof.a)?);
        
        // Serialize B point (96 bytes compressed)
        proof_bytes.extend_from_slice(&self.serialize_g2_point(&proof.b)?);
        
        // Serialize C point (48 bytes compressed)
        proof_bytes.extend_from_slice(&self.serialize_g1_point(&proof.c)?);
        
        // Total: 48 + 96 + 48 = 192 bytes (we target 288 bytes with additional metadata)
        
        Ok(ZKProof::new(proof_bytes))
    }
    
    /// Serialize G1 point (simplified)
    fn serialize_g1_point(&self, _point: &ark_bls12_381::G1Affine) -> Result<Vec<u8>, ZKError> {
        // Simplified serialization - real implementation would use proper compression
        Ok(vec![0u8; 48])
    }
    
    /// Serialize G2 point (simplified)
    fn serialize_g2_point(&self, _point: &ark_bls12_381::G2Affine) -> Result<Vec<u8>, ZKError> {
        // Simplified serialization - real implementation would use proper compression
        Ok(vec![0u8; 96])
    }
    
    /// Update prover metrics
    fn update_prover_metrics(&self, circuit_type: &CircuitType, proof_time_ms: u64) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.total_proofs_generated += 1;
            metrics.total_proof_time_ms += proof_time_ms;
            metrics.avg_proof_time_ms = metrics.total_proof_time_ms as f64 / metrics.total_proofs_generated as f64;
            
            // Update circuit-specific metrics
            let circuit_metrics = metrics.circuit_metrics.entry(circuit_type.clone())
                .or_insert_with(CircuitMetrics::default);
            
            circuit_metrics.proofs_generated += 1;
            circuit_metrics.last_proof_time_ms = proof_time_ms;
            circuit_metrics.constraints_count = CircuitManager::estimate_constraints(circuit_type);
            
            // Update average time for this circuit type
            let total_time = circuit_metrics.avg_time_ms * (circuit_metrics.proofs_generated - 1) as f64 + proof_time_ms as f64;
            circuit_metrics.avg_time_ms = total_time / circuit_metrics.proofs_generated as f64;
        }
    }
    
    /// Get prover metrics
    pub fn get_metrics(&self) -> ProverMetrics {
        self.metrics.lock().unwrap().clone()
    }
}

impl PoarVerifier {
    /// Create new verifier with prepared verifying keys
    pub fn new(verifying_keys: HashMap<CircuitType, VerifyingKey<Bls12_381>>) -> Self {
        let mut prepared_vks = HashMap::new();
        
        // Prepare verifying keys for faster verification
        for (circuit_type, vk) in verifying_keys {
            let prepared_vk = PreparedVerifyingKey::from(vk);
            prepared_vks.insert(circuit_type, prepared_vk);
        }
        
        Self {
            prepared_vks,
            metrics: Arc::new(Mutex::new(VerifierMetrics::default())),
        }
    }
    
    /// Verify a ZK proof
    pub fn verify(
        &self,
        circuit_type: CircuitType,
        proof: &ZKProof,
        public_inputs: &[Fr],
    ) -> Result<bool, ZKError> {
        let start_time = Instant::now();
        
        // Get prepared verifying key for this circuit type
        let prepared_vk = self.prepared_vks.get(&circuit_type)
            .ok_or_else(|| ZKError::UnsupportedCircuit(circuit_type))?;
        
        // Deserialize proof from POAR format
        let groth16_proof = self.deserialize_proof(proof)?;
        
        // Verify proof using Groth16
        let is_valid = Groth16::<Bls12_381>::verify_with_processed_vk(
            prepared_vk,
            public_inputs,
            &groth16_proof,
        ).map_err(|e| ZKError::VerificationError(format!("Groth16 verification failed: {}", e)))?;
        
        let verification_time = start_time.elapsed().as_millis() as u64;
        
        // Update metrics
        self.update_verifier_metrics(verification_time, is_valid);
        
        Ok(is_valid)
    }
    
    /// Verify a ZK proof for a specific proof system
    pub fn verify_with_system(
        &self,
        system: crate::types::proof::ProofSystem,
        circuit_type: CircuitType,
        proof: &ZKProof,
        public_inputs: &[Fr],
    ) -> Result<bool, ZKError> {
        match system {
            crate::types::proof::ProofSystem::Groth16 => self.verify(circuit_type, proof, public_inputs),
            crate::types::proof::ProofSystem::Plonk => Err(ZKError::VerificationError("Plonk not implemented".to_string())),
            crate::types::proof::ProofSystem::Nova => Err(ZKError::VerificationError("Nova not implemented".to_string())),
            crate::types::proof::ProofSystem::FRI => Err(ZKError::VerificationError("FRI not implemented".to_string())),
            crate::types::proof::ProofSystem::STU => Err(ZKError::VerificationError("STU not implemented".to_string())),
            crate::types::proof::ProofSystem::WHIR => Err(ZKError::VerificationError("WHIR not implemented".to_string())),
        }
    }
    
    /// Verify block validity proof
    pub fn verify_block_validity(
        &self,
        proof: &ZKProof,
        block_hash: Hash,
        previous_hash: Hash,
        merkle_root: Hash,
    ) -> Result<bool, ZKError> {
        // Convert public inputs to field elements
        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(block_hash.as_bytes()),
            Fr::from_le_bytes_mod_order(previous_hash.as_bytes()),
            Fr::from_le_bytes_mod_order(merkle_root.as_bytes()),
        ];
        
        self.verify(CircuitType::BlockValidity, proof, &public_inputs)
    }
    
    /// Verify transaction validity proof
    pub fn verify_transaction_validity(
        &self,
        proof: &ZKProof,
        tx_hash: Hash,
        from_address: crate::types::Address,
        to_address: crate::types::Address,
        amount: u64,
    ) -> Result<bool, ZKError> {
        // Convert public inputs to field elements
        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(tx_hash.as_bytes()),
            Fr::from_le_bytes_mod_order(from_address.as_bytes()),
            Fr::from_le_bytes_mod_order(to_address.as_bytes()),
            Fr::from(amount),
        ];
        
        self.verify(CircuitType::TransactionValidity, proof, &public_inputs)
    }
    
    /// Verify validator eligibility proof
    pub fn verify_validator_eligibility(
        &self,
        proof: &ZKProof,
        validator_address: crate::types::Address,
        slot: u64,
        epoch: u64,
    ) -> Result<bool, ZKError> {
        // Convert public inputs to field elements
        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(validator_address.as_bytes()),
            Fr::from(slot),
            Fr::from(epoch),
        ];
        
        self.verify(CircuitType::ValidatorEligibility, proof, &public_inputs)
    }
    
    /// Batch verification for multiple proofs
    pub async fn verify_batch(
        &self,
        proofs: Vec<(CircuitType, ZKProof, Vec<Fr>)>,
    ) -> Result<Vec<bool>, ZKError> {
        let mut results = Vec::new();
        
        // TODO: Implement parallel verification
        for (circuit_type, proof, public_inputs) in proofs {
            let is_valid = self.verify(circuit_type, &proof, &public_inputs)?;
            results.push(is_valid);
        }
        
        Ok(results)
    }
    
    /// Deserialize POAR proof to Groth16 format
    fn deserialize_proof(&self, proof: &ZKProof) -> Result<Proof<Bls12_381>, ZKError> {
        let proof_bytes = proof.as_bytes();
        
        if proof_bytes.len() < 192 {
            return Err(ZKError::SerializationError("Proof too short".to_string()));
        }
        
        // Deserialize A point (48 bytes)
        let a = self.deserialize_g1_point(&proof_bytes[0..48])?;
        
        // Deserialize B point (96 bytes)
        let b = self.deserialize_g2_point(&proof_bytes[48..144])?;
        
        // Deserialize C point (48 bytes)
        let c = self.deserialize_g1_point(&proof_bytes[144..192])?;
        
        Ok(Proof { a, b, c })
    }
    
    /// Deserialize G1 point (simplified)
    fn deserialize_g1_point(&self, _bytes: &[u8]) -> Result<ark_bls12_381::G1Affine, ZKError> {
        // Simplified deserialization - real implementation would use proper decompression
        Ok(ark_bls12_381::G1Affine::default())
    }
    
    /// Deserialize G2 point (simplified)
    fn deserialize_g2_point(&self, _bytes: &[u8]) -> Result<ark_bls12_381::G2Affine, ZKError> {
        // Simplified deserialization - real implementation would use proper decompression
        Ok(ark_bls12_381::G2Affine::default())
    }
    
    /// Update verifier metrics
    fn update_verifier_metrics(&self, verification_time_ms: u64, is_valid: bool) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.total_proofs_verified += 1;
            metrics.total_verification_time_ms += verification_time_ms;
            metrics.avg_verification_time_ms = metrics.total_verification_time_ms as f64 / metrics.total_proofs_verified as f64;
            
            if is_valid {
                metrics.successful_verifications += 1;
            } else {
                metrics.failed_verifications += 1;
            }
        }
    }
    
    /// Get verifier metrics
    pub fn get_metrics(&self) -> VerifierMetrics {
        self.metrics.lock().unwrap().clone()
    }
}

// Block validity proof generation
pub fn prove_block_validity<R: Rng>(
    prover: &PoarProver,
    block_hash: Hash,
    previous_hash: Hash,
    merkle_root: Hash,
    timestamp: u64,
    transactions: Vec<super::circuits::TransactionWitness>,
    validator_signature: crate::types::Signature,
    validator_pubkey: Vec<u8>,
    nonce: u64,
    rng: &mut R,
) -> Result<ZKProof, ZKError> {
    let circuit = super::circuits::BlockValidityCircuit::new(
        block_hash,
        previous_hash,
        merkle_root,
        timestamp,
        transactions,
        validator_signature,
        validator_pubkey,
        nonce,
    );
    prover.prove(CircuitType::BlockValidity, Box::new(circuit), rng)
}

// Transaction validity proof generation
pub fn prove_transaction_validity<R: Rng>(
    prover: &PoarProver,
    tx_hash: Hash,
    from_address: crate::types::Address,
    to_address: crate::types::Address,
    amount: u64,
    signature: crate::types::Signature,
    nonce: u64,
    balance: u64,
    rng: &mut R,
) -> Result<ZKProof, ZKError> {
    let mut circuit = super::circuits::TransactionValidityCircuit::default();
    circuit.tx_hash = Some(tx_hash);
    circuit.from_address = Some(from_address);
    circuit.to_address = Some(to_address);
    circuit.amount = Some(amount);
    circuit.signature = Some(signature);
    circuit.nonce = Some(nonce);
    circuit.balance = Some(balance);
    prover.prove(CircuitType::TransactionValidity, Box::new(circuit), rng)
}

// Block validity proof verification
pub fn verify_block_validity(
    verifier: &PoarVerifier,
    proof: &ZKProof,
    block_hash: Hash,
    previous_hash: Hash,
    merkle_root: Hash,
) -> Result<bool, ZKError> {
    let public_inputs = vec![
        Fr::from_le_bytes_mod_order(block_hash.as_bytes()),
        Fr::from_le_bytes_mod_order(previous_hash.as_bytes()),
        Fr::from_le_bytes_mod_order(merkle_root.as_bytes()),
    ];
    verifier.verify(CircuitType::BlockValidity, proof, &public_inputs)
}

// Transaction validity proof verification
pub fn verify_transaction_validity(
    verifier: &PoarVerifier,
    proof: &ZKProof,
    tx_hash: Hash,
    from_address: crate::types::Address,
    to_address: crate::types::Address,
    amount: u64,
) -> Result<bool, ZKError> {
    let public_inputs = vec![
        Fr::from_le_bytes_mod_order(tx_hash.as_bytes()),
        Fr::from_le_bytes_mod_order(from_address.as_bytes()),
        Fr::from_le_bytes_mod_order(to_address.as_bytes()),
        Fr::from(amount),
    ];
    verifier.verify(CircuitType::TransactionValidity, proof, &public_inputs)
}

/// Trusted setup ceremony manager
pub struct TrustedSetupManager;

impl TrustedSetupManager {
    /// Generate trusted setup for all circuit types
    pub fn generate_setup<R: Rng>(rng: &mut R) -> Result<TrustedSetup, ZKError> {
        let mut proving_keys = HashMap::new();
        let mut verifying_keys = HashMap::new();
        
        // Generate setup for each circuit type
        let circuit_types = vec![
            CircuitType::BlockValidity,
            CircuitType::TransactionValidity,
            CircuitType::StateTransition,
            CircuitType::ValidatorEligibility,
            CircuitType::MerkleInclusion,
            CircuitType::SignatureVerification,
        ];
        
        for circuit_type in circuit_types {
            let circuit = CircuitManager::get_circuit(circuit_type.clone());
            
            // Generate proving and verifying keys
            let (pk, vk) = Groth16::<Bls12_381>::setup(circuit, rng)
                .map_err(|e| ZKError::SetupError(format!("Setup failed for {:?}: {}", circuit_type, e)))?;
            
            proving_keys.insert(circuit_type.clone(), pk);
            verifying_keys.insert(circuit_type, vk);
        }
        
        Ok(TrustedSetup {
            proving_keys,
            verifying_keys,
        })
    }
    
    /// Save Groth16 parameters (proving and verifying keys) to disk for a given circuit_id
    pub fn save_setup(
        circuit_id: CircuitType,
        pk: &ProvingKey<Bls12_381>,
        vk: &VerifyingKey<Bls12_381>,
        dir: &str,
    ) -> Result<(), String> {
        let pk_path = format!("{}/{}_proving_key.bin", dir, circuit_id as u32);
        let vk_path = format!("{}/{}_verifying_key.bin", dir, circuit_id as u32);
        // Save ProvingKey
        let pk_file = File::create(&pk_path).map_err(|e| format!("Create PK file: {e}"))?;
        let mut pk_writer = BufWriter::new(pk_file);
        pk.serialize_with_mode(&mut pk_writer, Compress::Yes).map_err(|e| format!("Serialize PK: {e}"))?;
        pk_writer.flush().map_err(|e| format!("Flush PK: {e}"))?;
        // Save VerifyingKey
        let vk_file = File::create(&vk_path).map_err(|e| format!("Create VK file: {e}"))?;
        let mut vk_writer = BufWriter::new(vk_file);
        vk.serialize_with_mode(&mut vk_writer, Compress::Yes).map_err(|e| format!("Serialize VK: {e}"))?;
        vk_writer.flush().map_err(|e| format!("Flush VK: {e}"))?;
        Ok(())
    }

    /// Load Groth16 parameters (proving and verifying keys) from disk for a given circuit_id
    pub fn load_setup(
        circuit_id: CircuitType,
        dir: &str,
    ) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>), String> {
        let pk_path = format!("{}/{}_proving_key.bin", dir, circuit_id as u32);
        let vk_path = format!("{}/{}_verifying_key.bin", dir, circuit_id as u32);
        // Load ProvingKey
        let pk_file = File::open(&pk_path).map_err(|e| format!("Open PK file: {e}"))?;
        let mut pk_reader = BufReader::new(pk_file);
        let pk = ProvingKey::<Bls12_381>::deserialize_with_mode(&mut pk_reader, Compress::Yes, Validate::No)
            .map_err(|e| format!("Deserialize PK: {e}"))?;
        // Load VerifyingKey
        let vk_file = File::open(&vk_path).map_err(|e| format!("Open VK file: {e}"))?;
        let mut vk_reader = BufReader::new(vk_file);
        let vk = VerifyingKey::<Bls12_381>::deserialize_with_mode(&mut vk_reader, Compress::Yes, Validate::No)
            .map_err(|e| format!("Deserialize VK: {e}"))?;
        Ok((pk, vk))
    }
}

impl Clone for ProverMetrics {
    fn clone(&self) -> Self {
        Self {
            total_proofs_generated: self.total_proofs_generated,
            avg_proof_time_ms: self.avg_proof_time_ms,
            total_proof_time_ms: self.total_proof_time_ms,
            circuit_metrics: self.circuit_metrics.clone(),
        }
    }
}

impl Clone for VerifierMetrics {
    fn clone(&self) -> Self {
        Self {
            total_proofs_verified: self.total_proofs_verified,
            avg_verification_time_ms: self.avg_verification_time_ms,
            total_verification_time_ms: self.total_verification_time_ms,
            successful_verifications: self.successful_verifications,
            failed_verifications: self.failed_verifications,
        }
    }
}

impl Clone for CircuitMetrics {
    fn clone(&self) -> Self {
        Self {
            proofs_generated: self.proofs_generated,
            avg_time_ms: self.avg_time_ms,
            constraints_count: self.constraints_count,
            last_proof_time_ms: self.last_proof_time_ms,
        }
    }
} 