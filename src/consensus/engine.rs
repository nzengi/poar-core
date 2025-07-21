use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, RwLock};
use ark_std::rand::thread_rng;

use crate::types::{Hash, Address, Block, BlockHeader, Transaction, Validator, ZKProof, Signature, Poar, Proof, Valid, Zero, TokenUnit};
use crate::crypto::{ZKPoVPoseidon, PoseidonHash};
use super::circuits::{CircuitType, TransactionWitness, OptimizedCircuitType, CircuitOptimizer, OptimizationConfig};
use super::zksnark::{PoarProver, PoarVerifier, TrustedSetup, TrustedSetupManager};

/// ZK-PoV Consensus Engine for POAR blockchain
pub struct ConsensusEngine {
    /// Current blockchain state
    state: Arc<RwLock<ConsensusState>>,
    /// ZK proof prover
    prover: Arc<PoarProver>,
    /// ZK proof verifier
    verifier: Arc<PoarVerifier>,
    /// Poseidon hash for ZK-PoV
    poseidon: ZKPoVPoseidon,
    /// Circuit optimizer for performance
    circuit_optimizer: CircuitOptimizer,
    /// Validator registry
    validators: Arc<RwLock<ValidatorRegistry>>,
    /// Block proposal queue
    proposal_queue: Arc<Mutex<VecDeque<BlockProposal>>>,
    /// Consensus configuration
    config: ConsensusConfig,
    /// Event broadcasting
    event_sender: broadcast::Sender<ConsensusEvent>,
    /// Consensus metrics
    metrics: Arc<Mutex<ConsensusMetrics>>,
}

/// Current consensus state
#[derive(Debug, Clone)]
pub struct ConsensusState {
    pub latest_block: Option<Block>,
    pub latest_block_hash: Hash,
    pub latest_block_height: u64,
    pub current_epoch: u64,
    pub current_slot: u64,
    pub finalized_height: u64,
    pub pending_transactions: Vec<Transaction>,
    pub validator_set: Vec<Validator>,
}

/// Validator registry for consensus
#[derive(Debug, Default)]
pub struct ValidatorRegistry {
    pub active_validators: HashMap<Address, ValidatorInfo>,
    pub total_stake: u64,
    pub epoch_assignments: HashMap<u64, Vec<Address>>,
    pub slashed_validators: HashMap<Address, SlashingInfo>,
}

/// Validator information
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake: u64,
    pub public_key: Vec<u8>,
    pub status: ValidatorStatus,
    pub performance: ValidatorPerformance,
    pub last_proposal_slot: Option<u64>,
}

/// Validator status
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Slashed,
    Exiting,
}

/// Validator performance tracking
#[derive(Debug, Clone, Default)]
pub struct ValidatorPerformance {
    pub blocks_proposed: u64,
    pub blocks_validated: u64,
    pub slash_count: u64,
    pub reward_earned: u64,
    pub uptime_percentage: f64,
}

/// Slashing information
#[derive(Debug, Clone)]
pub struct SlashingInfo {
    pub reason: SlashingReason,
    pub amount_slashed: u64,
    pub timestamp: u64,
    pub evidence: Vec<u8>,
}

/// Slashing reasons
#[derive(Debug, Clone)]
pub enum SlashingReason {
    DoubleProposal,
    InvalidProof,
    Unavailability,
    MaliciousBehavior,
}

/// Block proposal
#[derive(Debug, Clone)]
pub struct BlockProposal {
    pub proposer: Address,
    pub block: Block,
    pub zk_proof: ZKProof,
    pub timestamp: u64,
    pub slot: u64,
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    pub chain_id: u64,
    pub block_time: Duration,
    pub finality_time: Duration,
    pub max_block_size: usize,
    pub max_transactions_per_block: usize,
    pub min_validator_stake: u64, // in ZERO units
    pub slash_percentage: u8,
    pub reward_per_block: u64, // in PROOF units
    pub epoch_length: u64,
    pub slots_per_epoch: u64,
}

/// Consensus events
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    BlockProposed(BlockProposal),
    BlockFinalized(Block),
    ValidatorSlashed(Address, SlashingReason),
    EpochTransition(u64),
    ConsensusFailure(String),
}

/// Consensus metrics
#[derive(Debug, Default)]
pub struct ConsensusMetrics {
    pub blocks_processed: u64,
    pub average_block_time: f64,
    pub average_finality_time: f64,
    pub failed_proposals: u64,
    pub total_validators: u64,
    pub total_stake: u64,
    pub network_participation: f64,
}

impl ConsensusEngine {
    /// Create new consensus engine
    pub fn new() -> Self {
        // Generate trusted setup (in production, this would be loaded)
        let mut rng = thread_rng();
        let setup = TrustedSetupManager::generate_setup(&mut rng)
            .expect("Failed to generate trusted setup");
        
        let prover = Arc::new(PoarProver::new(setup.clone()));
        let verifier = Arc::new(PoarVerifier::new(setup.verifying_keys));
        
        let (event_sender, _) = broadcast::channel(1000);
        
        let config = ConsensusConfig {
            chain_id: 2025,
            block_time: Duration::from_secs(5),
            finality_time: Duration::from_millis(2400),
            max_block_size: 1024 * 1024, // 1MB
            max_transactions_per_block: 10000,
            min_validator_stake: 32 * ZERO_PER_POAR, // 32 POAR minimum stake
            slash_percentage: 5,
            reward_per_block: 100, // 100 PROOF per block
            epoch_length: 32,
            slots_per_epoch: 32,
        };
        
        Self {
            state: Arc::new(RwLock::new(ConsensusState::default())),
            prover,
            verifier,
            poseidon: ZKPoVPoseidon::new(),
            circuit_optimizer: CircuitOptimizer::new(OptimizationConfig::default()),
            validators: Arc::new(RwLock::new(ValidatorRegistry::default())),
            proposal_queue: Arc::new(Mutex::new(VecDeque::new())),
            config,
            event_sender,
            metrics: Arc::new(Mutex::new(ConsensusMetrics::default())),
        }
    }
    
    /// Start the consensus engine
    pub async fn start(&mut self) -> Result<(), ConsensusError> {
        println!("🚀 Starting POAR ZK-PoV Consensus Engine...");
        
        // Initialize genesis block if needed
        self.initialize_genesis().await?;
        
        // Start consensus rounds
        self.start_consensus_rounds().await?;
        
        Ok(())
    }
    
    /// Initialize genesis block
    async fn initialize_genesis(&self) -> Result<(), ConsensusError> {
        let state = self.state.read().await;
        
        if state.latest_block.is_some() {
            return Ok(()); // Already initialized
        }
        
        drop(state);
        
        // Create genesis block
        let genesis_hash = Hash::hash(b"POAR_GENESIS_2025");
        let genesis_block = Block {
            header: BlockHeader {
                hash: genesis_hash,
                previous_hash: Hash::zero(),
                merkle_root: Hash::zero(),
                state_root: Hash::zero(),
                height: 0,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                validator: Address::zero(),
                signature: Signature::default(),
                zk_proof: ZKProof::default(),
                nonce: 0,
            },
            transactions: Vec::new(),
        };
        
        let mut state = self.state.write().await;
        state.latest_block = Some(genesis_block);
        state.latest_block_hash = genesis_hash;
        state.latest_block_height = 0;
        state.finalized_height = 0;
        
        println!("✅ Genesis block initialized: {}", genesis_hash);
        Ok(())
    }
    
    /// Start consensus rounds
    async fn start_consensus_rounds(&self) -> Result<(), ConsensusError> {
        let mut slot_timer = tokio::time::interval(self.config.block_time);
        
        loop {
            slot_timer.tick().await;
            
            if let Err(e) = self.process_consensus_round().await {
                eprintln!("❌ Consensus round failed: {}", e);
                let _ = self.event_sender.send(ConsensusEvent::ConsensusFailure(e.to_string()));
            }
        }
    }
    
    /// Process a single consensus round
    async fn process_consensus_round(&self) -> Result<(), ConsensusError> {
        let start_time = Instant::now();
        let state = self.state.read().await;
        let current_slot = state.current_slot + 1;
        let current_epoch = current_slot / self.config.slots_per_epoch;
        
        drop(state);
        
        // Select validator for this slot
        let proposer = self.select_proposer(current_slot, current_epoch).await?;
        
        // If we are the proposer, create and propose a block
        if self.is_local_validator(&proposer).await? {
            self.propose_block(proposer, current_slot).await?;
        }
        
        // Process any pending proposals
        self.process_pending_proposals().await?;
        
        // Update slot and epoch
        let mut state = self.state.write().await;
        state.current_slot = current_slot;
        state.current_epoch = current_epoch;
        
        // Check for epoch transition
        if current_slot % self.config.slots_per_epoch == 0 {
            drop(state);
            self.process_epoch_transition(current_epoch).await?;
        }
        
        // Update metrics
        self.update_consensus_metrics(start_time.elapsed()).await;
        
        Ok(())
    }
    
    /// Select validator for block proposal
    async fn select_proposer(&self, slot: u64, epoch: u64) -> Result<Address, ConsensusError> {
        let validators = self.validators.read().await;
        let epoch_validators = validators.epoch_assignments.get(&epoch)
            .ok_or(ConsensusError::NoValidatorsForEpoch)?;
        
        if epoch_validators.is_empty() {
            return Err(ConsensusError::NoActiveValidators);
        }
        
        // Simple round-robin selection based on slot
        let proposer_index = (slot % epoch_validators.len() as u64) as usize;
        Ok(epoch_validators[proposer_index])
    }
    
    /// Check if we control the validator
    async fn is_local_validator(&self, _validator: &Address) -> Result<bool, ConsensusError> {
        // TODO: Implement validator key management
        Ok(true) // For now, assume we are always the proposer
    }
    
    /// Propose a new block
    async fn propose_block(&self, proposer: Address, slot: u64) -> Result<(), ConsensusError> {
        let state = self.state.read().await;
        let pending_txs = state.pending_transactions.clone();
        let latest_block = state.latest_block.clone();
        let latest_height = state.latest_block_height;
        
        drop(state);
        
        // Select transactions for the block
        let selected_txs = self.select_transactions(pending_txs).await?;
        
        // Build the block
        let block = self.build_block(proposer, slot, latest_height + 1, selected_txs, latest_block).await?;
        
        // Generate ZK proof for block validity
        let proof = self.generate_block_proof(&block).await?;
        
        // Create block proposal
        let proposal = BlockProposal {
            proposer,
            block: block.clone(),
            zk_proof: proof,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            slot,
        };
        
        // Add to proposal queue
        self.proposal_queue.lock().unwrap().push_back(proposal.clone());
        
        // Broadcast proposal
        let _ = self.event_sender.send(ConsensusEvent::BlockProposed(proposal));
        
        println!("📦 Block proposed: height={}, proposer={}", latest_height + 1, proposer);
        
        Ok(())
    }
    
    /// Select transactions for inclusion in block
    async fn select_transactions(&self, mut pending_txs: Vec<Transaction>) -> Result<Vec<Transaction>, ConsensusError> {
        // Sort by fee (highest first)
        pending_txs.sort_by(|a, b| b.amount.cmp(&a.amount)); // Simplified fee sorting
        
        // Take up to max transactions per block
        pending_txs.truncate(self.config.max_transactions_per_block);
        
        Ok(pending_txs)
    }
    
    /// Build a new block
    async fn build_block(
        &self,
        proposer: Address,
        slot: u64,
        height: u64,
        transactions: Vec<Transaction>,
        previous_block: Option<Block>,
    ) -> Result<Block, ConsensusError> {
        let previous_hash = previous_block
            .map(|b| b.header.hash)
            .unwrap_or_else(Hash::zero);
        
        // Calculate Merkle root of transactions
        let merkle_root = self.calculate_merkle_root(&transactions);
        
        // Calculate state root (simplified)
        let state_root = Hash::hash(b"state_root_placeholder");
        
        let block_header = BlockHeader {
            hash: Hash::zero(), // Will be calculated after signing
            previous_hash,
            merkle_root,
            state_root,
            height,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            validator: proposer,
            signature: Signature::default(), // Will be signed
            zk_proof: ZKProof::default(), // Will be generated
            nonce: 0,
        };
        
        let block = Block {
            header: block_header,
            transactions,
        };
        
        Ok(block)
    }
    
    /// Generate optimized ZK proof for block validity
    async fn generate_block_proof(&self, block: &Block) -> Result<ZKProof, ConsensusError> {
        let start_time = std::time::Instant::now();
        
        // Create optimized block validity circuit
        let optimized_circuit = self.circuit_optimizer.optimize_circuit(
            OptimizedCircuitType::BlockValidityOptimized
        ).map_err(|e| ConsensusError::ProofGenerationFailed(e.to_string()))?;
        
        // Convert transactions to batch witnesses
        let batch_transactions: Vec<super::circuits::BatchTransactionWitness> = block.transactions.iter()
            .enumerate()
            .map(|(i, tx)| {
                super::circuits::BatchTransactionWitness {
                    from: tx.from,
                    to: tx.to,
                    amount: tx.amount,
                    signature: tx.signature.clone(),
                    nonce: tx.nonce,
                    batch_index: i as u32,
                }
            })
            .collect();
        
        // Generate optimized proof using optimized circuit
        let mut rng = ark_std::rand::thread_rng();
        
        let proof = match optimized_circuit {
            super::circuits::OptimizedCircuit::BlockValidity(opt_circuit) => {
                self.prover.prove(
                    super::circuits::OptimizedCircuitType::BlockValidityOptimized,
                    Box::new(opt_circuit),
                    &mut rng,
                ).map_err(|e| ConsensusError::ProofGenerationFailed(e.to_string()))?
            }
            _ => return Err(ConsensusError::ProofGenerationFailed("Invalid circuit type".to_string())),
        };
        
        // Update performance metrics
        let proof_time = start_time.elapsed();
        println!("⚡ Optimized proof generated in {:?}", proof_time);
        
        Ok(proof)
    }
    
    /// Generate parallel proofs for multiple blocks
    async fn generate_parallel_proofs(&self, blocks: &[Block]) -> Result<Vec<ZKProof>, ConsensusError> {
        let start_time = std::time::Instant::now();
        
        // Create parallel proof generation tasks
        let proof_tasks: Vec<_> = blocks.iter().map(|block| {
            let block_clone = block.clone();
            let optimizer_clone = self.circuit_optimizer.clone();
            let prover_clone = self.prover.clone();
            
            tokio::spawn(async move {
                // Create optimized circuit for this block
                let optimized_circuit = optimizer_clone.optimize_circuit(
                    OptimizedCircuitType::BlockValidityOptimized
                ).map_err(|e| ConsensusError::ProofGenerationFailed(e.to_string()))?;
                
                // Convert transactions to batch witnesses
                let batch_transactions: Vec<super::circuits::BatchTransactionWitness> = block_clone.transactions.iter()
                    .enumerate()
                    .map(|(i, tx)| {
                        super::circuits::BatchTransactionWitness {
                            from: tx.from,
                            to: tx.to,
                            amount: tx.amount,
                            signature: tx.signature.clone(),
                            nonce: tx.nonce,
                            batch_index: i as u32,
                        }
                    })
                    .collect();
                
                // Generate proof
                let mut rng = ark_std::rand::thread_rng();
                
                match optimized_circuit {
                    super::circuits::OptimizedCircuit::BlockValidity(opt_circuit) => {
                        prover_clone.prove(
                            OptimizedCircuitType::BlockValidityOptimized,
                            Box::new(opt_circuit),
                            &mut rng,
                        ).map_err(|e| ConsensusError::ProofGenerationFailed(e.to_string()))
                    }
                    _ => Err(ConsensusError::ProofGenerationFailed("Invalid circuit type".to_string())),
                }
            })
        }).collect();
        
        // Wait for all proofs to complete
        let proof_results = futures::future::join_all(proof_tasks).await;
        
        // Collect successful proofs
        let mut proofs = Vec::new();
        for result in proof_results {
            match result {
                Ok(proof_result) => {
                    match proof_result {
                        Ok(proof) => proofs.push(proof),
                        Err(e) => {
                            eprintln!("❌ Parallel proof generation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Parallel task failed: {}", e);
                }
            }
        }
        
        let total_time = start_time.elapsed();
        println!("⚡ Generated {} parallel proofs in {:?}", proofs.len(), total_time);
        
        Ok(proofs)
    }
    
    /// Process pending block proposals
    async fn process_pending_proposals(&self) -> Result<(), ConsensusError> {
        let mut queue = self.proposal_queue.lock().unwrap();
        let proposals: Vec<_> = queue.drain(..).collect();
        drop(queue);
        
        for proposal in proposals {
            if let Err(e) = self.validate_and_finalize_block(proposal).await {
                eprintln!("❌ Block validation failed: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Validate and finalize a block proposal
    async fn validate_and_finalize_block(&self, proposal: BlockProposal) -> Result<(), ConsensusError> {
        // Verify ZK proof
        let is_valid = self.verifier.verify_block_validity(
            &proposal.zk_proof,
            proposal.block.header.hash,
            proposal.block.header.previous_hash,
            proposal.block.header.merkle_root,
        ).map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;
        
        if !is_valid {
            return Err(ConsensusError::InvalidProof);
        }
        
        // Additional validation checks
        self.validate_block_structure(&proposal.block).await?;
        self.validate_proposer_eligibility(&proposal.proposer, proposal.slot).await?;
        
        // Finalize the block
        self.finalize_block(proposal.block).await?;
        
        Ok(())
    }
    
    /// Validate block structure
    async fn validate_block_structure(&self, block: &Block) -> Result<(), ConsensusError> {
        // Check block size
        let block_size = bincode::serialize(block).unwrap().len();
        if block_size > self.config.max_block_size {
            return Err(ConsensusError::BlockTooLarge);
        }
        
        // Check transaction count
        if block.transactions.len() > self.config.max_transactions_per_block {
            return Err(ConsensusError::TooManyTransactions);
        }
        
        // Validate transactions
        for tx in &block.transactions {
            self.validate_transaction(tx).await?;
        }
        
        Ok(())
    }
    
    /// Validate proposer eligibility
    async fn validate_proposer_eligibility(&self, proposer: &Address, slot: u64) -> Result<(), ConsensusError> {
        let validators = self.validators.read().await;
        let validator_info = validators.active_validators.get(proposer)
            .ok_or(ConsensusError::ValidatorNotFound)?;
        
        // Check if validator is active
        if validator_info.status != ValidatorStatus::Active {
            return Err(ConsensusError::ValidatorNotActive);
        }
        
        // Check minimum stake
        if validator_info.stake < self.config.min_validator_stake {
            return Err(ConsensusError::InsufficientStake);
        }
        
        // TODO: Verify validator was selected for this slot using VRF
        
        Ok(())
    }
    
    /// Validate a single transaction
    async fn validate_transaction(&self, _tx: &Transaction) -> Result<(), ConsensusError> {
        // TODO: Implement transaction validation
        // - Signature verification
        // - Balance checks
        // - Nonce verification
        // - Gas limits
        Ok(())
    }
    
    /// Finalize a block
    async fn finalize_block(&self, block: Block) -> Result<(), ConsensusError> {
        let mut state = self.state.write().await;
        
        // Update blockchain state
        state.latest_block = Some(block.clone());
        state.latest_block_hash = block.header.hash;
        state.latest_block_height = block.header.height;
        
        // Remove included transactions from pending
        for tx in &block.transactions {
            state.pending_transactions.retain(|pending_tx| pending_tx.hash != tx.hash);
        }
        
        drop(state);
        
        // Emit finalization event
        let _ = self.event_sender.send(ConsensusEvent::BlockFinalized(block.clone()));
        
        println!("✅ Block finalized: height={}, hash={}", block.header.height, block.header.hash);
        
        // Apply finality (2.4 second target)
        tokio::time::sleep(self.config.finality_time).await;
        
        let mut state = self.state.write().await;
        state.finalized_height = block.header.height;
        
        Ok(())
    }
    
    /// Process epoch transition
    async fn process_epoch_transition(&self, new_epoch: u64) -> Result<(), ConsensusError> {
        println!("🔄 Epoch transition: {}", new_epoch);
        
        // Update validator assignments for new epoch
        self.update_validator_assignments(new_epoch).await?;
        
        // Distribute rewards
        self.distribute_rewards(new_epoch - 1).await?;
        
        // Process slashing
        self.process_slashing().await?;
        
        // Emit epoch transition event
        let _ = self.event_sender.send(ConsensusEvent::EpochTransition(new_epoch));
        
        Ok(())
    }
    
    /// Update validator assignments for epoch
    async fn update_validator_assignments(&self, epoch: u64) -> Result<(), ConsensusError> {
        let mut validators = self.validators.write().await;
        
        // Get active validators
        let active_validators: Vec<Address> = validators.active_validators
            .iter()
            .filter(|(_, info)| info.status == ValidatorStatus::Active)
            .map(|(addr, _)| *addr)
            .collect();
        
        validators.epoch_assignments.insert(epoch, active_validators);
        
        Ok(())
    }
    
    /// Distribute rewards to validators
    async fn distribute_rewards(&self, _epoch: u64) -> Result<(), ConsensusError> {
        // TODO: Implement reward distribution based on performance
        Ok(())
    }
    
    /// Process validator slashing
    async fn process_slashing(&self) -> Result<(), ConsensusError> {
        // TODO: Implement slashing logic for malicious behavior
        Ok(())
    }
    
    /// Calculate Merkle root of transactions using Poseidon hash
    fn calculate_merkle_root(&self, transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::zero();
        }
        
        // Convert transaction hashes to field elements for Poseidon
        let tx_hashes: Vec<ark_bls12_381::Fr> = transactions.iter()
            .map(|tx| {
                // Convert transaction hash to field element
                let hash_bytes = tx.hash.as_bytes();
                ark_bls12_381::Fr::from_le_bytes_mod_order(hash_bytes)
            })
            .collect();
        
        // Use Poseidon to generate Merkle root
        let poseidon_root = self.poseidon.transaction_merkle_root(&tx_hashes);
        
        // Convert back to Hash type
        Hash::from_field_element(poseidon_root)
    }
    
    /// Update consensus metrics
    async fn update_consensus_metrics(&self, round_duration: Duration) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.blocks_processed += 1;
            
            let round_ms = round_duration.as_millis() as f64;
            metrics.average_block_time = (metrics.average_block_time * (metrics.blocks_processed - 1) as f64 + round_ms) / metrics.blocks_processed as f64;
        }
    }
    
    /// Get consensus metrics
    pub fn get_metrics(&self) -> ConsensusMetrics {
        self.metrics.lock().unwrap().clone()
    }
    
    /// Add validator to registry
    pub async fn register_validator(&self, validator_info: ValidatorInfo) -> Result<(), ConsensusError> {
        let mut validators = self.validators.write().await;
        validators.active_validators.insert(validator_info.address, validator_info);
        Ok(())
    }
    
    /// Add transaction to pending pool
    pub async fn add_transaction(&self, transaction: Transaction) -> Result<(), ConsensusError> {
        let mut state = self.state.write().await;
        state.pending_transactions.push(transaction);
        Ok(())
    }
    
    /// Get circuit optimization metrics
    pub fn get_circuit_metrics(&self) -> &super::circuits::OptimizationMetrics {
        self.circuit_optimizer.get_metrics()
    }
    
    /// Print performance comparison
    pub fn print_performance_comparison(&self) {
        let metrics = self.circuit_optimizer.get_metrics();
        
        println!("⚡ Circuit Optimization Performance:");
        println!("   Original constraints: {}", metrics.original_constraints);
        println!("   Optimized constraints: {}", metrics.optimized_constraints);
        println!("   Constraint reduction: {:.1}%", metrics.constraint_reduction_percentage);
        println!("   Proof generation time: {}ms", metrics.proof_generation_time_ms);
        println!("   Memory usage: {:.2}MB", metrics.memory_usage_mb);
        println!("   Batch efficiency: {:.1}%", metrics.batch_efficiency);
        
        // Calculate performance improvements
        let constraint_improvement = if metrics.original_constraints > 0 {
            (metrics.original_constraints as f64 / metrics.optimized_constraints as f64) * 100.0
        } else {
            0.0
        };
        
        println!("   🚀 Performance Improvements:");
        println!("      Constraint reduction: {:.1}x", constraint_improvement / 100.0);
        println!("      Memory efficiency: {:.1}x", 100.0 / metrics.memory_usage_mb.max(1.0));
        println!("      Batch processing: {:.1}x", metrics.batch_efficiency / 100.0);
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            latest_block: None,
            latest_block_hash: Hash::zero(),
            latest_block_height: 0,
            current_epoch: 0,
            current_slot: 0,
            finalized_height: 0,
            pending_transactions: Vec::new(),
            validator_set: Vec::new(),
        }
    }
}

/// Consensus error types
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("No validators for epoch")]
    NoValidatorsForEpoch,
    #[error("No active validators")]
    NoActiveValidators,
    #[error("Validator not found")]
    ValidatorNotFound,
    #[error("Validator not active")]
    ValidatorNotActive,
    #[error("Insufficient stake")]
    InsufficientStake,
    #[error("Block too large")]
    BlockTooLarge,
    #[error("Too many transactions")]
    TooManyTransactions,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
    #[error("State error: {0}")]
    StateError(String),
}
