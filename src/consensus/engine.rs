use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, RwLock};
use ark_std::rand::thread_rng;
use log::{error, warn};
use tokio::time::{sleep, Duration};
use tokio::task;
use serde::{Serialize, Deserialize};

use crate::types::{Hash, Address, Block, BlockHeader, Transaction, Validator, ZKProof, Signature, Poar, Proof, Valid, Zero, TokenUnit};
use crate::crypto::{ZKPoVPoseidon, PoseidonHash};
use super::circuits::{CircuitType, TransactionWitness, OptimizedCircuitType, CircuitOptimizer, OptimizationConfig};
use super::zksnark::{PoarProver, PoarVerifier, TrustedSetup, TrustedSetupManager};
use crate::crypto::poseidon_hash;
use crate::crypto::verify_signature;
use crate::types::token::{
    INITIAL_SUPPLY, MAX_SUPPLY, MIN_SUPPLY, BASE_REWARD, DECAY_FACTOR, BURN_RATIO,
    MIN_VALIDATOR_STAKE, EARLY_ADOPTER_BONUS, EARLY_ADOPTER_BONUS_EPOCHS,
    LOW_STAKE_BONUS, HIGH_STAKE_PENALTY,
    FEE_MINIMUM, FEE_TRANSFER_MIN, FEE_TRANSFER_MAX, VALIDATOR_STAKE_CAP, UNSTAKE_BONUS
};

use prometheus::{IntCounter, IntGauge, Encoder, TextEncoder, register_int_counter, register_int_gauge};
use std::collections::HashSet;
use crate::storage::state::GlobalState;
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;
use crate::storage::persistence::PersistentStorage;
use crate::network::network_manager::NetworkManager;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref BLOCKS_PROCESSED: IntCounter = register_int_counter!("blocks_processed", "Blocks processed by consensus engine").unwrap();
    static ref FAILED_PROPOSALS: IntCounter = register_int_counter!("failed_proposals", "Failed block proposals").unwrap();
    static ref AVERAGE_BLOCK_TIME: IntGauge = register_int_gauge!("average_block_time", "Average block time (ms)").unwrap();
}

/// The main consensus engine for the POAR blockchain.
///
/// Manages block production, validator registry, ZK proof integration, pending transactions,
/// consensus state, event broadcasting, and performance metrics. All consensus logic flows through this struct.
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
    /// Local validator keys (addresses for which this node has the private key)
    local_validator_keys: Arc<HashSet<Address>>,
    global_state: Arc<TokioRwLock<GlobalState>>, // Account state erişimi için
    storage: Arc<PersistentStorage>, // Persistent storage for consensus state
    pub chain_manager: ChainManager,
    pub network_manager: Option<Arc<Mutex<NetworkManager>>>, // NetworkManager erişimi için
    pub proposals: Vec<GovernanceProposal>,
    pub parameters: ParameterRegistry,
    pub emergency_halt: bool,
}

/// Represents the current state of the blockchain consensus.
///
/// Tracks the latest block, block hash, block height, epoch/slot, finalized height,
/// pending transactions, and the current validator set.
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
    pub total_supply: u64, // POAR total supply (in ZERO units)
}

/// On-chain slashing evidence
#[derive(Debug, Clone)]
pub struct SlashingEvidence {
    pub reason: SlashingReason,
    pub evidence_data: Vec<u8>,
    pub reported_by: Address,
    pub timestamp: u64,
}

const CHALLENGE_WINDOW_SLOTS: u64 = 32; // Example: 32 slot challenge window
const MAX_PENDING_TX: usize = 10_000; // Maximum number of pending transactions
const TX_MAX_AGE: u64 = 10; // Maximum age (in slots) for a transaction to stay in the pool

/// Registry of all validators participating in consensus.
///
/// Tracks active validators, total stake, epoch assignments, slashed validators,
/// on-chain slashing evidence, and challenge deadlines.
#[derive(Debug, Default)]
pub struct ValidatorRegistry {
    pub active_validators: HashMap<Address, ValidatorInfo>,
    pub total_stake: u64,
    pub epoch_assignments: HashMap<u64, Vec<Address>>,
    pub slashed_validators: HashMap<Address, SlashingInfo>,
    pub slashing_evidence: HashMap<Address, SlashingEvidence>, // New: evidence for each slashed validator
    pub challenge_deadlines: HashMap<Address, u64>, // New: slot until which challenge is allowed
}

/// Information about a single validator, including stake, public key, status, and performance.
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub address: Address,
    pub stake: u64,
    pub public_key: Vec<u8>,
    pub status: ValidatorStatus,
    pub performance: ValidatorPerformance,
    pub last_proposal_slot: Option<u64>,
}

/// The status of a validator in the registry.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidatorStatus {
    /// Validator is actively participating in consensus.
    Active,
    /// Validator is not currently participating.
    Inactive,
    /// Validator has been slashed for misbehavior.
    Slashed,
    /// Validator is in the process of exiting.
    Exiting,
}

/// Tracks performance statistics for a validator.
#[derive(Debug, Clone, Default)]
pub struct ValidatorPerformance {
    pub blocks_proposed: u64,
    pub blocks_validated: u64,
    pub slash_count: u64,
    pub reward_earned: u64,
    pub uptime_percentage: f64,
}

/// Information about a slashing event for a validator.
#[derive(Debug, Clone)]
pub struct SlashingInfo {
    pub reason: SlashingReason,
    pub amount_slashed: u64,
    pub timestamp: u64,
    pub evidence: Vec<u8>,
}

/// The reason for a validator being slashed.
#[derive(Debug, Clone)]
pub enum SlashingReason {
    /// Validator proposed two blocks in the same slot.
    DoubleProposal,
    /// Validator was unavailable for required duties.
    Unavailability,
    /// Validator engaged in malicious behavior.
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

/// Configuration parameters for consensus operation.
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

/// Events emitted by the consensus engine for monitoring and external systems.
#[derive(Debug, Clone)]
pub enum ConsensusEvent {
    BlockProposed(BlockProposal),
    BlockFinalized(Block),
    ValidatorSlashed(Address, SlashingReason),
    EpochTransition(u64),
    ConsensusFailure(String),
}

/// Performance metrics for the consensus engine, tracked in-memory and exported to Prometheus.
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

/// Message for finality gossip (broadcast to network)
pub struct FinalityGossip {
    pub block_header: BlockHeader,
    pub zk_proof: ZKProof,
}

impl ConsensusEngine {
    /// Creates a new consensus engine with persistent storage.
    ///
    /// Initializes state, validator registry, prover/verifier, event system, and metrics.
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
            min_validator_stake: 50_000 * ZERO_PER_POAR, // 50,000 POAR minimum stake
            slash_percentage: 5,
            reward_per_block: 100, // 100 PROOF per block
            epoch_length: 32,
            slots_per_epoch: 32,
        };
        
        let storage = Arc::new(PersistentStorage::new("/Users/zengi/Desktop/poar-core/data").expect("Failed to open RocksDB"));
        
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
            local_validator_keys: Arc::new(HashSet::new()), // Initialize local_validator_keys
            global_state: Arc::new(TokioRwLock::new(GlobalState::new())), // Initialize global_state
            storage,
            chain_manager: ChainManager {
                branches: HashMap::new(),
                canonical_tip: Hash::zero(),
                finalized_height: 0,
                reorg_depth_limit: 100, // Default reorg depth limit
            },
            network_manager: None, // Initialize network_manager
            proposals: Vec::new(),
            parameters: ParameterRegistry {
                block_time: Duration::from_secs(5),
                epoch_length: 32,
                min_validator_stake: 50_000 * ZERO_PER_POAR,
                fee_minimum: FEE_MINIMUM,
                reward_per_block: 100,
                decay_factor: DECAY_FACTOR,
                burn_ratio: BURN_RATIO,
                slashing: 5,
            },
            emergency_halt: false,
        }
    }
    
    /// Load consensus state from persistent storage if available.
    pub fn load_state_from_storage(&self) {
        if let Ok(state) = self.storage.load_consensus_state() {
            let mut s = self.state.blocking_write();
            *s = state;
        }
        // Optionally load state trie and pending transactions here as well
    }
    
    /// Starts the main consensus loop, processing slots and epochs asynchronously.
    ///
    /// Handles block proposal, validation, finalization, and event emission.
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
                gas_limit: 10_000_000, // Placeholder
                gas_used: 0, // Genesis or new block starts with 0
                difficulty: 1, // Placeholder
                extra_data: Vec::new(), // Empty for now
            },
            transactions: Vec::new(),
        };
        
        let mut state = self.state.write().await;
        state.latest_block = Some(genesis_block);
        state.latest_block_hash = genesis_hash;
        state.latest_block_height = 0;
        state.finalized_height = 0;
        state.total_supply = crate::types::token::INITIAL_SUPPLY; // Genesis'te başlat
        
        println!("✅ Genesis block initialized: {}", genesis_hash);
        Ok(())
    }
    
    /// Start consensus rounds
    async fn start_consensus_rounds(&self) -> Result<(), ConsensusError> {
        let mut backoff = 1;
        loop {
            match self.process_consensus_round().await {
                Ok(_) => {
                    backoff = 1; // Reset backoff on success
                }
                Err(e) => {
                    error!("Consensus round failed: {:?}", e);
                    // Exponential backoff for repeated failures
                    warn!("Retrying consensus round in {}s", backoff);
                    sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(60); // Cap backoff at 60s
                }
            }
        }
    }
    
    /// Process a consensus round: propose/accept block, finalize if needed, prune forks, gossip finality.
    async fn process_consensus_round(&mut self) -> Result<(), ConsensusError> {
        // Emergency halt: skip all consensus actions
        if self.emergency_halt {
            println!("[Governance] Emergency halt active: consensus paused");
            return Ok(());
        }
        let start_time = Instant::now();
        let state = self.state.read().await;
        let current_slot = state.current_slot + 1;
        let current_epoch = current_slot / self.parameters.epoch_length;
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
        if current_slot % self.parameters.epoch_length == 0 {
            drop(state);
            self.process_epoch_transition(current_epoch).await?;
        }
        // Update metrics
        self.update_consensus_metrics(start_time.elapsed()).await;
        // Example: let (block, zk_proof) = ...
        // Accept the block (local or P2P)
        // self.accept_block(block.clone(), &zk_proof).await?;

        // After block acceptance, check if finalized_height advanced
        let finalized_height = self.chain_manager.finalized_height;
        if let Some(branch) = self.chain_manager.get_canonical_chain() {
            // Find the finalized block in canonical chain
            if let Some(finalized_block) = branch.blocks.iter().find(|b| b.header.height == finalized_height) {
                // Finalize the block (update state, persist, etc.)
                self.finalize_block(finalized_block.clone()).await?;
                // Gossip finality to the network (placeholder)
                self.gossip_finality(finalized_block);
                // Prune old forks
                self.chain_manager.prune_old_branches();
            }
        }
        Ok(())
    }
    
    /// Deterministic proposer selection for a given slot and epoch
    async fn select_proposer(&self, slot: u64, epoch: u64) -> Result<Address, ConsensusError> {
        // Get validator set (clone to avoid holding lock)
        let validators: Vec<Address> = {
            let registry = self.validators.read().await;
            registry.active_validators.keys().cloned().collect()
        };
        if validators.is_empty() {
            return Err(ConsensusError::NoActiveValidators);
        }
        // Get latest block hash (clone to avoid holding lock)
        let latest_block_hash = {
            let state = self.state.read().await;
            state.latest_block_hash
        };
        // Deterministic seed: epoch || slot || latest_block_hash
        let mut seed = Vec::new();
        seed.extend_from_slice(&epoch.to_le_bytes());
        seed.extend_from_slice(&slot.to_le_bytes());
        seed.extend_from_slice(&latest_block_hash.0);
        // Use Poseidon hash for deterministic randomness
        let hash_bytes = poseidon_hash(&seed);
        let idx = (u64::from_le_bytes(hash_bytes[..8].try_into().unwrap()) % validators.len() as u64) as usize;
        Ok(validators[idx].clone())
    }
    
    /// Returns true if this node controls the private key for the given validator address
    async fn is_local_validator(&self, validator: &Address) -> Result<bool, ConsensusError> {
        // Real implementation: check if the address is in the local_validator_keys set
        Ok(self.local_validator_keys.contains(validator))
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
            gas_limit: 10_000_000, // Placeholder
            gas_used: 0, // Genesis or new block starts with 0
            difficulty: 1, // Placeholder
            extra_data: Vec::new(), // Empty for now
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
    
    /// Generate ZK proofs for multiple blocks in parallel (batch proof optimization)
    async fn generate_parallel_proofs(&self, blocks: &[Block]) -> Result<Vec<ZKProof>, ConsensusError> {
        // Spawn async tasks for each block proof
        let mut handles = Vec::with_capacity(blocks.len());
        for block in blocks {
            let block_clone = block.clone();
            let engine = self.clone(); // Ensure ConsensusEngine is Arc or Clone
            let handle = task::spawn(async move {
                engine.generate_block_proof(&block_clone).await
            });
            handles.push(handle);
        }
        // Collect results
        let mut proofs = Vec::with_capacity(blocks.len());
        for handle in handles {
            proofs.push(handle.await.unwrap()?);
        }
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
                self.record_failed_proposal(); // Increment failed proposals metric
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
        self.validate_proposer_eligibility(&proposal.proposer, proposal.slot, proposal.slot / self.config.slots_per_epoch).await?;
        
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
    
    /// Verify that the given proposer is eligible for the slot/epoch (deterministic selection)
    async fn validate_proposer_eligibility(&self, proposer: &Address, slot: u64, epoch: u64) -> Result<(), ConsensusError> {
        // For now, use deterministic selection (VRF can be added later)
        let expected = self.select_proposer(slot, epoch).await?;
        if proposer != &expected {
            return Err(ConsensusError::ValidatorNotActive);
        }
        Ok(())
    }
    
    /// Validate a transaction: signature, nonce, and (optionally) balance and fee
    async fn validate_transaction(&self, tx: &Transaction) -> Result<(), ConsensusError> {
        // 1. Signature check
        if !verify_signature(&tx.from, &tx.signature, &tx.hash()) {
            return Err(ConsensusError::InvalidProof); // Or ConsensusError::StateError("Invalid signature".to_string())
        }
        // 2. Nonce check (simulate, as state is not fully available here)
        // let expected_nonce = ...; // Would get from state
        // if tx.nonce != expected_nonce { return Err(ConsensusError::StateError("Invalid nonce".to_string())); }
        // 3. Balance check (simulate)
        // let balance = ...; // Would get from state
        // if tx.amount > balance { return Err(ConsensusError::StateError("Insufficient balance".to_string())); }
        // 4. Fee check
        if tx.fee < self.parameters.fee_minimum {
            return Err(ConsensusError::StateError("Fee below minimum".to_string()));
        }
        // For transfer transactions, enforce fee range
        if matches!(tx.tx_type, crate::types::TransactionType::Transfer) {
            if tx.fee < FEE_TRANSFER_MIN || tx.fee > FEE_TRANSFER_MAX {
                return Err(ConsensusError::StateError("Transfer fee outside allowed range".to_string()));
            }
        }
        Ok(())
    }
    
    /// Finalize a block and persist state to RocksDB, only if it is the canonical finalized block.
    async fn finalize_block(&self, block: Block) -> Result<(), ConsensusError> {
        let finalized_height = self.chain_manager.finalized_height;
        // Only finalize if this block is the canonical finalized block
        if block.header.height != finalized_height {
            // Not the finalized block, skip
            return Ok(());
        }
        let mut state = self.state.write().await;
        let mut global_state = self.global_state.write().await;
        
        // Update blockchain state
        state.latest_block = Some(block.clone());
        state.latest_block_hash = block.header.hash;
        state.latest_block_height = block.header.height;
        state.finalized_height = finalized_height;
        
        // Remove included transactions from pending
        for tx in &block.transactions {
            state.pending_transactions.retain(|pending_tx| pending_tx.hash != tx.hash);
        }
        
        // === POAR ECONOMY: Transaction Fee Burn and Total Supply Update ===
        let mut total_burned = 0u64;
        let mut total_fee_to_proposer = 0u64;
        for tx in &block.transactions {
            let fee = tx.fee;
            let mut burned = (fee as f64 * BURN_RATIO) as u64;
            // Burn floor control
            if state.total_supply.saturating_sub(burned) < MIN_SUPPLY {
                burned = 0;
            }
            total_burned += burned;
            // Remaining fee added to proposer
            total_fee_to_proposer += fee.saturating_sub(burned);
        }
        state.total_supply = state.total_supply.saturating_sub(total_burned);
        // Add fee to proposer account state
        let proposer = block.header.validator;
        let mut acc = global_state.get_account(&proposer).unwrap_or_else(|| crate::storage::state::AccountState::new(0));
        acc.balance = acc.balance.saturating_add(total_fee_to_proposer);
        global_state.set_account(proposer, acc);
        // ===============================================================
        
        // Persist state
        self.storage.save_consensus_state(&state)?;
        // Optionally save state trie and pending transactions
        
        Ok(())
    }
    
    /// Process epoch transition
    async fn process_epoch_transition(&self, new_epoch: u64) -> Result<(), ConsensusError> {
        println!("🔄 Epoch transition: {}", new_epoch);
        
        // Update validator assignments for new epoch
        self.update_validator_assignments(new_epoch).await?;
        
        // Distribute rewards
        self.distribute_rewards(new_epoch).await?;
        
        // Process slashing
        self.process_slashing().await?;
        
        // Process governance proposals
        self.process_governance(new_epoch, self.validators.read().await.active_validators.len());
        
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
    
    /// Distribute rewards to validators at the end of each epoch
    async fn distribute_rewards(&self, epoch: u64) -> Result<(), ConsensusError> {
        let mut registry = self.validators.write().await;
        let mut state = self.state.write().await;
        let mut global_state = self.global_state.write().await;

        // Total stake and stake ratio
        let total_stake = registry.total_stake as f64;
        let total_supply = state.total_supply as f64;
        let stake_ratio = if total_supply > 0.0 { total_stake / total_supply } else { 0.0 };

        // Dynamic stake multiplier
        let stake_multiplier = if stake_ratio < 0.6 {
            1.0 + LOW_STAKE_BONUS
        } else if stake_ratio > 0.8 {
            1.0 + HIGH_STAKE_PENALTY
        } else {
            1.0
        };

        // Early adopter bonus (first 2 years/730 epochs)
        let early_adopter_multiplier = if epoch < EARLY_ADOPTER_BONUS_EPOCHS {
            1.0 + EARLY_ADOPTER_BONUS
        } else {
            1.0
        };

        // Epoch reward with decay
        let mut epoch_reward = (BASE_REWARD as f64)
            * DECAY_FACTOR.powi(epoch as i32)
            * stake_multiplier
            * early_adopter_multiplier;

        // Total supply cap control
        let mut current_supply = state.total_supply as f64;
        if current_supply + epoch_reward > MAX_SUPPLY as f64 {
            epoch_reward = (MAX_SUPPLY as f64) - current_supply;
        }
        if current_supply >= MAX_SUPPLY as f64 || epoch_reward <= 0.0 {
            return Ok(()); // No mint, no reward
        }

        // Distribute validator rewards based on stake ratio and enforce stake cap
        let total_stake = registry.active_validators.values().map(|v| v.stake as f64).sum::<f64>();
        for (address, info) in registry.active_validators.iter_mut() {
            let share = if total_stake > 0.0 {
                (info.stake as f64) / total_stake
            } else {
                0.0
            };
            let mut reward = (epoch_reward * share).round() as u64;
            // Enforce validator stake cap (soft cap): if stake > 10% of total, reduce reward by 10%
            if share > VALIDATOR_STAKE_CAP {
                reward = ((reward as f64) * 0.90).round() as u64;
            }
            info.performance.reward_earned += reward;
            // Add reward to validator account state
            let mut acc = global_state.get_account(address).unwrap_or_else(|| crate::storage::state::AccountState::new(0));
            acc.balance = acc.balance.saturating_add(reward);
            global_state.set_account(*address, acc);
        }
        // Update total supply
        state.total_supply = (state.total_supply as f64 + epoch_reward).round() as u64;
        Ok(())
    }
    
    /// Process slashing for validators with valid evidence (after challenge window)
    async fn process_slashing(&self) -> Result<(), ConsensusError> {
        let mut registry = self.validators.write().await;
        let current_slot = {
            let state = self.state.read().await;
            state.current_slot
        };
        let mut to_slash = Vec::new();
        // Find validators with expired challenge window and valid evidence
        for (address, evidence) in registry.slashing_evidence.iter() {
            if let Some(deadline) = registry.challenge_deadlines.get(address) {
                if current_slot > *deadline {
                    to_slash.push(address.clone());
                }
            }
        }
        // Apply slashing: set status, remove from active, move to slashed_validators
        for address in to_slash {
            if let Some(mut info) = registry.active_validators.remove(&address) {
                info.status = ValidatorStatus::Slashed;
                registry.slashed_validators.insert(address.clone(), SlashingInfo {
                    reason: SlashingReason::MaliciousBehavior, // Or evidence.reason
                    amount_slashed: info.stake / 2, // Example: slash half the stake
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    evidence: Vec::new(), // Optionally store evidence
                });
            }
        }
        Ok(())
    }
    /// Check if a slashed validator can still challenge
    async fn can_challenge_slash(&self, address: &Address, current_slot: u64) -> bool {
        let registry = self.validators.read().await;
        if let Some(deadline) = registry.challenge_deadlines.get(address) {
            return current_slot <= *deadline;
        }
        false
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
    
    /// Update Prometheus metrics after each consensus round
    async fn update_consensus_metrics(&self, round_duration: Duration) {
        let mut metrics = self.metrics.lock().unwrap();
            metrics.blocks_processed += 1;
        metrics.average_block_time = (metrics.average_block_time * ((metrics.blocks_processed - 1) as f64) + round_duration.as_millis() as f64) / (metrics.blocks_processed as f64);
        // Update Prometheus metrics
        BLOCKS_PROCESSED.inc();
        AVERAGE_BLOCK_TIME.set(metrics.average_block_time as i64);
    }
    /// Increment failed proposals metric
    fn record_failed_proposal(&self) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.failed_proposals += 1;
        FAILED_PROPOSALS.inc();
    }
    /// Export Prometheus metrics as a string for scraping
    pub fn export_metrics(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
    
    /// Returns current consensus engine performance metrics.
    pub fn get_metrics(&self) -> ConsensusMetrics {
        self.metrics.lock().unwrap().clone()
    }
    
    /// Registers a new validator in the registry.
    ///
    /// Updates the validator set and assignments for the current epoch.
    pub async fn register_validator(&self, validator_info: ValidatorInfo) -> Result<(), ConsensusError> {
        let mut validators = self.validators.write().await;
        validators.active_validators.insert(validator_info.address, validator_info);
        Ok(())
    }
    
    /// Adds a transaction to the pending pool with POAR-specific prioritization and DoS protection.
    /// - Validates signature and nonce (simulated)
    /// - Rejects duplicates
    /// - Removes old transactions
    /// - Evicts lowest-fee/oldest if pool is full and new tx is higher priority
    pub async fn add_transaction(&self, transaction: Transaction) -> Result<(), ConsensusError> {
        self.validate_transaction(&transaction).await?;

        let mut state = self.state.write().await;
        let current_slot = state.current_slot; // Simulate slot from state

        // Duplicate kontrolü
        if state.pending_transactions.iter().any(|tx| tx.hash() == transaction.hash()) {
            log::info!("Rejected duplicate transaction: {}", transaction.hash());
            return Err(ConsensusError::StateError("Duplicate transaction".to_string()));
        }

        // Yaş limiti: çok eski işlemleri havuzdan çıkar
        state.pending_transactions.retain(|tx| tx.slot + TX_MAX_AGE >= current_slot);

        // Havuz doluysa, en düşük fee'li ve en eski işlemi bul
        if state.pending_transactions.len() >= MAX_PENDING_TX {
            if let Some((min_idx, min_tx)) = state.pending_transactions.iter().enumerate().min_by_key(|(_, tx)| (tx.amount, tx.slot)) {
                if transaction.amount > min_tx.amount || (transaction.amount == min_tx.amount && transaction.slot > min_tx.slot) {
                    // Evict the lowest-fee/oldest transaction
                    let evicted = state.pending_transactions.remove(min_idx);
                    log::info!("Evicted tx {} for new tx {}", evicted.hash(), transaction.hash());
                    // Prometheus metric: evictions (if available)
                    state.pending_transactions.push(transaction);
                    return Ok(());
                } else {
                    log::info!("Rejected low-priority tx {} (pool full)", transaction.hash());
                    // Prometheus metric: rejections (if available)
                    return Err(ConsensusError::TooManyTransactions);
                }
            } else {
                return Err(ConsensusError::TooManyTransactions);
            }
        }

        // Nonce kontrolü (simüle, gerçek state ile entegre edilecek)
        // let expected_nonce = ...;
        // if transaction.nonce != expected_nonce { return Err(ConsensusError::StateError("Invalid nonce".to_string())); }

        state.pending_transactions.push(transaction);
        Ok(())
    }
    
    /// Returns circuit optimization metrics for ZK proof generation.
    pub fn get_circuit_metrics(&self) -> &super::circuits::OptimizationMetrics {
        self.circuit_optimizer.get_metrics()
    }
    
    /// Prints a performance comparison of different proof/circuit optimizations.
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

    /// Apply unstake bonus if stake ratio is too high (circulation too low)
    pub async fn apply_unstake_bonus(&self, address: &Address, amount: u64) -> u64 {
        let registry = self.validators.read().await;
        let state = self.state.read().await;
        let total_stake = registry.total_stake as f64;
        let total_supply = state.total_supply as f64;
        let stake_ratio = if total_supply > 0.0 { total_stake / total_supply } else { 0.0 };
        // If stake ratio > 90%, apply +2% bonus to unstaking amount
        if stake_ratio > 0.9 {
            ((amount as f64) * (1.0 + UNSTAKE_BONUS)).round() as u64
        } else {
            amount
        }
    }

    /// Accept a new block (local or P2P), validate ZK proof, update chain branches, and apply fork choice.
    pub async fn accept_block(&mut self, block: Block, zk_proof: &ZKProof) -> Result<(), ConsensusError> {
        // 1. Validate ZK proof for the block
        let is_valid = self.verifier.verify_block_validity(
            zk_proof,
            block.header.hash,
            block.header.previous_hash,
            block.header.merkle_root,
        ).map_err(|e| ConsensusError::ProofVerificationFailed(e.to_string()))?;
        if !is_valid {
            return Err(ConsensusError::InvalidProof);
        }

        // 2. Add block to chain branches
        self.chain_manager.add_block(block.clone());

        // 3. Run fork choice to select canonical chain
        self.chain_manager.select_fork_choice();

        // 4. Finality: if canonical tip height > finalized_height + reorg_depth_limit, finalize new blocks
        let canonical_chain = self.chain_manager.get_canonical_chain();
        if let Some(branch) = canonical_chain {
            if let Some(tip_block) = branch.blocks.last() {
                let tip_height = tip_block.header.height;
                let finalized_height = self.chain_manager.finalized_height;
                let reorg_limit = self.chain_manager.reorg_depth_limit;
                if tip_height > finalized_height + reorg_limit {
                    // Finalize up to (tip_height - reorg_limit)
                    self.chain_manager.finalized_height = tip_height - reorg_limit;
                    self.chain_manager.prune_old_branches();
                }
            }
        }
        Ok(())
    }

    /// Gossip finalized block info to the network (real implementation)
    fn gossip_finality(&self, finalized_block: &Block) {
        let gossip_msg = FinalityGossip {
            block_header: finalized_block.header.clone(),
            zk_proof: finalized_block.header.zk_proof.clone(),
        };
        if let Some(network) = self.network_manager.as_ref() {
            let mut net = network.lock().unwrap();
            net.broadcast_finality_gossip(gossip_msg);
        }
    }

    /// Handle incoming finality gossip (update local finalized_height if needed)
    pub fn on_finality_gossip(&mut self, gossip: FinalityGossip) {
        // If the gossiped finalized block is ahead, update local finalized_height
        let gossiped_height = gossip.block_header.height;
        if gossiped_height > self.chain_manager.finalized_height {
            self.chain_manager.finalized_height = gossiped_height;
            // Optionally trigger local finalization
        }
    }

    /// Submit a new governance proposal (returns proposal ID)
    pub fn submit_proposal(&mut self, proposer: Address, proposal_type: ProposalType, payload: Vec<u8>, current_epoch: u64) -> u64 {
        let id = self.proposals.len() as u64 + 1;
        let proposal = GovernanceProposal {
            id,
            proposer,
            proposal_type,
            payload,
            start_epoch: current_epoch,
            end_epoch: current_epoch + 1, // 1 epoch voting period
            votes_for: vec![],
            votes_against: vec![],
            status: ProposalStatus::Pending,
        };
        self.proposals.push(proposal);
        id
    }

    /// Vote on a governance proposal
    pub fn vote_on_proposal(&mut self, proposal_id: u64, validator: Address, approve: bool) {
        if let Some(proposal) = self.proposals.iter_mut().find(|p| p.id == proposal_id && p.status == ProposalStatus::Pending) {
            if approve {
                if !proposal.votes_for.contains(&validator) {
                    proposal.votes_for.push(validator);
                }
            } else {
                if !proposal.votes_against.contains(&validator) {
                    proposal.votes_against.push(validator);
                }
            }
        }
    }

    /// Process governance proposals at epoch end
    pub fn process_governance(&mut self, current_epoch: u64, total_validators: usize) {
        for proposal in self.proposals.iter_mut().filter(|p| p.status == ProposalStatus::Pending && p.end_epoch <= current_epoch) {
            let total_votes = proposal.votes_for.len() + proposal.votes_against.len();
            let quorum = total_votes as f64 / total_validators as f64 >= 0.5;
            let threshold = proposal.votes_for.len() as f64 / total_votes.max(1) as f64 >= 0.66;
            if quorum && threshold {
                proposal.status = ProposalStatus::Accepted;
                self.apply_proposal(proposal);
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
        }
    }

    /// Apply an accepted proposal (parameter change, emergency halt, etc.)
    fn apply_proposal(&mut self, proposal: &GovernanceProposal) {
        match proposal.proposal_type {
            ProposalType::ParameterChange => {
                // Decode payload as (key, value) and update parameter
                if let Ok((key, value)) = bincode::deserialize::<(String, serde_json::Value)>(&proposal.payload) {
                    match key.as_str() {
                        "block_time" => {
                            if let Some(secs) = value.as_u64() {
                                self.parameters.block_time = Duration::from_secs(secs);
                                println!("[Governance] block_time updated to {}s", secs);
                            }
                        }
                        "epoch_length" => {
                            if let Some(v) = value.as_u64() {
                                self.parameters.epoch_length = v;
                                println!("[Governance] epoch_length updated to {}", v);
                            }
                        }
                        "min_validator_stake" => {
                            if let Some(v) = value.as_u64() {
                                self.parameters.min_validator_stake = v;
                                println!("[Governance] min_validator_stake updated to {}", v);
                            }
                        }
                        "fee_minimum" => {
                            if let Some(v) = value.as_u64() {
                                self.parameters.fee_minimum = v;
                                println!("[Governance] fee_minimum updated to {}", v);
                            }
                        }
                        "reward_per_block" => {
                            if let Some(v) = value.as_u64() {
                                self.parameters.reward_per_block = v;
                                println!("[Governance] reward_per_block updated to {}", v);
                            }
                        }
                        "decay_factor" => {
                            if let Some(v) = value.as_f64() {
                                self.parameters.decay_factor = v;
                                println!("[Governance] decay_factor updated to {}", v);
                            }
                        }
                        "burn_ratio" => {
                            if let Some(v) = value.as_f64() {
                                self.parameters.burn_ratio = v;
                                println!("[Governance] burn_ratio updated to {}", v);
                            }
                        }
                        "slashing" => {
                            if let Some(v) = value.as_u64() {
                                self.parameters.slashing = v as u8;
                                println!("[Governance] slashing updated to {}", v);
                            }
                        }
                        _ => println!("[Governance] Unknown parameter: {}", key),
                    }
                }
            }
            ProposalType::EmergencyHalt => {
                self.emergency_halt = true;
                println!("[Governance] Emergency halt activated: id={}", proposal.id);
            }
            ProposalType::CodeUpgradeSignal => {
                println!("[Governance] Code upgrade signal accepted: id={}", proposal.id);
            }
        }
    }

    /// Example: Submit a parameter change proposal (for testing/demo)
    pub fn example_submit_param_change(&mut self, proposer: Address, key: &str, value: serde_json::Value, current_epoch: u64) -> u64 {
        let payload = bincode::serialize(&(key.to_string(), value)).unwrap();
        let id = self.submit_proposal(proposer, ProposalType::ParameterChange, payload, current_epoch);
        println!("[Governance] Parameter change proposal submitted: id={}, key={}", id, key);
        id
    }

    /// Example: Vote on a proposal and process governance (for testing/demo)
    pub fn example_vote_and_process(&mut self, proposal_id: u64, validator: Address, approve: bool, current_epoch: u64) {
        self.vote_on_proposal(proposal_id, validator, approve);
        let total_validators = self.validators.read().unwrap().active_validators.len();
        self.process_governance(current_epoch, total_validators);
        if let Some(p) = self.proposals.iter().find(|p| p.id == proposal_id) {
            println!("[Governance] Proposal id={} status={:?}", proposal_id, p.status);
        }
    }

    /// Example: Emergency halt and recovery (for testing/demo)
    pub fn example_emergency_halt_and_recover(&mut self, proposer: Address, validator: Address, current_epoch: u64) {
        // Submit emergency halt proposal
        let id = self.submit_proposal(proposer, ProposalType::EmergencyHalt, vec![], current_epoch);
        println!("[Governance] Emergency halt proposal submitted: id={}", id);
        // Vote and process
        let total_validators = self.validators.read().unwrap().active_validators.len();
        self.vote_on_proposal(id, validator, true);
        self.process_governance(current_epoch + 1, total_validators);
        if self.emergency_halt {
            println!("[Governance] Chain is now halted!");
        }
        // Submit recovery proposal (could be a special proposal type or another emergency halt to false)
        // For demo, just reset emergency_halt manually
        self.emergency_halt = false;
        println!("[Governance] Chain recovered from halt (manual for demo)");
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
            total_supply: crate::types::token::INITIAL_SUPPLY, // Genesis'te başlat
        }
    }
}

/// Represents a chain branch (fork) in the blockchain.
pub struct ChainBranch {
    /// Blocks in this branch (ordered from genesis to tip)
    pub blocks: Vec<Block>,
    /// Hash of the tip (last) block
    pub tip_hash: Hash,
    /// Length of the branch (number of blocks)
    pub length: u64,
    /// Hash of the parent block (for fork tracking)
    pub parent_hash: Hash,
}

/// Manages all chain branches and fork choice logic.
pub struct ChainManager {
    /// All known branches, indexed by tip hash
    pub branches: HashMap<Hash, ChainBranch>,
    /// Hash of the canonical chain tip
    pub canonical_tip: Hash,
    /// Height of the last finalized block
    pub finalized_height: u64,
    /// Maximum allowed reorg depth
    pub reorg_depth_limit: u64,
}

impl ChainManager {
    /// Add a new block to the appropriate branch, or create a new branch if needed.
    pub fn add_block(&mut self, block: Block) {
        let parent_hash = block.header.previous_hash;
        let block_hash = block.header.hash;
        // If parent exists, extend that branch
        if let Some(parent_branch) = self.branches.get(&parent_hash).cloned() {
            let mut new_branch = parent_branch.clone();
            new_branch.blocks.push(block.clone());
            new_branch.tip_hash = block_hash;
            new_branch.length += 1;
            self.branches.insert(block_hash, new_branch);
        } else {
            // New branch (fork) starting from this block
            let branch = ChainBranch {
                blocks: vec![block.clone()],
                tip_hash: block_hash,
                length: 1,
                parent_hash,
            };
            self.branches.insert(block_hash, branch);
        }
    }

    /// Select the canonical chain using the fork choice rule (longest valid chain).
    pub fn select_fork_choice(&mut self) {
        let mut best_tip = self.canonical_tip;
        let mut best_length = 0;
        for (tip, branch) in &self.branches {
            if branch.length > best_length {
                best_tip = *tip;
                best_length = branch.length;
            } else if branch.length == best_length {
                // Tie-breaker: choose lower hash
                if tip < &best_tip {
                    best_tip = *tip;
                }
            }
        }
        self.canonical_tip = best_tip;
    }

    /// Get the canonical chain as a vector of blocks (from genesis to tip).
    pub fn get_canonical_chain(&self) -> Option<&ChainBranch> {
        self.branches.get(&self.canonical_tip)
    }

    /// Prune branches that are too far behind the finalized block (to save memory).
    pub fn prune_old_branches(&mut self) {
        let finalized = self.finalized_height;
        self.branches.retain(|_, branch| {
            // Keep branches whose tip is within reorg_depth_limit of finalized_height
            if let Some(last_block) = branch.blocks.last() {
                last_block.header.height + self.reorg_depth_limit >= finalized
            } else {
                false
            }
        });
    }
}

impl NetworkManager {
    /// Broadcast a finality gossip message to the network (placeholder)
    pub fn broadcast_finality_gossip(&mut self, gossip: FinalityGossip) {
        // TODO: Serialize and publish to a dedicated finality topic
    }
}

/// Errors that can occur during consensus operation.
#[derive(thiserror::Error, Debug)]
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

/// Types of governance proposals
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalType {
    /// Change a consensus or economic parameter
    ParameterChange,
    /// Emergency halt the chain
    EmergencyHalt,
    /// Signal for code/protocol upgrade (hard fork)
    CodeUpgradeSignal,
}

/// Status of a governance proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Pending,
    Accepted,
    Rejected,
    Executed,
}

/// Governance proposal struct for on-chain voting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Unique proposal ID
    pub id: u64,
    /// Address of the proposer (validator)
    pub proposer: Address,
    /// Type of proposal
    pub proposal_type: ProposalType,
    /// Encoded payload (parameter change, halt, etc.)
    pub payload: Vec<u8>,
    /// Epoch when voting starts
    pub start_epoch: u64,
    /// Epoch when voting ends
    pub end_epoch: u64,
    /// Validators who voted for
    pub votes_for: Vec<Address>,
    /// Validators who voted against
    pub votes_against: Vec<Address>,
    /// Current status
    pub status: ProposalStatus,
}

/// Registry for all consensus/economic parameters that can be changed via governance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRegistry {
    pub block_time: Duration,
    pub epoch_length: u64,
    pub min_validator_stake: u64,
    pub fee_minimum: u64,
    pub reward_per_block: u64,
    pub decay_factor: f64,
    pub burn_ratio: f64,
    pub slashing: u8,
    // Add more parameters as needed
}
