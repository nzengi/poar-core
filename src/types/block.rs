use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{Hash, Address, Transaction, ZKProof, Signature};

/// POAR blockchain block with ZK-proof integration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    /// Block header containing metadata and ZK proofs
    pub header: BlockHeader,
    /// List of transactions in this block
    pub transactions: Vec<Transaction>,
}

/// Block header with ZK-proof integration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    /// Unique block hash
    pub hash: Hash,
    /// Hash of the previous block
    pub previous_hash: Hash,
    /// Merkle root of all transactions
    pub merkle_root: Hash,
    /// State root after applying all transactions
    pub state_root: Hash,
    /// Block height/number
    pub height: u64,
    /// Unix timestamp when block was created
    pub timestamp: u64,
    /// Address of the validator who proposed this block
    pub validator: Address,
    /// Validator's signature over the block
    pub signature: Signature,
    /// Zero-knowledge proof of block validity
    pub zk_proof: ZKProof,
    /// Nonce used for block hash calculation
    pub nonce: u64,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Total gas used by all transactions
    pub gas_used: u64,
    /// Block difficulty (for ZK-PoV adaptation)
    pub difficulty: u64,
    /// Extra data field (max 32 bytes)
    pub extra_data: Vec<u8>,
}

/// Block validation result
#[derive(Debug, Clone, PartialEq)]
pub enum BlockValidationResult {
    Valid,
    InvalidHash,
    InvalidPreviousHash,
    InvalidMerkleRoot,
    InvalidStateRoot,
    InvalidZKProof,
    InvalidSignature,
    InvalidTimestamp,
    InvalidGasLimit,
    InvalidTransactions,
    BlockTooLarge,
    TooManyTransactions,
}

/// Block builder for constructing valid blocks
pub struct BlockBuilder {
    previous_hash: Hash,
    height: u64,
    validator: Address,
    transactions: Vec<Transaction>,
    gas_limit: u64,
    extra_data: Vec<u8>,
}

/// Block validation context
pub struct BlockValidationContext {
    pub max_block_size: usize,
    pub max_transactions_per_block: usize,
    pub max_gas_limit: u64,
    pub genesis_timestamp: u64,
    pub block_time_target: u64,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self { header, transactions }
    }

    /// Create genesis block
    pub fn genesis() -> Self {
        let genesis_hash = Hash::hash(b"POAR_GENESIS_2025");
        let mut genesis_header = BlockHeader {
            hash: Hash::zero(), // temporary, will be set below
            previous_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::zero(),
            height: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            validator: Address::zero(),
            signature: Signature::default(),
            zk_proof: ZKProof::default(),
            nonce: 0,
            gas_limit: 15_000_000, // 15M gas limit
            gas_used: 0,
            difficulty: 1000,
            extra_data: b"POAR Genesis Block".to_vec(),
        };
        // Calculate the correct hash
        let block = Self {
            header: genesis_header,
            transactions: Vec::new(),
        };
        let mut header = block.header.clone();
        header.hash = block.calculate_hash();
        Self {
            header,
            transactions: Vec::new(),
        }
    }

    /// Get block size in bytes
    pub fn size(&self) -> usize {
        bincode::serialize(self).unwrap_or_default().len()
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Calculate total gas used by all transactions
    pub fn calculate_gas_used(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.gas_limit).sum()
    }

    /// Validate block structure and content
    pub fn validate(&self, context: &BlockValidationContext) -> BlockValidationResult {
        // 1. Validate block size
        if self.size() > context.max_block_size {
            return BlockValidationResult::BlockTooLarge;
        }

        // 2. Validate transaction count
        if self.transactions.len() > context.max_transactions_per_block {
            return BlockValidationResult::TooManyTransactions;
        }

        // 3. Validate gas limit
        if self.header.gas_limit > context.max_gas_limit {
            return BlockValidationResult::InvalidGasLimit;
        }

        // 4. Validate gas used
        let calculated_gas_used = self.calculate_gas_used();
        if self.header.gas_used != calculated_gas_used {
            return BlockValidationResult::InvalidGasLimit;
        }

        // 5. Validate merkle root
        let calculated_merkle_root = self.calculate_merkle_root();
        if self.header.merkle_root != calculated_merkle_root {
            return BlockValidationResult::InvalidMerkleRoot;
        }

        // 6. Validate timestamp
        if !self.validate_timestamp(context) {
            return BlockValidationResult::InvalidTimestamp;
        }

        // 7. Validate transactions
        if !self.validate_transactions() {
            return BlockValidationResult::InvalidTransactions;
        }

        // 8. Validate block hash
        let calculated_hash = self.calculate_hash();
        if self.header.hash != calculated_hash {
            return BlockValidationResult::InvalidHash;
        }

        BlockValidationResult::Valid
    }

    /// Calculate block hash
    pub fn calculate_hash(&self) -> Hash {
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(self.header.previous_hash.as_bytes());
        hash_input.extend_from_slice(self.header.merkle_root.as_bytes());
        hash_input.extend_from_slice(self.header.state_root.as_bytes());
        hash_input.extend_from_slice(&self.header.height.to_le_bytes());
        hash_input.extend_from_slice(&self.header.timestamp.to_le_bytes());
        hash_input.extend_from_slice(self.header.validator.as_bytes());
        hash_input.extend_from_slice(&self.header.nonce.to_le_bytes());
        hash_input.extend_from_slice(&self.header.gas_limit.to_le_bytes());
        hash_input.extend_from_slice(&self.header.gas_used.to_le_bytes());
        hash_input.extend_from_slice(&self.header.difficulty.to_le_bytes());
        hash_input.extend_from_slice(&self.header.extra_data);

        Hash::hash(&hash_input)
    }

    /// Calculate merkle root of transactions
    pub fn calculate_merkle_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return Hash::zero();
        }

        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash).collect();
        self.calculate_merkle_root_from_hashes(&tx_hashes)
    }

    /// Calculate merkle root from hash list
    fn calculate_merkle_root_from_hashes(&self, hashes: &[Hash]) -> Hash {
        if hashes.is_empty() {
            return Hash::zero();
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined_hash = if chunk.len() == 2 {
                    Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[1].as_bytes()])
                } else {
                    // If odd number, hash with itself
                    Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[0].as_bytes()])
                };
                next_level.push(combined_hash);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Validate block timestamp
    fn validate_timestamp(&self, context: &BlockValidationContext) -> bool {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        // Block timestamp should not be too far in the future (max 15 minutes)
        if self.header.timestamp > current_time + 900 {
            return false;
        }

        // Block timestamp should not be before genesis
        if self.header.timestamp < context.genesis_timestamp {
            return false;
        }

        // For non-genesis blocks, timestamp should be after previous block
        if self.header.height > 0 {
            // This would need previous block timestamp, simplified for now
            return true;
        }

        true
    }

    /// Validate all transactions in the block
    fn validate_transactions(&self) -> bool {
        for tx in &self.transactions {
            if !tx.validate_basic() {
                return false;
            }
        }
        true
    }

    /// Sign block with validator's private key
    pub fn sign(&mut self, validator_signature: Signature) {
        self.header.signature = validator_signature;
    }

    /// Add ZK proof to block
    pub fn add_zk_proof(&mut self, proof: ZKProof) {
        self.header.zk_proof = proof;
    }

    /// Update block hash after all modifications
    pub fn finalize_hash(&mut self) {
        self.header.hash = self.calculate_hash();
    }

    /// Get block reward for validator
    pub fn get_block_reward(&self) -> u64 {
        // Base reward + fee rewards
        let base_reward = 100; // 100 POAR base reward
        let fee_rewards: u64 = self.transactions.iter().map(|tx| tx.fee).sum();
        base_reward + fee_rewards
    }

    /// Check if block is genesis
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0 && self.header.previous_hash.is_zero()
    }

    /// Get block age in seconds
    pub fn age_seconds(&self) -> u64 {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        current_time.saturating_sub(self.header.timestamp)
    }
}

impl BlockBuilder {
    /// Create new block builder
    pub fn new(previous_hash: Hash, height: u64, validator: Address) -> Self {
        Self {
            previous_hash,
            height,
            validator,
            transactions: Vec::new(),
            gas_limit: 15_000_000, // Default 15M gas
            extra_data: Vec::new(),
        }
    }

    /// Add transaction to block
    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// Add multiple transactions
    pub fn add_transactions(mut self, transactions: Vec<Transaction>) -> Self {
        self.transactions.extend(transactions);
        self
    }

    /// Set gas limit
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set extra data
    pub fn extra_data(mut self, extra_data: Vec<u8>) -> Self {
        self.extra_data = extra_data;
        self
    }

    /// Build the block (without signatures and proofs)
    pub fn build(self, state_root: Hash) -> Block {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let gas_used = self.transactions.iter().map(|tx| tx.gas_limit).sum();

        // Calculate merkle root
        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash).collect();
        let merkle_root = if tx_hashes.is_empty() {
            Hash::zero()
        } else {
            calculate_merkle_root_from_hashes(&tx_hashes)
        };

        let mut block_header = BlockHeader {
            hash: Hash::zero(), // Will be calculated after signing
            previous_hash: self.previous_hash,
            merkle_root,
            state_root,
            height: self.height,
            timestamp,
            validator: self.validator,
            signature: Signature::default(), // Will be filled later
            zk_proof: ZKProof::default(), // Will be filled later
            nonce: 0,
            gas_limit: self.gas_limit,
            gas_used,
            difficulty: 1000, // Default difficulty
            extra_data: self.extra_data,
        };

        let mut block = Block {
            header: block_header,
            transactions: self.transactions,
        };

        // Calculate final hash
        block.header.hash = block.calculate_hash();
        block
    }
}

impl Default for BlockValidationContext {
    fn default() -> Self {
        Self {
            max_block_size: 1024 * 1024, // 1MB
            max_transactions_per_block: 10000,
            max_gas_limit: 30_000_000, // 30M gas
            genesis_timestamp: 1640995200, // 2022-01-01
            block_time_target: 5, // 5 seconds
        }
    }
}

/// Helper function for merkle root calculation
fn calculate_merkle_root_from_hashes(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::zero();
    }

    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current_level = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let combined_hash = if chunk.len() == 2 {
                Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[1].as_bytes()])
            } else {
                Hash::hash_multiple(&[chunk[0].as_bytes(), chunk[0].as_bytes()])
            };
            next_level.push(combined_hash);
        }

        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();
        assert_eq!(genesis.header.height, 0);
        assert!(genesis.header.previous_hash.is_zero());
        assert!(genesis.is_genesis());
        assert_eq!(genesis.transaction_count(), 0);
    }

    #[test]
    fn test_block_builder() {
        let previous_hash = Hash::hash(b"previous_block");
        let validator = Address::from_bytes([1u8; 20]);
        let state_root = Hash::hash(b"state_root");

        let block = BlockBuilder::new(previous_hash, 1, validator)
            .gas_limit(20_000_000)
            .extra_data(b"test_block".to_vec())
            .build(state_root);

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.previous_hash, previous_hash);
        assert_eq!(block.header.validator, validator);
        assert_eq!(block.header.gas_limit, 20_000_000);
    }

    #[test]
    fn test_merkle_root_calculation() {
        let hash1 = Hash::hash(b"tx1");
        let hash2 = Hash::hash(b"tx2");
        let hashes = vec![hash1, hash2];

        let merkle_root = calculate_merkle_root_from_hashes(&hashes);
        assert!(!merkle_root.is_zero());

        // Test with single hash
        let single_merkle = calculate_merkle_root_from_hashes(&[hash1]);
        assert_eq!(single_merkle, hash1);

        // Test with empty hashes
        let empty_merkle = calculate_merkle_root_from_hashes(&[]);
        assert!(empty_merkle.is_zero());
    }

    #[test]
    fn test_block_validation() {
        let context = BlockValidationContext::default();
        let genesis = Block::genesis();
        
        // Genesis block should be valid
        let result = genesis.validate(&context);
        assert_eq!(result, BlockValidationResult::Valid);
    }
} 