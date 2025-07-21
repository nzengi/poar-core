use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use crate::types::{Hash, Address, Transaction, Poar, Proof, Valid, Zero, TokenUnit, TokenUtils};

/// Account state in POAR blockchain
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountState {
    /// Account balance in ZERO units (smallest unit)
    pub balance: u64,
    /// Transaction nonce (number of transactions sent)
    pub nonce: u64,
    /// Code hash for smart contracts (empty for regular accounts)
    pub code_hash: Hash,
    /// Storage root for smart contract storage
    pub storage_root: Hash,
}

/// Global blockchain state
#[derive(Debug, Clone)]
pub struct GlobalState {
    /// All account states
    accounts: Arc<RwLock<HashMap<Address, AccountState>>>,
    /// State root hash
    state_root: Arc<RwLock<Hash>>,
    /// State version/height
    version: Arc<RwLock<u64>>,
}

/// State transition result
#[derive(Debug, Clone, PartialEq)]
pub enum StateTransitionResult {
    Success(StateChanges),
    InsufficientBalance,
    InvalidNonce,
    AccountNotFound,
    ContractExecutionFailed,
    GasLimitExceeded,
}

/// State changes from executing a transaction
#[derive(Debug, Clone, Default)]
pub struct StateChanges {
    /// Account balance changes
    pub balance_changes: HashMap<Address, i64>, // i64 for negative changes
    /// Nonce updates
    pub nonce_updates: HashMap<Address, u64>,
    /// New accounts created
    pub new_accounts: HashMap<Address, AccountState>,
    /// Smart contract storage changes
    pub storage_changes: HashMap<Address, HashMap<Hash, Hash>>,
    /// Gas used
    pub gas_used: u64,
}

/// State manager for handling all state operations
pub struct StateManager {
    /// Current state
    state: GlobalState,
    /// State history for rollbacks
    state_history: Vec<(u64, HashMap<Address, AccountState>)>,
    /// Maximum history size
    max_history_size: usize,
}

/// State trie for efficient state management
pub struct StateTrie {
    /// Root node of the trie
    root: Option<TrieNode>,
    /// Trie cache for performance
    cache: HashMap<Hash, TrieNode>,
}

/// Trie node for state storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrieNode {
    /// Node hash
    pub hash: Hash,
    /// Node data
    pub data: TrieNodeData,
}

/// Trie node data types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNodeData {
    /// Leaf node with account state
    Leaf {
        key: Vec<u8>,
        value: AccountState,
    },
    /// Branch node with children
    Branch {
        children: [Option<Hash>; 16],
        value: Option<AccountState>,
    },
    /// Extension node
    Extension {
        key: Vec<u8>,
        child: Hash,
    },
}

impl AccountState {
    /// Create new account state
    pub fn new(balance: u64) -> Self {
        Self {
            balance,
            nonce: 0,
            code_hash: Hash::zero(),
            storage_root: Hash::zero(),
        }
    }

    /// Create contract account state
    pub fn new_contract(balance: u64, code_hash: Hash, storage_root: Hash) -> Self {
        Self {
            balance,
            nonce: 0,
            code_hash,
            storage_root,
        }
    }

    /// Check if account is a contract
    pub fn is_contract(&self) -> bool {
        !self.code_hash.is_zero()
    }

    /// Check if account exists (has non-zero balance or nonce)
    pub fn exists(&self) -> bool {
        self.balance > 0 || self.nonce > 0 || !self.code_hash.is_zero()
    }

    /// Apply balance change
    pub fn apply_balance_change(&mut self, change: i64) -> Result<(), String> {
        if change < 0 {
            let decrease = (-change) as u64;
            if self.balance < decrease {
                return Err("Insufficient balance".to_string());
            }
            self.balance -= decrease;
        } else {
            self.balance += change as u64;
        }
        Ok(())
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self) {
        self.nonce += 1;
    }
}

impl GlobalState {
    /// Create new global state
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            state_root: Arc::new(RwLock::new(Hash::zero())),
            version: Arc::new(RwLock::new(0)),
        }
    }

    /// Get account state
    pub fn get_account(&self, address: &Address) -> Option<AccountState> {
        self.accounts.read().unwrap().get(address).cloned()
    }

    /// Set account state
    pub fn set_account(&self, address: Address, state: AccountState) {
        self.accounts.write().unwrap().insert(address, state);
    }

    /// Get account balance in ZERO units
    pub fn get_balance(&self, address: &Address) -> u64 {
        self.get_account(address).map(|acc| acc.balance).unwrap_or(0)
    }

    /// Get account balance in POAR units
    pub fn get_balance_poar(&self, address: &Address) -> Poar {
        let balance_in_zero = self.get_balance(address);
        Zero::new(balance_in_zero).to_poar()
    }

    /// Get account balance in PROOF units
    pub fn get_balance_proof(&self, address: &Address) -> Proof {
        let balance_in_zero = self.get_balance(address);
        Zero::new(balance_in_zero).to_proof()
    }

    /// Get account balance in VALID units
    pub fn get_balance_valid(&self, address: &Address) -> Valid {
        let balance_in_zero = self.get_balance(address);
        Zero::new(balance_in_zero).to_valid()
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> u64 {
        self.get_account(address).map(|acc| acc.nonce).unwrap_or(0)
    }

    /// Check if account exists
    pub fn account_exists(&self, address: &Address) -> bool {
        self.get_account(address).map(|acc| acc.exists()).unwrap_or(false)
    }

    /// Create new account
    pub fn create_account(&self, address: Address, initial_balance: u64) {
        let account_state = AccountState::new(initial_balance);
        self.set_account(address, account_state);
    }

    /// Transfer value between accounts
    pub fn transfer(&self, from: &Address, to: &Address, amount: u64) -> Result<StateChanges, String> {
        let mut changes = StateChanges::default();

        // Get sender account
        let mut sender = self.get_account(from).ok_or("Sender account not found")?;
        if sender.balance < amount {
            return Err("Insufficient balance".to_string());
        }

        // Get or create receiver account
        let mut receiver = self.get_account(to).unwrap_or_else(|| AccountState::new(0));

        // Apply transfer
        sender.balance -= amount;
        receiver.balance += amount;

        // Update accounts
        self.set_account(*from, sender);
        self.set_account(*to, receiver);

        // Record changes
        changes.balance_changes.insert(*from, -(amount as i64));
        changes.balance_changes.insert(*to, amount as i64);

        Ok(changes)
    }

    /// Apply transaction to state
    pub fn apply_transaction(&self, tx: &Transaction) -> StateTransitionResult {
        let mut changes = StateChanges::default();

        // Get sender account
        let sender_account = match self.get_account(&tx.from) {
            Some(account) => account,
            None => return StateTransitionResult::AccountNotFound,
        };

        // Validate nonce
        if tx.nonce != sender_account.nonce {
            return StateTransitionResult::InvalidNonce;
        }

        // Calculate total cost (amount + fee)
        let total_cost = tx.amount + tx.fee;
        if sender_account.balance < total_cost {
            return StateTransitionResult::InsufficientBalance;
        }

        // Apply transaction based on type
        match tx.tx_type {
            crate::types::TransactionType::Transfer => {
                // Standard transfer
                match self.transfer(&tx.from, &tx.to, tx.amount) {
                    Ok(mut transfer_changes) => {
                        changes.balance_changes.extend(transfer_changes.balance_changes);
                        
                        // Apply fee (send to validator/burn)
                        if let Some(sender_change) = changes.balance_changes.get_mut(&tx.from) {
                            *sender_change -= tx.fee as i64;
                        }
                        
                        // Increment sender nonce
                        let mut sender = self.get_account(&tx.from).unwrap();
                        sender.increment_nonce();
                        self.set_account(tx.from, sender);
                        changes.nonce_updates.insert(tx.from, sender_account.nonce + 1);
                        
                        changes.gas_used = tx.gas_limit; // Simplified
                        StateTransitionResult::Success(changes)
                    }
                    Err(_) => StateTransitionResult::InsufficientBalance,
                }
            }
            crate::types::TransactionType::ValidatorStaking => {
                // Staking transaction - lock tokens for validation
                let mut sender = sender_account.clone();
                if sender.balance < total_cost {
                    return StateTransitionResult::InsufficientBalance;
                }

                sender.balance -= total_cost;
                sender.increment_nonce();
                self.set_account(tx.from, sender);

                changes.balance_changes.insert(tx.from, -(total_cost as i64));
                changes.nonce_updates.insert(tx.from, sender_account.nonce + 1);
                changes.gas_used = tx.gas_limit;

                StateTransitionResult::Success(changes)
            }
            _ => {
                // Other transaction types (contracts, etc.) - simplified
                changes.gas_used = tx.gas_limit;
                StateTransitionResult::Success(changes)
            }
        }
    }

    /// Calculate state root hash
    pub fn calculate_state_root(&self) -> Hash {
        let accounts = self.accounts.read().unwrap();
        let mut state_data = Vec::new();

        // Sort accounts by address for deterministic hash
        let mut sorted_accounts: Vec<_> = accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| addr.as_bytes());

        for (address, account) in sorted_accounts {
            state_data.extend_from_slice(address.as_bytes());
            state_data.extend_from_slice(&account.balance.to_le_bytes());
            state_data.extend_from_slice(&account.nonce.to_le_bytes());
            state_data.extend_from_slice(account.code_hash.as_bytes());
            state_data.extend_from_slice(account.storage_root.as_bytes());
        }

        let state_root = Hash::hash(&state_data);
        *self.state_root.write().unwrap() = state_root;
        state_root
    }

    /// Get current state root
    pub fn get_state_root(&self) -> Hash {
        *self.state_root.read().unwrap()
    }

    /// Get current version
    pub fn get_version(&self) -> u64 {
        *self.version.read().unwrap()
    }

    /// Increment version
    pub fn increment_version(&self) {
        *self.version.write().unwrap() += 1;
    }

    /// Get total supply
    pub fn get_total_supply(&self) -> u64 {
        self.accounts.read().unwrap().values().map(|acc| acc.balance).sum()
    }

    /// Get account count
    pub fn get_account_count(&self) -> usize {
        self.accounts.read().unwrap().len()
    }
}

impl StateManager {
    /// Create new state manager
    pub fn new() -> Self {
        Self {
            state: GlobalState::new(),
            state_history: Vec::new(),
            max_history_size: 1000, // Keep last 1000 states
        }
    }

    /// Execute transaction and update state
    pub fn execute_transaction(&mut self, tx: &Transaction) -> StateTransitionResult {
        // Save current state to history
        self.save_state_to_history();

        // Apply transaction
        let result = self.state.apply_transaction(tx);

        match result {
            StateTransitionResult::Success(_) => {
                // Update state root
                self.state.calculate_state_root();
                self.state.increment_version();
                println!("✅ Transaction executed: {}", &tx.hash.to_hex()[..8]);
            }
            _ => {
                // Rollback on failure
                self.rollback_to_previous_state();
                println!("❌ Transaction failed: {}", &tx.hash.to_hex()[..8]);
            }
        }

        result
    }

    /// Execute multiple transactions in batch
    pub fn execute_batch(&mut self, transactions: &[Transaction]) -> Vec<StateTransitionResult> {
        let mut results = Vec::new();
        
        for tx in transactions {
            let result = self.execute_transaction(tx);
            results.push(result);
        }

        results
    }

    /// Save current state to history
    fn save_state_to_history(&mut self) {
        let current_version = self.state.get_version();
        let accounts = self.state.accounts.read().unwrap().clone();
        
        self.state_history.push((current_version, accounts));

        // Maintain history size limit
        if self.state_history.len() > self.max_history_size {
            self.state_history.remove(0);
        }
    }

    /// Rollback to previous state
    fn rollback_to_previous_state(&mut self) {
        if let Some((version, accounts)) = self.state_history.pop() {
            *self.state.accounts.write().unwrap() = accounts;
            *self.state.version.write().unwrap() = version;
            self.state.calculate_state_root();
            println!("🔄 Rolled back to state version {}", version);
        }
    }

    /// Get current state
    pub fn get_state(&self) -> &GlobalState {
        &self.state
    }

    /// Get state statistics
    pub fn get_stats(&self) -> StateStats {
        StateStats {
            total_accounts: self.state.get_account_count(),
            total_supply: self.state.get_total_supply(),
            state_version: self.state.get_version(),
            state_root: self.state.get_state_root(),
            history_size: self.state_history.len(),
        }
    }
}

/// State statistics
#[derive(Debug, Clone)]
pub struct StateStats {
    pub total_accounts: usize,
    pub total_supply: u64,
    pub state_version: u64,
    pub state_root: Hash,
    pub history_size: usize,
}

impl StateTrie {
    /// Create new state trie
    pub fn new() -> Self {
        Self {
            root: None,
            cache: HashMap::new(),
        }
    }

    /// Insert account into trie
    pub fn insert(&mut self, address: Address, account: AccountState) -> Hash {
        // Simplified trie insertion - in production would use proper Patricia trie
        let key = address.as_bytes().to_vec();
        let leaf = TrieNode {
            hash: Hash::hash(&[&key, &bincode::serialize(&account).unwrap()].concat()),
            data: TrieNodeData::Leaf { key, value: account },
        };
        
        let hash = leaf.hash;
        self.cache.insert(hash, leaf);
        hash
    }

    /// Get account from trie
    pub fn get(&self, address: &Address) -> Option<AccountState> {
        let key = address.as_bytes();
        
        // Simplified lookup - would traverse trie in production
        for node in self.cache.values() {
            if let TrieNodeData::Leaf { key: node_key, value } = &node.data {
                if node_key == key {
                    return Some(value.clone());
                }
            }
        }
        
        None
    }

    /// Calculate trie root hash
    pub fn calculate_root(&self) -> Hash {
        if self.cache.is_empty() {
            return Hash::zero();
        }

        // Simplified root calculation
        let mut all_hashes = Vec::new();
        for node in self.cache.values() {
            all_hashes.push(node.hash);
        }
        
        all_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Hash::hash_multiple(&all_hashes.iter().map(|h| h.as_bytes()).collect::<Vec<_>>())
    }
}

impl Default for GlobalState {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TransactionType;

    #[test]
    fn test_account_state() {
        let mut account = AccountState::new(1000);
        assert_eq!(account.balance, 1000);
        assert_eq!(account.nonce, 0);
        assert!(!account.is_contract());

        account.increment_nonce();
        assert_eq!(account.nonce, 1);

        assert!(account.apply_balance_change(-500).is_ok());
        assert_eq!(account.balance, 500);
    }

    #[test]
    fn test_state_transfer() {
        let state = GlobalState::new();
        let from = Address::from_bytes([1u8; 20]).unwrap();
        let to = Address::from_bytes([2u8; 20]).unwrap();

        // Create accounts
        state.create_account(from, 1000);
        state.create_account(to, 0);

        // Transfer
        let result = state.transfer(&from, &to, 500);
        assert!(result.is_ok());

        assert_eq!(state.get_balance(&from), 500);
        assert_eq!(state.get_balance(&to), 500);
    }

    #[test]
    fn test_state_manager() {
        let mut manager = StateManager::new();
        let from = Address::from_bytes([1u8; 20]).unwrap();
        let to = Address::from_bytes([2u8; 20]).unwrap();

        // Setup accounts
        manager.state.create_account(from, 1000);
        manager.state.create_account(to, 0);

        // Create transaction
        let tx = Transaction::new(
            from,
            to,
            500,
            50,
            21000,
            1_000_000,
            0,
            Vec::new(),
            TransactionType::Transfer,
        );

        // Execute transaction
        let result = manager.execute_transaction(&tx);
        assert!(matches!(result, StateTransitionResult::Success(_)));

        assert_eq!(manager.state.get_balance(&from), 450); // 1000 - 500 - 50
        assert_eq!(manager.state.get_balance(&to), 500);
        assert_eq!(manager.state.get_nonce(&from), 1);
    }
}
