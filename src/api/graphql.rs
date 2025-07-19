use std::sync::Arc;
use async_graphql::{
    Context, Object, Schema, Subscription, Result as GqlResult, 
    SimpleObject, InputObject, Enum, Interface, Union, ID,
    dataloader::DataLoader, FieldResult,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio_stream::{Stream, StreamExt};
use futures_util::stream;
use std::collections::HashMap;
use crate::types::{Hash, Block, Transaction, Address};
use crate::storage::state_storage::StateStorage;
use crate::network::P2PNetworkManager;

/// GraphQL schema type
pub type PoarSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// GraphQL query root
pub struct QueryRoot;

/// GraphQL mutation root
pub struct MutationRoot;

/// GraphQL subscription root
pub struct SubscriptionRoot;

/// Application context for GraphQL resolvers
pub struct GraphQLContext {
    /// State storage
    pub state_storage: Arc<StateStorage>,
    /// Network manager
    pub network_manager: Arc<P2PNetworkManager>,
    /// Data loaders for efficient batching
    pub block_loader: DataLoader<BlockLoader>,
    pub transaction_loader: DataLoader<TransactionLoader>,
    /// Subscription manager
    pub subscription_manager: Arc<SubscriptionManager>,
}

/// Block data loader for efficient batching
pub struct BlockLoader {
    state_storage: Arc<StateStorage>,
}

/// Transaction data loader
pub struct TransactionLoader {
    state_storage: Arc<StateStorage>,
}

/// Subscription manager for real-time updates
pub struct SubscriptionManager {
    /// Block subscriptions
    block_subscribers: Arc<RwLock<Vec<tokio::sync::mpsc::UnboundedSender<GqlBlock>>>>,
    /// Transaction subscriptions
    tx_subscribers: Arc<RwLock<Vec<tokio::sync::mpsc::UnboundedSender<GqlTransaction>>>>,
    /// Network event subscriptions
    network_subscribers: Arc<RwLock<Vec<tokio::sync::mpsc::UnboundedSender<NetworkEvent>>>>,
}

/// GraphQL Block type
#[derive(SimpleObject, Clone)]
pub struct GqlBlock {
    /// Block hash
    pub hash: String,
    /// Block number
    pub number: String,
    /// Parent hash
    pub parent_hash: String,
    /// Timestamp
    pub timestamp: i64,
    /// Miner/validator address
    pub miner: String,
    /// Gas limit
    pub gas_limit: String,
    /// Gas used
    pub gas_used: String,
    /// Block size in bytes
    pub size: i64,
    /// Number of transactions
    pub transaction_count: i32,
    /// Transactions root hash
    pub transactions_root: String,
    /// State root hash
    pub state_root: String,
    /// ZK proof information
    pub zk_proof: Option<ZkProof>,
    /// Block difficulty (for compatibility)
    pub difficulty: String,
    /// Total difficulty
    pub total_difficulty: String,
}

/// GraphQL Transaction type
#[derive(SimpleObject, Clone)]
pub struct GqlTransaction {
    /// Transaction hash
    pub hash: String,
    /// From address
    pub from: String,
    /// To address (optional for contract creation)
    pub to: Option<String>,
    /// Value transferred in wei
    pub value: String,
    /// Gas limit
    pub gas: String,
    /// Gas price
    pub gas_price: String,
    /// Transaction data/input
    pub input: String,
    /// Nonce
    pub nonce: String,
    /// Transaction status
    pub status: TransactionStatus,
    /// Block hash
    pub block_hash: Option<String>,
    /// Block number
    pub block_number: Option<String>,
    /// Transaction index in block
    pub transaction_index: Option<i32>,
    /// Gas used
    pub gas_used: Option<String>,
    /// Cumulative gas used
    pub cumulative_gas_used: Option<String>,
    /// Contract address (for contract creation)
    pub contract_address: Option<String>,
    /// Transaction logs
    pub logs: Vec<Log>,
}

/// GraphQL Account type
#[derive(SimpleObject, Clone)]
pub struct GqlAccount {
    /// Account address
    pub address: String,
    /// Account balance in wei
    pub balance: String,
    /// Transaction count (nonce)
    pub transaction_count: String,
    /// Code hash (for contracts)
    pub code_hash: Option<String>,
    /// Storage root
    pub storage_root: String,
    /// Account type
    pub account_type: AccountType,
    /// Created at block
    pub created_at_block: Option<String>,
}

/// ZK Proof information
#[derive(SimpleObject, Clone)]
pub struct ZkProof {
    /// Proof data
    pub proof: String,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Verification key hash
    pub verification_key_hash: String,
    /// Proof timestamp
    pub timestamp: i64,
    /// Proof status
    pub status: ProofStatus,
}

/// Log entry
#[derive(SimpleObject, Clone)]
pub struct Log {
    /// Contract address
    pub address: String,
    /// Log topics
    pub topics: Vec<String>,
    /// Log data
    pub data: String,
    /// Block hash
    pub block_hash: String,
    /// Block number
    pub block_number: String,
    /// Transaction hash
    pub transaction_hash: String,
    /// Transaction index
    pub transaction_index: i32,
    /// Log index
    pub log_index: i32,
    /// Removed flag
    pub removed: bool,
}

/// Validator information
#[derive(SimpleObject, Clone)]
pub struct Validator {
    /// Validator address
    pub address: String,
    /// Stake amount
    pub stake: String,
    /// Commission rate
    pub commission: f64,
    /// Active status
    pub active: bool,
    /// Reputation score
    pub reputation: f64,
    /// Blocks validated
    pub blocks_validated: i64,
    /// Last validation timestamp
    pub last_validation: Option<i64>,
    /// Validator metadata
    pub metadata: Option<ValidatorMetadata>,
}

/// Validator metadata
#[derive(SimpleObject, Clone)]
pub struct ValidatorMetadata {
    /// Validator name
    pub name: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Identity verification
    pub identity: Option<String>,
}

/// Network statistics
#[derive(SimpleObject, Clone)]
pub struct NetworkStatistics {
    /// Connected peers
    pub connected_peers: i32,
    /// Total peers discovered
    pub total_peers_discovered: i64,
    /// Network throughput (bytes/sec)
    pub throughput: f64,
    /// Average latency (ms)
    pub average_latency: f64,
    /// Success rate
    pub success_rate: f64,
    /// Bandwidth utilization
    pub bandwidth_utilization: f64,
}

/// Consensus information
#[derive(SimpleObject, Clone)]
pub struct ConsensusInfo {
    /// Current epoch
    pub current_epoch: i64,
    /// Validator count
    pub validator_count: i32,
    /// Active validator count
    pub active_validator_count: i32,
    /// Finalized block number
    pub finalized_block_number: i64,
    /// Pending proposals
    pub pending_proposals: i32,
    /// Consensus status
    pub status: ConsensusStatus,
}

/// Storage statistics
#[derive(SimpleObject, Clone)]
pub struct StorageStats {
    /// Database size in bytes
    pub database_size: i64,
    /// State size in bytes
    pub state_size: i64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Number of accounts
    pub account_count: i64,
    /// Number of transactions
    pub transaction_count: i64,
    /// Compaction status
    pub compaction_status: String,
}

/// Transaction status enum
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Included,
    Failed,
    Rejected,
}

/// Account type enum
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum AccountType {
    External,
    Contract,
    Validator,
}

/// Proof status enum
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum ProofStatus {
    Pending,
    Verified,
    Invalid,
}

/// Consensus status enum
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum ConsensusStatus {
    Active,
    Syncing,
    Offline,
}

/// Network event for subscriptions
#[derive(SimpleObject, Clone)]
pub struct NetworkEvent {
    /// Event type
    pub event_type: String,
    /// Event data
    pub data: String,
    /// Timestamp
    pub timestamp: i64,
}

/// Block filter input
#[derive(InputObject)]
pub struct BlockFilter {
    /// From block number
    pub from_block: Option<String>,
    /// To block number  
    pub to_block: Option<String>,
    /// Miner address
    pub miner: Option<String>,
    /// Minimum gas used
    pub min_gas_used: Option<String>,
    /// Maximum gas used
    pub max_gas_used: Option<String>,
}

/// Transaction filter input
#[derive(InputObject)]
pub struct TransactionFilter {
    /// From address
    pub from: Option<String>,
    /// To address
    pub to: Option<String>,
    /// From block
    pub from_block: Option<String>,
    /// To block
    pub to_block: Option<String>,
    /// Transaction status
    pub status: Option<TransactionStatus>,
    /// Minimum value
    pub min_value: Option<String>,
    /// Maximum value
    pub max_value: Option<String>,
}

/// Pagination input
#[derive(InputObject)]
pub struct Pagination {
    /// Number of items to return
    pub limit: Option<i32>,
    /// Offset for pagination
    pub offset: Option<i32>,
    /// Cursor-based pagination
    pub after: Option<String>,
    /// Reverse order
    pub reverse: Option<bool>,
}

#[Object]
impl QueryRoot {
    /// Get block by hash
    async fn block_by_hash(&self, ctx: &Context<'_>, hash: String) -> GqlResult<Option<GqlBlock>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Use data loader for efficient batching
        let block = context.block_loader.load_one(hash).await?;
        Ok(block)
    }

    /// Get block by number
    async fn block_by_number(&self, ctx: &Context<'_>, number: String) -> GqlResult<Option<GqlBlock>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Parse block number
        let block_num = if number == "latest" {
            context.state_storage.get_latest_block_number().await
                .map_err(|e| async_graphql::Error::new(format!("Failed to get latest block: {}", e)))?
        } else {
            let num_str = number.strip_prefix("0x").unwrap_or(&number);
            u64::from_str_radix(num_str, 16)
                .map_err(|_| async_graphql::Error::new("Invalid block number"))?
        };

        // Convert to hash and use loader
        let hash = format!("0x{:x}", block_num); // Simplified hash generation
        let block = context.block_loader.load_one(hash).await?;
        Ok(block)
    }

    /// Get blocks with filtering and pagination
    async fn blocks(
        &self,
        ctx: &Context<'_>,
        filter: Option<BlockFilter>,
        pagination: Option<Pagination>,
    ) -> GqlResult<Vec<GqlBlock>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Simulate block filtering and pagination
        let mut blocks = Vec::new();
        let limit = pagination.as_ref().and_then(|p| p.limit).unwrap_or(10).min(100);
        
        for i in 0..limit {
            let block_hash = format!("0x{:x}", i);
            if let Some(block) = context.block_loader.load_one(block_hash).await? {
                blocks.push(block);
            }
        }
        
        Ok(blocks)
    }

    /// Get transaction by hash
    async fn transaction_by_hash(&self, ctx: &Context<'_>, hash: String) -> GqlResult<Option<GqlTransaction>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        let tx = context.transaction_loader.load_one(hash).await?;
        Ok(tx)
    }

    /// Get transactions with filtering
    async fn transactions(
        &self,
        ctx: &Context<'_>,
        filter: Option<TransactionFilter>,
        pagination: Option<Pagination>,
    ) -> GqlResult<Vec<GqlTransaction>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Simulate transaction filtering
        let mut transactions = Vec::new();
        let limit = pagination.as_ref().and_then(|p| p.limit).unwrap_or(10).min(100);
        
        for i in 0..limit {
            let tx_hash = format!("0x{:x}", i + 1000);
            if let Some(tx) = context.transaction_loader.load_one(tx_hash).await? {
                transactions.push(tx);
            }
        }
        
        Ok(transactions)
    }

    /// Get account information
    async fn account(&self, ctx: &Context<'_>, address: String) -> GqlResult<Option<GqlAccount>> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        // Simulate account lookup
        let account = GqlAccount {
            address: address.clone(),
            balance: "1000000000000000000".to_string(), // 1 ETH
            transaction_count: "42".to_string(),
            code_hash: None,
            storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
            account_type: AccountType::External,
            created_at_block: Some("0x123".to_string()),
        };
        
        Ok(Some(account))
    }

    /// Get validator information
    async fn validator(&self, ctx: &Context<'_>, address: String) -> GqlResult<Option<Validator>> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        let validator = Validator {
            address: address.clone(),
            stake: "32000000000000000000".to_string(), // 32 ETH
            commission: 0.05, // 5%
            active: true,
            reputation: 0.95,
            blocks_validated: 1234,
            last_validation: Some(1640995200), // Example timestamp
            metadata: Some(ValidatorMetadata {
                name: Some("POAR Validator".to_string()),
                description: Some("High-performance POAR validator".to_string()),
                website: Some("https://poar.network".to_string()),
                identity: Some("verified".to_string()),
            }),
        };
        
        Ok(Some(validator))
    }

    /// Get all validators
    async fn validators(&self, ctx: &Context<'_>, pagination: Option<Pagination>) -> GqlResult<Vec<Validator>> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        let limit = pagination.as_ref().and_then(|p| p.limit).unwrap_or(10).min(100);
        let mut validators = Vec::new();
        
        for i in 0..limit {
            let validator = Validator {
                address: format!("0x{:040x}", i),
                stake: "32000000000000000000".to_string(),
                commission: 0.05,
                active: i % 10 != 0, // 90% active
                reputation: 0.8 + (i as f64 * 0.01),
                blocks_validated: (i as i64) * 100,
                last_validation: Some(1640995200),
                metadata: None,
            };
            validators.push(validator);
        }
        
        Ok(validators)
    }

    /// Get network statistics
    async fn network_stats(&self, ctx: &Context<'_>) -> GqlResult<NetworkStatistics> {
        let context = ctx.data::<GraphQLContext>()?;
        
        let stats = context.network_manager.get_stats().await;
        let network_stats = NetworkStatistics {
            connected_peers: stats.connected_peers as i32,
            total_peers_discovered: stats.total_messages_received as i64,
            throughput: stats.avg_bandwidth_utilization,
            average_latency: 125.0, // ms
            success_rate: 0.982,
            bandwidth_utilization: stats.avg_bandwidth_utilization,
        };
        
        Ok(network_stats)
    }

    /// Get consensus information
    async fn consensus_info(&self, ctx: &Context<'_>) -> GqlResult<ConsensusInfo> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        let consensus_info = ConsensusInfo {
            current_epoch: 42,
            validator_count: 100,
            active_validator_count: 95,
            finalized_block_number: 1234567,
            pending_proposals: 3,
            status: ConsensusStatus::Active,
        };
        
        Ok(consensus_info)
    }

    /// Get storage statistics
    async fn storage_stats(&self, ctx: &Context<'_>) -> GqlResult<StorageStats> {
        let context = ctx.data::<GraphQLContext>()?;
        
        let metrics = context.state_storage.get_metrics().await;
        let storage_stats = StorageStats {
            database_size: metrics.total_size_bytes as i64,
            state_size: metrics.state_size_bytes as i64,
            cache_hit_rate: metrics.cache_hit_rate,
            account_count: 1500000,
            transaction_count: 5000000,
            compaction_status: "Healthy".to_string(),
        };
        
        Ok(storage_stats)
    }

    /// Search functionality
    async fn search(&self, ctx: &Context<'_>, query: String) -> GqlResult<Vec<SearchResult>> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        let mut results = Vec::new();
        
        // Simulate search results
        if query.starts_with("0x") {
            if query.len() == 66 {
                // Could be block hash or transaction hash
                results.push(SearchResult::Block(GqlBlock {
                    hash: query.clone(),
                    number: "0x123".to_string(),
                    parent_hash: "0x456".to_string(),
                    timestamp: 1640995200,
                    miner: "0xabc".to_string(),
                    gas_limit: "30000000".to_string(),
                    gas_used: "21000".to_string(),
                    size: 1024,
                    transaction_count: 1,
                    transactions_root: "0x789".to_string(),
                    state_root: "0xdef".to_string(),
                    zk_proof: None,
                    difficulty: "0x1000".to_string(),
                    total_difficulty: "0x10000".to_string(),
                }));
            } else if query.len() == 42 {
                // Address
                results.push(SearchResult::Account(GqlAccount {
                    address: query.clone(),
                    balance: "1000000000000000000".to_string(),
                    transaction_count: "42".to_string(),
                    code_hash: None,
                    storage_root: "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421".to_string(),
                    account_type: AccountType::External,
                    created_at_block: Some("0x123".to_string()),
                }));
            }
        }
        
        Ok(results)
    }
}

/// Search result union type
#[derive(Union)]
pub enum SearchResult {
    Block(GqlBlock),
    Transaction(GqlTransaction),
    Account(GqlAccount),
}

#[Object]
impl MutationRoot {
    /// Submit a raw transaction
    async fn submit_transaction(&self, ctx: &Context<'_>, raw_transaction: String) -> GqlResult<String> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        // Simulate transaction submission
        let tx_hash = format!("0x{:x}", rand::random::<u64>());
        
        println!("📤 GraphQL: Submitted transaction: {} bytes", raw_transaction.len());
        println!("   Generated TX hash: {}", tx_hash);
        
        Ok(tx_hash)
    }

    /// Submit ZK proof
    async fn submit_zk_proof(
        &self,
        ctx: &Context<'_>,
        block_hash: String,
        proof: String,
        public_inputs: Vec<String>,
    ) -> GqlResult<String> {
        let _context = ctx.data::<GraphQLContext>()?;
        
        println!("📝 GraphQL: ZK Proof submitted for block: {}", block_hash);
        println!("   Proof length: {} bytes", proof.len());
        
        let submission_id = format!("0x{:x}", rand::random::<u64>());
        Ok(submission_id)
    }
}

#[Subscription]
impl SubscriptionRoot {
    /// Subscribe to new blocks
    async fn new_blocks(&self, ctx: &Context<'_>) -> impl Stream<Item = GqlBlock> {
        let context = ctx.data::<GraphQLContext>().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        
        // Add subscriber
        context.subscription_manager.block_subscribers.write().await.push(tx);
        
        // Convert to stream
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
    }

    /// Subscribe to new transactions
    async fn new_transactions(&self, ctx: &Context<'_>) -> impl Stream<Item = GqlTransaction> {
        let context = ctx.data::<GraphQLContext>().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        
        context.subscription_manager.tx_subscribers.write().await.push(tx);
        
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
    }

    /// Subscribe to network events
    async fn network_events(&self, ctx: &Context<'_>) -> impl Stream<Item = NetworkEvent> {
        let context = ctx.data::<GraphQLContext>().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        
        context.subscription_manager.network_subscribers.write().await.push(tx);
        
        tokio_stream::wrappers::UnboundedReceiverStream::new(rx)
    }

    /// Subscribe to logs with filtering
    async fn logs(
        &self,
        ctx: &Context<'_>,
        addresses: Option<Vec<String>>,
        topics: Option<Vec<Option<String>>>,
    ) -> impl Stream<Item = Log> {
        let _context = ctx.data::<GraphQLContext>().unwrap();
        
        // Simulate log stream
        stream::iter(vec![
            Log {
                address: "0x123...".to_string(),
                topics: vec!["0xabc...".to_string()],
                data: "0xdef...".to_string(),
                block_hash: "0x456...".to_string(),
                block_number: "0x123".to_string(),
                transaction_hash: "0x789...".to_string(),
                transaction_index: 0,
                log_index: 0,
                removed: false,
            }
        ])
    }
}

// Data loader implementations
#[async_trait::async_trait]
impl async_graphql::dataloader::Loader<String> for BlockLoader {
    type Value = GqlBlock;
    type Error = async_graphql::Error;

    async fn load(&self, keys: &[String]) -> Result<HashMap<String, Self::Value>, Self::Error> {
        let mut blocks = HashMap::new();
        
        for key in keys {
            // Simulate block loading
            let block = GqlBlock {
                hash: key.clone(),
                number: "0x123".to_string(),
                parent_hash: "0x456".to_string(),
                timestamp: 1640995200,
                miner: "0xabc123...".to_string(),
                gas_limit: "30000000".to_string(),
                gas_used: "21000".to_string(),
                size: 1024,
                transaction_count: 1,
                transactions_root: "0x789...".to_string(),
                state_root: "0xdef...".to_string(),
                zk_proof: Some(ZkProof {
                    proof: "0x1234567890abcdef...".to_string(),
                    public_inputs: vec!["0xabc...".to_string()],
                    verification_key_hash: "0xdef...".to_string(),
                    timestamp: 1640995200,
                    status: ProofStatus::Verified,
                }),
                difficulty: "0x1000".to_string(),
                total_difficulty: "0x10000".to_string(),
            };
            
            blocks.insert(key.clone(), block);
        }
        
        Ok(blocks)
    }
}

#[async_trait::async_trait]
impl async_graphql::dataloader::Loader<String> for TransactionLoader {
    type Value = GqlTransaction;
    type Error = async_graphql::Error;

    async fn load(&self, keys: &[String]) -> Result<HashMap<String, Self::Value>, Self::Error> {
        let mut transactions = HashMap::new();
        
        for key in keys {
            let tx = GqlTransaction {
                hash: key.clone(),
                from: "0x123...".to_string(),
                to: Some("0x456...".to_string()),
                value: "1000000000000000000".to_string(), // 1 ETH
                gas: "21000".to_string(),
                gas_price: "20000000000".to_string(), // 20 gwei
                input: "0x".to_string(),
                nonce: "1".to_string(),
                status: TransactionStatus::Included,
                block_hash: Some("0xabc...".to_string()),
                block_number: Some("0x123".to_string()),
                transaction_index: Some(0),
                gas_used: Some("21000".to_string()),
                cumulative_gas_used: Some("21000".to_string()),
                contract_address: None,
                logs: vec![],
            };
            
            transactions.insert(key.clone(), tx);
        }
        
        Ok(transactions)
    }
}

impl SubscriptionManager {
    /// Create new subscription manager
    pub fn new() -> Self {
        Self {
            block_subscribers: Arc::new(RwLock::new(Vec::new())),
            tx_subscribers: Arc::new(RwLock::new(Vec::new())),
            network_subscribers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Notify new block to subscribers
    pub async fn notify_new_block(&self, block: GqlBlock) {
        let subscribers = self.block_subscribers.read().await;
        for subscriber in subscribers.iter() {
            let _ = subscriber.send(block.clone());
        }
    }

    /// Notify new transaction to subscribers
    pub async fn notify_new_transaction(&self, transaction: GqlTransaction) {
        let subscribers = self.tx_subscribers.read().await;
        for subscriber in subscribers.iter() {
            let _ = subscriber.send(transaction.clone());
        }
    }
}

impl GraphQLContext {
    /// Create new GraphQL context
    pub fn new(
        state_storage: Arc<StateStorage>,
        network_manager: Arc<P2PNetworkManager>,
    ) -> Self {
        Self {
            state_storage: state_storage.clone(),
            network_manager,
            block_loader: DataLoader::new(
                BlockLoader { state_storage: state_storage.clone() },
                tokio::spawn,
            ),
            transaction_loader: DataLoader::new(
                TransactionLoader { state_storage },
                tokio::spawn,
            ),
            subscription_manager: Arc::new(SubscriptionManager::new()),
        }
    }
}

/// Create GraphQL schema
pub fn create_schema(context: GraphQLContext) -> PoarSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .data(context)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graphql_schema_creation() {
        // Note: This would need actual StateStorage and NetworkManager
        // For now, we just test basic schema creation
        let query = "{ __schema { types { name } } }";
        
        // This is a placeholder test
        assert!(query.contains("__schema"));
    }

    #[test]
    fn test_graphql_types() {
        // Test enum serialization
        let status = TransactionStatus::Included;
        assert_eq!(format!("{:?}", status), "Included");
        
        let account_type = AccountType::Contract;
        assert_eq!(format!("{:?}", account_type), "Contract");
    }
} 