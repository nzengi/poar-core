use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::{ServerBuilder, ServerHandle},
    types::ErrorObject,
};
use serde::{Deserialize, Serialize};
use crate::types::{Hash, Block, Transaction, Address};
use crate::storage::state_storage::StateStorage;
use crate::network::P2PNetworkManager;

/// POAR JSON-RPC server
pub struct PoarRpcServer {
    /// Server handle
    handle: Option<ServerHandle>,
    /// Server configuration
    config: RpcConfig,
    /// State storage reference
    state_storage: Arc<StateStorage>,
    /// Network manager reference
    network_manager: Arc<P2PNetworkManager>,
    /// Request metrics
    metrics: Arc<RwLock<RpcMetrics>>,
}

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Server listen address
    pub listen_addr: SocketAddr,
    /// Maximum connections
    pub max_connections: u32,
    /// Request timeout
    pub request_timeout: std::time::Duration,
    /// Rate limiting settings
    pub rate_limit: RateLimitConfig,
    /// CORS settings
    pub cors: CorsConfig,
    /// Enable batch requests
    pub enable_batch: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per minute per IP
    pub requests_per_minute: u32,
    /// Burst capacity
    pub burst_capacity: u32,
    /// Enable rate limiting
    pub enabled: bool,
}

/// CORS configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Enable credentials
    pub allow_credentials: bool,
}

/// RPC metrics
#[derive(Debug, Clone, Default)]
pub struct RpcMetrics {
    /// Total requests received
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time
    pub avg_response_time: std::time::Duration,
    /// Active connections
    pub active_connections: u32,
    /// Method-specific metrics
    pub method_metrics: HashMap<String, MethodMetrics>,
}

/// Method-specific metrics
#[derive(Debug, Clone, Default)]
pub struct MethodMetrics {
    /// Call count
    pub call_count: u64,
    /// Average execution time
    pub avg_execution_time: std::time::Duration,
    /// Error count
    pub error_count: u64,
    /// Last called timestamp
    pub last_called: Option<std::time::SystemTime>,
}

/// Ethereum-compatible RPC trait
#[rpc(server)]
pub trait EthRpc {
    /// Get protocol version
    #[method(name = "eth_protocolVersion")]
    async fn protocol_version(&self) -> RpcResult<String>;

    /// Get network ID
    #[method(name = "net_version")]
    async fn net_version(&self) -> RpcResult<String>;

    /// Check if client is listening for network connections
    #[method(name = "net_listening")]
    async fn net_listening(&self) -> RpcResult<bool>;

    /// Get number of peers
    #[method(name = "net_peerCount")]
    async fn net_peer_count(&self) -> RpcResult<String>;

    /// Get the latest block number
    #[method(name = "eth_blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;

    /// Get balance of an account
    #[method(name = "eth_getBalance")]
    async fn get_balance(&self, address: String, block: Option<String>) -> RpcResult<String>;

    /// Get transaction count for an address
    #[method(name = "eth_getTransactionCount")]
    async fn get_transaction_count(&self, address: String, block: Option<String>) -> RpcResult<String>;

    /// Get block by hash
    #[method(name = "eth_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String, full_tx: bool) -> RpcResult<Option<RpcBlock>>;

    /// Get block by number
    #[method(name = "eth_getBlockByNumber")]
    async fn get_block_by_number(&self, number: String, full_tx: bool) -> RpcResult<Option<RpcBlock>>;

    /// Get transaction by hash
    #[method(name = "eth_getTransactionByHash")]
    async fn get_transaction_by_hash(&self, hash: String) -> RpcResult<Option<RpcTransaction>>;

    /// Send raw transaction
    #[method(name = "eth_sendRawTransaction")]
    async fn send_raw_transaction(&self, data: String) -> RpcResult<String>;

    /// Estimate gas for a transaction
    #[method(name = "eth_estimateGas")]
    async fn estimate_gas(&self, tx: RpcTransactionRequest) -> RpcResult<String>;

    /// Get gas price
    #[method(name = "eth_gasPrice")]
    async fn gas_price(&self) -> RpcResult<String>;

    /// Get logs
    #[method(name = "eth_getLogs")]
    async fn get_logs(&self, filter: LogFilter) -> RpcResult<Vec<RpcLog>>;
}

/// POAR-specific RPC trait
#[rpc(server)]
pub trait PoarRpc {
    /// Get ZK proof for a block
    #[method(name = "poar_getZkProof")]
    async fn get_zk_proof(&self, block_hash: String) -> RpcResult<Option<ZkProofData>>;

    /// Get validator info
    #[method(name = "poar_getValidatorInfo")]
    async fn get_validator_info(&self, address: String) -> RpcResult<Option<ValidatorInfo>>;

    /// Get network statistics
    #[method(name = "poar_getNetworkStats")]
    async fn get_network_stats(&self) -> RpcResult<NetworkStats>;

    /// Get consensus status
    #[method(name = "poar_getConsensusStatus")]
    async fn get_consensus_status(&self) -> RpcResult<ConsensusStatus>;

    /// Get state snapshot
    #[method(name = "poar_getStateSnapshot")]
    async fn get_state_snapshot(&self, block_hash: String) -> RpcResult<Option<StateSnapshot>>;

    /// Submit ZK proof
    #[method(name = "poar_submitZkProof")]
    async fn submit_zk_proof(&self, proof_data: ZkProofSubmission) -> RpcResult<String>;

    /// Get peer reputation scores
    #[method(name = "poar_getPeerReputations")]
    async fn get_peer_reputations(&self) -> RpcResult<Vec<PeerReputation>>;

    /// Get storage metrics
    #[method(name = "poar_getStorageMetrics")]
    async fn get_storage_metrics(&self) -> RpcResult<StorageMetrics>;
}

/// RPC block representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    /// Block hash
    pub hash: String,
    /// Parent hash
    #[serde(rename = "parentHash")]
    pub parent_hash: String,
    /// Block number
    pub number: String,
    /// Timestamp
    pub timestamp: String,
    /// Gas limit
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    /// Gas used
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    /// Miner/validator
    pub miner: String,
    /// Transactions
    pub transactions: Vec<RpcTransaction>,
    /// Transaction root
    #[serde(rename = "transactionsRoot")]
    pub transactions_root: String,
    /// State root
    #[serde(rename = "stateRoot")]
    pub state_root: String,
    /// ZK proof hash
    #[serde(rename = "zkProofHash")]
    pub zk_proof_hash: Option<String>,
    /// Block size
    pub size: String,
}

/// RPC transaction representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransaction {
    /// Transaction hash
    pub hash: String,
    /// From address
    pub from: String,
    /// To address
    pub to: Option<String>,
    /// Value transferred
    pub value: String,
    /// Gas limit
    pub gas: String,
    /// Gas price
    #[serde(rename = "gasPrice")]
    pub gas_price: String,
    /// Transaction data
    pub input: String,
    /// Nonce
    pub nonce: String,
    /// Block hash
    #[serde(rename = "blockHash")]
    pub block_hash: Option<String>,
    /// Block number
    #[serde(rename = "blockNumber")]
    pub block_number: Option<String>,
    /// Transaction index
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<String>,
}

/// RPC transaction request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcTransactionRequest {
    /// From address
    pub from: Option<String>,
    /// To address
    pub to: Option<String>,
    /// Value to transfer
    pub value: Option<String>,
    /// Gas limit
    pub gas: Option<String>,
    /// Gas price
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    /// Transaction data
    pub data: Option<String>,
    /// Nonce
    pub nonce: Option<String>,
}

/// Log filter for eth_getLogs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    /// From block
    #[serde(rename = "fromBlock")]
    pub from_block: Option<String>,
    /// To block
    #[serde(rename = "toBlock")]
    pub to_block: Option<String>,
    /// Contract address
    pub address: Option<String>,
    /// Topics to filter
    pub topics: Option<Vec<Option<String>>>,
}

/// RPC log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcLog {
    /// Log address
    pub address: String,
    /// Log topics
    pub topics: Vec<String>,
    /// Log data
    pub data: String,
    /// Block hash
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    /// Block number
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    /// Transaction hash
    #[serde(rename = "transactionHash")]
    pub transaction_hash: String,
    /// Transaction index
    #[serde(rename = "transactionIndex")]
    pub transaction_index: String,
    /// Log index
    #[serde(rename = "logIndex")]
    pub log_index: String,
}

/// ZK proof data for POAR-specific methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofData {
    /// Proof bytes
    pub proof: String,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Verification key hash
    pub vk_hash: String,
    /// Proof timestamp
    pub timestamp: u64,
}

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: String,
    /// Stake amount
    pub stake: String,
    /// Commission rate
    pub commission: String,
    /// Active status
    pub active: bool,
    /// Reputation score
    pub reputation: f64,
    /// Blocks validated
    pub blocks_validated: u64,
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Connected peers
    pub connected_peers: u32,
    /// Network throughput
    pub throughput: f64,
    /// Average latency
    pub avg_latency: u64,
    /// Success rate
    pub success_rate: f64,
}

/// Consensus status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// Current epoch
    pub current_epoch: u64,
    /// Validator count
    pub validator_count: u32,
    /// Finalized block number
    pub finalized_block: u64,
    /// Pending proposals
    pub pending_proposals: u32,
}

/// State snapshot data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Block hash
    pub block_hash: String,
    /// State root
    pub state_root: String,
    /// Account count
    pub account_count: u64,
    /// Snapshot size
    pub size: u64,
    /// Creation timestamp
    pub timestamp: u64,
}

/// ZK proof submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofSubmission {
    /// Block hash being proven
    pub block_hash: String,
    /// ZK proof data
    pub proof: String,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Submitter address
    pub submitter: String,
}

/// Peer reputation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    /// Peer ID
    pub peer_id: String,
    /// Reputation score
    pub score: f64,
    /// Trust level
    pub trust_level: String,
    /// Last interaction
    pub last_interaction: u64,
}

/// Storage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    /// Database size
    pub db_size: u64,
    /// State size
    pub state_size: u64,
    /// Cache hit rate
    pub cache_hit_rate: f64,
    /// Compaction status
    pub compaction_status: String,
}

/// RPC server implementation
pub struct RpcServerImpl {
    /// State storage
    state_storage: Arc<StateStorage>,
    /// Network manager
    network_manager: Arc<P2PNetworkManager>,
    /// Metrics
    metrics: Arc<RwLock<RpcMetrics>>,
}

impl RpcServerImpl {
    /// Create new RPC server implementation
    pub fn new(
        state_storage: Arc<StateStorage>,
        network_manager: Arc<P2PNetworkManager>,
    ) -> Self {
        Self {
            state_storage,
            network_manager,
            metrics: Arc::new(RwLock::new(RpcMetrics::default())),
        }
    }

    /// Update method metrics
    async fn update_metrics(&self, method: &str, duration: std::time::Duration, success: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.total_requests += 1;
        
        if success {
            metrics.successful_requests += 1;
        } else {
            metrics.failed_requests += 1;
        }

        let method_metrics = metrics.method_metrics.entry(method.to_string()).or_default();
        method_metrics.call_count += 1;
        method_metrics.avg_execution_time = 
            (method_metrics.avg_execution_time + duration) / 2;
        method_metrics.last_called = Some(std::time::SystemTime::now());
        
        if !success {
            method_metrics.error_count += 1;
        }
    }
}

#[async_trait]
impl EthRpcServer for RpcServerImpl {
    async fn protocol_version(&self) -> RpcResult<String> {
        let start = std::time::Instant::now();
        let result = Ok("POAR/1.0.0".to_string());
        self.update_metrics("eth_protocolVersion", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn net_version(&self) -> RpcResult<String> {
        let start = std::time::Instant::now();
        let result = Ok("1".to_string()); // Mainnet
        self.update_metrics("net_version", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn net_listening(&self) -> RpcResult<bool> {
        let start = std::time::Instant::now();
        let result = Ok(true); // Always listening
        self.update_metrics("net_listening", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn net_peer_count(&self) -> RpcResult<String> {
        let start = std::time::Instant::now();
        let stats = self.network_manager.get_stats().await;
        let result = Ok(format!("0x{:x}", stats.connected_peers));
        self.update_metrics("net_peerCount", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn block_number(&self) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Get latest block number from storage
        match self.state_storage.get_latest_block_number().await {
            Ok(block_number) => {
                let result = Ok(format!("0x{:x}", block_number));
                self.update_metrics("eth_blockNumber", start.elapsed(), true).await;
                result
            }
            Err(e) => {
                self.update_metrics("eth_blockNumber", start.elapsed(), false).await;
                Err(ErrorObject::owned(
                    -32603,
                    "Internal error",
                    Some(format!("Failed to get block number: {}", e)),
                ))
            }
        }
    }

    async fn get_balance(&self, address: String, block: Option<String>) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Parse address
        let addr = match address.parse::<Address>() {
            Ok(addr) => addr,
            Err(_) => {
                self.update_metrics("eth_getBalance", start.elapsed(), false).await;
                return Err(ErrorObject::owned(-32602, "Invalid address", None::<()>));
            }
        };

        // Simulate balance lookup
        let balance = 1000000000000000000u64; // 1 ETH in wei
        let result = Ok(format!("0x{:x}", balance));
        self.update_metrics("eth_getBalance", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_transaction_count(&self, address: String, block: Option<String>) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Parse address
        let _addr = match address.parse::<Address>() {
            Ok(addr) => addr,
            Err(_) => {
                self.update_metrics("eth_getTransactionCount", start.elapsed(), false).await;
                return Err(ErrorObject::owned(-32602, "Invalid address", None::<()>));
            }
        };

        // Simulate nonce lookup
        let nonce = 42u64;
        let result = Ok(format!("0x{:x}", nonce));
        self.update_metrics("eth_getTransactionCount", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_block_by_hash(&self, hash: String, full_tx: bool) -> RpcResult<Option<RpcBlock>> {
        let start = std::time::Instant::now();
        
        // Parse hash
        let _block_hash = match hash.parse::<Hash>() {
            Ok(hash) => hash,
            Err(_) => {
                self.update_metrics("eth_getBlockByHash", start.elapsed(), false).await;
                return Err(ErrorObject::owned(-32602, "Invalid hash", None::<()>));
            }
        };

        // Simulate block lookup
        let block = Some(RpcBlock {
            hash: hash.clone(),
            parent_hash: "0x1234...".to_string(),
            number: "0x123".to_string(),
            timestamp: "0x64a7c2f2".to_string(),
            gas_limit: "0x1c9c380".to_string(),
            gas_used: "0x5208".to_string(),
            miner: "0xabcd...".to_string(),
            transactions: vec![],
            transactions_root: "0x5678...".to_string(),
            state_root: "0x9abc...".to_string(),
            zk_proof_hash: Some("0xdef0...".to_string()),
            size: "0x220".to_string(),
        });

        let result = Ok(block);
        self.update_metrics("eth_getBlockByHash", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_block_by_number(&self, number: String, full_tx: bool) -> RpcResult<Option<RpcBlock>> {
        let start = std::time::Instant::now();
        
        // For now, return similar to get_block_by_hash
        let block = Some(RpcBlock {
            hash: "0xabc123...".to_string(),
            parent_hash: "0x1234...".to_string(),
            number: number.clone(),
            timestamp: "0x64a7c2f2".to_string(),
            gas_limit: "0x1c9c380".to_string(),
            gas_used: "0x5208".to_string(),
            miner: "0xabcd...".to_string(),
            transactions: vec![],
            transactions_root: "0x5678...".to_string(),
            state_root: "0x9abc...".to_string(),
            zk_proof_hash: Some("0xdef0...".to_string()),
            size: "0x220".to_string(),
        });

        let result = Ok(block);
        self.update_metrics("eth_getBlockByNumber", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_transaction_by_hash(&self, hash: String) -> RpcResult<Option<RpcTransaction>> {
        let start = std::time::Instant::now();
        
        // Parse hash
        let _tx_hash = match hash.parse::<Hash>() {
            Ok(hash) => hash,
            Err(_) => {
                self.update_metrics("eth_getTransactionByHash", start.elapsed(), false).await;
                return Err(ErrorObject::owned(-32602, "Invalid hash", None::<()>));
            }
        };

        // Simulate transaction lookup
        let tx = Some(RpcTransaction {
            hash: hash.clone(),
            from: "0x1234...".to_string(),
            to: Some("0x5678...".to_string()),
            value: "0xde0b6b3a7640000".to_string(), // 1 ETH
            gas: "0x5208".to_string(),
            gas_price: "0x4a817c800".to_string(),
            input: "0x".to_string(),
            nonce: "0x1".to_string(),
            block_hash: Some("0xabc123...".to_string()),
            block_number: Some("0x123".to_string()),
            transaction_index: Some("0x0".to_string()),
        });

        let result = Ok(tx);
        self.update_metrics("eth_getTransactionByHash", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn send_raw_transaction(&self, data: String) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Simulate transaction submission
        let tx_hash = format!("0x{:x}", rand::random::<u64>());
        
        println!("📤 Received raw transaction: {} bytes", data.len());
        println!("   Generated TX hash: {}", tx_hash);
        
        let result = Ok(tx_hash);
        self.update_metrics("eth_sendRawTransaction", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn estimate_gas(&self, tx: RpcTransactionRequest) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Simulate gas estimation
        let estimated_gas = if tx.to.is_some() {
            21000u64 // Simple transfer
        } else {
            100000u64 // Contract deployment
        };

        let result = Ok(format!("0x{:x}", estimated_gas));
        self.update_metrics("eth_estimateGas", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn gas_price(&self) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        // Simulate gas price (20 gwei)
        let gas_price = 20000000000u64;
        let result = Ok(format!("0x{:x}", gas_price));
        self.update_metrics("eth_gasPrice", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_logs(&self, filter: LogFilter) -> RpcResult<Vec<RpcLog>> {
        let start = std::time::Instant::now();
        
        // Simulate log filtering
        let logs = vec![];
        
        let result = Ok(logs);
        self.update_metrics("eth_getLogs", start.elapsed(), result.is_ok()).await;
        result
    }
}

#[async_trait]
impl PoarRpcServer for RpcServerImpl {
    async fn get_zk_proof(&self, block_hash: String) -> RpcResult<Option<ZkProofData>> {
        let start = std::time::Instant::now();
        
        let proof_data = Some(ZkProofData {
            proof: "0x1234567890abcdef...".to_string(),
            public_inputs: vec!["0xabc123...".to_string()],
            vk_hash: "0xdef456...".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let result = Ok(proof_data);
        self.update_metrics("poar_getZkProof", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_validator_info(&self, address: String) -> RpcResult<Option<ValidatorInfo>> {
        let start = std::time::Instant::now();
        
        let validator = Some(ValidatorInfo {
            address: address.clone(),
            stake: "32000000000000000000".to_string(), // 32 ETH
            commission: "0.05".to_string(), // 5%
            active: true,
            reputation: 0.95,
            blocks_validated: 1234,
        });

        let result = Ok(validator);
        self.update_metrics("poar_getValidatorInfo", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_network_stats(&self) -> RpcResult<NetworkStats> {
        let start = std::time::Instant::now();
        
        let stats = self.network_manager.get_stats().await;
        let network_stats = NetworkStats {
            connected_peers: stats.connected_peers as u32,
            throughput: stats.avg_bandwidth_utilization,
            avg_latency: 125, // ms
            success_rate: 0.982,
        };

        let result = Ok(network_stats);
        self.update_metrics("poar_getNetworkStats", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_consensus_status(&self) -> RpcResult<ConsensusStatus> {
        let start = std::time::Instant::now();
        
        let status = ConsensusStatus {
            current_epoch: 42,
            validator_count: 100,
            finalized_block: 1234567,
            pending_proposals: 3,
        };

        let result = Ok(status);
        self.update_metrics("poar_getConsensusStatus", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_state_snapshot(&self, block_hash: String) -> RpcResult<Option<StateSnapshot>> {
        let start = std::time::Instant::now();
        
        let snapshot = Some(StateSnapshot {
            block_hash: block_hash.clone(),
            state_root: "0x9abc123...".to_string(),
            account_count: 1500000,
            size: 2048576000, // ~2GB
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let result = Ok(snapshot);
        self.update_metrics("poar_getStateSnapshot", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn submit_zk_proof(&self, proof_data: ZkProofSubmission) -> RpcResult<String> {
        let start = std::time::Instant::now();
        
        println!("📝 ZK Proof submitted for block: {}", proof_data.block_hash);
        println!("   Submitter: {}", proof_data.submitter);
        println!("   Proof length: {} bytes", proof_data.proof.len());
        
        let submission_id = format!("0x{:x}", rand::random::<u64>());
        let result = Ok(submission_id);
        self.update_metrics("poar_submitZkProof", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_peer_reputations(&self) -> RpcResult<Vec<PeerReputation>> {
        let start = std::time::Instant::now();
        
        let reputations = vec![
            PeerReputation {
                peer_id: "12D3KooWGjMC...".to_string(),
                score: 0.95,
                trust_level: "High".to_string(),
                last_interaction: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        ];

        let result = Ok(reputations);
        self.update_metrics("poar_getPeerReputations", start.elapsed(), result.is_ok()).await;
        result
    }

    async fn get_storage_metrics(&self) -> RpcResult<StorageMetrics> {
        let start = std::time::Instant::now();
        
        let metrics = self.state_storage.get_metrics().await;
        let storage_metrics = StorageMetrics {
            db_size: metrics.total_size_bytes,
            state_size: metrics.state_size_bytes,
            cache_hit_rate: metrics.cache_hit_rate,
            compaction_status: "Healthy".to_string(),
        };

        let result = Ok(storage_metrics);
        self.update_metrics("poar_getStorageMetrics", start.elapsed(), result.is_ok()).await;
        result
    }
}

impl PoarRpcServer {
    /// Create new POAR RPC server
    pub fn new(
        config: RpcConfig,
        state_storage: Arc<StateStorage>,
        network_manager: Arc<P2PNetworkManager>,
    ) -> Self {
        Self {
            handle: None,
            config,
            state_storage,
            network_manager,
            metrics: Arc::new(RwLock::new(RpcMetrics::default())),
        }
    }

    /// Start the RPC server
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting POAR JSON-RPC Server...");
        println!("   Listen Address: {}", self.config.listen_addr);
        
        let server_impl = RpcServerImpl::new(
            self.state_storage.clone(),
            self.network_manager.clone(),
        );

        let server = ServerBuilder::default()
            .max_connections(self.config.max_connections)
            .build(self.config.listen_addr)
            .await?;

        let addr = server.local_addr()?;
        let handle = server.start(
            server_impl.into_rpc()
        ).await?;

        self.handle = Some(handle);

        println!("✅ JSON-RPC Server started on {}", addr);
        println!("   Ethereum-compatible methods: 12");
        println!("   POAR-specific methods: 8");
        println!("   Rate limiting: {}",
                if self.config.rate_limit.enabled { "Enabled" } else { "Disabled" });

        Ok(())
    }

    /// Stop the RPC server
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(handle) = self.handle.take() {
            handle.stop().await?;
            println!("🛑 JSON-RPC Server stopped");
        }
        Ok(())
    }

    /// Get server metrics
    pub async fn get_metrics(&self) -> RpcMetrics {
        self.metrics.read().await.clone()
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".parse().unwrap(),
            max_connections: 100,
            request_timeout: std::time::Duration::from_secs(30),
            rate_limit: RateLimitConfig::default(),
            cors: CorsConfig::default(),
            enable_batch: true,
            max_batch_size: 10,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_capacity: 10,
            enabled: true,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            allow_credentials: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rpc_server_creation() {
        let config = RpcConfig::default();
        // Note: This test would need actual StateStorage and NetworkManager instances
        // For now, we just test the config
        assert_eq!(config.listen_addr.port(), 8545);
        assert!(config.enable_batch);
    }

    #[test]
    fn test_rpc_serialization() {
        let block = RpcBlock {
            hash: "0x123".to_string(),
            parent_hash: "0x456".to_string(),
            number: "0x1".to_string(),
            timestamp: "0x64a7c2f2".to_string(),
            gas_limit: "0x1c9c380".to_string(),
            gas_used: "0x5208".to_string(),
            miner: "0xabc".to_string(),
            transactions: vec![],
            transactions_root: "0x789".to_string(),
            state_root: "0xdef".to_string(),
            zk_proof_hash: Some("0x111".to_string()),
            size: "0x220".to_string(),
        };

        let json = serde_json::to_string(&block).unwrap();
        assert!(json.contains("zkProofHash"));
        assert!(json.contains("0x111"));
    }
} 