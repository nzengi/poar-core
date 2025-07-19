use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, RwLock, Mutex};
use libp2p::{PeerId, Multiaddr};
use serde::{Serialize, Deserialize};
use futures::future::BoxFuture;
use async_trait::async_trait;
use crate::types::{Hash, Block, Transaction};
use crate::network::{NetworkEvent, MessageType, NetworkError};

/// Protocol message propagation manager
pub struct MessagePropagationManager {
    /// Message cache for deduplication
    message_cache: Arc<RwLock<MessageCache>>,
    /// Protocol handlers registry
    protocol_handlers: Arc<RwLock<HashMap<String, Box<dyn ProtocolHandler + Send + Sync>>>>,
    /// Message routing table
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Propagation configuration
    config: PropagationConfig,
    /// Message statistics
    stats: Arc<RwLock<PropagationStats>>,
    /// Priority queue for message processing
    priority_queue: Arc<Mutex<MessagePriorityQueue>>,
    /// Rate limiter for message propagation
    rate_limiter: Arc<RateLimiter>,
}

/// Message cache for deduplication and tracking
#[derive(Debug)]
struct MessageCache {
    /// Cache entries
    entries: HashMap<Hash, CacheEntry>,
    /// Time-based cleanup queue
    cleanup_queue: VecDeque<(Instant, Hash)>,
    /// Maximum cache size
    max_size: usize,
    /// Cache TTL
    ttl: Duration,
}

/// Cache entry for messages
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Message hash
    message_hash: Hash,
    /// First seen timestamp
    first_seen: Instant,
    /// Peers who sent this message
    sources: HashSet<PeerId>,
    /// Peers to whom we've forwarded
    forwarded_to: HashSet<PeerId>,
    /// Message priority
    priority: MessagePriority,
    /// Propagation status
    status: PropagationStatus,
}

/// Message propagation status
#[derive(Debug, Clone, PartialEq)]
enum PropagationStatus {
    Received,
    Validated,
    Propagating,
    Propagated,
    Rejected,
}

/// Message priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    Critical = 0,     // Consensus messages
    High = 1,         // Block announcements
    Normal = 2,       // Transactions
    Low = 3,          // Peer announcements
    Background = 4,   // Maintenance messages
}

/// Protocol handler trait
#[async_trait]
pub trait ProtocolHandler {
    /// Handle incoming message
    async fn handle_message(
        &self,
        from: PeerId,
        message: ProtocolMessage,
    ) -> Result<ProtocolResponse, ProtocolError>;
    
    /// Get protocol name
    fn protocol_name(&self) -> &'static str;
    
    /// Get supported message types
    fn supported_messages(&self) -> Vec<String>;
    
    /// Validate message format
    async fn validate_message(&self, message: &ProtocolMessage) -> bool;
}

/// Generic protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Protocol identifier
    pub protocol: String,
    /// Message type
    pub message_type: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message ID for tracking
    pub message_id: Hash,
    /// Sender peer ID
    pub sender: PeerId,
    /// Message timestamp
    pub timestamp: u64,
    /// Message TTL (Time To Live)
    pub ttl: u8,
    /// Priority level
    pub priority: MessagePriority,
    /// Routing hints
    pub routing_hints: RoutingHints,
}

/// Routing hints for message propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingHints {
    /// Target peer count
    pub target_peer_count: Option<usize>,
    /// Geographic preferences
    pub geo_preferences: Vec<String>,
    /// Exclude specific peers
    pub exclude_peers: HashSet<PeerId>,
    /// Propagation strategy
    pub strategy: PropagationStrategy,
}

/// Message propagation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PropagationStrategy {
    /// Flood to all connected peers
    Flood,
    /// Random selection of peers
    Random(usize),
    /// Geographic distribution
    Geographic,
    /// Gossip-based propagation
    Gossip,
    /// Directed to specific peers
    Directed(Vec<PeerId>),
}

/// Protocol response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolResponse {
    /// Response type
    pub response_type: ResponseType,
    /// Response payload
    pub payload: Vec<u8>,
    /// Should propagate this response
    pub should_propagate: bool,
    /// Propagation hints
    pub propagation_hints: Option<RoutingHints>,
}

/// Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseType {
    Ack,
    Data,
    Error,
    Redirect,
    Throttle,
}

/// Routing table for efficient message forwarding
#[derive(Debug)]
struct RoutingTable {
    /// Peer capabilities
    peer_capabilities: HashMap<PeerId, PeerCapabilities>,
    /// Geographic distribution
    geo_distribution: HashMap<String, Vec<PeerId>>,
    /// Protocol support mapping
    protocol_support: HashMap<String, HashSet<PeerId>>,
    /// Bandwidth utilization per peer
    bandwidth_usage: HashMap<PeerId, BandwidthUsage>,
}

/// Peer capabilities for routing decisions
#[derive(Debug, Clone)]
struct PeerCapabilities {
    /// Maximum bandwidth
    max_bandwidth: u64,
    /// Supported protocols
    protocols: HashSet<String>,
    /// Geographic location
    location: Option<String>,
    /// Relay capability
    can_relay: bool,
    /// Archive node
    is_archive: bool,
    /// Validator node
    is_validator: bool,
}

/// Bandwidth usage tracking
#[derive(Debug, Clone)]
struct BandwidthUsage {
    /// Bytes sent in current window
    bytes_sent: u64,
    /// Bytes received in current window
    bytes_received: u64,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
}

/// Message priority queue
#[derive(Debug)]
struct MessagePriorityQueue {
    /// Priority queues for different message types
    queues: HashMap<MessagePriority, VecDeque<QueuedMessage>>,
    /// Total queued messages
    total_queued: usize,
    /// Maximum queue size
    max_size: usize,
}

/// Queued message with metadata
#[derive(Debug, Clone)]
struct QueuedMessage {
    /// The message
    message: ProtocolMessage,
    /// Source peer
    from: PeerId,
    /// Queued timestamp
    queued_at: Instant,
    /// Processing attempts
    attempts: u32,
}

/// Rate limiter for message propagation
pub struct RateLimiter {
    /// Token buckets per peer
    peer_buckets: Arc<RwLock<HashMap<PeerId, TokenBucket>>>,
    /// Global rate limit
    global_bucket: Arc<Mutex<TokenBucket>>,
    /// Rate limiting configuration
    config: RateLimitConfig,
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Available tokens
    tokens: f64,
    /// Maximum tokens
    capacity: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
    /// Last refill time
    last_refill: Instant,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Global messages per second
    pub global_rate: f64,
    /// Per-peer messages per second
    pub per_peer_rate: f64,
    /// Burst capacity
    pub burst_capacity: f64,
    /// Rate limit window
    pub window_duration: Duration,
}

/// Propagation configuration
#[derive(Debug, Clone)]
pub struct PropagationConfig {
    /// Maximum message cache size
    pub max_cache_size: usize,
    /// Message TTL in cache
    pub message_ttl: Duration,
    /// Maximum propagation fanout
    pub max_fanout: usize,
    /// Propagation delay for batching
    pub propagation_delay: Duration,
    /// Rate limiting config
    pub rate_limit: RateLimitConfig,
    /// Enable message compression
    pub enable_compression: bool,
    /// Compression threshold (bytes)
    pub compression_threshold: usize,
}

/// Propagation statistics
#[derive(Debug, Clone, Default)]
pub struct PropagationStats {
    /// Total messages received
    pub messages_received: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Messages in cache
    pub cached_messages: u64,
    /// Duplicate messages filtered
    pub duplicates_filtered: u64,
    /// Rate limited messages
    pub rate_limited: u64,
    /// Average propagation time
    pub avg_propagation_time: Duration,
    /// Bandwidth utilization
    pub bandwidth_utilization: f64,
    /// Protocol-specific stats
    pub protocol_stats: HashMap<String, ProtocolStats>,
}

/// Per-protocol statistics
#[derive(Debug, Clone, Default)]
pub struct ProtocolStats {
    /// Messages handled
    pub messages_handled: u64,
    /// Processing time
    pub avg_processing_time: Duration,
    /// Error rate
    pub error_rate: f64,
    /// Success rate
    pub success_rate: f64,
}

/// Protocol-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Message validation failed: {0}")]
    ValidationFailed(String),
    #[error("Protocol not supported: {0}")]
    ProtocolNotSupported(String),
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),
    #[error("Processing timeout")]
    ProcessingTimeout,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Block propagation protocol handler
pub struct BlockPropagationHandler {
    /// Block validation callback
    block_validator: Arc<dyn Fn(&Block) -> BoxFuture<'static, bool> + Send + Sync>,
    /// Statistics
    stats: Arc<RwLock<ProtocolStats>>,
}

/// Transaction propagation protocol handler
pub struct TransactionPropagationHandler {
    /// Transaction validation callback
    tx_validator: Arc<dyn Fn(&Transaction) -> BoxFuture<'static, bool> + Send + Sync>,
    /// Transaction pool
    tx_pool: Arc<dyn TransactionPool + Send + Sync>,
    /// Statistics
    stats: Arc<RwLock<ProtocolStats>>,
}

/// Transaction pool trait
#[async_trait]
pub trait TransactionPool {
    /// Add transaction to pool
    async fn add_transaction(&self, tx: Transaction) -> Result<(), String>;
    /// Check if transaction exists
    async fn contains_transaction(&self, hash: &Hash) -> bool;
}

/// Consensus message protocol handler
pub struct ConsensusPropagationHandler {
    /// Consensus message validator
    consensus_validator: Arc<dyn Fn(&[u8]) -> BoxFuture<'static, bool> + Send + Sync>,
    /// Statistics
    stats: Arc<RwLock<ProtocolStats>>,
}

impl MessagePropagationManager {
    /// Create new message propagation manager
    pub fn new(config: PropagationConfig) -> Self {
        Self {
            message_cache: Arc::new(RwLock::new(MessageCache::new(
                config.max_cache_size,
                config.message_ttl,
            ))),
            protocol_handlers: Arc::new(RwLock::new(HashMap::new())),
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
            config: config.clone(),
            stats: Arc::new(RwLock::new(PropagationStats::default())),
            priority_queue: Arc::new(Mutex::new(MessagePriorityQueue::new(1000))),
            rate_limiter: Arc::new(RateLimiter::new(config.rate_limit)),
        }
    }

    /// Register a protocol handler
    pub async fn register_protocol_handler<H>(&self, handler: H)
    where
        H: ProtocolHandler + Send + Sync + 'static,
    {
        let protocol_name = handler.protocol_name().to_string();
        self.protocol_handlers.write().await.insert(protocol_name.clone(), Box::new(handler));
        
        println!("📋 Registered protocol handler: {}", protocol_name);
    }

    /// Handle incoming message
    pub async fn handle_incoming_message(
        &self,
        from: PeerId,
        message: ProtocolMessage,
    ) -> Result<(), ProtocolError> {
        // Check rate limit
        if !self.rate_limiter.check_rate_limit(&from).await {
            self.stats.write().await.rate_limited += 1;
            return Err(ProtocolError::RateLimitExceeded);
        }

        // Check for duplicate
        if self.is_duplicate_message(&message.message_id).await {
            self.stats.write().await.duplicates_filtered += 1;
            return Ok(());
        }

        // Add to cache
        self.add_to_cache(&message, from).await;

        // Add to priority queue
        self.enqueue_message(message, from).await?;

        Ok(())
    }

    /// Process messages from priority queue
    pub async fn start_message_processing(&self) {
        let priority_queue = self.priority_queue.clone();
        let protocol_handlers = self.protocol_handlers.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            loop {
                if let Some(queued_msg) = Self::dequeue_message(&priority_queue).await {
                    let handlers = protocol_handlers.read().await;
                    
                    if let Some(handler) = handlers.get(&queued_msg.message.protocol) {
                        let start_time = Instant::now();
                        
                        match handler.handle_message(queued_msg.from, queued_msg.message.clone()).await {
                            Ok(response) => {
                                // Handle successful processing
                                Self::update_protocol_stats(
                                    &stats,
                                    &queued_msg.message.protocol,
                                    start_time.elapsed(),
                                    true,
                                ).await;

                                // Propagate if needed
                                if response.should_propagate {
                                    // Implement propagation logic here
                                }
                            }
                            Err(e) => {
                                println!("⚠️  Protocol handler error: {}", e);
                                Self::update_protocol_stats(
                                    &stats,
                                    &queued_msg.message.protocol,
                                    start_time.elapsed(),
                                    false,
                                ).await;
                            }
                        }
                    }
                } else {
                    // No messages in queue, sleep briefly
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });
    }

    /// Propagate message to network
    pub async fn propagate_message(
        &self,
        message: ProtocolMessage,
        strategy: PropagationStrategy,
    ) -> Result<usize, ProtocolError> {
        let routing_table = self.routing_table.read().await;
        let target_peers = self.select_target_peers(&routing_table, &strategy).await;

        let propagated_count = target_peers.len();
        
        // Update cache
        self.mark_as_propagated(&message.message_id, &target_peers).await;

        // Update stats
        let mut stats = self.stats.write().await;
        stats.messages_sent += propagated_count as u64;

        println!("📡 Propagated message to {} peers using strategy: {:?}", 
                propagated_count, strategy);

        Ok(propagated_count)
    }

    /// Select target peers based on strategy
    async fn select_target_peers(
        &self,
        routing_table: &RoutingTable,
        strategy: &PropagationStrategy,
    ) -> Vec<PeerId> {
        match strategy {
            PropagationStrategy::Flood => {
                routing_table.peer_capabilities.keys().cloned().collect()
            }
            PropagationStrategy::Random(count) => {
                use rand::seq::SliceRandom;
                let mut peers: Vec<_> = routing_table.peer_capabilities.keys().cloned().collect();
                peers.shuffle(&mut rand::thread_rng());
                peers.into_iter().take(*count).collect()
            }
            PropagationStrategy::Geographic => {
                // Select peers from different geographic regions
                let mut selected = Vec::new();
                for (_, peers) in &routing_table.geo_distribution {
                    if let Some(peer) = peers.first() {
                        selected.push(*peer);
                    }
                }
                selected
            }
            PropagationStrategy::Gossip => {
                // Implement gossip-based selection
                use rand::seq::SliceRandom;
                let mut peers: Vec<_> = routing_table.peer_capabilities.keys().cloned().collect();
                peers.shuffle(&mut rand::thread_rng());
                peers.into_iter().take(6).collect() // Typical gossip fanout
            }
            PropagationStrategy::Directed(peers) => {
                peers.clone()
            }
        }
    }

    /// Check if message is duplicate
    async fn is_duplicate_message(&self, message_id: &Hash) -> bool {
        self.message_cache.read().await.entries.contains_key(message_id)
    }

    /// Add message to cache
    async fn add_to_cache(&self, message: &ProtocolMessage, from: PeerId) {
        let mut cache = self.message_cache.write().await;
        
        let entry = CacheEntry {
            message_hash: message.message_id,
            first_seen: Instant::now(),
            sources: {
                let mut sources = HashSet::new();
                sources.insert(from);
                sources
            },
            forwarded_to: HashSet::new(),
            priority: message.priority.clone(),
            status: PropagationStatus::Received,
        };

        cache.entries.insert(message.message_id, entry);
        cache.cleanup_queue.push_back((Instant::now(), message.message_id));

        // Cleanup old entries
        cache.cleanup_expired();
    }

    /// Mark message as propagated
    async fn mark_as_propagated(&self, message_id: &Hash, peers: &[PeerId]) {
        let mut cache = self.message_cache.write().await;
        if let Some(entry) = cache.entries.get_mut(message_id) {
            entry.forwarded_to.extend(peers.iter().cloned());
            entry.status = PropagationStatus::Propagated;
        }
    }

    /// Enqueue message for processing
    async fn enqueue_message(&self, message: ProtocolMessage, from: PeerId) -> Result<(), ProtocolError> {
        let queued_msg = QueuedMessage {
            message: message.clone(),
            from,
            queued_at: Instant::now(),
            attempts: 0,
        };

        let mut queue = self.priority_queue.lock().await;
        queue.enqueue(queued_msg, message.priority)?;

        Ok(())
    }

    /// Dequeue message for processing
    async fn dequeue_message(priority_queue: &Arc<Mutex<MessagePriorityQueue>>) -> Option<QueuedMessage> {
        let mut queue = priority_queue.lock().await;
        queue.dequeue()
    }

    /// Update protocol statistics
    async fn update_protocol_stats(
        stats: &Arc<RwLock<PropagationStats>>,
        protocol: &str,
        processing_time: Duration,
        success: bool,
    ) {
        let mut stats_guard = stats.write().await;
        let protocol_stats = stats_guard.protocol_stats
            .entry(protocol.to_string())
            .or_insert_with(ProtocolStats::default);

        protocol_stats.messages_handled += 1;
        protocol_stats.avg_processing_time = 
            (protocol_stats.avg_processing_time + processing_time) / 2;

        if success {
            protocol_stats.success_rate = 
                (protocol_stats.success_rate + 1.0) / 2.0;
        } else {
            protocol_stats.error_rate = 
                (protocol_stats.error_rate + 1.0) / 2.0;
        }
    }

    /// Get propagation statistics
    pub async fn get_stats(&self) -> PropagationStats {
        self.stats.read().await.clone()
    }
}

impl MessageCache {
    /// Create new message cache
    fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            cleanup_queue: VecDeque::new(),
            max_size,
            ttl,
        }
    }

    /// Cleanup expired entries
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        
        while let Some((timestamp, hash)) = self.cleanup_queue.front() {
            if now.duration_since(*timestamp) > self.ttl {
                let (_, hash) = self.cleanup_queue.pop_front().unwrap();
                self.entries.remove(&hash);
            } else {
                break;
            }
        }

        // Enforce size limit
        while self.entries.len() > self.max_size {
            if let Some((_, hash)) = self.cleanup_queue.pop_front() {
                self.entries.remove(&hash);
            } else {
                break;
            }
        }
    }
}

impl RoutingTable {
    /// Create new routing table
    fn new() -> Self {
        Self {
            peer_capabilities: HashMap::new(),
            geo_distribution: HashMap::new(),
            protocol_support: HashMap::new(),
            bandwidth_usage: HashMap::new(),
        }
    }

    /// Update peer capabilities
    pub fn update_peer_capabilities(&mut self, peer_id: PeerId, capabilities: PeerCapabilities) {
        self.peer_capabilities.insert(peer_id, capabilities);
    }
}

impl MessagePriorityQueue {
    /// Create new priority queue
    fn new(max_size: usize) -> Self {
        let mut queues = HashMap::new();
        queues.insert(MessagePriority::Critical, VecDeque::new());
        queues.insert(MessagePriority::High, VecDeque::new());
        queues.insert(MessagePriority::Normal, VecDeque::new());
        queues.insert(MessagePriority::Low, VecDeque::new());
        queues.insert(MessagePriority::Background, VecDeque::new());

        Self {
            queues,
            total_queued: 0,
            max_size,
        }
    }

    /// Enqueue message
    fn enqueue(&mut self, message: QueuedMessage, priority: MessagePriority) -> Result<(), ProtocolError> {
        if self.total_queued >= self.max_size {
            return Err(ProtocolError::MessageTooLarge(0));
        }

        if let Some(queue) = self.queues.get_mut(&priority) {
            queue.push_back(message);
            self.total_queued += 1;
        }

        Ok(())
    }

    /// Dequeue message (highest priority first)
    fn dequeue(&mut self) -> Option<QueuedMessage> {
        for priority in &[
            MessagePriority::Critical,
            MessagePriority::High,
            MessagePriority::Normal,
            MessagePriority::Low,
            MessagePriority::Background,
        ] {
            if let Some(queue) = self.queues.get_mut(priority) {
                if let Some(message) = queue.pop_front() {
                    self.total_queued -= 1;
                    return Some(message);
                }
            }
        }
        None
    }
}

impl RateLimiter {
    /// Create new rate limiter
    fn new(config: RateLimitConfig) -> Self {
        Self {
            peer_buckets: Arc::new(RwLock::new(HashMap::new())),
            global_bucket: Arc::new(Mutex::new(TokenBucket::new(
                config.global_rate,
                config.burst_capacity,
            ))),
            config,
        }
    }

    /// Check rate limit for peer
    async fn check_rate_limit(&self, peer_id: &PeerId) -> bool {
        // Check global rate limit
        if !self.global_bucket.lock().await.consume(1.0) {
            return false;
        }

        // Check per-peer rate limit
        let mut buckets = self.peer_buckets.write().await;
        let bucket = buckets.entry(*peer_id).or_insert_with(|| {
            TokenBucket::new(self.config.per_peer_rate, self.config.burst_capacity)
        });

        bucket.consume(1.0)
    }
}

impl TokenBucket {
    /// Create new token bucket
    fn new(refill_rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Consume tokens
    fn consume(&mut self, tokens: f64) -> bool {
        self.refill();
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;
        
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }
}

#[async_trait]
impl ProtocolHandler for BlockPropagationHandler {
    async fn handle_message(
        &self,
        from: PeerId,
        message: ProtocolMessage,
    ) -> Result<ProtocolResponse, ProtocolError> {
        // Deserialize block
        let block: Block = bincode::deserialize(&message.payload)
            .map_err(|e| ProtocolError::SerializationError(e.to_string()))?;

        // Validate block
        if !(self.block_validator)(&block).await {
            return Err(ProtocolError::ValidationFailed("Block validation failed".to_string()));
        }

        // Update stats
        self.stats.write().await.messages_handled += 1;

        Ok(ProtocolResponse {
            response_type: ResponseType::Ack,
            payload: vec![],
            should_propagate: true,
            propagation_hints: Some(RoutingHints {
                target_peer_count: Some(8),
                geo_preferences: vec![],
                exclude_peers: {
                    let mut exclude = HashSet::new();
                    exclude.insert(from);
                    exclude
                },
                strategy: PropagationStrategy::Gossip,
            }),
        })
    }

    fn protocol_name(&self) -> &'static str {
        "poar-blocks"
    }

    fn supported_messages(&self) -> Vec<String> {
        vec!["block_announcement".to_string(), "block_request".to_string()]
    }

    async fn validate_message(&self, message: &ProtocolMessage) -> bool {
        message.protocol == self.protocol_name() && !message.payload.is_empty()
    }
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 10000,
            message_ttl: Duration::from_secs(300), // 5 minutes
            max_fanout: 8,
            propagation_delay: Duration::from_millis(100),
            rate_limit: RateLimitConfig::default(),
            enable_compression: true,
            compression_threshold: 1024, // 1KB
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_rate: 1000.0,        // 1000 messages/sec globally
            per_peer_rate: 100.0,       // 100 messages/sec per peer
            burst_capacity: 50.0,       // 50 message burst
            window_duration: Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_message_propagation_manager() {
        let config = PropagationConfig::default();
        let manager = MessagePropagationManager::new(config);
        
        // Test basic functionality
        assert_eq!(manager.get_stats().await.messages_received, 0);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10.0, 10.0);
        
        // Should be able to consume up to capacity
        assert!(bucket.consume(5.0));
        assert!(bucket.consume(5.0));
        assert!(!bucket.consume(1.0)); // Should be empty now
    }

    #[test]
    fn test_message_priority_queue() {
        let mut queue = MessagePriorityQueue::new(100);
        
        let high_msg = QueuedMessage {
            message: ProtocolMessage {
                protocol: "test".to_string(),
                message_type: "high".to_string(),
                payload: vec![],
                message_id: Hash::hash(b"high"),
                sender: PeerId::random(),
                timestamp: 0,
                ttl: 10,
                priority: MessagePriority::High,
                routing_hints: RoutingHints {
                    target_peer_count: None,
                    geo_preferences: vec![],
                    exclude_peers: HashSet::new(),
                    strategy: PropagationStrategy::Flood,
                },
            },
            from: PeerId::random(),
            queued_at: Instant::now(),
            attempts: 0,
        };

        let normal_msg = QueuedMessage {
            message: ProtocolMessage {
                protocol: "test".to_string(),
                message_type: "normal".to_string(),
                payload: vec![],
                message_id: Hash::hash(b"normal"),
                sender: PeerId::random(),
                timestamp: 0,
                ttl: 10,
                priority: MessagePriority::Normal,
                routing_hints: RoutingHints {
                    target_peer_count: None,
                    geo_preferences: vec![],
                    exclude_peers: HashSet::new(),
                    strategy: PropagationStrategy::Flood,
                },
            },
            from: PeerId::random(),
            queued_at: Instant::now(),
            attempts: 0,
        };

        // Add normal priority first
        queue.enqueue(normal_msg, MessagePriority::Normal).unwrap();
        // Add high priority second
        queue.enqueue(high_msg, MessagePriority::High).unwrap();

        // High priority should come out first
        let dequeued = queue.dequeue().unwrap();
        assert_eq!(dequeued.message.message_type, "high");
    }
}
