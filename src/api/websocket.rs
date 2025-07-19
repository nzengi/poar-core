use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State, Query,
    },
    http::StatusCode,
    response::Response,
    routing::get,
    Router,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock, Mutex};
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;
use std::time::{Duration, SystemTime};

/// WebSocket server manager
pub struct WebSocketServer {
    /// Connected clients
    clients: Arc<RwLock<HashMap<Uuid, WebSocketClient>>>,
    /// Broadcast channels for different event types
    block_tx: broadcast::Sender<BlockEvent>,
    transaction_tx: broadcast::Sender<TransactionEvent>,
    network_tx: broadcast::Sender<NetworkEvent>,
    system_tx: broadcast::Sender<SystemEvent>,
    /// Subscription manager
    subscription_manager: Arc<SubscriptionManager>,
    /// Connection metrics
    metrics: Arc<RwLock<WebSocketMetrics>>,
}

/// WebSocket client information
#[derive(Debug, Clone)]
pub struct WebSocketClient {
    /// Client ID
    pub id: Uuid,
    /// Client IP address
    pub ip_address: String,
    /// Connection timestamp
    pub connected_at: SystemTime,
    /// Active subscriptions
    pub subscriptions: HashSet<String>,
    /// Message count
    pub message_count: u64,
    /// Last activity
    pub last_activity: SystemTime,
    /// User agent
    pub user_agent: Option<String>,
}

/// Subscription manager for organizing client subscriptions
pub struct SubscriptionManager {
    /// Block subscriptions
    block_subscribers: Arc<Mutex<HashMap<Uuid, broadcast::Sender<BlockEvent>>>>,
    /// Transaction subscriptions
    tx_subscribers: Arc<Mutex<HashMap<Uuid, broadcast::Sender<TransactionEvent>>>>,
    /// Network event subscriptions
    network_subscribers: Arc<Mutex<HashMap<Uuid, broadcast::Sender<NetworkEvent>>>>,
    /// System event subscriptions
    system_subscribers: Arc<Mutex<HashMap<Uuid, broadcast::Sender<SystemEvent>>>>,
    /// Custom subscriptions
    custom_subscribers: Arc<Mutex<HashMap<String, HashMap<Uuid, broadcast::Sender<CustomEvent>>>>>,
}

/// WebSocket metrics
#[derive(Debug, Clone, Default)]
pub struct WebSocketMetrics {
    /// Total connections
    pub total_connections: u64,
    /// Current active connections
    pub active_connections: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Subscription counts by type
    pub subscription_counts: HashMap<String, u64>,
    /// Average connection duration
    pub avg_connection_duration: Duration,
    /// Peak concurrent connections
    pub peak_connections: u64,
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Subscribe to events
    Subscribe { topics: Vec<String> },
    /// Unsubscribe from events
    Unsubscribe { topics: Vec<String> },
    /// Ping message
    Ping { timestamp: u64 },
    /// Pong response
    Pong { timestamp: u64 },
    /// Block event
    BlockEvent(BlockEvent),
    /// Transaction event
    TransactionEvent(TransactionEvent),
    /// Network event
    NetworkEvent(NetworkEvent),
    /// System event
    SystemEvent(SystemEvent),
    /// Custom event
    CustomEvent(CustomEvent),
    /// Error message
    Error { message: String, code: u16 },
    /// Success response
    Success { message: String },
}

/// Block-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    /// Event type
    pub event: String,
    /// Block data
    pub block: BlockData,
    /// Timestamp
    pub timestamp: u64,
}

/// Transaction-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEvent {
    /// Event type
    pub event: String,
    /// Transaction data
    pub transaction: TransactionData,
    /// Timestamp
    pub timestamp: u64,
}

/// Network-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Event type
    pub event: String,
    /// Network data
    pub data: NetworkEventData,
    /// Timestamp
    pub timestamp: u64,
}

/// System-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    /// Event type
    pub event: String,
    /// System data
    pub data: SystemEventData,
    /// Timestamp
    pub timestamp: u64,
}

/// Custom events for extensibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomEvent {
    /// Event type/topic
    pub topic: String,
    /// Event data
    pub data: serde_json::Value,
    /// Timestamp
    pub timestamp: u64,
}

/// Block data for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    /// Block hash
    pub hash: String,
    /// Block number
    pub number: u64,
    /// Parent hash
    pub parent_hash: String,
    /// Timestamp
    pub timestamp: u64,
    /// Miner
    pub miner: String,
    /// Gas used
    pub gas_used: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Transaction count
    pub transaction_count: u32,
    /// Block size
    pub size: u64,
    /// ZK proof hash
    pub zk_proof_hash: Option<String>,
}

/// Transaction data for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    /// Transaction hash
    pub hash: String,
    /// From address
    pub from: String,
    /// To address
    pub to: Option<String>,
    /// Value
    pub value: String,
    /// Gas price
    pub gas_price: String,
    /// Gas limit
    pub gas: u64,
    /// Transaction status
    pub status: String,
    /// Block hash
    pub block_hash: Option<String>,
    /// Block number
    pub block_number: Option<u64>,
}

/// Network event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventData {
    /// Peer ID (for peer events)
    pub peer_id: Option<String>,
    /// Message count
    pub message_count: Option<u64>,
    /// Bandwidth data
    pub bandwidth: Option<f64>,
    /// Latency data
    pub latency: Option<f64>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// System event data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEventData {
    /// CPU usage
    pub cpu_usage: Option<f64>,
    /// Memory usage
    pub memory_usage: Option<u64>,
    /// Disk usage
    pub disk_usage: Option<u64>,
    /// Error message (for error events)
    pub error_message: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// WebSocket connection parameters
#[derive(Debug, Deserialize)]
pub struct WebSocketParams {
    /// Initial subscriptions
    pub subscribe: Option<String>,
    /// Authentication token
    pub token: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
}

impl WebSocketServer {
    /// Create new WebSocket server
    pub fn new() -> Self {
        let (block_tx, _) = broadcast::channel(1000);
        let (transaction_tx, _) = broadcast::channel(1000);
        let (network_tx, _) = broadcast::channel(1000);
        let (system_tx, _) = broadcast::channel(1000);

        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            block_tx,
            transaction_tx,
            network_tx,
            system_tx,
            subscription_manager: Arc::new(SubscriptionManager::new()),
            metrics: Arc::new(RwLock::new(WebSocketMetrics::default())),
        }
    }

    /// Create WebSocket router
    pub fn create_router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/ws", get(websocket_handler))
            .route("/ws/status", get(websocket_status))
            .route("/ws/metrics", get(websocket_metrics))
            .with_state(self)
    }

    /// Handle new WebSocket connection
    pub async fn handle_connection(
        &self,
        websocket: WebSocket,
        client_id: Uuid,
        ip_address: String,
        params: WebSocketParams,
    ) {
        println!("🔌 New WebSocket connection: {} from {}", client_id, ip_address);

        // Create client record
        let client = WebSocketClient {
            id: client_id,
            ip_address: ip_address.clone(),
            connected_at: SystemTime::now(),
            subscriptions: HashSet::new(),
            message_count: 0,
            last_activity: SystemTime::now(),
            user_agent: None,
        };

        // Add to clients map
        self.clients.write().await.insert(client_id, client);

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.total_connections += 1;
            metrics.active_connections += 1;
            metrics.peak_connections = metrics.peak_connections.max(metrics.active_connections);
        }

        // Split the WebSocket
        let (mut sender, mut receiver) = websocket.split();

        // Create channels for this client
        let (client_tx, mut client_rx) = tokio::sync::mpsc::unbounded_channel::<WebSocketMessage>();

        // Handle initial subscriptions
        if let Some(topics) = params.subscribe {
            let topics: Vec<String> = topics.split(',').map(|s| s.trim().to_string()).collect();
            self.subscribe_client(client_id, &topics).await;
        }

        // Spawn task to send messages to client
        let clients = self.clients.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            while let Some(msg) = client_rx.recv().await {
                let json_msg = serde_json::to_string(&msg).unwrap_or_else(|_| {
                    serde_json::to_string(&WebSocketMessage::Error {
                        message: "Serialization error".to_string(),
                        code: 500,
                    }).unwrap()
                });

                if sender.send(Message::Text(json_msg)).await.is_err() {
                    break;
                }

                // Update client activity
                if let Some(mut client) = clients.write().await.get_mut(&client_id) {
                    client.message_count += 1;
                    client.last_activity = SystemTime::now();
                }

                // Update metrics
                metrics.write().await.messages_sent += 1;
            }
        });

        // Handle incoming messages
        let subscription_manager = self.subscription_manager.clone();
        let clients_ref = self.clients.clone();
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    self.metrics.write().await.messages_received += 1;

                    match serde_json::from_str::<WebSocketMessage>(&text) {
                        Ok(ws_msg) => {
                            self.handle_client_message(client_id, ws_msg, &client_tx).await;
                        }
                        Err(e) => {
                            let error_msg = WebSocketMessage::Error {
                                message: format!("Invalid JSON: {}", e),
                                code: 400,
                            };
                            let _ = client_tx.send(error_msg);
                        }
                    }
                }
                Ok(Message::Binary(_)) => {
                    let error_msg = WebSocketMessage::Error {
                        message: "Binary messages not supported".to_string(),
                        code: 400,
                    };
                    let _ = client_tx.send(error_msg);
                }
                Ok(Message::Ping(_)) => {
                    // WebSocket ping/pong is handled automatically
                }
                Ok(Message::Pong(_)) => {
                    // Update last activity
                    if let Some(mut client) = clients_ref.write().await.get_mut(&client_id) {
                        client.last_activity = SystemTime::now();
                    }
                }
                Ok(Message::Close(_)) => {
                    break;
                }
                Err(e) => {
                    println!("⚠️  WebSocket error for {}: {}", client_id, e);
                    break;
                }
            }
        }

        // Cleanup on disconnect
        self.cleanup_client(client_id).await;
        println!("🔌 WebSocket disconnected: {}", client_id);
    }

    /// Handle client messages
    async fn handle_client_message(
        &self,
        client_id: Uuid,
        message: WebSocketMessage,
        client_tx: &tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
    ) {
        match message {
            WebSocketMessage::Subscribe { topics } => {
                self.subscribe_client(client_id, &topics).await;
                let response = WebSocketMessage::Success {
                    message: format!("Subscribed to {} topics", topics.len()),
                };
                let _ = client_tx.send(response);
            }
            WebSocketMessage::Unsubscribe { topics } => {
                self.unsubscribe_client(client_id, &topics).await;
                let response = WebSocketMessage::Success {
                    message: format!("Unsubscribed from {} topics", topics.len()),
                };
                let _ = client_tx.send(response);
            }
            WebSocketMessage::Ping { timestamp } => {
                let response = WebSocketMessage::Pong { timestamp };
                let _ = client_tx.send(response);
            }
            _ => {
                let error_msg = WebSocketMessage::Error {
                    message: "Unsupported message type".to_string(),
                    code: 400,
                };
                let _ = client_tx.send(error_msg);
            }
        }
    }

    /// Subscribe client to topics
    async fn subscribe_client(&self, client_id: Uuid, topics: &[String]) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(&client_id) {
            for topic in topics {
                client.subscriptions.insert(topic.clone());
                
                // Update subscription metrics
                let mut metrics = self.metrics.write().await;
                *metrics.subscription_counts.entry(topic.clone()).or_insert(0) += 1;
                
                println!("📩 Client {} subscribed to: {}", client_id, topic);
            }
        }
    }

    /// Unsubscribe client from topics
    async fn unsubscribe_client(&self, client_id: Uuid, topics: &[String]) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(&client_id) {
            for topic in topics {
                if client.subscriptions.remove(topic) {
                    // Update subscription metrics
                    let mut metrics = self.metrics.write().await;
                    if let Some(count) = metrics.subscription_counts.get_mut(topic) {
                        *count = count.saturating_sub(1);
                    }
                    
                    println!("📩 Client {} unsubscribed from: {}", client_id, topic);
                }
            }
        }
    }

    /// Cleanup client on disconnect
    async fn cleanup_client(&self, client_id: Uuid) {
        // Remove from clients map
        if let Some(client) = self.clients.write().await.remove(&client_id) {
            // Update subscription metrics
            let mut metrics = self.metrics.write().await;
            for topic in &client.subscriptions {
                if let Some(count) = metrics.subscription_counts.get_mut(topic) {
                    *count = count.saturating_sub(1);
                }
            }
            
            // Update connection metrics
            metrics.active_connections = metrics.active_connections.saturating_sub(1);
            
            // Calculate connection duration
            if let Ok(duration) = SystemTime::now().duration_since(client.connected_at) {
                metrics.avg_connection_duration = 
                    (metrics.avg_connection_duration + duration) / 2;
            }
        }

        // Remove from subscription manager
        self.subscription_manager.remove_client(client_id).await;
    }

    /// Broadcast block event
    pub async fn broadcast_block_event(&self, event: BlockEvent) {
        let _ = self.block_tx.send(event.clone());
        
        // Send to subscribed clients
        let clients = self.clients.read().await;
        for (client_id, client) in clients.iter() {
            if client.subscriptions.contains("blocks") || 
               client.subscriptions.contains("newBlocks") {
                // In a real implementation, you'd send to the client's channel
                println!("📡 Sending block event to client: {}", client_id);
            }
        }
    }

    /// Broadcast transaction event
    pub async fn broadcast_transaction_event(&self, event: TransactionEvent) {
        let _ = self.transaction_tx.send(event.clone());
        
        // Send to subscribed clients
        let clients = self.clients.read().await;
        for (client_id, client) in clients.iter() {
            if client.subscriptions.contains("transactions") || 
               client.subscriptions.contains("pendingTransactions") {
                println!("📡 Sending transaction event to client: {}", client_id);
            }
        }
    }

    /// Get WebSocket metrics
    pub async fn get_metrics(&self) -> WebSocketMetrics {
        self.metrics.read().await.clone()
    }

    /// Get connected clients count
    pub async fn get_client_count(&self) -> usize {
        self.clients.read().await.len()
    }
}

impl SubscriptionManager {
    /// Create new subscription manager
    pub fn new() -> Self {
        Self {
            block_subscribers: Arc::new(Mutex::new(HashMap::new())),
            tx_subscribers: Arc::new(Mutex::new(HashMap::new())),
            network_subscribers: Arc::new(Mutex::new(HashMap::new())),
            system_subscribers: Arc::new(Mutex::new(HashMap::new())),
            custom_subscribers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Remove client from all subscriptions
    pub async fn remove_client(&self, client_id: Uuid) {
        self.block_subscribers.lock().await.remove(&client_id);
        self.tx_subscribers.lock().await.remove(&client_id);
        self.network_subscribers.lock().await.remove(&client_id);
        self.system_subscribers.lock().await.remove(&client_id);
        
        // Remove from custom subscriptions
        let mut custom = self.custom_subscribers.lock().await;
        for (_, subscribers) in custom.iter_mut() {
            subscribers.remove(&client_id);
        }
    }
}

/// WebSocket handler endpoint
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WebSocketParams>,
    State(server): State<Arc<WebSocketServer>>,
) -> Response {
    let client_id = Uuid::new_v4();
    let ip_address = "127.0.0.1".to_string(); // In real implementation, extract from headers
    
    ws.on_upgrade(move |websocket| {
        server.handle_connection(websocket, client_id, ip_address, params)
    })
}

/// WebSocket status endpoint
pub async fn websocket_status(
    State(server): State<Arc<WebSocketServer>>,
) -> axum::Json<serde_json::Value> {
    let metrics = server.get_metrics().await;
    let client_count = server.get_client_count().await;
    
    axum::Json(serde_json::json!({
        "status": "active",
        "connected_clients": client_count,
        "total_connections": metrics.total_connections,
        "messages_sent": metrics.messages_sent,
        "messages_received": metrics.messages_received,
        "subscriptions": metrics.subscription_counts,
        "peak_connections": metrics.peak_connections
    }))
}

/// WebSocket metrics endpoint
pub async fn websocket_metrics(
    State(server): State<Arc<WebSocketServer>>,
) -> axum::Json<WebSocketMetrics> {
    axum::Json(server.get_metrics().await)
}

/// Create sample events for testing
impl WebSocketServer {
    /// Create sample block event
    pub fn create_sample_block_event() -> BlockEvent {
        BlockEvent {
            event: "newBlock".to_string(),
            block: BlockData {
                hash: format!("0x{:064x}", rand::random::<u64>()),
                number: 1234567,
                parent_hash: format!("0x{:064x}", rand::random::<u64>()),
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                miner: "0x742d35Cc6646C0532631a6f4E76b5Ca3D70eeE8f".to_string(),
                gas_used: 15000000,
                gas_limit: 30000000,
                transaction_count: 45,
                size: 2048,
                zk_proof_hash: Some(format!("0x{:064x}", rand::random::<u64>())),
            },
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Create sample transaction event
    pub fn create_sample_transaction_event() -> TransactionEvent {
        TransactionEvent {
            event: "pendingTransaction".to_string(),
            transaction: TransactionData {
                hash: format!("0x{:064x}", rand::random::<u64>()),
                from: "0x742d35Cc6646C0532631a6f4E76b5Ca3D70eeE8f".to_string(),
                to: Some("0x8ba1f109551bD432803012645Hac136c13067".to_string()),
                value: "1000000000000000000".to_string(), // 1 ETH
                gas_price: "20000000000".to_string(), // 20 gwei
                gas: 21000,
                status: "pending".to_string(),
                block_hash: None,
                block_number: None,
            },
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Start event simulation for testing
    pub async fn start_event_simulation(&self) {
        let server = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                // Simulate new block
                if rand::random::<f64>() < 0.3 {
                    let block_event = WebSocketServer::create_sample_block_event();
                    server.broadcast_block_event(block_event).await;
                }
                
                // Simulate new transaction
                if rand::random::<f64>() < 0.7 {
                    let tx_event = WebSocketServer::create_sample_transaction_event();
                    server.broadcast_transaction_event(tx_event).await;
                }
            }
        });
    }
}

impl Clone for WebSocketServer {
    fn clone(&self) -> Self {
        Self {
            clients: self.clients.clone(),
            block_tx: self.block_tx.clone(),
            transaction_tx: self.transaction_tx.clone(),
            network_tx: self.network_tx.clone(),
            system_tx: self.system_tx.clone(),
            subscription_manager: self.subscription_manager.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_message_serialization() {
        let ping_msg = WebSocketMessage::Ping { timestamp: 1234567890 };
        let json = serde_json::to_string(&ping_msg).unwrap();
        assert!(json.contains("Ping"));
        assert!(json.contains("1234567890"));
        
        let parsed: WebSocketMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            WebSocketMessage::Ping { timestamp } => assert_eq!(timestamp, 1234567890),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_block_event_creation() {
        let event = WebSocketServer::create_sample_block_event();
        assert_eq!(event.event, "newBlock");
        assert!(event.block.number > 0);
        assert!(event.block.hash.starts_with("0x"));
    }

    #[tokio::test]
    async fn test_websocket_server_creation() {
        let server = WebSocketServer::new();
        assert_eq!(server.get_client_count().await, 0);
        
        let metrics = server.get_metrics().await;
        assert_eq!(metrics.total_connections, 0);
        assert_eq!(metrics.active_connections, 0);
    }

    #[tokio::test]
    async fn test_subscription_management() {
        let server = WebSocketServer::new();
        let client_id = Uuid::new_v4();
        
        // Add mock client
        let client = WebSocketClient {
            id: client_id,
            ip_address: "127.0.0.1".to_string(),
            connected_at: SystemTime::now(),
            subscriptions: HashSet::new(),
            message_count: 0,
            last_activity: SystemTime::now(),
            user_agent: None,
        };
        server.clients.write().await.insert(client_id, client);
        
        // Test subscription
        server.subscribe_client(client_id, &["blocks".to_string()]).await;
        
        let clients = server.clients.read().await;
        let client = clients.get(&client_id).unwrap();
        assert!(client.subscriptions.contains("blocks"));
        
        let metrics = server.get_metrics().await;
        assert_eq!(metrics.subscription_counts.get("blocks"), Some(&1));
    }
} 