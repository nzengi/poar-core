use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use libp2p::{
    Swarm, PeerId, Multiaddr, 
    swarm::{SwarmEvent, SwarmBuilder, NetworkBehaviour},
    tcp, noise, yamux, mplex,
    gossipsub::{self, Gossipsub, GossipsubMessage, IdentTopic as Topic},
    kad::{self, Kademlia, KademliaEvent},
    mdns::{self, Mdns},
    ping::{self, Ping},
    identify::{self, Identify},
    autonat::{self, Autonat},
    relay,
    dcutr,
};
use futures::StreamExt;
use serde::{Serialize, Deserialize};
use crate::types::{Hash, Block, Transaction};

/// P2P Network Manager for POAR blockchain
pub struct P2PNetworkManager {
    /// libp2p swarm instance
    swarm: Arc<Mutex<Swarm<PoarNetworkBehaviour>>>,
    /// Network configuration
    config: NetworkConfig,
    /// Connected peers information
    peers: Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
    /// Message handlers
    message_handlers: Arc<RwLock<HashMap<MessageType, Box<dyn MessageHandler + Send + Sync>>>>,
    /// Network statistics
    stats: Arc<RwLock<NetworkStats>>,
    /// Event sender for application layer
    event_sender: mpsc::UnboundedSender<NetworkEvent>,
    /// Shutdown signal
    shutdown: Arc<tokio::sync::Notify>,
}

/// Network behavior combining multiple protocols
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PoarNetworkEvent")]
pub struct PoarNetworkBehaviour {
    /// Gossipsub for message propagation
    gossipsub: Gossipsub,
    /// Kademlia DHT for peer discovery
    kademlia: Kademlia<kad::store::MemoryStore>,
    /// mDNS for local network discovery
    mdns: Mdns,
    /// Ping protocol for connectivity testing
    ping: Ping,
    /// Identify protocol for peer information
    identify: Identify,
    /// AutoNAT for NAT detection
    autonat: Autonat,
    /// Relay protocol for NAT traversal
    relay: relay::Behaviour,
    /// DCUtR for direct connection upgrade
    dcutr: dcutr::Behaviour,
}

/// Network behavior events
#[derive(Debug)]
pub enum PoarNetworkEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(KademliaEvent),
    Mdns(mdns::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Autonat(autonat::Event),
    Relay(relay::Event),
    Dcutr(dcutr::Event),
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Local peer ID
    pub local_peer_id: PeerId,
    /// Listen addresses
    pub listen_addresses: Vec<Multiaddr>,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Gossipsub configuration
    pub gossipsub_config: GossipsubConfig,
    /// Kademlia configuration
    pub kademlia_config: KademliaConfig,
    /// Enable relay server
    pub enable_relay_server: bool,
    /// Enable hole punching
    pub enable_hole_punching: bool,
    /// Bandwidth limits
    pub bandwidth_limits: BandwidthLimits,
}

/// Gossipsub protocol configuration
#[derive(Debug, Clone)]
pub struct GossipsubConfig {
    /// Message validation mode
    pub validation_mode: gossipsub::ValidationMode,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Message cache time
    pub message_cache_time: Duration,
    /// Maximum message size
    pub max_message_size: usize,
    /// Duplicate cache time
    pub duplicate_cache_time: Duration,
}

/// Kademlia DHT configuration
#[derive(Debug, Clone)]
pub struct KademliaConfig {
    /// Replication factor
    pub replication_factor: usize,
    /// Query timeout
    pub query_timeout: Duration,
    /// Record TTL
    pub record_ttl: Duration,
    /// Provider record TTL
    pub provider_record_ttl: Duration,
}

/// Bandwidth limits configuration
#[derive(Debug, Clone)]
pub struct BandwidthLimits {
    /// Maximum inbound bandwidth (bytes/sec)
    pub max_inbound_bandwidth: u64,
    /// Maximum outbound bandwidth (bytes/sec)
    pub max_outbound_bandwidth: u64,
    /// Per-peer bandwidth limit
    pub per_peer_bandwidth_limit: u64,
}

/// Peer information
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Addresses
    pub addresses: Vec<Multiaddr>,
    /// Connection status
    pub status: PeerStatus,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Reputation score
    pub reputation: i32,
    /// Protocol support
    pub protocols: HashSet<String>,
    /// Network statistics
    pub stats: PeerStats,
    /// Geographic information
    pub geo_info: Option<GeoInfo>,
}

/// Peer connection status
#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    Connecting,
    Connected,
    Disconnected,
    Banned,
}

/// Per-peer statistics
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Connection uptime
    pub uptime: Duration,
    /// Average latency
    pub average_latency: Duration,
}

/// Geographic information for peers
#[derive(Debug, Clone)]
pub struct GeoInfo {
    /// Country code
    pub country: String,
    /// City
    pub city: String,
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// ISP information
    pub isp: String,
}

/// Network statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Total peers connected
    pub connected_peers: usize,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Total messages sent
    pub total_messages_sent: u64,
    /// Total messages received
    pub total_messages_received: u64,
    /// Network uptime
    pub uptime: Duration,
    /// Average bandwidth utilization
    pub avg_bandwidth_utilization: f64,
    /// Connection attempts
    pub connection_attempts: u64,
    /// Successful connections
    pub successful_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
}

/// Network events for application layer
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// New message received
    MessageReceived {
        from: PeerId,
        message_type: MessageType,
        data: Vec<u8>,
    },
    /// Block received
    BlockReceived {
        from: PeerId,
        block: Block,
    },
    /// Transaction received
    TransactionReceived {
        from: PeerId,
        transaction: Transaction,
    },
    /// Peer discovery update
    PeerDiscovered(PeerId, Vec<Multiaddr>),
    /// Network error
    NetworkError(String),
}

/// Message types in the network
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Block,
    Transaction,
    ConsensusMessage,
    StateSync,
    PeerAnnouncement,
    Ping,
    Custom(String),
}

/// Message handler trait
pub trait MessageHandler {
    /// Handle incoming message
    fn handle_message(&self, from: PeerId, data: Vec<u8>) -> Result<(), NetworkError>;
}

/// Network-specific errors
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Message validation failed: {0}")]
    MessageValidationFailed(String),
    #[error("Peer not found: {0}")]
    PeerNotFound(PeerId),
    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Message to be sent over the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message type
    pub message_type: MessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message timestamp
    pub timestamp: u64,
    /// Message ID for deduplication
    pub message_id: Hash,
    /// Sender information
    pub sender: PeerId,
    /// TTL for message propagation
    pub ttl: u8,
}

impl P2PNetworkManager {
    /// Create a new P2P network manager
    pub async fn new(config: NetworkConfig) -> Result<(Self, mpsc::UnboundedReceiver<NetworkEvent>), NetworkError> {
        // Create identity and transport
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        println!("🆔 Local Peer ID: {}", local_peer_id);

        // Create transport
        let transport = tcp::tokio::Transport::default()
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::NoiseAuthenticated::xx(&local_key)?)
            .multiplex(yamux::YamuxConfig::default())
            .boxed();

        // Configure Gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .heartbeat_interval(config.gossipsub_config.heartbeat_interval)
            .validation_mode(config.gossipsub_config.validation_mode)
            .message_id_fn(|message| {
                // Custom message ID function
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                message.data.hash(&mut hasher);
                hasher.finish().to_string().into_bytes()
            })
            .max_transmit_size(config.gossipsub_config.max_message_size)
            .duplicate_cache_time(config.gossipsub_config.duplicate_cache_time)
            .build()
            .map_err(|e| NetworkError::ProtocolError(format!("Gossipsub config error: {}", e)))?;

        let mut gossipsub = Gossipsub::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::ProtocolError(format!("Gossipsub creation error: {}", e)))?;

        // Subscribe to topics
        let block_topic = Topic::new("poar-blocks");
        let tx_topic = Topic::new("poar-transactions");
        let consensus_topic = Topic::new("poar-consensus");
        
        gossipsub.subscribe(&block_topic)?;
        gossipsub.subscribe(&tx_topic)?;
        gossipsub.subscribe(&consensus_topic)?;

        // Configure Kademlia DHT
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kademlia = Kademlia::new(local_peer_id, store);
        
        // Add bootstrap nodes
        for (peer_id, addr) in &config.bootstrap_nodes {
            kademlia.add_address(peer_id, addr.clone());
        }

        // Create mDNS for local discovery
        let mdns = Mdns::new(mdns::Config::default())
            .map_err(|e| NetworkError::ProtocolError(format!("mDNS error: {}", e)))?;

        // Create other protocols
        let ping = Ping::new(ping::Config::new());
        let identify = Identify::new(identify::Config::new(
            "/poar/1.0.0".to_string(),
            local_key.public(),
        ));
        let autonat = Autonat::new(local_peer_id, autonat::Config::default());
        let relay = relay::Behaviour::new(local_peer_id, relay::Config::default());
        let dcutr = dcutr::Behaviour::new(local_peer_id);

        // Create network behavior
        let behaviour = PoarNetworkBehaviour {
            gossipsub,
            kademlia,
            mdns,
            ping,
            identify,
            autonat,
            relay,
            dcutr,
        };

        // Create swarm
        let swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
            .build();

        // Create event channel
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let manager = Self {
            swarm: Arc::new(Mutex::new(swarm)),
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            message_handlers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(NetworkStats::default())),
            event_sender,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        };

        Ok((manager, event_receiver))
    }

    /// Start the network manager
    pub async fn start(&self) -> Result<(), NetworkError> {
        println!("🚀 Starting POAR P2P Network Manager...");

        // Start listening on configured addresses
        let mut swarm = self.swarm.lock().await;
        for addr in &self.config.listen_addresses {
            swarm.listen_on(addr.clone())?;
            println!("👂 Listening on: {}", addr);
        }

        // Bootstrap DHT
        if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
            println!("⚠️  DHT bootstrap warning: {}", e);
        }

        drop(swarm);

        // Start main event loop
        self.start_event_loop().await;

        println!("✅ P2P Network Manager started successfully");
        Ok(())
    }

    /// Start the main event processing loop
    async fn start_event_loop(&self) {
        let swarm = self.swarm.clone();
        let event_sender = self.event_sender.clone();
        let peers = self.peers.clone();
        let stats = self.stats.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut swarm = swarm.lock().await;
            
            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        Self::handle_swarm_event(event, &event_sender, &peers, &stats).await;
                    }
                    _ = shutdown.notified() => {
                        println!("🛑 Shutting down P2P network manager");
                        break;
                    }
                }
            }
        });
    }

    /// Handle swarm events
    async fn handle_swarm_event(
        event: SwarmEvent<PoarNetworkEvent>,
        event_sender: &mpsc::UnboundedSender<NetworkEvent>,
        peers: &Arc<RwLock<HashMap<PeerId, PeerInfo>>>,
        stats: &Arc<RwLock<NetworkStats>>,
    ) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("📍 New listen address: {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("🤝 Connected to peer: {}", peer_id);
                
                // Update peer info
                let mut peers_map = peers.write().await;
                peers_map.insert(peer_id, PeerInfo {
                    peer_id,
                    addresses: vec![],
                    status: PeerStatus::Connected,
                    last_seen: Instant::now(),
                    reputation: 100, // Default reputation
                    protocols: HashSet::new(),
                    stats: PeerStats::default(),
                    geo_info: None,
                });

                // Update stats
                let mut network_stats = stats.write().await;
                network_stats.connected_peers = peers_map.len();
                network_stats.successful_connections += 1;

                // Send event
                let _ = event_sender.send(NetworkEvent::PeerConnected(peer_id));
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("❌ Disconnected from peer: {}", peer_id);
                
                // Update peer status
                let mut peers_map = peers.write().await;
                if let Some(peer_info) = peers_map.get_mut(&peer_id) {
                    peer_info.status = PeerStatus::Disconnected;
                    peer_info.last_seen = Instant::now();
                }

                // Update stats
                let mut network_stats = stats.write().await;
                network_stats.connected_peers = peers_map.iter().filter(|(_, p)| p.status == PeerStatus::Connected).count();

                // Send event
                let _ = event_sender.send(NetworkEvent::PeerDisconnected(peer_id));
            }
            SwarmEvent::Behaviour(PoarNetworkEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                Self::handle_gossipsub_message(propagation_source, message, event_sender, stats).await;
            }
            SwarmEvent::Behaviour(PoarNetworkEvent::Kademlia(kad_event)) => {
                Self::handle_kademlia_event(kad_event, event_sender).await;
            }
            SwarmEvent::Behaviour(PoarNetworkEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    println!("🔍 Discovered peer via mDNS: {} at {}", peer_id, multiaddr);
                    let _ = event_sender.send(NetworkEvent::PeerDiscovered(peer_id, vec![multiaddr]));
                }
            }
            SwarmEvent::Behaviour(PoarNetworkEvent::Ping(ping::Event { peer, result })) => {
                match result {
                    Ok(rtt) => {
                        // Update peer latency
                        let mut peers_map = peers.write().await;
                        if let Some(peer_info) = peers_map.get_mut(&peer) {
                            peer_info.stats.average_latency = rtt;
                        }
                    }
                    Err(e) => {
                        println!("⚠️  Ping failed for peer {}: {}", peer, e);
                    }
                }
            }
            SwarmEvent::Behaviour(PoarNetworkEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                // Update peer protocol information
                let mut peers_map = peers.write().await;
                if let Some(peer_info) = peers_map.get_mut(&peer_id) {
                    peer_info.protocols = info.protocols.into_iter().collect();
                    peer_info.addresses = info.listen_addrs;
                }
                
                println!("🔍 Identified peer: {} with {} protocols", peer_id, info.protocols.len());
            }
            _ => {
                // Handle other events
            }
        }
    }

    /// Handle Gossipsub messages
    async fn handle_gossipsub_message(
        source: PeerId,
        message: GossipsubMessage,
        event_sender: &mpsc::UnboundedSender<NetworkEvent>,
        stats: &Arc<RwLock<NetworkStats>>,
    ) {
        // Update stats
        let mut network_stats = stats.write().await;
        network_stats.total_messages_received += 1;
        network_stats.total_bytes_received += message.data.len() as u64;
        drop(network_stats);

        // Try to deserialize as NetworkMessage
        match postcard::from_bytes::<NetworkMessage>(&message.data) {
            Ok(network_msg) => {
                let _ = event_sender.send(NetworkEvent::MessageReceived {
                    from: source,
                    message_type: network_msg.message_type,
                    data: network_msg.payload,
                });
            }
            Err(e) => {
                println!("⚠️  Failed to deserialize message from {}: {}", source, e);
            }
        }
    }

    /// Handle Kademlia DHT events
    async fn handle_kademlia_event(
        event: KademliaEvent,
        event_sender: &mpsc::UnboundedSender<NetworkEvent>,
    ) {
        match event {
            KademliaEvent::RoutingUpdated { peer, addresses, .. } => {
                println!("🗺️  DHT routing updated for peer: {}", peer);
                let _ = event_sender.send(NetworkEvent::PeerDiscovered(peer, addresses.into_vec()));
            }
            KademliaEvent::OutboundQueryProgressed { result, .. } => {
                match result {
                    kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { peer, num_remaining })) => {
                        println!("🔗 Bootstrap progress: {} peers remaining", num_remaining);
                    }
                    kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })) => {
                        println!("👥 Found {} closest peers", peers.len());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Send a message to a specific peer
    pub async fn send_message_to_peer(
        &self,
        peer_id: PeerId,
        message_type: MessageType,
        data: Vec<u8>,
    ) -> Result<(), NetworkError> {
        let network_msg = NetworkMessage {
            message_type,
            payload: data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_id: Hash::hash(&rand::random::<[u8; 32]>()),
            sender: self.config.local_peer_id,
            ttl: 10,
        };

        let serialized = postcard::to_allocvec(&network_msg)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        // Send via gossipsub (for now, direct peer messaging would need additional protocol)
        let mut swarm = self.swarm.lock().await;
        let topic = Topic::new("poar-direct-messages");
        
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, serialized) {
            return Err(NetworkError::ProtocolError(format!("Failed to publish message: {}", e)));
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_messages_sent += 1;
        stats.total_bytes_sent += network_msg.payload.len() as u64;

        Ok(())
    }

    /// Broadcast message to all peers
    pub async fn broadcast_message(
        &self,
        message_type: MessageType,
        data: Vec<u8>,
    ) -> Result<(), NetworkError> {
        let topic = match message_type {
            MessageType::Block => Topic::new("poar-blocks"),
            MessageType::Transaction => Topic::new("poar-transactions"),
            MessageType::ConsensusMessage => Topic::new("poar-consensus"),
            _ => Topic::new("poar-general"),
        };

        let network_msg = NetworkMessage {
            message_type,
            payload: data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            message_id: Hash::hash(&rand::random::<[u8; 32]>()),
            sender: self.config.local_peer_id,
            ttl: 10,
        };

        let serialized = postcard::to_allocvec(&network_msg)
            .map_err(|e| NetworkError::SerializationError(e.to_string()))?;

        let mut swarm = self.swarm.lock().await;
        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, serialized) {
            return Err(NetworkError::ProtocolError(format!("Failed to broadcast message: {}", e)));
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_messages_sent += 1;
        stats.total_bytes_sent += network_msg.payload.len() as u64;

        println!("📡 Broadcasted message type: {:?}", network_msg.message_type);
        Ok(())
    }

    /// Get network statistics
    pub async fn get_stats(&self) -> NetworkStats {
        self.stats.read().await.clone()
    }

    /// Get connected peers
    pub async fn get_connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().await
            .values()
            .filter(|p| p.status == PeerStatus::Connected)
            .cloned()
            .collect()
    }

    /// Shutdown the network manager
    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
        println!("🛑 P2P Network Manager shutdown initiated");
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            local_peer_id: PeerId::random(),
            listen_addresses: vec![
                "/ip4/0.0.0.0/tcp/30303".parse().unwrap(),
                "/ip6/::/tcp/30303".parse().unwrap(),
            ],
            bootstrap_nodes: vec![],
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
            gossipsub_config: GossipsubConfig::default(),
            kademlia_config: KademliaConfig::default(),
            enable_relay_server: false,
            enable_hole_punching: true,
            bandwidth_limits: BandwidthLimits::default(),
        }
    }
}

impl Default for GossipsubConfig {
    fn default() -> Self {
        Self {
            validation_mode: gossipsub::ValidationMode::Strict,
            heartbeat_interval: Duration::from_secs(1),
            message_cache_time: Duration::from_secs(60),
            max_message_size: 1024 * 1024, // 1MB
            duplicate_cache_time: Duration::from_secs(60),
        }
    }
}

impl Default for KademliaConfig {
    fn default() -> Self {
        Self {
            replication_factor: 20,
            query_timeout: Duration::from_secs(60),
            record_ttl: Duration::from_secs(3600), // 1 hour
            provider_record_ttl: Duration::from_secs(3600),
        }
    }
}

impl Default for BandwidthLimits {
    fn default() -> Self {
        Self {
            max_inbound_bandwidth: 10 * 1024 * 1024,  // 10 MB/s
            max_outbound_bandwidth: 10 * 1024 * 1024, // 10 MB/s
            per_peer_bandwidth_limit: 1024 * 1024,    // 1 MB/s per peer
        }
    }
}

impl libp2p::swarm::behaviour::FromSwarm for PoarNetworkBehaviour {
    fn from_swarm(
        &mut self,
        event: &libp2p::swarm::FromSwarm,
        _context: &mut std::task::Context<'_>,
    ) {
        // Handle swarm events that need to be passed to individual behaviors
        self.gossipsub.on_swarm_event(event);
        self.kademlia.on_swarm_event(event);
        self.mdns.on_swarm_event(event);
        self.ping.on_swarm_event(event);
        self.identify.on_swarm_event(event);
        self.autonat.on_swarm_event(event);
        self.relay.on_swarm_event(event);
        self.dcutr.on_swarm_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_manager_creation() {
        let config = NetworkConfig::default();
        let result = P2PNetworkManager::new(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_message_serialization() {
        let message = NetworkMessage {
            message_type: MessageType::Block,
            payload: b"test data".to_vec(),
            timestamp: 1234567890,
            message_id: Hash::hash(b"test"),
            sender: PeerId::random(),
            ttl: 10,
        };

        let serialized = postcard::to_allocvec(&message).unwrap();
        let deserialized: NetworkMessage = postcard::from_bytes(&serialized).unwrap();
        
        assert_eq!(message.message_type, deserialized.message_type);
        assert_eq!(message.payload, deserialized.payload);
    }
}
