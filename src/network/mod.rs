// POAR Network Module
// P2P networking layer for blockchain communication

pub mod p2p;
pub mod discovery;
pub mod protocol;

pub use p2p::{
    P2PNetworkManager, NetworkConfig, NetworkEvent, MessageType, NetworkError,
    PeerInfo, PeerStatus, NetworkStats, GossipsubConfig, KademliaConfig
};

pub use discovery::{
    PeerDiscoveryManager, DiscoveryConfig, PeerRecord, ReputationSystem, 
    ReputationScore, TrustLevel, BanReason, DiscoveryStats
};

pub use protocol::{
    MessagePropagationManager, ProtocolHandler, ProtocolMessage, PropagationConfig,
    MessagePriority, PropagationStrategy, ProtocolResponse, PropagationStats
}; 