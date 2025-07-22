use libp2p::{
    identity, PeerId, Swarm, Multiaddr,
    core::upgrade,
    noise::{Keypair, NoiseConfig, X25519Spec, AuthenticKeypair, AuthenticNoiseKeypairRef},
    tcp::TcpConfig,
    yamux,
    mdns::{Mdns, MdnsConfig},
    kad::{Kademlia, store::MemoryStore},
    gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent, MessageAuthenticity, Topic, IdentTopic},
    swarm::{SwarmEvent, NetworkBehaviour},
    Transport,
};
use prost::Message;
use bincode;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use crate::types::{Block, Transaction};
use std::collections::HashMap;
use crate::proto::poar::{Block as ProtoBlock, Transaction as ProtoTransaction};
use crate::proto::poar::FinalityGossip as ProtoFinalityGossip;
use crate::consensus::engine::{FinalityGossip, ZKProof};

/// NetworkManager handles P2P networking for POAR using libp2p.
pub struct NetworkManager {
    pub swarm: Swarm<MyBehaviour>,
    pub local_peer_id: PeerId,
    pub block_topic: IdentTopic,
    pub tx_topic: IdentTopic,
    pub finality_topic: IdentTopic,
    block_callbacks: Arc<Mutex<Vec<Box<dyn Fn(Block) + Send>>>>,
    tx_callbacks: Arc<Mutex<Vec<Box<dyn Fn(Transaction) + Send>>>>,
    light_client_callbacks: Arc<Mutex<Vec<Box<dyn Fn(BlockHeader, ZKProof) + Send>>>>,
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "MyEvent")]
pub struct MyBehaviour {
    pub gossipsub: Gossipsub,
    pub mdns: Mdns,
    pub kademlia: Kademlia<MemoryStore>,
}

#[derive(Debug)]
pub enum MyEvent {
    Gossipsub(GossipsubEvent),
    Mdns(libp2p::mdns::MdnsEvent),
    Kademlia(libp2p::kad::KademliaEvent),
}

impl From<GossipsubEvent> for MyEvent {
    fn from(event: GossipsubEvent) -> Self { MyEvent::Gossipsub(event) }
}
impl From<libp2p::mdns::MdnsEvent> for MyEvent {
    fn from(event: libp2p::mdns::MdnsEvent) -> Self { MyEvent::Mdns(event) }
}
impl From<libp2p::kad::KademliaEvent> for MyEvent {
    fn from(event: libp2p::kad::KademliaEvent) -> Self { MyEvent::Kademlia(event) }
}

impl NetworkManager {
    /// Create and configure a new NetworkManager with libp2p, mDNS, DHT, and Gossipsub.
    pub async fn new() -> Self {
        // Generate identity keypair
        let id_keys = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(id_keys.public());

        // TCP transport with Noise encryption and Yamux multiplexing
        let noise_keys = Keypair::<X25519Spec>::new().into_authentic(&id_keys).expect("Noise key generation failed");
        let transport = TcpConfig::new()
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(yamux::YamuxConfig::default())
            .boxed();

        // Gossipsub setup
        let gossipsub_config = GossipsubConfig::default();
        let mut gossipsub = Gossipsub::new(MessageAuthenticity::Signed(id_keys.clone()), gossipsub_config).expect("Gossipsub init failed");
        let block_topic = IdentTopic::new("poar-block");
        let tx_topic = IdentTopic::new("poar-tx");
        let finality_topic = IdentTopic::new("poar-finality");
        gossipsub.subscribe(&block_topic).unwrap();
        gossipsub.subscribe(&tx_topic).unwrap();
        gossipsub.subscribe(&finality_topic).unwrap();

        // mDNS for local peer discovery
        let mdns = Mdns::new(MdnsConfig::default()).await.expect("mDNS init failed");

        // Kademlia DHT
        let store = MemoryStore::new(local_peer_id.clone());
        let kademlia = Kademlia::new(local_peer_id.clone(), store);

        // Compose behaviour
        let behaviour = MyBehaviour { gossipsub, mdns, kademlia };
        let mut swarm = Swarm::new(transport, behaviour, local_peer_id.clone());

        Self {
            swarm,
            local_peer_id,
            block_topic,
            tx_topic,
            finality_topic,
            block_callbacks: Arc::new(Mutex::new(Vec::new())),
            tx_callbacks: Arc::new(Mutex::new(Vec::new())),
            light_client_callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Broadcast a new block to the network
    pub fn broadcast_block(&mut self, block: Block) {
        let proto_block: ProtoBlock = block.into();
        let mut buf = Vec::new();
        if proto_block.encode(&mut buf).is_ok() {
            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.block_topic.clone(), buf);
        }
    }

    /// Broadcast a new transaction to the network
    pub fn broadcast_transaction(&mut self, tx: Transaction) {
        let proto_tx: ProtoTransaction = tx.into();
        let mut buf = Vec::new();
        if proto_tx.encode(&mut buf).is_ok() {
            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.tx_topic.clone(), buf);
        }
    }

    /// Broadcast a finality gossip message to the network
    pub fn broadcast_finality_gossip(&mut self, gossip: crate::consensus::engine::FinalityGossip) {
        // Convert to Protobuf
        let mut buf = Vec::new();
        let proto = ProtoFinalityGossip {
            block_header: bincode::serialize(&gossip.block_header).unwrap_or_default(),
            zk_proof: gossip.zk_proof.to_bytes(),
        };
        if proto.encode(&mut buf).is_ok() {
            let _ = self.swarm.behaviour_mut().gossipsub.publish(self.finality_topic.clone(), buf);
        }
    }

    /// Register a callback for when a new block is received
    pub fn on_block_received<F>(&mut self, callback: F)
    where F: Fn(Block) + Send + 'static {
        self.block_callbacks.lock().unwrap().push(Box::new(callback));
    }

    /// Register a callback for when a new transaction is received
    pub fn on_transaction_received<F>(&mut self, callback: F)
    where F: Fn(Transaction) + Send + 'static {
        self.tx_callbacks.lock().unwrap().push(Box::new(callback));
    }

    /// Register a callback for when a finalized block is received (for light clients)
    pub fn on_finalized_block<F>(&mut self, callback: F)
    where F: Fn(BlockHeader, ZKProof) + Send + 'static {
        self.light_client_callbacks.lock().unwrap().push(Box::new(callback));
    }

    pub async fn start(&mut self, consensus: Arc<Mutex<crate::consensus::engine::ConsensusEngine>>) {
        loop {
            match self.swarm.next_event().await {
                SwarmEvent::Behaviour(MyEvent::Gossipsub(GossipsubEvent::Message { propagation_source: _, message_id: _, message })) => {
                    if message.topic == self.block_topic.hash() {
                        match ProtoBlock::decode(&*message.data) {
                            Ok(proto_block) => {
                                let block: Block = proto_block.into();
                                for cb in self.block_callbacks.lock().unwrap().iter() {
                                    cb(block.clone());
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to decode block: {}", e);
                            }
                        }
                    } else if message.topic == self.tx_topic.hash() {
                        match ProtoTransaction::decode(&*message.data) {
                            Ok(proto_tx) => {
                                let tx: Transaction = proto_tx.into();
                                for cb in self.tx_callbacks.lock().unwrap().iter() {
                                    cb(tx.clone());
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to decode transaction: {}", e);
                            }
                        }
                    } else if message.topic == self.finality_topic.hash() {
                        // Handle finality gossip
                        if let Ok(proto) = ProtoFinalityGossip::decode(&*message.data) {
                            if let Ok(header) = bincode::deserialize(&proto.block_header) {
                                let gossip = crate::consensus::engine::FinalityGossip {
                                    block_header: header.clone(),
                                    zk_proof: ZKProof::from_bytes(&proto.zk_proof),
                                };
                                let mut consensus = consensus.lock().unwrap();
                                consensus.on_finality_gossip(gossip);
                                // Notify light client callbacks
                                let zk_proof = ZKProof::from_bytes(&proto.zk_proof);
                                for cb in self.light_client_callbacks.lock().unwrap().iter() {
                                    cb(header.clone(), zk_proof.clone());
                                }
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(MyEvent::Mdns(event)) => {
                    // Handle mDNS peer discovery
                    match event {
                        libp2p::mdns::MdnsEvent::Discovered(peers) => {
                            // Add discovered peers to Kademlia DHT
                            for (peer_id, _addr) in peers {
                                self.swarm.behaviour_mut().kademlia.add_address(&peer_id, _addr.clone());
                            }
                        }
                        libp2p::mdns::MdnsEvent::Expired(peers) => {
                            // Remove expired peers from Kademlia DHT
                            for (peer_id, _addr) in peers {
                                self.swarm.behaviour_mut().kademlia.remove_address(&peer_id, &_addr);
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(MyEvent::Kademlia(_event)) => {
                    // Handle DHT events (can be extended for custom logic)
                }
                _ => {}
            }
        }
    }
}

/// TODO: Define Protobuf message types for Block and Transaction if not already present. 