use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{RwLock, Mutex};
use libp2p::{PeerId, Multiaddr};
use serde::{Serialize, Deserialize};
use trust_dns_resolver::{TokioAsyncResolver, config::*};

/// Advanced peer discovery manager
pub struct PeerDiscoveryManager {
    /// Known peers database
    peers_db: Arc<RwLock<HashMap<PeerId, PeerRecord>>>,
    /// Bootstrap nodes
    bootstrap_nodes: Vec<BootstrapNode>,
    /// Reputation system
    reputation_system: Arc<ReputationSystem>,
    /// Geographic distribution tracker
    geo_tracker: Arc<GeoTracker>,
    /// Discovery configuration
    config: DiscoveryConfig,
    /// DNS resolver for seed nodes
    dns_resolver: Arc<TokioAsyncResolver>,
    /// Banned peers
    banned_peers: Arc<RwLock<HashMap<PeerId, BanInfo>>>,
    /// Discovery statistics
    stats: Arc<RwLock<DiscoveryStats>>,
}

/// Peer record with comprehensive information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses
    pub addresses: Vec<AddressInfo>,
    /// Reputation score
    pub reputation: ReputationScore,
    /// First seen timestamp
    pub first_seen: SystemTime,
    /// Last seen timestamp
    pub last_seen: SystemTime,
    /// Connection history
    pub connection_history: ConnectionHistory,
    /// Supported protocols
    pub protocols: HashSet<String>,
    /// Geographic information
    pub geo_info: Option<GeoLocation>,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Trust level
    pub trust_level: TrustLevel,
}

/// Address information with quality metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The multiaddress
    pub address: Multiaddr,
    /// Address quality score
    pub quality_score: f64,
    /// Last successful connection
    pub last_successful: Option<SystemTime>,
    /// Connection attempts
    pub connection_attempts: u32,
    /// Success rate
    pub success_rate: f64,
    /// Average latency
    pub average_latency: Duration,
    /// Address type classification
    pub address_type: AddressType,
}

/// Address type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AddressType {
    Public,
    Private,
    Relay,
    WebRTC,
    Tor,
    Unknown,
}

/// Connection history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionHistory {
    /// Total connection attempts
    pub total_attempts: u32,
    /// Successful connections
    pub successful_connections: u32,
    /// Failed connections
    pub failed_connections: u32,
    /// Average session duration
    pub avg_session_duration: Duration,
    /// Last connection attempt
    pub last_attempt: Option<SystemTime>,
    /// Connection quality trend
    pub quality_trend: QualityTrend,
}

/// Quality trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QualityTrend {
    Improving,
    Stable,
    Declining,
    Unknown,
}

/// Peer capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Is a validator
    pub is_validator: bool,
    /// Supports full sync
    pub supports_full_sync: bool,
    /// Supports light client
    pub supports_light_client: bool,
    /// Archive node capability
    pub is_archive_node: bool,
    /// Relay capability
    pub supports_relay: bool,
    /// Maximum bandwidth
    pub max_bandwidth: Option<u64>,
    /// Storage capacity
    pub storage_capacity: Option<u64>,
}

/// Trust level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Banned = 0,
    Untrusted = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Verified = 5,
}

/// Bootstrap node configuration
#[derive(Debug, Clone)]
pub struct BootstrapNode {
    /// Peer ID
    pub peer_id: PeerId,
    /// Bootstrap addresses
    pub addresses: Vec<Multiaddr>,
    /// DNS seed domain
    pub dns_seed: Option<String>,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Geographic region
    pub region: Option<String>,
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Maximum peers to track
    pub max_peers: usize,
    /// Peer discovery interval
    pub discovery_interval: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Reputation update interval
    pub reputation_update_interval: Duration,
    /// Geographic distribution requirements
    pub geo_requirements: GeoRequirements,
    /// Quality thresholds
    pub quality_thresholds: QualityThresholds,
    /// Bootstrap configuration
    pub bootstrap_config: BootstrapConfig,
}

/// Geographic distribution requirements
#[derive(Debug, Clone)]
pub struct GeoRequirements {
    /// Minimum number of different countries
    pub min_countries: usize,
    /// Minimum number of different continents
    pub min_continents: usize,
    /// Maximum peers per country
    pub max_peers_per_country: usize,
    /// Prefer geographic diversity
    pub prefer_diversity: bool,
}

/// Quality thresholds for peer selection
#[derive(Debug, Clone)]
pub struct QualityThresholds {
    /// Minimum reputation score
    pub min_reputation: f64,
    /// Minimum success rate
    pub min_success_rate: f64,
    /// Maximum acceptable latency
    pub max_latency: Duration,
    /// Minimum uptime percentage
    pub min_uptime: f64,
}

/// Bootstrap configuration
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<String>,
    /// Hardcoded bootstrap peers
    pub hardcoded_peers: Vec<String>,
    /// Bootstrap timeout
    pub bootstrap_timeout: Duration,
    /// Retry attempts
    pub retry_attempts: u32,
}

/// Ban information for peers
#[derive(Debug, Clone)]
pub struct BanInfo {
    /// Ban timestamp
    pub banned_at: SystemTime,
    /// Ban duration
    pub duration: Duration,
    /// Ban reason
    pub reason: BanReason,
    /// Ban severity
    pub severity: BanSeverity,
}

/// Reasons for banning peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BanReason {
    MaliciousActivity,
    RepeatedConnectionFailures,
    ProtocolViolation,
    SpamBehavior,
    InvalidMessages,
    ConsensusAttack,
    Manual,
}

/// Ban severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BanSeverity {
    Warning,
    Temporary,
    Extended,
    Permanent,
}

/// Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    /// Total peers discovered
    pub total_discovered: u64,
    /// Successful connections
    pub successful_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
    /// DNS queries performed
    pub dns_queries: u64,
    /// Geographic distribution
    pub geo_distribution: HashMap<String, u32>,
    /// Average peer quality
    pub avg_peer_quality: f64,
    /// Discovery efficiency
    pub discovery_efficiency: f64,
}

/// Reputation system for peer scoring
pub struct ReputationSystem {
    /// Reputation scores
    scores: Arc<RwLock<HashMap<PeerId, ReputationScore>>>,
    /// Reputation config
    config: ReputationConfig,
    /// Score history
    history: Arc<RwLock<HashMap<PeerId, Vec<ReputationEvent>>>>,
}

/// Reputation score with breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Overall score (0-1000)
    pub overall: f64,
    /// Connection reliability (0-100)
    pub connection_reliability: f64,
    /// Message quality (0-100)
    pub message_quality: f64,
    /// Protocol compliance (0-100)
    pub protocol_compliance: f64,
    /// Network contribution (0-100)
    pub network_contribution: f64,
    /// Validator performance (0-100, if applicable)
    pub validator_performance: Option<f64>,
    /// Last updated
    pub last_updated: SystemTime,
}

/// Reputation configuration
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Base reputation for new peers
    pub base_reputation: f64,
    /// Maximum reputation
    pub max_reputation: f64,
    /// Minimum reputation
    pub min_reputation: f64,
    /// Decay rate per day
    pub decay_rate: f64,
    /// Weight factors for different components
    pub weights: ReputationWeights,
}

/// Weight factors for reputation components
#[derive(Debug, Clone)]
pub struct ReputationWeights {
    pub connection_reliability: f64,
    pub message_quality: f64,
    pub protocol_compliance: f64,
    pub network_contribution: f64,
    pub validator_performance: f64,
}

/// Reputation events for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: ReputationEventType,
    /// Score impact
    pub score_impact: f64,
    /// Event description
    pub description: String,
}

/// Types of reputation events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationEventType {
    ConnectionSuccess,
    ConnectionFailure,
    MessageValidation,
    ProtocolViolation,
    NetworkContribution,
    ValidatorAction,
    ManualAdjustment,
}

/// Geographic tracker for peer distribution
pub struct GeoTracker {
    /// Peer geographic information
    geo_data: Arc<RwLock<HashMap<PeerId, GeoLocation>>>,
    /// Geographic distribution stats
    distribution: Arc<RwLock<GeoDistribution>>,
    /// GeoIP service configuration
    geoip_config: GeoIPConfig,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// Country name
    pub country_name: String,
    /// Continent code
    pub continent: String,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Timezone
    pub timezone: Option<String>,
    /// ISP information
    pub isp: Option<String>,
    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,
}

/// Geographic distribution statistics
#[derive(Debug, Clone, Default)]
pub struct GeoDistribution {
    /// Peers per country
    pub countries: HashMap<String, u32>,
    /// Peers per continent
    pub continents: HashMap<String, u32>,
    /// Diversity score (0-1)
    pub diversity_score: f64,
    /// Distribution entropy
    pub entropy: f64,
}

/// GeoIP service configuration
#[derive(Debug, Clone)]
pub struct GeoIPConfig {
    /// GeoIP service URL
    pub service_url: String,
    /// API key for service
    pub api_key: Option<String>,
    /// Cache duration for geo data
    pub cache_duration: Duration,
    /// Enable geo tracking
    pub enabled: bool,
}

impl PeerDiscoveryManager {
    /// Create new peer discovery manager
    pub async fn new(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        let dns_resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        )?;

        let reputation_system = ReputationSystem::new(ReputationConfig::default());
        let geo_tracker = GeoTracker::new(GeoIPConfig::default());

        Ok(Self {
            peers_db: Arc::new(RwLock::new(HashMap::new())),
            bootstrap_nodes: Self::create_bootstrap_nodes(),
            reputation_system: Arc::new(reputation_system),
            geo_tracker: Arc::new(geo_tracker),
            config,
            dns_resolver: Arc::new(dns_resolver),
            banned_peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(DiscoveryStats::default())),
        })
    }

    /// Start peer discovery process
    pub async fn start_discovery(&self) -> Result<(), DiscoveryError> {
        println!("🔍 Starting peer discovery process...");

        // Bootstrap from DNS seeds
        self.bootstrap_from_dns().await?;

        // Bootstrap from hardcoded peers
        self.bootstrap_from_hardcoded().await?;

        // Start continuous discovery loop
        self.start_discovery_loop().await;

        println!("✅ Peer discovery started successfully");
        Ok(())
    }

    /// Bootstrap peers from DNS seeds
    async fn bootstrap_from_dns(&self) -> Result<(), DiscoveryError> {
        println!("🌐 Bootstrapping from DNS seeds...");

        for seed in &self.config.bootstrap_config.dns_seeds {
            match self.resolve_dns_seed(seed).await {
                Ok(addresses) => {
                    println!("📍 Found {} addresses from DNS seed: {}", addresses.len(), seed);
                    for addr in addresses {
                        self.add_discovered_peer(None, vec![addr]).await;
                    }
                }
                Err(e) => {
                    println!("⚠️  Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }

        Ok(())
    }

    /// Resolve DNS seed to get peer addresses
    async fn resolve_dns_seed(&self, seed: &str) -> Result<Vec<Multiaddr>, DiscoveryError> {
        let mut addresses = Vec::new();

        // Query TXT records for peer information
        match self.dns_resolver.txt_lookup(seed).await {
            Ok(response) => {
                for record in response.iter() {
                    let txt_data = record.to_string();
                    if let Ok(addr) = txt_data.parse::<Multiaddr>() {
                        addresses.push(addr);
                    }
                }
            }
            Err(e) => {
                return Err(DiscoveryError::DnsResolutionFailed(e.to_string()));
            }
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.dns_queries += 1;

        Ok(addresses)
    }

    /// Bootstrap from hardcoded peers
    async fn bootstrap_from_hardcoded(&self) -> Result<(), DiscoveryError> {
        println!("📋 Bootstrapping from hardcoded peers...");

        for peer_str in &self.config.bootstrap_config.hardcoded_peers {
            if let Ok(addr) = peer_str.parse::<Multiaddr>() {
                self.add_discovered_peer(None, vec![addr]).await;
            }
        }

        Ok(())
    }

    /// Add a discovered peer to the database
    pub async fn add_discovered_peer(&self, peer_id: Option<PeerId>, addresses: Vec<Multiaddr>) {
        let peer_id = peer_id.unwrap_or_else(PeerId::random);
        
        let mut peers_db = self.peers_db.write().await;
        
        match peers_db.get_mut(&peer_id) {
            Some(existing_peer) => {
                // Update existing peer with new addresses
                for addr in addresses {
                    if !existing_peer.addresses.iter().any(|a| a.address == addr) {
                        existing_peer.addresses.push(AddressInfo {
                            address: addr,
                            quality_score: 50.0, // Default score
                            last_successful: None,
                            connection_attempts: 0,
                            success_rate: 0.0,
                            average_latency: Duration::from_millis(100),
                            address_type: AddressType::Unknown,
                        });
                    }
                }
                existing_peer.last_seen = SystemTime::now();
            }
            None => {
                // Create new peer record
                let address_infos: Vec<AddressInfo> = addresses.into_iter().map(|addr| {
                    AddressInfo {
                        address: addr,
                        quality_score: 50.0,
                        last_successful: None,
                        connection_attempts: 0,
                        success_rate: 0.0,
                        average_latency: Duration::from_millis(100),
                        address_type: AddressType::Unknown,
                    }
                }).collect();

                let peer_record = PeerRecord {
                    peer_id,
                    addresses: address_infos,
                    reputation: ReputationScore::default(),
                    first_seen: SystemTime::now(),
                    last_seen: SystemTime::now(),
                    connection_history: ConnectionHistory::default(),
                    protocols: HashSet::new(),
                    geo_info: None,
                    capabilities: PeerCapabilities::default(),
                    trust_level: TrustLevel::Untrusted,
                };

                peers_db.insert(peer_id, peer_record);

                // Update stats
                let mut stats = self.stats.write().await;
                stats.total_discovered += 1;
            }
        }

        println!("🆕 Added/updated peer: {}", peer_id);
    }

    /// Get best peers for connection
    pub async fn get_best_peers(&self, count: usize) -> Vec<PeerRecord> {
        let peers_db = self.peers_db.read().await;
        let banned_peers = self.banned_peers.read().await;

        let mut candidates: Vec<_> = peers_db
            .values()
            .filter(|peer| {
                // Filter out banned peers
                !banned_peers.contains_key(&peer.peer_id) &&
                // Filter by quality thresholds
                peer.reputation.overall >= self.config.quality_thresholds.min_reputation &&
                peer.connection_history.successful_connections > 0
            })
            .cloned()
            .collect();

        // Sort by overall quality score
        candidates.sort_by(|a, b| {
            let score_a = self.calculate_peer_score(a);
            let score_b = self.calculate_peer_score(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates.into_iter().take(count).collect()
    }

    /// Calculate overall peer score for ranking
    fn calculate_peer_score(&self, peer: &PeerRecord) -> f64 {
        let mut score = peer.reputation.overall;

        // Boost score for high-quality addresses
        let avg_address_quality: f64 = peer.addresses.iter()
            .map(|addr| addr.quality_score)
            .sum::<f64>() / peer.addresses.len().max(1) as f64;
        
        score += avg_address_quality * 0.1;

        // Boost score for good connection history
        if peer.connection_history.total_attempts > 0 {
            let success_rate = peer.connection_history.successful_connections as f64 / 
                             peer.connection_history.total_attempts as f64;
            score += success_rate * 100.0;
        }

        // Boost score for validator capabilities
        if peer.capabilities.is_validator {
            score += 50.0;
        }

        // Boost score for high trust level
        score += match peer.trust_level {
            TrustLevel::Verified => 100.0,
            TrustLevel::High => 50.0,
            TrustLevel::Medium => 20.0,
            TrustLevel::Low => 5.0,
            TrustLevel::Untrusted => 0.0,
            TrustLevel::Banned => -1000.0,
        };

        score
    }

    /// Ban a peer
    pub async fn ban_peer(&self, peer_id: PeerId, reason: BanReason, duration: Duration) {
        let ban_info = BanInfo {
            banned_at: SystemTime::now(),
            duration,
            reason: reason.clone(),
            severity: match reason {
                BanReason::MaliciousActivity | BanReason::ConsensusAttack => BanSeverity::Permanent,
                BanReason::ProtocolViolation | BanReason::SpamBehavior => BanSeverity::Extended,
                BanReason::InvalidMessages => BanSeverity::Temporary,
                BanReason::RepeatedConnectionFailures => BanSeverity::Warning,
                BanReason::Manual => BanSeverity::Temporary,
            },
        };

        self.banned_peers.write().await.insert(peer_id, ban_info);
        
        // Update reputation
        self.reputation_system.record_event(
            peer_id,
            ReputationEventType::ProtocolViolation,
            -100.0,
            format!("Banned for: {:?}", reason),
        ).await;

        println!("🚫 Banned peer {} for {:?}", peer_id, reason);
    }

    /// Start continuous discovery loop
    async fn start_discovery_loop(&self) {
        let peers_db = self.peers_db.clone();
        let stats = self.stats.clone();
        let interval = self.config.discovery_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            
            loop {
                ticker.tick().await;
                
                // Perform periodic discovery tasks
                Self::cleanup_expired_bans(&peers_db).await;
                Self::update_peer_scores(&stats).await;
                
                // Additional discovery logic would go here
            }
        });
    }

    /// Cleanup expired bans
    async fn cleanup_expired_bans(banned_peers: &Arc<RwLock<HashMap<PeerId, BanInfo>>>) {
        let mut banned = banned_peers.write().await;
        let now = SystemTime::now();
        
        banned.retain(|_, ban_info| {
            match ban_info.severity {
                BanSeverity::Permanent => true,
                _ => {
                    if let Ok(elapsed) = now.duration_since(ban_info.banned_at) {
                        elapsed < ban_info.duration
                    } else {
                        false
                    }
                }
            }
        });
    }

    /// Update peer scores periodically
    async fn update_peer_scores(stats: &Arc<RwLock<DiscoveryStats>>) {
        // Placeholder for score updates
        let mut stats_guard = stats.write().await;
        stats_guard.discovery_efficiency = 0.85; // Example value
    }

    /// Create default bootstrap nodes
    fn create_bootstrap_nodes() -> Vec<BootstrapNode> {
        vec![
            BootstrapNode {
                peer_id: PeerId::random(),
                addresses: vec![
                    "/ip4/34.226.58.39/tcp/30303".parse().unwrap(),
                    "/ip4/18.196.70.2/tcp/30303".parse().unwrap(),
                ],
                dns_seed: Some("seed.poar.network".to_string()),
                trust_level: TrustLevel::Verified,
                region: Some("global".to_string()),
            },
        ]
    }

    /// Get discovery statistics
    pub async fn get_stats(&self) -> DiscoveryStats {
        self.stats.read().await.clone()
    }
}

impl ReputationSystem {
    /// Create new reputation system
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            scores: Arc::new(RwLock::new(HashMap::new())),
            config,
            history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a reputation event
    pub async fn record_event(
        &self,
        peer_id: PeerId,
        event_type: ReputationEventType,
        impact: f64,
        description: String,
    ) {
        // Update score
        let mut scores = self.scores.write().await;
        let score = scores.entry(peer_id).or_insert_with(ReputationScore::default);
        
        match event_type {
            ReputationEventType::ConnectionSuccess => {
                score.connection_reliability = (score.connection_reliability + impact).min(100.0);
            }
            ReputationEventType::ConnectionFailure => {
                score.connection_reliability = (score.connection_reliability + impact).max(0.0);
            }
            ReputationEventType::MessageValidation => {
                score.message_quality = (score.message_quality + impact).clamp(0.0, 100.0);
            }
            ReputationEventType::ProtocolViolation => {
                score.protocol_compliance = (score.protocol_compliance + impact).max(0.0);
            }
            _ => {}
        }

        // Update overall score
        score.overall = self.calculate_overall_score(score);
        score.last_updated = SystemTime::now();

        // Record event in history
        let event = ReputationEvent {
            timestamp: SystemTime::now(),
            event_type,
            score_impact: impact,
            description,
        };

        let mut history = self.history.write().await;
        history.entry(peer_id).or_insert_with(Vec::new).push(event);
    }

    /// Calculate overall reputation score
    fn calculate_overall_score(&self, score: &ReputationScore) -> f64 {
        let weights = &self.config.weights;
        
        let weighted_sum = 
            score.connection_reliability * weights.connection_reliability +
            score.message_quality * weights.message_quality +
            score.protocol_compliance * weights.protocol_compliance +
            score.network_contribution * weights.network_contribution +
            score.validator_performance.unwrap_or(0.0) * weights.validator_performance;

        let total_weight = weights.connection_reliability + 
                          weights.message_quality + 
                          weights.protocol_compliance + 
                          weights.network_contribution + 
                          weights.validator_performance;

        (weighted_sum / total_weight).clamp(self.config.min_reputation, self.config.max_reputation)
    }
}

impl GeoTracker {
    /// Create new geographic tracker
    pub fn new(config: GeoIPConfig) -> Self {
        Self {
            geo_data: Arc::new(RwLock::new(HashMap::new())),
            distribution: Arc::new(RwLock::new(GeoDistribution::default())),
            geoip_config: config,
        }
    }

    /// Get geographic location for peer
    pub async fn get_location(&self, peer_id: &PeerId) -> Option<GeoLocation> {
        self.geo_data.read().await.get(peer_id).cloned()
    }

    /// Update geographic distribution
    pub async fn update_distribution(&self) {
        let geo_data = self.geo_data.read().await;
        let mut distribution = self.distribution.write().await;

        distribution.countries.clear();
        distribution.continents.clear();

        for location in geo_data.values() {
            *distribution.countries.entry(location.country.clone()).or_insert(0) += 1;
            *distribution.continents.entry(location.continent.clone()).or_insert(0) += 1;
        }

        // Calculate diversity score
        let total_peers = geo_data.len() as f64;
        if total_peers > 0.0 {
            let country_diversity = distribution.countries.len() as f64 / total_peers;
            let continent_diversity = distribution.continents.len() as f64 / total_peers;
            distribution.diversity_score = (country_diversity + continent_diversity) / 2.0;
        }
    }
}

/// Discovery errors
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
    #[error("Bootstrap failed: {0}")]
    BootstrapFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Address parse error: {0}")]
    AddressParseError(String),
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self {
            overall: 50.0,
            connection_reliability: 50.0,
            message_quality: 50.0,
            protocol_compliance: 50.0,
            network_contribution: 50.0,
            validator_performance: None,
            last_updated: SystemTime::now(),
        }
    }
}

impl Default for ConnectionHistory {
    fn default() -> Self {
        Self {
            total_attempts: 0,
            successful_connections: 0,
            failed_connections: 0,
            avg_session_duration: Duration::from_secs(0),
            last_attempt: None,
            quality_trend: QualityTrend::Unknown,
        }
    }
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            is_validator: false,
            supports_full_sync: true,
            supports_light_client: false,
            is_archive_node: false,
            supports_relay: false,
            max_bandwidth: None,
            storage_capacity: None,
        }
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            base_reputation: 50.0,
            max_reputation: 1000.0,
            min_reputation: 0.0,
            decay_rate: 0.01, // 1% per day
            weights: ReputationWeights::default(),
        }
    }
}

impl Default for ReputationWeights {
    fn default() -> Self {
        Self {
            connection_reliability: 0.3,
            message_quality: 0.25,
            protocol_compliance: 0.25,
            network_contribution: 0.15,
            validator_performance: 0.05,
        }
    }
}

impl Default for GeoIPConfig {
    fn default() -> Self {
        Self {
            service_url: "https://ipapi.co".to_string(),
            api_key: None,
            cache_duration: Duration::from_secs(3600 * 24), // 24 hours
            enabled: true,
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_peers: 1000,
            discovery_interval: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
            reputation_update_interval: Duration::from_secs(60),
            geo_requirements: GeoRequirements::default(),
            quality_thresholds: QualityThresholds::default(),
            bootstrap_config: BootstrapConfig::default(),
        }
    }
}

impl Default for GeoRequirements {
    fn default() -> Self {
        Self {
            min_countries: 5,
            min_continents: 3,
            max_peers_per_country: 20,
            prefer_diversity: true,
        }
    }
}

impl Default for QualityThresholds {
    fn default() -> Self {
        Self {
            min_reputation: 25.0,
            min_success_rate: 0.5,
            max_latency: Duration::from_millis(1000),
            min_uptime: 0.8,
        }
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            dns_seeds: vec![
                "seed.poar.network".to_string(),
                "seed2.poar.network".to_string(),
            ],
            hardcoded_peers: vec![],
            bootstrap_timeout: Duration::from_secs(30),
            retry_attempts: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_discovery_manager_creation() {
        let config = DiscoveryConfig::default();
        let discovery_manager = PeerDiscoveryManager::new(config).await;
        assert!(discovery_manager.is_ok());
    }

    #[tokio::test]
    async fn test_reputation_system() {
        let reputation_system = ReputationSystem::new(ReputationConfig::default());
        let peer_id = PeerId::random();
        
        reputation_system.record_event(
            peer_id,
            ReputationEventType::ConnectionSuccess,
            10.0,
            "Successful connection".to_string(),
        ).await;

        let scores = reputation_system.scores.read().await;
        assert!(scores.contains_key(&peer_id));
    }

    #[test]
    fn test_peer_score_calculation() {
        let manager = tokio_test::block_on(async {
            PeerDiscoveryManager::new(DiscoveryConfig::default()).await.unwrap()
        });

        let peer = PeerRecord {
            peer_id: PeerId::random(),
            addresses: vec![],
            reputation: ReputationScore {
                overall: 75.0,
                ..Default::default()
            },
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            connection_history: ConnectionHistory::default(),
            protocols: HashSet::new(),
            geo_info: None,
            capabilities: PeerCapabilities::default(),
            trust_level: TrustLevel::High,
        };

        let score = manager.calculate_peer_score(&peer);
        assert!(score > 75.0); // Should be boosted by trust level
    }
}
