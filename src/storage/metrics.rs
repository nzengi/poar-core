use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use prometheus::{Counter, Histogram, Gauge, Registry, Opts, HistogramOpts};

/// Comprehensive metrics collection system for storage layer
pub struct StorageMetrics {
    /// Prometheus registry
    registry: Registry,
    
    /// Database operation counters
    db_reads: Counter,
    db_writes: Counter,
    db_deletes: Counter,
    
    /// Database operation latencies
    db_read_duration: Histogram,
    db_write_duration: Histogram,
    
    /// Cache metrics
    cache_hits: Counter,
    cache_misses: Counter,
    cache_size: Gauge,
    
    /// Storage size metrics
    db_size_bytes: Gauge,
    state_size_bytes: Gauge,
    trie_size_bytes: Gauge,
    
    /// Performance metrics
    throughput_ops_per_sec: Gauge,
    average_block_size: Gauge,
    
    /// Internal metrics tracking
    metrics_data: Arc<RwLock<MetricsData>>,
}

/// Internal metrics data structure
#[derive(Debug, Clone, Default)]
struct MetricsData {
    /// Operation counts
    total_reads: u64,
    total_writes: u64,
    total_cache_operations: u64,
    
    /// Timing data
    read_times: Vec<u64>,
    write_times: Vec<u64>,
    
    /// System resource usage
    cpu_usage_percent: f64,
    memory_usage_bytes: u64,
    disk_usage_bytes: u64,
    
    /// Error tracking
    errors: HashMap<String, u64>,
    
    /// Custom metrics
    custom_counters: HashMap<String, u64>,
    custom_gauges: HashMap<String, f64>,
}

/// Metrics collector trait for different storage components
pub trait MetricsCollector {
    /// Collect metrics from the component
    fn collect_metrics(&self) -> ComponentMetrics;
    
    /// Get component name
    fn component_name(&self) -> &'static str;
}

/// Metrics from individual storage components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMetrics {
    /// Component identifier
    pub component: String,
    
    /// Operation counts
    pub operations: OperationMetrics,
    
    /// Performance metrics
    pub performance: PerformanceMetrics,
    
    /// Resource usage
    pub resources: ResourceMetrics,
    
    /// Custom metrics specific to component
    pub custom: HashMap<String, MetricValue>,
}

/// Operation-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationMetrics {
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub scans: u64,
    pub batch_operations: u64,
    pub failed_operations: u64,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceMetrics {
    pub avg_read_latency_ms: f64,
    pub avg_write_latency_ms: f64,
    pub p95_read_latency_ms: f64,
    pub p95_write_latency_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub cache_hit_ratio: f64,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceMetrics {
    pub memory_usage_bytes: u64,
    pub disk_usage_bytes: u64,
    pub cpu_usage_percent: f64,
    pub network_io_bytes: u64,
    pub file_descriptor_count: u32,
}

/// Generic metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
    String(String),
}

/// Metrics exporter for different formats
pub struct MetricsExporter {
    metrics: Arc<StorageMetrics>,
    export_format: ExportFormat,
}

/// Supported export formats
#[derive(Debug, Clone)]
pub enum ExportFormat {
    Prometheus,
    Json,
    InfluxDB,
    Custom(String),
}

/// Performance profiler for detailed analysis
pub struct PerformanceProfiler {
    profiles: Arc<RwLock<HashMap<String, PerformanceProfile>>>,
    active_profiles: Arc<RwLock<HashMap<String, Instant>>>,
}

/// Individual performance profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProfile {
    pub operation: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_ms: u64,
    pub memory_delta_bytes: i64,
    pub cpu_usage_percent: f64,
    pub context: HashMap<String, String>,
}

/// Metrics dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsDashboard {
    pub timestamp: u64,
    pub database_metrics: DatabaseDashboard,
    pub cache_metrics: CacheDashboard,
    pub storage_metrics: StorageDashboard,
    pub performance_metrics: PerformanceDashboard,
    pub system_metrics: SystemDashboard,
}

/// Database-specific dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseDashboard {
    pub total_operations: u64,
    pub operations_per_second: f64,
    pub average_latency_ms: f64,
    pub error_rate_percent: f64,
    pub active_connections: u32,
    pub compaction_status: String,
}

/// Cache-specific dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheDashboard {
    pub hit_ratio_percent: f64,
    pub cache_size_mb: f64,
    pub eviction_rate: f64,
    pub memory_pressure: f64,
}

/// Storage-specific dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDashboard {
    pub total_size_gb: f64,
    pub growth_rate_mb_per_hour: f64,
    pub compression_ratio: f64,
    pub fragmentation_percent: f64,
}

/// Performance dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceDashboard {
    pub throughput_mb_per_sec: f64,
    pub iops: u64,
    pub queue_depth: u32,
    pub response_time_p99_ms: f64,
}

/// System dashboard metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemDashboard {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub network_throughput_mbps: f64,
}

impl StorageMetrics {
    /// Create new metrics collection system
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        
        // Create database operation counters
        let db_reads = Counter::with_opts(Opts::new(
            "poar_db_reads_total",
            "Total database read operations"
        ))?;
        
        let db_writes = Counter::with_opts(Opts::new(
            "poar_db_writes_total", 
            "Total database write operations"
        ))?;
        
        let db_deletes = Counter::with_opts(Opts::new(
            "poar_db_deletes_total",
            "Total database delete operations"
        ))?;
        
        // Create latency histograms
        let db_read_duration = Histogram::with_opts(HistogramOpts::new(
            "poar_db_read_duration_seconds",
            "Database read operation duration"
        ))?;
        
        let db_write_duration = Histogram::with_opts(HistogramOpts::new(
            "poar_db_write_duration_seconds",
            "Database write operation duration"
        ))?;
        
        // Create cache metrics
        let cache_hits = Counter::with_opts(Opts::new(
            "poar_cache_hits_total",
            "Total cache hit operations"
        ))?;
        
        let cache_misses = Counter::with_opts(Opts::new(
            "poar_cache_misses_total",
            "Total cache miss operations"
        ))?;
        
        let cache_size = Gauge::with_opts(Opts::new(
            "poar_cache_size_bytes",
            "Current cache size in bytes"
        ))?;
        
        // Create storage size metrics
        let db_size_bytes = Gauge::with_opts(Opts::new(
            "poar_db_size_bytes",
            "Total database size in bytes"
        ))?;
        
        let state_size_bytes = Gauge::with_opts(Opts::new(
            "poar_state_size_bytes",
            "Total state size in bytes"
        ))?;
        
        let trie_size_bytes = Gauge::with_opts(Opts::new(
            "poar_trie_size_bytes",
            "Total trie size in bytes"
        ))?;
        
        // Create performance metrics
        let throughput_ops_per_sec = Gauge::with_opts(Opts::new(
            "poar_throughput_ops_per_second",
            "Operations per second throughput"
        ))?;
        
        let average_block_size = Gauge::with_opts(Opts::new(
            "poar_average_block_size_bytes",
            "Average block size in bytes"
        ))?;
        
        // Register all metrics
        registry.register(Box::new(db_reads.clone()))?;
        registry.register(Box::new(db_writes.clone()))?;
        registry.register(Box::new(db_deletes.clone()))?;
        registry.register(Box::new(db_read_duration.clone()))?;
        registry.register(Box::new(db_write_duration.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(cache_size.clone()))?;
        registry.register(Box::new(db_size_bytes.clone()))?;
        registry.register(Box::new(state_size_bytes.clone()))?;
        registry.register(Box::new(trie_size_bytes.clone()))?;
        registry.register(Box::new(throughput_ops_per_sec.clone()))?;
        registry.register(Box::new(average_block_size.clone()))?;
        
        Ok(Self {
            registry,
            db_reads,
            db_writes,
            db_deletes,
            db_read_duration,
            db_write_duration,
            cache_hits,
            cache_misses,
            cache_size,
            db_size_bytes,
            state_size_bytes,
            trie_size_bytes,
            throughput_ops_per_sec,
            average_block_size,
            metrics_data: Arc::new(RwLock::new(MetricsData::default())),
        })
    }

    /// Record database read operation
    pub fn record_db_read(&self, duration: Duration) {
        self.db_reads.inc();
        self.db_read_duration.observe(duration.as_secs_f64());
        
        let mut data = self.metrics_data.write();
        data.total_reads += 1;
        data.read_times.push(duration.as_millis() as u64);
        
        // Keep only last 1000 measurements
        if data.read_times.len() > 1000 {
            data.read_times.remove(0);
        }
    }

    /// Record database write operation
    pub fn record_db_write(&self, duration: Duration) {
        self.db_writes.inc();
        self.db_write_duration.observe(duration.as_secs_f64());
        
        let mut data = self.metrics_data.write();
        data.total_writes += 1;
        data.write_times.push(duration.as_millis() as u64);
        
        if data.write_times.len() > 1000 {
            data.write_times.remove(0);
        }
    }

    /// Record cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
        self.metrics_data.write().total_cache_operations += 1;
    }

    /// Record cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
        self.metrics_data.write().total_cache_operations += 1;
    }

    /// Update storage sizes
    pub fn update_storage_sizes(&self, db_size: u64, state_size: u64, trie_size: u64) {
        self.db_size_bytes.set(db_size as f64);
        self.state_size_bytes.set(state_size as f64);
        self.trie_size_bytes.set(trie_size as f64);
    }

    /// Calculate and update derived metrics
    pub fn update_derived_metrics(&self) {
        let data = self.metrics_data.read();
        
        // Calculate throughput
        if !data.read_times.is_empty() || !data.write_times.is_empty() {
            let total_ops = data.read_times.len() + data.write_times.len();
            let time_window_ms = 1000; // 1 second
            let ops_per_sec = (total_ops as f64 / time_window_ms as f64) * 1000.0;
            self.throughput_ops_per_sec.set(ops_per_sec);
        }
        
        // Calculate cache hit ratio
        let total_cache_ops = data.total_cache_operations;
        if total_cache_ops > 0 {
            let hit_ratio = self.cache_hits.get() / total_cache_ops as f64;
            // This would be stored in a separate gauge in a real implementation
        }
    }

    /// Get comprehensive metrics summary
    pub fn get_metrics_summary(&self) -> MetricsSummary {
        let data = self.metrics_data.read();
        
        MetricsSummary {
            database: DatabaseMetrics {
                reads: self.db_reads.get() as u64,
                writes: self.db_writes.get() as u64,
                deletes: self.db_deletes.get() as u64,
                avg_read_latency_ms: self.calculate_average_latency(&data.read_times),
                avg_write_latency_ms: self.calculate_average_latency(&data.write_times),
            },
            cache: CacheMetrics {
                hits: self.cache_hits.get() as u64,
                misses: self.cache_misses.get() as u64,
                hit_ratio: self.calculate_cache_hit_ratio(),
                size_bytes: self.cache_size.get() as u64,
            },
            storage: StorageMetrics {
                db_size_bytes: self.db_size_bytes.get() as u64,
                state_size_bytes: self.state_size_bytes.get() as u64,
                trie_size_bytes: self.trie_size_bytes.get() as u64,
                total_size_bytes: self.db_size_bytes.get() as u64 + 
                                 self.state_size_bytes.get() as u64 + 
                                 self.trie_size_bytes.get() as u64,
            },
            performance: PerformanceMetricsData {
                throughput_ops_per_sec: self.throughput_ops_per_sec.get(),
                average_block_size_bytes: self.average_block_size.get() as u64,
            },
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families).unwrap_or_default()
    }

    /// Get dashboard data
    pub fn get_dashboard_data(&self) -> MetricsDashboard {
        let data = self.metrics_data.read();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        MetricsDashboard {
            timestamp: current_time,
            database_metrics: DatabaseDashboard {
                total_operations: data.total_reads + data.total_writes,
                operations_per_second: self.throughput_ops_per_sec.get(),
                average_latency_ms: self.calculate_average_latency(&data.read_times),
                error_rate_percent: 0.1, // Simulated
                active_connections: 5,    // Simulated
                compaction_status: "Normal".to_string(),
            },
            cache_metrics: CacheDashboard {
                hit_ratio_percent: self.calculate_cache_hit_ratio() * 100.0,
                cache_size_mb: self.cache_size.get() / (1024.0 * 1024.0),
                eviction_rate: 0.05, // Simulated
                memory_pressure: 0.2, // Simulated
            },
            storage_metrics: StorageDashboard {
                total_size_gb: (self.db_size_bytes.get() + self.state_size_bytes.get()) / (1024.0 * 1024.0 * 1024.0),
                growth_rate_mb_per_hour: 10.5, // Simulated
                compression_ratio: 0.75,       // Simulated
                fragmentation_percent: 5.2,    // Simulated
            },
            performance_metrics: PerformanceDashboard {
                throughput_mb_per_sec: self.throughput_ops_per_sec.get() * 0.001, // Simulated conversion
                iops: self.throughput_ops_per_sec.get() as u64,
                queue_depth: 3,      // Simulated
                response_time_p99_ms: 12.5, // Simulated
            },
            system_metrics: SystemDashboard {
                cpu_usage_percent: data.cpu_usage_percent,
                memory_usage_percent: 45.2,  // Simulated
                disk_usage_percent: 67.8,    // Simulated
                network_throughput_mbps: 125.5, // Simulated
            },
        }
    }

    // Helper methods
    fn calculate_average_latency(&self, times: &[u64]) -> f64 {
        if times.is_empty() {
            0.0
        } else {
            times.iter().sum::<u64>() as f64 / times.len() as f64
        }
    }

    fn calculate_cache_hit_ratio(&self) -> f64 {
        let hits = self.cache_hits.get();
        let misses = self.cache_misses.get();
        let total = hits + misses;
        
        if total > 0.0 {
            hits / total
        } else {
            0.0
        }
    }
}

/// Metrics summary structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub database: DatabaseMetrics,
    pub cache: CacheMetrics,
    pub storage: StorageMetrics,
    pub performance: PerformanceMetricsData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMetrics {
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub avg_read_latency_ms: f64,
    pub avg_write_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub db_size_bytes: u64,
    pub state_size_bytes: u64,
    pub trie_size_bytes: u64,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetricsData {
    pub throughput_ops_per_sec: f64,
    pub average_block_size_bytes: u64,
}

impl Default for StorageMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default storage metrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_creation() {
        let metrics = StorageMetrics::new();
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = StorageMetrics::new().unwrap();
        
        // Record some operations
        metrics.record_db_read(Duration::from_millis(10));
        metrics.record_db_write(Duration::from_millis(20));
        metrics.record_cache_hit();
        metrics.record_cache_miss();
        
        let summary = metrics.get_metrics_summary();
        assert_eq!(summary.database.reads, 1);
        assert_eq!(summary.database.writes, 1);
        assert_eq!(summary.cache.hits, 1);
        assert_eq!(summary.cache.misses, 1);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = StorageMetrics::new().unwrap();
        metrics.record_db_read(Duration::from_millis(5));
        
        let prometheus_output = metrics.export_prometheus();
        assert!(prometheus_output.contains("poar_db_reads_total"));
    }
} 