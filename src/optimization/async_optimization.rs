use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinHandle;
use futures_util::stream::{FuturesUnordered, StreamExt};

use super::{PerformanceMetrics, OptimizationConfig};

/// Async optimization configuration
#[derive(Debug, Clone)]
pub struct AsyncOptimizationConfig {
    pub enable_task_pooling: bool,
    pub enable_adaptive_concurrency: bool,
    pub enable_priority_scheduling: bool,
    pub enable_load_balancing: bool,
    pub enable_backpressure_control: bool,
    pub max_concurrent_tasks: usize,
    pub task_timeout_secs: u64,
    pub worker_pool_size: usize,
    pub queue_size_limit: usize,
    pub backpressure_threshold: f64,
}

impl Default for AsyncOptimizationConfig {
    fn default() -> Self {
        Self {
            enable_task_pooling: true,
            enable_adaptive_concurrency: true,
            enable_priority_scheduling: true,
            enable_load_balancing: true,
            enable_backpressure_control: true,
            max_concurrent_tasks: 1000,
            task_timeout_secs: 30,
            worker_pool_size: num_cpus::get() * 2,
            queue_size_limit: 10000,
            backpressure_threshold: 0.8,
        }
    }
}

/// Async performance statistics
#[derive(Debug, Clone)]
pub struct AsyncStats {
    pub active_tasks: usize,
    pub completed_tasks_per_second: f64,
    pub average_task_duration_ms: f64,
    pub queue_length: usize,
    pub worker_utilization: f64,
    pub concurrency_level: usize,
    pub timeout_ratio: f64,
    pub backpressure_events_per_minute: f64,
    pub task_scheduling_latency_ms: f64,
    pub timestamp: Instant,
}

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Critical = 0,  // Consensus operations
    High = 1,      // Block processing
    Normal = 2,    // Transaction processing
    Low = 3,       // Background tasks
}

/// Async task wrapper with metadata
#[derive(Debug)]
pub struct AsyncTask {
    pub id: String,
    pub priority: TaskPriority,
    pub created_at: Instant,
    pub timeout: Duration,
    pub task: Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + Unpin>,
}

/// Adaptive concurrency controller
#[derive(Debug)]
pub struct ConcurrencyController {
    current_limit: usize,
    max_limit: usize,
    min_limit: usize,
    target_latency_ms: f64,
    adjustment_interval: Duration,
    last_adjustment: Instant,
    performance_history: Vec<(usize, f64)>, // (concurrency, latency)
}

impl ConcurrencyController {
    pub fn new(initial_limit: usize, max_limit: usize) -> Self {
        Self {
            current_limit: initial_limit,
            max_limit,
            min_limit: 1,
            target_latency_ms: 100.0, // Target 100ms latency
            adjustment_interval: Duration::from_secs(5),
            last_adjustment: Instant::now(),
            performance_history: Vec::new(),
        }
    }

    pub fn adjust_concurrency(&mut self, current_latency_ms: f64) -> usize {
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return self.current_limit;
        }

        self.performance_history.push((self.current_limit, current_latency_ms));
        
        // Keep only recent history
        if self.performance_history.len() > 20 {
            self.performance_history.remove(0);
        }

        // Simple adaptive algorithm
        if current_latency_ms > self.target_latency_ms * 1.2 {
            // Latency too high, reduce concurrency
            self.current_limit = (self.current_limit * 9 / 10).max(self.min_limit);
        } else if current_latency_ms < self.target_latency_ms * 0.8 {
            // Latency acceptable, can increase concurrency
            self.current_limit = (self.current_limit * 11 / 10).min(self.max_limit);
        }

        self.last_adjustment = Instant::now();
        self.current_limit
    }

    pub fn get_current_limit(&self) -> usize {
        self.current_limit
    }
}

/// Priority-based task scheduler
#[derive(Debug)]
pub struct PriorityTaskScheduler {
    task_queues: HashMap<TaskPriority, Vec<AsyncTask>>,
    active_tasks: HashMap<String, JoinHandle<()>>,
    semaphore: Arc<Semaphore>,
    stats: AsyncStats,
}

impl PriorityTaskScheduler {
    pub fn new(max_concurrent: usize) -> Self {
        let mut task_queues = HashMap::new();
        task_queues.insert(TaskPriority::Critical, Vec::new());
        task_queues.insert(TaskPriority::High, Vec::new());
        task_queues.insert(TaskPriority::Normal, Vec::new());
        task_queues.insert(TaskPriority::Low, Vec::new());

        Self {
            task_queues,
            active_tasks: HashMap::new(),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            stats: AsyncStats {
                active_tasks: 0,
                completed_tasks_per_second: 0.0,
                average_task_duration_ms: 0.0,
                queue_length: 0,
                worker_utilization: 0.0,
                concurrency_level: 0,
                timeout_ratio: 0.0,
                backpressure_events_per_minute: 0.0,
                task_scheduling_latency_ms: 0.0,
                timestamp: Instant::now(),
            },
        }
    }

    pub async fn schedule_task(&mut self, task: AsyncTask) -> Result<(), Box<dyn std::error::Error>> {
        let queue = self.task_queues.get_mut(&task.priority)
            .ok_or("Invalid task priority")?;
        
        queue.push(task);
        self.update_queue_stats();
        
        Ok(())
    }

    pub async fn run_next_task(&mut self) -> Option<String> {
        // Execute tasks by priority order
        for priority in [TaskPriority::Critical, TaskPriority::High, TaskPriority::Normal, TaskPriority::Low] {
            if let Some(task) = self.task_queues.get_mut(&priority).and_then(|q| q.pop()) {
                return Some(self.execute_task(task).await);
            }
        }
        None
    }

    async fn execute_task(&mut self, task: AsyncTask) -> String {
        let task_id = task.id.clone();
        let start_time = Instant::now();
        
        // Acquire semaphore permit
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();
        
        let handle = tokio::spawn(async move {
            let _permit = permit; // Keep permit alive
            
            // Execute task with timeout
            let result = tokio::time::timeout(task.timeout, task.task).await;
            
            match result {
                Ok(Ok(())) => {
                    log::debug!("Task {} completed successfully", task_id);
                }
                Ok(Err(e)) => {
                    log::error!("Task {} failed: {}", task_id, e);
                }
                Err(_) => {
                    log::warn!("Task {} timed out", task_id);
                }
            }
        });
        
        self.active_tasks.insert(task_id.clone(), handle);
        self.stats.active_tasks = self.active_tasks.len();
        
        task_id
    }

    fn update_queue_stats(&mut self) {
        self.stats.queue_length = self.task_queues.values().map(|q| q.len()).sum();
        self.stats.timestamp = Instant::now();
    }

    pub fn get_stats(&self) -> AsyncStats {
        self.stats.clone()
    }
}

/// Load balancer for distributing tasks across workers
#[derive(Debug)]
pub struct TaskLoadBalancer {
    workers: Vec<String>,
    current_loads: HashMap<String, usize>,
    round_robin_index: usize,
    balancing_strategy: LoadBalancingStrategy,
}

#[derive(Debug, Clone)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    LeastConnections,
    WeightedRoundRobin(HashMap<String, f64>),
    AdaptiveLoad,
}

impl TaskLoadBalancer {
    pub fn new(workers: Vec<String>, strategy: LoadBalancingStrategy) -> Self {
        let current_loads = workers.iter().map(|w| (w.clone(), 0)).collect();
        
        Self {
            workers,
            current_loads,
            round_robin_index: 0,
            balancing_strategy: strategy,
        }
    }

    pub fn select_worker(&mut self) -> Option<String> {
        match self.balancing_strategy {
            LoadBalancingStrategy::RoundRobin => {
                if self.workers.is_empty() {
                    return None;
                }
                
                let worker = self.workers[self.round_robin_index].clone();
                self.round_robin_index = (self.round_robin_index + 1) % self.workers.len();
                Some(worker)
            }
            LoadBalancingStrategy::LeastConnections => {
                self.current_loads.iter()
                    .min_by_key(|(_, &load)| load)
                    .map(|(worker, _)| worker.clone())
            }
            LoadBalancingStrategy::AdaptiveLoad => {
                // Select worker with lowest load and good performance
                self.current_loads.iter()
                    .min_by_key(|(_, &load)| load)
                    .map(|(worker, _)| worker.clone())
            }
            _ => self.workers.first().cloned(),
        }
    }

    pub fn update_worker_load(&mut self, worker: &str, load: usize) {
        self.current_loads.insert(worker.to_string(), load);
    }
}

/// Main async optimizer
pub struct AsyncOptimizer {
    config: AsyncOptimizationConfig,
    task_scheduler: Arc<RwLock<PriorityTaskScheduler>>,
    concurrency_controller: Arc<RwLock<ConcurrencyController>>,
    load_balancer: Arc<RwLock<TaskLoadBalancer>>,
    async_stats: Arc<RwLock<AsyncStats>>,
    optimization_active: Arc<RwLock<bool>>,
}

impl AsyncOptimizer {
    /// Create a new async optimizer
    pub fn new(optimization_config: &OptimizationConfig) -> Self {
        let config = AsyncOptimizationConfig::default();
        
        let task_scheduler = PriorityTaskScheduler::new(config.max_concurrent_tasks);
        let concurrency_controller = ConcurrencyController::new(
            config.worker_pool_size,
            config.max_concurrent_tasks,
        );
        
        let workers: Vec<String> = (0..config.worker_pool_size)
            .map(|i| format!("worker_{}", i))
            .collect();
        let load_balancer = TaskLoadBalancer::new(workers, LoadBalancingStrategy::LeastConnections);

        Self {
            config,
            task_scheduler: Arc::new(RwLock::new(task_scheduler)),
            concurrency_controller: Arc::new(RwLock::new(concurrency_controller)),
            load_balancer: Arc::new(RwLock::new(load_balancer)),
            async_stats: Arc::new(RwLock::new(AsyncStats {
                active_tasks: 0,
                completed_tasks_per_second: 0.0,
                average_task_duration_ms: 0.0,
                queue_length: 0,
                worker_utilization: 0.0,
                concurrency_level: 0,
                timeout_ratio: 0.0,
                backpressure_events_per_minute: 0.0,
                task_scheduling_latency_ms: 0.0,
                timestamp: Instant::now(),
            })),
            optimization_active: Arc::new(RwLock::new(false)),
        }
    }

    /// Initialize async optimization
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        *self.optimization_active.write().await = true;

        log::info!("Initializing async optimization");
        log::info!("Task pooling: {}", self.config.enable_task_pooling);
        log::info!("Adaptive concurrency: {}", self.config.enable_adaptive_concurrency);
        log::info!("Priority scheduling: {}", self.config.enable_priority_scheduling);
        log::info!("Max concurrent tasks: {}", self.config.max_concurrent_tasks);
        log::info!("Worker pool size: {}", self.config.worker_pool_size);

        // Start task processing loop
        self.start_task_processing_loop().await;

        // Start concurrency adjustment if enabled
        if self.config.enable_adaptive_concurrency {
            self.start_concurrency_adjustment().await;
        }

        // Start async monitoring
        self.start_async_monitoring().await;

        log::info!("Async optimization initialized successfully");
        Ok(())
    }

    /// Optimize async performance based on current metrics
    pub async fn optimize(&self, metrics: &PerformanceMetrics) -> Result<(), Box<dyn std::error::Error>> {
        let async_stats = self.get_async_stats().await;
        
        log::debug!("Async optimization - Active tasks: {}, Queue length: {}, Latency: {:.2}ms", 
                   async_stats.active_tasks, async_stats.queue_length, async_stats.task_scheduling_latency_ms);

        // Adjust concurrency based on performance
        if self.config.enable_adaptive_concurrency {
            let mut controller = self.concurrency_controller.write().await;
            let new_limit = controller.adjust_concurrency(async_stats.task_scheduling_latency_ms);
            log::debug!("Adjusted concurrency limit to: {}", new_limit);
        }

        // Handle backpressure
        if async_stats.queue_length > self.config.queue_size_limit {
            self.handle_backpressure().await?;
        }

        // Optimize worker utilization
        if async_stats.worker_utilization < 0.7 {
            self.optimize_worker_distribution().await?;
        }

        Ok(())
    }

    /// Execute async task with optimization
    pub async fn execute_optimized_task<F, R>(
        &self,
        task_id: String,
        priority: TaskPriority,
        future: F,
    ) -> Result<R, Box<dyn std::error::Error>>
    where
        F: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
        R: Send + 'static,
    {
        let start_time = Instant::now();
        
        // Create async task wrapper
        let (sender, receiver) = tokio::sync::oneshot::channel();
        
        let wrapped_task = Box::new(async move {
            let result = future.await;
            let _ = sender.send(result);
            Ok(())
        });

        let task = AsyncTask {
            id: task_id.clone(),
            priority,
            created_at: start_time,
            timeout: Duration::from_secs(self.config.task_timeout_secs),
            task: wrapped_task,
        };

        // Schedule task
        {
            let mut scheduler = self.task_scheduler.write().await;
            scheduler.schedule_task(task).await?;
        }

        // Wait for result
        let result = receiver.await??;
        
        // Update statistics
        let execution_time = start_time.elapsed().as_millis() as f64;
        self.update_task_stats(execution_time).await;
        
        Ok(result)
    }

    /// Get current async statistics
    pub async fn get_async_stats(&self) -> AsyncStats {
        self.async_stats.read().await.clone()
    }

    /// Start task processing loop
    async fn start_task_processing_loop(&self) {
        let task_scheduler = Arc::clone(&self.task_scheduler);
        let optimization_active = Arc::clone(&self.optimization_active);

        for worker_id in 0..self.config.worker_pool_size {
            let scheduler = Arc::clone(&task_scheduler);
            let active = Arc::clone(&optimization_active);
            
            tokio::spawn(async move {
                while *active.read().await {
                    let task_id = {
                        let mut scheduler = scheduler.write().await;
                        scheduler.run_next_task().await
                    };
                    
                    if task_id.is_none() {
                        // No tasks available, sleep briefly
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            });
        }
    }

    /// Start concurrency adjustment loop
    async fn start_concurrency_adjustment(&self) {
        let concurrency_controller = Arc::clone(&self.concurrency_controller);
        let async_stats = Arc::clone(&self.async_stats);
        let optimization_active = Arc::clone(&self.optimization_active);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            
            while *optimization_active.read().await {
                interval.tick().await;
                
                let stats = async_stats.read().await;
                let latency = stats.task_scheduling_latency_ms;
                
                let mut controller = concurrency_controller.write().await;
                controller.adjust_concurrency(latency);
            }
        });
    }

    /// Start async monitoring
    async fn start_async_monitoring(&self) {
        let task_scheduler = Arc::clone(&self.task_scheduler);
        let async_stats = Arc::clone(&self.async_stats);
        let optimization_active = Arc::clone(&self.optimization_active);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            
            while *optimization_active.read().await {
                interval.tick().await;
                
                let scheduler_stats = {
                    let scheduler = task_scheduler.read().await;
                    scheduler.get_stats()
                };
                
                let mut stats = async_stats.write().await;
                *stats = scheduler_stats;
                stats.timestamp = Instant::now();
            }
        });
    }

    /// Handle backpressure situations
    async fn handle_backpressure(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::warn!("Handling backpressure - queue length exceeded threshold");
        
        // Drop low priority tasks
        // Increase processing capacity temporarily
        // Apply flow control
        
        Ok(())
    }

    /// Optimize worker distribution
    async fn optimize_worker_distribution(&self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Optimizing worker distribution due to low utilization");
        
        // Rebalance tasks across workers
        // Adjust worker pool size
        // Optimize task assignment
        
        Ok(())
    }

    /// Update task execution statistics
    async fn update_task_stats(&self, execution_time_ms: f64) {
        let mut stats = self.async_stats.write().await;
        
        // Update average with exponential moving average
        stats.average_task_duration_ms = 0.9 * stats.average_task_duration_ms + 0.1 * execution_time_ms;
        stats.timestamp = Instant::now();
    }

    /// Create a task batching executor for better throughput
    pub async fn execute_batch_tasks<F, R>(
        &self,
        tasks: Vec<F>,
        priority: TaskPriority,
    ) -> Vec<Result<R, Box<dyn std::error::Error>>>
    where
        F: std::future::Future<Output = Result<R, Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
        R: Send + 'static,
    {
        let mut futures = FuturesUnordered::new();
        
        for (i, task) in tasks.into_iter().enumerate() {
            let task_id = format!("batch_task_{}", i);
            let future = self.execute_optimized_task(task_id, priority, task);
            futures.push(future);
        }
        
        let mut results = Vec::new();
        while let Some(result) = futures.next().await {
            results.push(result);
        }
        
        results
    }
} 