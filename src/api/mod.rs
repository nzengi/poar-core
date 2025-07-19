pub mod jsonrpc;
pub mod graphql;
pub mod rest;
pub mod websocket;

use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    Router,
    http::{
        StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
        Method,
    },
    middleware,
    response::Json,
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
    compression::CompressionLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
};
use tokio::sync::RwLock;
use serde_json::json;
use utoipa_swagger_ui::SwaggerUi;
use std::time::Duration;

use crate::storage::state_storage::StateStorage;
use crate::network::P2PNetworkManager;
use jsonrpc::{PoarRpcServer, RpcConfig};
use graphql::{create_schema, GraphQLContext, PoarSchema};
use rest::{create_router as create_rest_router, ApiState, ApiDoc};
use websocket::WebSocketServer;

/// Main API server that combines all API types
pub struct PoarApiServer {
    /// JSON-RPC server
    rpc_server: Option<PoarRpcServer>,
    /// GraphQL schema
    graphql_schema: PoarSchema,
    /// WebSocket server
    websocket_server: Arc<WebSocketServer>,
    /// REST API state
    api_state: ApiState,
    /// Server configuration
    config: ApiServerConfig,
    /// Server metrics
    metrics: Arc<RwLock<ApiServerMetrics>>,
}

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// HTTP server address
    pub http_addr: SocketAddr,
    /// JSON-RPC specific config
    pub rpc_config: RpcConfig,
    /// Enable GraphQL
    pub enable_graphql: bool,
    /// Enable WebSocket
    pub enable_websocket: bool,
    /// Enable REST API
    pub enable_rest: bool,
    /// Enable Swagger UI
    pub enable_swagger: bool,
    /// Request timeout
    pub request_timeout: Duration,
    /// Request body size limit
    pub max_request_size: usize,
    /// Enable compression
    pub enable_compression: bool,
    /// CORS configuration
    pub cors_config: CorsConfig,
    /// Rate limiting
    pub rate_limiting: RateLimitingConfig,
}

/// CORS configuration
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    pub allowed_methods: Vec<Method>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
}

/// Rate limiting configuration
#[derive(Debug, Clone)]
pub struct RateLimitingConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per minute
    pub requests_per_minute: u32,
    /// Burst capacity
    pub burst_capacity: u32,
}

/// API server metrics
#[derive(Debug, Clone, Default)]
pub struct ApiServerMetrics {
    /// Total requests across all APIs
    pub total_requests: u64,
    /// Requests by API type
    pub requests_by_api: std::collections::HashMap<String, u64>,
    /// Response times by API type
    pub response_times: std::collections::HashMap<String, Duration>,
    /// Error counts by API type
    pub error_counts: std::collections::HashMap<String, u64>,
    /// Active connections
    pub active_connections: u64,
    /// Server uptime
    pub uptime: Duration,
    /// Start time
    pub start_time: std::time::SystemTime,
}

impl PoarApiServer {
    /// Create new API server
    pub async fn new(
        config: ApiServerConfig,
        state_storage: Arc<StateStorage>,
        network_manager: Arc<P2PNetworkManager>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        println!("🚀 Initializing POAR API Server...");

        // Initialize JSON-RPC server
        let rpc_server = if config.rpc_config.listen_addr.port() > 0 {
            Some(PoarRpcServer::new(
                config.rpc_config.clone(),
                state_storage.clone(),
                network_manager.clone(),
            ))
        } else {
            None
        };

        // Initialize GraphQL context and schema
        let graphql_context = GraphQLContext::new(
            state_storage.clone(),
            network_manager.clone(),
        );
        let graphql_schema = create_schema(graphql_context);

        // Initialize WebSocket server
        let websocket_server = Arc::new(WebSocketServer::new());

        // Initialize REST API state
        let api_state = ApiState {
            state_storage,
            network_manager,
            metrics: Arc::new(RwLock::new(rest::ApiMetrics::default())),
        };

        let server = Self {
            rpc_server,
            graphql_schema,
            websocket_server,
            api_state,
            config,
            metrics: Arc::new(RwLock::new(ApiServerMetrics {
                start_time: std::time::SystemTime::now(),
                ..Default::default()
            })),
        };

        println!("✅ API Server initialized");
        println!("   JSON-RPC: {}", if server.rpc_server.is_some() { "Enabled" } else { "Disabled" });
        println!("   GraphQL: {}", if server.config.enable_graphql { "Enabled" } else { "Disabled" });
        println!("   REST API: {}", if server.config.enable_rest { "Enabled" } else { "Disabled" });
        println!("   WebSocket: {}", if server.config.enable_websocket { "Enabled" } else { "Disabled" });

        Ok(server)
    }

    /// Start all API servers
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting POAR API Server on {}...", self.config.http_addr);

        // Start JSON-RPC server if enabled
        if let Some(ref mut rpc_server) = self.rpc_server {
            rpc_server.start().await?;
        }

        // Start WebSocket event simulation
        if self.config.enable_websocket {
            self.websocket_server.start_event_simulation().await;
        }

        // Create the main HTTP router
        let app = self.create_router().await;

        // Start HTTP server
        let listener = tokio::net::TcpListener::bind(self.config.http_addr).await?;
        
        println!("✅ POAR API Server started successfully!");
        println!("   HTTP Address: {}", self.config.http_addr);
        if self.config.enable_swagger {
            println!("   Swagger UI: http://{}/swagger-ui/", self.config.http_addr);
        }
        if self.config.enable_graphql {
            println!("   GraphQL Playground: http://{}/graphql", self.config.http_addr);
        }
        if self.config.enable_websocket {
            println!("   WebSocket: ws://{}/ws", self.config.http_addr);
        }

        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Create the main HTTP router combining all APIs
    async fn create_router(&self) -> Router {
        let mut app = Router::new();

        // Add health check endpoint
        app = app.route("/health", axum::routing::get(health_check));

        // Add REST API routes if enabled
        if self.config.enable_rest {
            let rest_router = create_rest_router(self.api_state.clone());
            app = app.nest("/api/v1", rest_router);
        }

        // Add GraphQL if enabled
        if self.config.enable_graphql {
            app = app
                .route("/graphql", 
                    axum::routing::get(graphql_playground)
                        .post(graphql_handler)
                )
                .route("/graphql/ws", 
                    axum::routing::get(graphql_subscription_handler)
                )
                .with_state(self.graphql_schema.clone());
        }

        // Add WebSocket if enabled
        if self.config.enable_websocket {
            let ws_router = self.websocket_server.clone().create_router();
            app = app.merge(ws_router);
        }

        // Add Swagger UI if enabled
        if self.config.enable_swagger {
            app = app.merge(
                SwaggerUi::new("/swagger-ui")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            );
        }

        // Add middleware layers
        let middleware_stack = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .layer(TimeoutLayer::new(self.config.request_timeout))
            .layer(RequestBodyLimitLayer::new(self.config.max_request_size))
            .layer(self.create_cors_layer())
            .layer(middleware::from_fn(metrics_middleware));

        app.layer(middleware_stack)
    }

    /// Create CORS layer
    fn create_cors_layer(&self) -> CorsLayer {
        let mut cors = CorsLayer::new();

        if self.config.cors_config.allowed_origins.contains(&"*".to_string()) {
            cors = cors.allow_origin(Any);
        } else {
            for origin in &self.config.cors_config.allowed_origins {
                if let Ok(origin) = origin.parse() {
                    cors = cors.allow_origin(origin);
                }
            }
        }

        cors = cors
            .allow_methods(self.config.cors_config.allowed_methods.clone())
            .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

        if self.config.cors_config.allow_credentials {
            cors = cors.allow_credentials(true);
        }

        cors
    }

    /// Get server metrics
    pub async fn get_metrics(&self) -> ApiServerMetrics {
        let mut metrics = self.metrics.read().await.clone();
        
        // Update uptime
        if let Ok(elapsed) = std::time::SystemTime::now().duration_since(metrics.start_time) {
            metrics.uptime = elapsed;
        }

        // Get WebSocket metrics
        if self.config.enable_websocket {
            let ws_metrics = self.websocket_server.get_metrics().await;
            metrics.active_connections = ws_metrics.active_connections;
        }

        metrics
    }

    /// Stop the server
    pub async fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🛑 Stopping POAR API Server...");

        // Stop JSON-RPC server
        if let Some(ref mut rpc_server) = self.rpc_server {
            rpc_server.stop().await?;
        }

        println!("✅ POAR API Server stopped");
        Ok(())
    }
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "version": "1.0.0",
        "apis": {
            "json_rpc": "active",
            "graphql": "active", 
            "rest": "active",
            "websocket": "active"
        }
    }))
}

/// GraphQL handler
async fn graphql_handler(
    axum::extract::State(schema): axum::extract::State<PoarSchema>,
    req: async_graphql_axum::GraphQLRequest,
) -> async_graphql_axum::GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// GraphQL playground
async fn graphql_playground() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql")
            .subscription_endpoint("/graphql/ws")
    ))
}

/// GraphQL subscription handler
async fn graphql_subscription_handler(
    axum::extract::State(schema): axum::extract::State<PoarSchema>,
    protocol: async_graphql_axum::GraphQLProtocol,
    websocket: axum::extract::WebSocketUpgrade,
) -> axum::response::Response {
    websocket.on_upgrade(move |stream| {
        async_graphql_axum::GraphQLSubscription::new(stream, schema, protocol)
            .serve()
    })
}

/// Metrics middleware
async fn metrics_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Result<axum::response::Response> {
    let start = std::time::Instant::now();
    
    // Process request
    let response = next.run(req).await;
    
    let duration = start.elapsed();
    
    // Log request metrics
    println!("📊 Request processed in {:?}", duration);
    
    Ok(response)
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:3000".parse().unwrap(),
            rpc_config: RpcConfig::default(),
            enable_graphql: true,
            enable_websocket: true,
            enable_rest: true,
            enable_swagger: true,
            request_timeout: Duration::from_secs(30),
            max_request_size: 10 * 1024 * 1024, // 10MB
            enable_compression: true,
            cors_config: CorsConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![Method::GET, Method::POST, Method::PUT, Method::DELETE],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            allow_credentials: false,
        }
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 1000,
            burst_capacity: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_server_config_default() {
        let config = ApiServerConfig::default();
        assert_eq!(config.http_addr.port(), 3000);
        assert!(config.enable_graphql);
        assert!(config.enable_rest);
        assert!(config.enable_websocket);
    }

    #[test]
    fn test_cors_config() {
        let cors_config = CorsConfig::default();
        assert!(cors_config.allowed_origins.contains(&"*".to_string()));
        assert!(cors_config.allowed_methods.contains(&Method::GET));
        assert!(cors_config.allowed_methods.contains(&Method::POST));
    }

    #[tokio::test]
    async fn test_metrics_initialization() {
        let metrics = ApiServerMetrics::default();
        assert_eq!(metrics.total_requests, 0);
        assert!(metrics.requests_by_api.is_empty());
    }
} 