mod cli;
mod consensus;
mod crypto;
mod network;
mod storage;
mod types;
mod utils;
mod vm;
mod wallet;
mod testing;
mod optimization;

use cli::PoarCli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Parse command line arguments and run CLI
    let app = PoarCli::new();
    let matches = app.get_matches();
    
    PoarCli::handle_matches(matches).await
}
