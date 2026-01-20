mod engine;
mod tui;

use anyhow::Result;
use engine::{CoreEngine, Config};
use std::fs;
use std::sync::Arc;
use tokio::task;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Load Config
    let config_content = fs::read_to_string("profiles.toml")?;
    let config: Config = toml::from_str(&config_content)?;

    // Initialize Engine
    let engine = Arc::new(CoreEngine::new(config));
    let engine_clone = engine.clone();

    // Run Engine in background
    let _engine_handle = task::spawn(async move {
        if let Err(e) = engine_clone.run().await {
            eprintln!("Engine error: {}", e);
        }
    });

    // Run TUI
    let mut tui_app = tui::TuiApp::new(engine.get_stats());
    tui_app.run().await?;

    // --- IMPORTANT: FORCE EXIT ---
    // This kills the background engine tasks immediately
    std::process::exit(0);
}
