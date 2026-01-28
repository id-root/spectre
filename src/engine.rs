use anyhow::{anyhow, Result, Context};
use log::{info, warn}; 
use rquest::{Client, Proxy};
use rquest::header::{HeaderMap, HeaderValue, ACCEPT};
use rquest_util::Emulation;
use headless_chrome::{Browser, LaunchOptions, Tab};
use headless_chrome::protocol::cdp::Network;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use rand::Rng;

// --- Configuration Structs ---
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub profiles: HashMap<String, String>,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GeneralConfig {
    pub target_url: String,
    pub concurrency: usize,
    pub debug_mode: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct NetworkConfig {
    pub proxies: Vec<String>,
}

// --- Enterprise Logger ---
#[derive(Clone)]
pub struct SpectreLogger {
    file: Arc<Mutex<File>>,
}

impl SpectreLogger {
    pub fn new() -> Result<Self> {
        fs::create_dir_all("logs").context("Failed to create logs directory")?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let filename = format!("logs/session_{}.jsonl", timestamp);
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filename)
            .context(format!("Failed to open log file: {}", filename))?;

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    pub fn log(&self, worker_id: &str, event: &str, msg: &str, meta: Option<&str>) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let meta_clean = meta.unwrap_or("null");
        
        let log_line = format!(
            "{{\"ts\": {}, \"worker\": \"{}\", \"event\": \"{}\", \"msg\": \"{}\", \"meta\": {}}}\n",
            timestamp, worker_id, event, msg, meta_clean
        );

        if event == "VERDICT_BLOCKED" || event == "REQ_FAILED" {
            eprintln!("[{}] {} - {}", worker_id, event, msg);
        }

        if let Ok(mut handle) = self.file.lock() {
            let _ = handle.write_all(log_line.as_bytes());
        }
    }
}


pub struct StructuralHasher;

impl StructuralHasher {
    pub fn hash(html: &str) -> u64 {
        let mut s = DefaultHasher::new();
        let mut in_tag = false;
        
        for c in html.chars() {
            if c == '<' { in_tag = true; }
            if c == '>' { in_tag = false; }
            if in_tag {
                c.hash(&mut s);
            }
        }
        s.finish()
    }
}

// --- Browser Solver (Biometric Spoofing) ---
pub struct BrowserSolver;

impl BrowserSolver {
    fn find_chrome_binary() -> Option<PathBuf> {
        let possible_paths = [
            "/usr/bin/chromium", 
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome", 
            "/snap/bin/chromium", 
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ];
        for path_str in possible_paths {
            if Path::new(path_str).exists() { return Some(PathBuf::from(path_str)); }
        }
        None
    }

    fn simulate_human_behavior(tab: &Arc<Tab>) -> Result<()> {
        let mut rng = rand::thread_rng();
        
        let end_x = rng.gen_range(100..800) as f64;
        let end_y = rng.gen_range(100..600) as f64;
        
        for i in 0..5 {
            let x = end_x * (i as f64 / 5.0);
            let y = end_y * (i as f64 / 5.0);
             tab.evaluate(&format!(
                "document.elementFromPoint({}, {})?.dispatchEvent(new MouseEvent('mousemove', {{bubbles: true, clientX: {}, clientY: {}}}));",
                x, y, x, y
            ), false)?;
            std::thread::sleep(Duration::from_millis(rng.gen_range(50..150)));
        }

        tab.evaluate("window.scrollBy(0, window.innerHeight / 2);", false)?;
        std::thread::sleep(Duration::from_millis(500));
        
        Ok(())
    }

    pub fn solve(url: &str, proxy: Option<&str>, logger: &SpectreLogger, worker_id: &str) -> Result<String> {
        logger.log(worker_id, "BROWSER_INIT", "Initializing Headless Chrome", None);

        let mut args = vec![
            "--no-sandbox", 
            "--disable-gpu", 
            "--window-size=1920,1080", 
            "--disable-blink-features=AutomationControlled",
        ];

        let proxy_arg;
        if let Some(p) = proxy {
            let cleaned = p.replace("http://", "").replace("https://", "");
            proxy_arg = format!("--proxy-server={}", cleaned);
            args.push(&proxy_arg);
        }

        let options = LaunchOptions {
            path: Self::find_chrome_binary(),
            headless: true,
            args: args.iter().map(|s| std::ffi::OsStr::new(s)).collect(),
            ..Default::default()
        };

        let browser = Browser::new(options).context("Failed to launch browser")?;
        let tab = browser.new_tab()?;

        tab.call_method(Network::SetUserAgentOverride {
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36".into(),
            accept_language: Some("en-US,en;q=0.9".into()),
            platform: Some("Windows".into()),
            user_agent_metadata: None,
        })?;

        logger.log(worker_id, "BROWSER_NAV", "Navigating to Target", Some(&format!("\"{}\"", url)));
        tab.navigate_to(url)?;
        
        if let Err(e) = Self::simulate_human_behavior(&tab) {
            logger.log(worker_id, "BROWSER_WARN", "Biometric simulation failed", Some(&format!("\"{}\"", e)));
        }

        let start_time = Instant::now();
        let timeout = Duration::from_secs(30); 

        while start_time.elapsed() < timeout {
            if let Ok(content) = tab.get_content() {
                if content.contains("OWASP Juice Shop") || content.contains("app-root") || content.contains("Access Granted") {
                     if let Ok(cookies) = tab.get_cookies() {
                         let cookie_str = cookies.iter()
                            .map(|c| format!("{}={}", c.name, c.value))
                            .collect::<Vec<String>>()
                            .join("; ");
                         
                         if !cookie_str.is_empty() {
                            logger.log(worker_id, "BROWSER_SUCCESS", "Challenge Solved", Some(&format!("\"{}\"", cookie_str)));
                            return Ok(cookie_str);
                         }
                     }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        Err(anyhow!("Browser failed to solve challenge within timeout"))
    }
}

// --- Client Factory ---
pub struct ClientFactory {
    profiles: HashMap<String, String>,
}

impl ClientFactory {
    pub fn new(profiles: HashMap<String, String>) -> Self {
        Self { profiles }
    }

    pub fn create_client(&self, profile_key: &str, proxy_url: Option<&str>) -> Result<Client> {
        let impersonation_str = self.profiles.get(profile_key)
            .ok_or_else(|| anyhow!("Profile not found: {}", profile_key))?;

        let emulation = match impersonation_str.as_str() {
            "chrome_130" => Emulation::Chrome130,
            "safari_16" => Emulation::Safari16_5,
            _ => Emulation::Chrome130,
        };

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"));

        let mut builder = Client::builder()
            .emulation(emulation)
            .default_headers(headers);
            
        if let Some(proxy) = proxy_url {
            builder = builder.proxy(Proxy::all(proxy)?);
        }

        let client = builder.build().context("Failed to build TLS client")?;
        Ok(client)
    }
}

// --- Enhanced Response Analyzer ---
#[derive(Debug)]
pub enum Verdict {
    Success,
    Blocked(String), 
    Challenge(String), 
}

pub struct ResponseAnalyzer;

impl ResponseAnalyzer {
    pub fn analyze(status: u16, body: &str, logger: Option<(&SpectreLogger, &str)>) -> Verdict {
        let body_lower = body.to_lowercase();

        if body.contains("OWASP Juice Shop") || body.contains("app-root") || body.contains("Access Granted") {
            return Verdict::Success;
        }

        if body_lower.contains("checking your browser") || body_lower.contains("enable javascript") {
            return Verdict::Challenge("Generic JS".into());
        }
        if body_lower.contains("cloudflare") && body_lower.contains("ray id") {
             return Verdict::Challenge("Cloudflare".into());
        }

        if status == 403 || status == 429 {
            return Verdict::Blocked(format!("HTTP {}", status));
        }
        
        let block_words = ["access denied", "attention required", "security check"];
        for word in block_words {
            if body_lower.contains(word) {
                if let Some((log, w_id)) = logger {
                    let snippet = body.chars().take(200).collect::<String>().replace("\"", "'"); 
                    log.log(w_id, "DEBUG_BLOCK", "Suspicious body content", Some(&format!("\"{}\"", snippet)));
                }
                return Verdict::Blocked(format!("Keyword: {}", word));
            }
        }

        if status >= 200 && status < 300 {
            Verdict::Success
        } else {
            Verdict::Blocked(format!("Status {}", status))
        }
    }
}

// --- Grid Manager ---
#[derive(Debug, Clone)]
struct Node {
    url: String,
    failures: usize,
    cooldown_until: Option<Instant>,
}

pub struct GridManager {
    nodes: Vec<Node>,
    index: usize,
}

impl GridManager {
    pub fn new(proxies: Vec<String>) -> Self {
        let nodes = proxies.into_iter().map(|url| Node {
            url, failures: 0, cooldown_until: None,
        }).collect();
        Self { nodes, index: 0 }
    }

    pub fn get_next_node(&mut self) -> Option<String> {
        let start_index = self.index;
        loop {
            if self.nodes.is_empty() { return None; }
            let node = &mut self.nodes[self.index];
            
            if let Some(cooldown) = node.cooldown_until {
                if Instant::now() < cooldown {
                    self.advance();
                    if self.index == start_index { return None; }
                    continue;
                } else {
                    node.cooldown_until = None;
                    node.failures = 0; 
                }
            }
            let url = node.url.clone();
            self.advance();
            return Some(url);
        }
    }

    fn advance(&mut self) {
        if self.nodes.is_empty() { return; }
        self.index = (self.index + 1) % self.nodes.len();
    }

    pub fn report_failure(&mut self, proxy_url: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.url == proxy_url) {
            node.failures += 1;
            if node.failures > 3 {
                node.cooldown_until = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }

    pub fn report_success(&mut self, proxy_url: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.url == proxy_url) {
            node.failures = 0;
        }
    }
}

// --- Core Engine ---
#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    pub total_requests: Arc<AtomicUsize>,
    pub successful_requests: Arc<AtomicUsize>,
    pub blocked_requests: Arc<AtomicUsize>,
    pub failed_requests: Arc<AtomicUsize>,
}

pub struct CoreEngine {
    config: Config,
    stats: EngineStats,
    logger: Arc<SpectreLogger>, 
    baseline_hash: Arc<Mutex<Option<u64>>>, 
}

impl CoreEngine {
    pub fn new(config: Config) -> Self {
        let logger = Arc::new(SpectreLogger::new().expect("CRITICAL: Failed to initialize logging subsystem"));
        Self { 
            config, 
            stats: EngineStats::default(),
            logger,
            baseline_hash: Arc::new(Mutex::new(None)),
        }
    }

    pub fn get_stats(&self) -> EngineStats {
        self.stats.clone()
    }

    pub async fn run(&self) -> Result<()> {
        let (_tx, _rx) = mpsc::channel::<()>(self.config.general.concurrency);
        let grid_manager = Arc::new(Mutex::new(GridManager::new(self.config.network.proxies.clone())));
        let client_factory = Arc::new(ClientFactory::new(self.config.profiles.clone()));
        let target_url = self.config.general.target_url.clone();

        for i in 0..self.config.general.concurrency {
            let grid_manager = grid_manager.clone();
            let client_factory = client_factory.clone();
            let target_url = target_url.clone();
            let stats = self.stats.clone();
            let logger = self.logger.clone();
            let baseline_hash = self.baseline_hash.clone();
            let worker_id = format!("Worker-{:02}", i);
            let debug_mode = self.config.general.debug_mode;

            tokio::spawn(async move {
                loop {
                    let proxy_opt = {
                        let mut gm = grid_manager.lock().unwrap();
                        gm.get_next_node()
                    };

                    if let Some(proxy_url) = proxy_opt {
                        logger.log(&worker_id, "REQ_START", "Starting request cycle", Some(&format!("\"{}\"", proxy_url)));
                        let client_res = client_factory.create_client("desktop", Some(&proxy_url));
                        
                        match client_res {
                            Ok(client) => {
                                stats.total_requests.fetch_add(1, Ordering::Relaxed);
                                match client.get(&target_url).send().await {
                                    Ok(resp) => {
                                        let status = resp.status().as_u16();
                                        let body_bytes = resp.bytes().await.unwrap_or_default();
                                        let body_str = String::from_utf8_lossy(&body_bytes);
                                        
                                        let current_hash = StructuralHasher::hash(&body_str);
                                        // Renamed to _is_structurally_blocked to silence warning
                                        let _is_structurally_blocked = false; 
                                        {
                                            let mut base = baseline_hash.lock().unwrap();
                                            if base.is_none() && status == 200 {
                                                *base = Some(current_hash);
                                                logger.log(&worker_id, "LEARNING", "Baseline Structure Hash Acquired", Some(&format!("{}", current_hash)));
                                            } else if let Some(base_val) = *base {
                                                if status == 200 && current_hash != base_val {
                                                    logger.log(&worker_id, "STRUCT_DIFF", "Page structure deviation detected", Some(&format!("{} != {}", current_hash, base_val)));
                                                    // _is_structurally_blocked = true; 
                                                }
                                            }
                                        }

                                        let verdict = ResponseAnalyzer::analyze(status, &body_str, if debug_mode { Some((&logger, &worker_id)) } else { None });

                                        match verdict {
                                            Verdict::Success => {
                                                logger.log(&worker_id, "VERDICT_SUCCESS", "Request passed", None);
                                                stats.successful_requests.fetch_add(1, Ordering::Relaxed);
                                                let mut gm = grid_manager.lock().unwrap();
                                                gm.report_success(&proxy_url);
                                            },
                                            Verdict::Blocked(reason) => {
                                                logger.log(&worker_id, "VERDICT_BLOCKED", &format!("Blocked by {}", reason), None);
                                                stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                                                let mut gm = grid_manager.lock().unwrap();
                                                gm.report_failure(&proxy_url);
                                            },
                                            Verdict::Challenge(reason) => {
                                                logger.log(&worker_id, "VERDICT_CHALLENGE", &format!("Challenge detected: {}", reason), None);
                                                
                                                let url_clone = target_url.clone();
                                                let proxy_clone = proxy_url.clone();
                                                let logger_clone = logger.clone();
                                                let w_id_clone = worker_id.clone();
                                                
                                                let solved = tokio::task::spawn_blocking(move || {
                                                    BrowserSolver::solve(&url_clone, Some(&proxy_clone), &logger_clone, &w_id_clone)
                                                }).await;

                                                match solved {
                                                    Ok(Ok(cookie_str)) => {
                                                        if let Ok(mut file) = std::fs::File::create("last_cookie.txt") {
                                                            let _ = file.write_all(cookie_str.as_bytes());
                                                        }
                                                        stats.successful_requests.fetch_add(1, Ordering::Relaxed);
                                                        let mut gm = grid_manager.lock().unwrap();
                                                        gm.report_success(&proxy_url);
                                                    }
                                                    _ => {
                                                        stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                                                        let mut gm = grid_manager.lock().unwrap();
                                                        gm.report_failure(&proxy_url);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        logger.log(&worker_id, "REQ_FAILED", "Network Error", Some(&format!("\"{}\"", e)));
                                        stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                                        let mut gm = grid_manager.lock().unwrap();
                                        gm.report_failure(&proxy_url);
                                    }
                                }
                            }
                            Err(_) => {
                                stats.failed_requests.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }

        match tokio::signal::ctrl_c().await {
             Ok(()) => {},
             Err(err) => eprintln!("Shutdown signal error: {}", err),
        }
        Ok(())
    }
}
