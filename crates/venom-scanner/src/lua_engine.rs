//! Experimental Lua registry models.
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `lua`.
//! - **Execution:** host/library only; no repository runtime caller.
//! - **Default `venom scan`:** no.
//! - **Support:** experimental.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Registered source execution is unavailable and fails closed.

use crate::lua_config::LuaEngineConfig;
#[cfg(test)]
use mlua::Lua;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Script categories (type-safe, no typos, autocomplete)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScriptCategory {
    #[serde(rename = "web")]
    Web,
    #[serde(rename = "dns")]
    DNS,
    #[serde(rename = "smb")]
    SMB,
    #[serde(rename = "ssh")]
    SSH,
    #[serde(rename = "database")]
    Database,
}

impl ScriptCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScriptCategory::Web => "web",
            ScriptCategory::DNS => "dns",
            ScriptCategory::SMB => "smb",
            ScriptCategory::SSH => "ssh",
            ScriptCategory::Database => "database",
        }
    }

    pub fn all() -> &'static [ScriptCategory] {
        &[
            ScriptCategory::Web,
            ScriptCategory::DNS,
            ScriptCategory::SMB,
            ScriptCategory::SSH,
            ScriptCategory::Database,
        ]
    }
}

impl FromStr for ScriptCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "web" => Ok(ScriptCategory::Web),
            "dns" => Ok(ScriptCategory::DNS),
            "smb" => Ok(ScriptCategory::SMB),
            "ssh" => Ok(ScriptCategory::SSH),
            "database" => Ok(ScriptCategory::Database),
            _ => Err(format!("Unknown category: {}", s)),
        }
    }
}

impl std::fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Intended script lifecycle status model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LuaScriptStatus {
    #[serde(rename = "loaded")]
    Loaded, // Registered metadata; source execution is currently unavailable
    #[serde(rename = "running")]
    Running, // Reserved for a future executable host
    #[serde(rename = "completed")]
    Completed, // Reserved for a future executable host
    #[serde(rename = "failed")]
    Failed, // Host-reported execution error
    #[serde(rename = "timeout")]
    Timeout, // Host-reported execution timeout
}

impl LuaScriptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            LuaScriptStatus::Loaded => "loaded",
            LuaScriptStatus::Running => "running",
            LuaScriptStatus::Completed => "completed",
            LuaScriptStatus::Failed => "failed",
            LuaScriptStatus::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for LuaScriptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Immutable script metadata (P1 refactor: single responsibility)
/// Never changes after script creation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LuaScriptMetadata {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: PathBuf,
    pub categories: Vec<ScriptCategory>,
    pub timeout_ms: u64,
}

/// Mutable script instance state (P1 refactor: single responsibility)
/// Changes during script lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaScriptInstance {
    pub metadata: LuaScriptMetadata,
    pub enabled: bool,
    pub status: LuaScriptStatus,
    pub execution_count: u32,
    pub last_run_time_ms: Option<u64>,
    pub last_error: Option<String>,
}

/// Lua script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaScript {
    pub id: Uuid, // Unique identifier (prevents duplicate xss.lua conflicts)
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub script_path: PathBuf, // Canonicalized, safe path (prevents ../../../../etc/passwd)
    pub categories: Vec<ScriptCategory>, // Type-safe: Web, DNS, SMB, SSH, Database (no typos)
    pub enabled: bool,
    pub timeout_ms: u64,
    pub status: LuaScriptStatus, // Intended lifecycle state; execution is unavailable
}

impl LuaScript {
    /// Create new Lua script with path validation
    ///
    /// # Arguments
    /// * `name` - Script name
    /// * `script_path` - Path to script (must be within scripts/ root)
    /// * `script_root` - Root directory for scripts (e.g., "./scripts/")
    ///
    /// # Returns
    /// * `Ok(LuaScript)` if path is valid and within root
    /// * `Err(String)` if path traversal or invalid
    pub fn new_safe(
        name: impl Into<String>,
        script_path: impl AsRef<Path>,
        script_root: &Path,
    ) -> Result<Self, String> {
        let path_buf = PathBuf::from(script_path.as_ref());

        // Canonicalize both paths to resolve ../../ and symlinks
        let canonical_script = path_buf
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize script path: {}", e))?;
        let canonical_root = script_root
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize root path: {}", e))?;

        // SECURITY: Ensure script is within root directory
        if !canonical_script.starts_with(&canonical_root) {
            return Err(format!(
                "Path traversal detected: {} is outside root {}",
                canonical_script.display(),
                canonical_root.display()
            ));
        }

        Ok(Self {
            id: Uuid::new_v4(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: canonical_script,
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: LuaScriptStatus::Loaded,
        })
    }

    /// Create new script without validation (for testing only)
    #[cfg(test)]
    pub fn new_unsafe(name: impl Into<String>, script_path: impl Into<PathBuf>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            author: "Unknown".to_string(),
            script_path: script_path.into(),
            categories: vec![],
            enabled: true,
            timeout_ms: 5000,
            status: LuaScriptStatus::Loaded,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    pub fn with_categories(mut self, cats: Vec<ScriptCategory>) -> Self {
        self.categories = cats;
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Attempt to execute a script.
    ///
    /// Execution currently fails closed because this Experimental registry does
    /// not load the registered source file. It must not synthesize a successful
    /// result for code it never read.
    pub async fn execute(&self, context: LuaContext) -> LuaExecutionResult {
        let start = Instant::now();
        let script_id = self.id.to_string();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let execution_time_ms = start.elapsed().as_millis() as u64;
        let _ = context;
        LuaExecutionResult {
            script_id,
            success: false,
            output: String::new(),
            error: Some(
                "Lua execution is unavailable: registered script source loading is not implemented"
                    .to_owned(),
            ),
            execution_time_ms,
            return_value: None,
            timestamp_ms,
        }
    }

    /// Build the intended restricted VM for test-only policy verification.
    ///
    /// Blocks all dangerous operations:
    /// - os.execute, os.system (command execution)
    /// - io.open, io.read, io.write (file access)
    /// - package.loadlib, require (code loading)
    /// - debug.* (VM inspection/manipulation)
    /// - Unlimited memory and CPU
    #[cfg(test)]
    fn setup_sandbox(lua: &Lua) -> Result<(), String> {
        let globals = lua.globals();

        // ═════════════════════════════════════════════════════════════════
        // BLOCK DANGEROUS OPERATIONS (P1 Security)
        // ═════════════════════════════════════════════════════════════════

        // 1️⃣ Block OS module - prevents os.execute("rm -rf /")
        //    ✗ os.execute()
        //    ✗ os.system()
        //    ✗ os.getenv()
        globals
            .set("os", mlua::Nil)
            .map_err(|e| format!("Failed to block os module: {}", e))?;

        // 2️⃣ Block IO module - prevents io.open("/etc/passwd")
        //    ✗ io.open()
        //    ✗ io.read()
        //    ✗ io.write()
        //    ✗ io.input()
        //    ✗ io.output()
        globals
            .set("io", mlua::Nil)
            .map_err(|e| format!("Failed to block io module: {}", e))?;

        // 3️⃣ Block Debug module - prevents introspection/manipulation
        //    ✗ debug.getinfo()
        //    ✗ debug.getlocal()
        //    ✗ debug.setlocal()
        //    ✗ debug.sethook()
        globals
            .set("debug", mlua::Nil)
            .map_err(|e| format!("Failed to block debug module: {}", e))?;

        // 4️⃣ Block Package module - prevents code loading
        //    ✗ package.loadlib() - load C libraries
        //    ✗ package.loadstring() - load arbitrary code
        //    ✗ require() - load modules
        globals
            .set("package", mlua::Nil)
            .map_err(|e| format!("Failed to block package module: {}", e))?;

        // 5️⃣ Block dofile() - prevents executing external files
        //    ✗ dofile("malicious.lua")
        globals
            .set("dofile", mlua::Nil)
            .map_err(|e| format!("Failed to block dofile: {}", e))?;

        // 6️⃣ Block loadfile() - prevents loading external files
        //    ✗ loadfile("malicious.lua")
        globals
            .set("loadfile", mlua::Nil)
            .map_err(|e| format!("Failed to block loadfile: {}", e))?;

        // 7️⃣ Block require() - prevents module loading
        //    ✗ require("socket")
        //    ✗ require("os")
        globals
            .set("require", mlua::Nil)
            .map_err(|e| format!("Failed to block require: {}", e))?;

        // 8️⃣ Block load() - prevents dynamic code execution
        //    ✗ load("malicious code")
        globals
            .set("load", mlua::Nil)
            .map_err(|e| format!("Failed to block load: {}", e))?;

        // 9️⃣ Block loadstring() alias
        globals
            .set("loadstring", mlua::Nil)
            .map_err(|e| format!("Failed to block loadstring: {}", e))?;

        // 🔟 Note: socket module blocked if LuaSocket available
        // globals.set("socket", mlua::Nil)?;

        // ═════════════════════════════════════════════════════════════════
        // RESOURCE LIMITS (P1 Resource Protection)
        // ═════════════════════════════════════════════════════════════════

        // Set memory limit: 50MB max (prevents unbounded memory growth)
        // mlua will raise error if scripts try to allocate more
        lua.set_memory_limit(50_000_000) // 50 MB
            .map_err(|e| format!("Failed to set memory limit: {}", e))?;

        Ok(())
    }

    /// Build intended context globals for test-only policy verification.
    #[cfg(test)]
    fn setup_globals(lua: &Lua, context: &LuaContext) -> Result<(), String> {
        let globals = lua.globals();

        // Safe read-only globals: target, payload, parameters

        globals
            .set("target", context.target.clone())
            .map_err(|e| format!("Failed to set target: {}", e))?;

        globals
            .set("payload", context.payload.clone())
            .map_err(|e| format!("Failed to set payload: {}", e))?;

        // Create parameters table from HashMap
        let params_table = lua
            .create_table()
            .map_err(|e| format!("Failed to create params table: {}", e))?;

        for (key, value) in &context.parameters {
            params_table
                .set(key.clone(), value.clone())
                .map_err(|e| format!("Failed to set parameter {}: {}", key, e))?;
        }

        globals
            .set("parameters", params_table)
            .map_err(|e| format!("Failed to set parameters: {}", e))?;

        // Allowed safe functions: string, table, math, utf8
        // These are already available by default in Lua

        Ok(())
    }
}

/// Lua script execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaContext {
    pub target: String,
    pub payload: String,
    pub parameters: HashMap<String, String>,
    pub timeout_ms: u64,
}

impl LuaContext {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            payload: String::new(),
            parameters: HashMap::new(),
            timeout_ms: 5000,
        }
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

/// Lua script execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaExecutionResult {
    pub script_id: String,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    pub return_value: Option<String>,
    pub timestamp_ms: u64, // P0: Timestamp for exponential decay
}

/// Bounded execution history with exponential decay (P0 - not FIFO)
///
/// Recent data weighted more heavily than old data.
/// Formula: weight = alpha ^ ((current_time - entry_time) / half_life)
/// Example: 9 min old response = 20% weight, current = 80% weight
#[derive(Debug, Clone)]
pub struct BoundedExecutionHistory {
    entries: std::collections::VecDeque<LuaExecutionResult>,
    max_size: usize,
    decay_half_life_ms: u64, // Half-life for exponential decay (default 5min)
}

impl BoundedExecutionHistory {
    /// Create new bounded history with max size
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_size),
            max_size,
            decay_half_life_ms: 5 * 60 * 1000, // 5 minutes half-life
        }
    }

    /// Create with custom decay half-life (in milliseconds)
    pub fn with_decay(max_size: usize, half_life_ms: u64) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_size),
            max_size,
            decay_half_life_ms: half_life_ms,
        }
    }

    /// Add execution result (removes oldest if at capacity)
    pub fn push(&mut self, result: LuaExecutionResult) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(result);
    }

    /// Get all entries (oldest first)
    pub fn all(&self) -> Vec<LuaExecutionResult> {
        self.entries.iter().cloned().collect()
    }

    /// Get recent N entries (newest first)
    pub fn recent(&self, n: usize) -> Vec<LuaExecutionResult> {
        self.entries.iter().rev().take(n).cloned().collect()
    }

    /// Calculate exponential decay weight for an entry (P0 - ML ready)
    ///
    /// Formula: weight = 0.5 ^ (age_ms / half_life_ms)
    ///
    /// Examples (half_life = 5 min):
    /// - Age 0 min:     weight = 1.0 (current)
    /// - Age 2.5 min:   weight = 0.707 (70%)
    /// - Age 5 min:     weight = 0.5 (50%)
    /// - Age 10 min:    weight = 0.25 (25%)
    /// - Age 15 min:    weight = 0.125 (12.5%)
    pub fn decay_weight(&self, entry: &LuaExecutionResult, current_time_ms: u64) -> f32 {
        let age_ms = current_time_ms.saturating_sub(entry.timestamp_ms);
        if age_ms == 0 {
            return 1.0;
        }

        let age_ratio = age_ms as f32 / self.decay_half_life_ms as f32;
        0.5_f32.powf(age_ratio)
    }

    /// Get success rate with exponential decay (not simple average)
    ///
    /// Returns: weighted success count / weighted total count
    pub fn success_rate_decayed(&self, current_time_ms: u64) -> f32 {
        if self.entries.is_empty() {
            return 0.0;
        }

        let mut weighted_success = 0.0;
        let mut weighted_total = 0.0;

        for entry in &self.entries {
            let weight = self.decay_weight(entry, current_time_ms);
            weighted_total += weight;
            if entry.success {
                weighted_success += weight;
            }
        }

        if weighted_total == 0.0 {
            return 0.0;
        }

        weighted_success / weighted_total
    }

    /// Get average execution time with exponential decay
    pub fn avg_time_decayed(&self, current_time_ms: u64) -> f32 {
        if self.entries.is_empty() {
            return 0.0;
        }

        let mut weighted_time = 0.0;
        let mut weighted_total = 0.0;

        for entry in &self.entries {
            let weight = self.decay_weight(entry, current_time_ms);
            weighted_total += weight;
            weighted_time += (entry.execution_time_ms as f32) * weight;
        }

        if weighted_total == 0.0 {
            return 0.0;
        }

        weighted_time / weighted_total
    }

    /// Get size
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the history contains no executions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Lua Script Registry
pub struct LuaScriptRegistry {
    scripts: Arc<dashmap::DashMap<String, LuaScript>>,
    execution_history: Arc<dashmap::DashMap<String, BoundedExecutionHistory>>,
    enabled_count: Arc<std::sync::atomic::AtomicU32>,
    max_history_size: usize,
}

impl LuaScriptRegistry {
    /// Creates an experimental Lua script registry from host configuration.
    pub fn from_config(config: &LuaEngineConfig) -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size: config.history_size, // From config
        }
    }

    /// Creates new Lua script registry with bounded execution history (100 entries per script)
    pub fn new() -> Self {
        Self::from_config(&LuaEngineConfig::default())
    }

    /// Creates new registry with custom history size limit
    pub fn with_history_size(max_history_size: usize) -> Self {
        Self {
            scripts: Arc::new(dashmap::DashMap::new()),
            execution_history: Arc::new(dashmap::DashMap::new()),
            enabled_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            max_history_size,
        }
    }

    /// Registers a Lua script
    pub fn register(&self, script: LuaScript) {
        if script.enabled {
            self.enabled_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.scripts.insert(script.id.to_string(), script);
    }

    /// Gets script by ID
    pub fn get(&self, script_id: &str) -> Option<LuaScript> {
        self.scripts.get(script_id).map(|s| s.clone())
    }

    /// Lists all scripts
    pub fn list_all(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Lists enabled scripts
    pub fn list_enabled(&self) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| ref_multi.value().enabled)
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Lists scripts by category
    pub fn list_by_category(&self, category: &str) -> Vec<LuaScript> {
        self.scripts
            .iter()
            .filter(|ref_multi| {
                ref_multi
                    .value()
                    .categories
                    .iter()
                    .any(|script_category| script_category.as_str() == category)
            })
            .map(|ref_multi| ref_multi.value().clone())
            .collect()
    }

    /// Records execution result (enforces bounded history size)
    pub fn record_execution(&self, result: LuaExecutionResult) {
        let script_id = result.script_id.clone();
        if let Some(mut history) = self.execution_history.get_mut(&script_id) {
            history.push(result);
        } else {
            let mut history = BoundedExecutionHistory::new(self.max_history_size);
            history.push(result);
            self.execution_history.insert(script_id, history);
        }
    }

    /// Gets execution history for script (oldest first)
    pub fn get_history(&self, script_id: &str) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.all())
            .unwrap_or_default()
    }

    /// Gets recent N execution results for script (newest first)
    pub fn get_recent_history(&self, script_id: &str, n: usize) -> Vec<LuaExecutionResult> {
        self.execution_history
            .get(script_id)
            .map(|h| h.recent(n))
            .unwrap_or_default()
    }

    /// Gets script count
    pub fn count(&self) -> usize {
        self.scripts.len()
    }

    /// Gets enabled script count
    pub fn enabled_count(&self) -> u32 {
        self.enabled_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Enables/disables script
    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<(), String> {
        if let Some(mut script) = self.scripts.get_mut(script_id) {
            let was_enabled = script.enabled;
            script.enabled = enabled;

            if enabled && !was_enabled {
                self.enabled_count
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            } else if !enabled && was_enabled {
                self.enabled_count
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        } else {
            Err(format!("Script {} not found", script_id))
        }
    }

    /// Unregisters script
    pub fn unregister(&self, script_id: &str) -> Result<(), String> {
        if let Some((_, script)) = self.scripts.remove(script_id) {
            if script.enabled {
                self.enabled_count
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.execution_history.remove(script_id);
            Ok(())
        } else {
            Err(format!("Script {} not found", script_id))
        }
    }
}

impl Default for LuaScriptRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_execution_never_synthesizes_success_or_echoes_context() {
        let script = LuaScript::new_unsafe("fixture", "fixture.lua");
        let result = script
            .execute(
                LuaContext::new("https://private.example.invalid/path")
                    .with_payload("private-payload")
                    .with_parameter("token", "private-value"),
            )
            .await;

        assert!(!result.success);
        assert!(result.output.is_empty());
        assert!(result.return_value.is_none());
        let diagnostic = result
            .error
            .as_deref()
            .expect("fixed unavailable diagnostic");
        assert_eq!(
            diagnostic,
            "Lua execution is unavailable: registered script source loading is not implemented"
        );
        assert!(!diagnostic.contains("private.example.invalid"));
        assert!(!diagnostic.contains("private-payload"));
        assert!(!diagnostic.contains("private-value"));
    }

    #[test]
    fn intended_test_vm_removes_ambient_capabilities() {
        let lua = Lua::new();
        LuaScript::setup_sandbox(&lua).expect("sandbox policy");
        let globals = lua.globals();

        for name in [
            "os",
            "io",
            "debug",
            "package",
            "dofile",
            "loadfile",
            "require",
            "load",
            "loadstring",
        ] {
            let value: mlua::Value = globals.get(name).expect("sandbox global");
            assert!(matches!(value, mlua::Value::Nil), "{name} must be absent");
        }
    }

    #[test]
    fn intended_test_globals_are_explicitly_supplied() {
        let lua = Lua::new();
        let context = LuaContext::new("https://example.invalid")
            .with_payload("marker")
            .with_parameter("mode", "fixture");

        LuaScript::setup_globals(&lua, &context).expect("test globals");
        let globals = lua.globals();
        assert_eq!(
            globals.get::<_, String>("target").expect("target global"),
            "https://example.invalid"
        );
        assert_eq!(
            globals.get::<_, String>("payload").expect("payload global"),
            "marker"
        );
        let parameters: mlua::Table = globals.get("parameters").expect("parameters table");
        assert_eq!(
            parameters.get::<_, String>("mode").expect("mode parameter"),
            "fixture"
        );
    }
}
