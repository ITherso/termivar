//! Bounded, host-owned execution for registered Lua source snapshots.
//!
//! This opt-in library surface is not part of either repository CLI runtime.
//! It creates a fresh Lua 5.4 VM for every request, exposes only immutable
//! context accessors plus bounded output, and never reopens source after
//! registration.
//!
//! The VM is an in-process cooperative boundary, not process isolation. Lua
//! instruction hooks interrupt bytecode loops, but cannot hard-preempt a defect
//! inside the Lua VM or a long native/C operation. This host therefore loads no
//! standard libraries and exposes no capability-bearing callbacks.
//! Portable path validation cannot defeat a writer racing changes inside the
//! approved tree, so that root must remain trusted and non-writable throughout
//! registration. Later file replacement is harmless because execution uses the
//! private registration-time snapshot.

use crate::lua_config::{LuaConfigError, LuaEngineConfig};
use mlua::{
    ChunkMode, Error as MluaError, HookTriggers, Lua, LuaOptions, MultiValue, StdLib, Value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::future::{poll_fn, Future};
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const MAX_SCRIPT_NAME_BYTES: usize = 128;
const MAX_SCRIPT_VERSION_BYTES: usize = 64;
const REGISTERED_CHUNK_NAME: &str = "@venom:registered";
const ABORT_CANCELLED: &str = "venom:cancelled";
const ABORT_DEADLINE: &str = "venom:deadline";
const ABORT_INSTRUCTION: &str = "venom:instruction-limit";
const ABORT_OUTPUT: &str = "venom:output-limit";
const ABORT_OUTPUT_ENCODING: &str = "venom:output-encoding";
const ABORT_OUTPUT_TYPE: &str = "venom:output-type";
const ABORT_OUTPUT_NUMBER: &str = "venom:output-number";
const IMMUTABLE_CONTEXT: &str = "venom:immutable-context";

/// Script categories used by inert registry metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptCategory {
    Web,
    Dns,
    Smb,
    Ssh,
    Database,
}

impl ScriptCategory {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Dns => "dns",
            Self::Smb => "smb",
            Self::Ssh => "ssh",
            Self::Database => "database",
        }
    }

    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Web, Self::Dns, Self::Smb, Self::Ssh, Self::Database]
    }
}

impl FromStr for ScriptCategory {
    type Err = LuaRegistrationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("web") {
            Ok(Self::Web)
        } else if value.eq_ignore_ascii_case("dns") {
            Ok(Self::Dns)
        } else if value.eq_ignore_ascii_case("smb") {
            Ok(Self::Smb)
        } else if value.eq_ignore_ascii_case("ssh") {
            Ok(Self::Ssh)
        } else if value.eq_ignore_ascii_case("database") {
            Ok(Self::Database)
        } else {
            Err(LuaRegistrationError::InvalidCategory)
        }
    }
}

impl fmt::Display for ScriptCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fixed registration failure that never includes a path, source, or OS error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaRegistrationError {
    InvalidConfig(LuaConfigError),
    InvalidName,
    InvalidVersion,
    InvalidCategory,
    InvalidPath,
    OutsideApprovedRoot,
    SymlinkRejected,
    NotRegularFile,
    SourceTooLarge,
    SourceNotUtf8,
    SourceChangedDuringRegistration,
    SourceReadFailed,
}

impl fmt::Display for LuaRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfig(_) => "invalid Lua engine configuration",
            Self::InvalidName => "invalid Lua script name",
            Self::InvalidVersion => "invalid Lua script version",
            Self::InvalidCategory => "invalid Lua script category",
            Self::InvalidPath => "invalid Lua script path",
            Self::OutsideApprovedRoot => "Lua script is outside the approved root",
            Self::SymlinkRejected => "Lua script path contains a symbolic link",
            Self::NotRegularFile => "Lua script source is not a regular file",
            Self::SourceTooLarge => "Lua script source exceeds its configured limit",
            Self::SourceNotUtf8 => "Lua script source must be UTF-8 text",
            Self::SourceChangedDuringRegistration => {
                "Lua script source changed during registration"
            },
            Self::SourceReadFailed => "Lua script source could not be read",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LuaRegistrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            _ => None,
        }
    }
}

/// Inert, serializable metadata. It cannot be deserialized into execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaScriptManifest {
    id: String,
    name: String,
    version: String,
    categories: Vec<ScriptCategory>,
    enabled: bool,
    source_bytes: u64,
    source_sha256: String,
}

impl LuaScriptManifest {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub fn categories(&self) -> &[ScriptCategory] {
        &self.categories
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
}

/// Opaque executable source created only through bounded registration.
#[derive(Clone)]
pub struct LuaScript {
    name: String,
    version: String,
    categories: Vec<ScriptCategory>,
    enabled: bool,
    source: Arc<str>,
    source_bytes: u64,
    source_digest: [u8; 32],
}

impl fmt::Debug for LuaScript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LuaScript")
            .field("id", &self.id())
            .field("name", &self.name)
            .field("version", &self.version)
            .field("categories", &self.categories)
            .field("enabled", &self.enabled)
            .field("source_bytes", &self.source_bytes)
            .finish_non_exhaustive()
    }
}

impl LuaScript {
    pub fn new_safe(
        name: impl Into<String>,
        script_path: impl AsRef<Path>,
        approved_root: &Path,
    ) -> Result<Self, LuaRegistrationError> {
        Self::new_safe_with_config(
            name,
            script_path,
            approved_root,
            &LuaEngineConfig::default(),
        )
    }

    pub fn new_safe_with_config(
        name: impl Into<String>,
        script_path: impl AsRef<Path>,
        approved_root: &Path,
        config: &LuaEngineConfig,
    ) -> Result<Self, LuaRegistrationError> {
        config
            .validate()
            .map_err(LuaRegistrationError::InvalidConfig)?;
        let name = name.into();
        validate_identifier(&name, MAX_SCRIPT_NAME_BYTES)
            .map_err(|()| LuaRegistrationError::InvalidName)?;
        let source =
            read_registered_source(script_path.as_ref(), approved_root, config.max_source_bytes)?;
        let source_bytes =
            u64::try_from(source.len()).map_err(|_| LuaRegistrationError::SourceTooLarge)?;
        let source_digest: [u8; 32] = Sha256::digest(source.as_bytes()).into();
        Ok(Self {
            name,
            version: "1.0.0".to_owned(),
            categories: Vec::new(),
            enabled: true,
            source: Arc::from(source),
            source_bytes,
            source_digest,
        })
    }

    pub fn with_version(
        mut self,
        version: impl Into<String>,
    ) -> Result<Self, LuaRegistrationError> {
        let version = version.into();
        validate_identifier(&version, MAX_SCRIPT_VERSION_BYTES)
            .map_err(|()| LuaRegistrationError::InvalidVersion)?;
        self.version = version;
        Ok(self)
    }

    #[must_use]
    pub fn with_categories(mut self, mut categories: Vec<ScriptCategory>) -> Self {
        categories.sort_unstable();
        categories.dedup();
        self.categories = categories;
        self
    }

    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn id(&self) -> String {
        stable_script_id(&self.name, &self.version, &self.source_digest)
    }

    #[must_use]
    pub fn manifest(&self) -> LuaScriptManifest {
        self.manifest_with_enabled(self.enabled)
    }

    fn manifest_with_enabled(&self, enabled: bool) -> LuaScriptManifest {
        LuaScriptManifest {
            id: self.id(),
            name: self.name.clone(),
            version: self.version.clone(),
            categories: self.categories.clone(),
            enabled,
            source_bytes: self.source_bytes,
            source_sha256: hex_digest(&self.source_digest),
        }
    }
}

/// Immutable host input exposed to Lua through read-only accessors.
#[derive(Clone)]
pub struct LuaContext {
    target: String,
    payload: String,
    parameters: BTreeMap<String, String>,
}

impl fmt::Debug for LuaContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LuaContext")
            .field("target_bytes", &self.target.len())
            .field("payload_bytes", &self.payload.len())
            .field("parameter_count", &self.parameters.len())
            .finish()
    }
}

impl LuaContext {
    #[must_use]
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            payload: String::new(),
            parameters: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = payload.into();
        self
    }

    #[must_use]
    pub fn with_parameter(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    fn validate(&self, config: &LuaEngineConfig) -> Result<(), LuaExecutionError> {
        if self.target.len() > config.max_target_bytes {
            return Err(LuaExecutionError::ContextTargetLimit);
        }
        if self.payload.len() > config.max_payload_bytes {
            return Err(LuaExecutionError::ContextPayloadLimit);
        }
        if self.parameters.len() > config.max_parameters {
            return Err(LuaExecutionError::ContextParameterCountLimit);
        }
        let mut total = self
            .target
            .len()
            .checked_add(self.payload.len())
            .ok_or(LuaExecutionError::ContextTotalLimit)?;
        for (key, value) in &self.parameters {
            if key.len() > config.max_parameter_key_bytes {
                return Err(LuaExecutionError::ContextParameterKeyLimit);
            }
            if value.len() > config.max_parameter_value_bytes {
                return Err(LuaExecutionError::ContextParameterValueLimit);
            }
            total = total
                .checked_add(key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or(LuaExecutionError::ContextTotalLimit)?;
            if total > config.max_context_bytes {
                return Err(LuaExecutionError::ContextTotalLimit);
            }
        }
        if total > config.max_context_bytes {
            return Err(LuaExecutionError::ContextTotalLimit);
        }
        Ok(())
    }
}

/// Cloneable host cancellation signal checked from the VM instruction hook.
#[derive(Clone, Default)]
pub struct LuaCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl fmt::Debug for LuaCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LuaCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl LuaCancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LuaExecutionStatus {
    Completed,
    Rejected,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LuaExecutionError {
    ScriptDisabled,
    ConcurrencyLimit,
    ContextTargetLimit,
    ContextPayloadLimit,
    ContextParameterCountLimit,
    ContextParameterKeyLimit,
    ContextParameterValueLimit,
    ContextTotalLimit,
    Syntax,
    Runtime,
    MemoryLimit,
    InstructionLimit,
    DeadlineExceeded,
    Cancelled,
    OutputLimit,
    OutputNotUtf8,
    UnsupportedOutputType,
    NonFiniteOutputNumber,
    ReturnLimit,
    ReturnNotUtf8,
    NonFiniteReturnNumber,
    UnsupportedReturnType,
    MultipleReturnValues,
    HostFailure,
}

impl LuaExecutionError {
    #[must_use]
    pub fn status(self) -> LuaExecutionStatus {
        match self {
            Self::ScriptDisabled
            | Self::ConcurrencyLimit
            | Self::ContextTargetLimit
            | Self::ContextPayloadLimit
            | Self::ContextParameterCountLimit
            | Self::ContextParameterKeyLimit
            | Self::ContextParameterValueLimit
            | Self::ContextTotalLimit => LuaExecutionStatus::Rejected,
            Self::InstructionLimit | Self::DeadlineExceeded => LuaExecutionStatus::TimedOut,
            Self::Cancelled => LuaExecutionStatus::Cancelled,
            _ => LuaExecutionStatus::Failed,
        }
    }
}

impl fmt::Display for LuaExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScriptDisabled => "script is disabled",
            Self::ConcurrencyLimit => "concurrent execution limit reached",
            Self::ContextTargetLimit => "context target limit exceeded",
            Self::ContextPayloadLimit => "context payload limit exceeded",
            Self::ContextParameterCountLimit => "context parameter count limit exceeded",
            Self::ContextParameterKeyLimit => "context parameter key limit exceeded",
            Self::ContextParameterValueLimit => "context parameter value limit exceeded",
            Self::ContextTotalLimit => "context total limit exceeded",
            Self::Syntax => "script syntax error",
            Self::Runtime => "script runtime error",
            Self::MemoryLimit => "Lua VM memory limit exceeded",
            Self::InstructionLimit => "Lua VM instruction limit exceeded",
            Self::DeadlineExceeded => "Lua execution deadline exceeded",
            Self::Cancelled => "Lua execution cancelled",
            Self::OutputLimit => "Lua output limit exceeded",
            Self::OutputNotUtf8 => "Lua output must be UTF-8",
            Self::UnsupportedOutputType => "Lua emitted an unsupported value type",
            Self::NonFiniteOutputNumber => "Lua emitted a non-finite number",
            Self::ReturnLimit => "Lua return value limit exceeded",
            Self::ReturnNotUtf8 => "Lua return string must be UTF-8",
            Self::NonFiniteReturnNumber => "Lua returned a non-finite number",
            Self::UnsupportedReturnType => "Lua returned an unsupported value type",
            Self::MultipleReturnValues => "Lua returned more than one value",
            Self::HostFailure => "Lua host failure",
        })
    }
}

impl std::error::Error for LuaExecutionError {}

/// Scalar value projected from a completed Lua invocation.
///
/// The executor only constructs [`Self::Number`] for finite values. Constructing
/// this public data enum directly does not grant script execution authority.
#[derive(Clone, PartialEq)]
pub enum LuaReturnValue {
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String(String),
}

impl fmt::Debug for LuaReturnValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boolean(_) => formatter.write_str("Boolean(<redacted>)"),
            Self::Integer(_) => formatter.write_str("Integer(<redacted>)"),
            Self::Number(_) => formatter.write_str("Number(<redacted>)"),
            Self::String(value) => formatter
                .debug_struct("String")
                .field("bytes", &value.len())
                .finish(),
        }
    }
}

impl LuaReturnValue {
    fn retained_bytes(&self) -> usize {
        match self {
            Self::Boolean(_) => 1,
            Self::Integer(_) | Self::Number(_) => 8,
            Self::String(value) => value.len(),
        }
    }
}

#[derive(Clone)]
pub struct LuaExecutionResult {
    script_id: String,
    script_version: String,
    source_sha256: String,
    status: LuaExecutionStatus,
    error: Option<LuaExecutionError>,
    output: String,
    return_value: Option<LuaReturnValue>,
    execution_time_ms: u64,
}

impl fmt::Debug for LuaExecutionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LuaExecutionResult")
            .field("script_id", &self.script_id)
            .field("script_version", &self.script_version)
            .field("source_sha256", &self.source_sha256)
            .field("status", &self.status)
            .field("error", &self.error)
            .field("output_bytes", &self.output.len())
            .field(
                "return_bytes",
                &self
                    .return_value
                    .as_ref()
                    .map(LuaReturnValue::retained_bytes),
            )
            .field("execution_time_ms", &self.execution_time_ms)
            .finish()
    }
}

impl LuaExecutionResult {
    #[must_use]
    pub fn script_id(&self) -> &str {
        &self.script_id
    }
    #[must_use]
    pub fn script_version(&self) -> &str {
        &self.script_version
    }
    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }
    #[must_use]
    pub fn status(&self) -> LuaExecutionStatus {
        self.status
    }
    #[must_use]
    pub fn success(&self) -> bool {
        self.status == LuaExecutionStatus::Completed
    }
    #[must_use]
    pub fn error(&self) -> Option<LuaExecutionError> {
        self.error
    }
    #[must_use]
    pub fn output(&self) -> &str {
        &self.output
    }
    #[must_use]
    pub fn return_value(&self) -> Option<&LuaReturnValue> {
        self.return_value.as_ref()
    }
    #[must_use]
    pub fn execution_time_ms(&self) -> u64 {
        self.execution_time_ms
    }
    fn completed(
        provenance: ExecutionProvenance,
        output: String,
        return_value: Option<LuaReturnValue>,
        started: Instant,
    ) -> Self {
        Self {
            script_id: provenance.script_id,
            script_version: provenance.script_version,
            source_sha256: provenance.source_sha256,
            status: LuaExecutionStatus::Completed,
            error: None,
            output,
            return_value,
            execution_time_ms: elapsed_ms(started),
        }
    }

    fn failed(provenance: ExecutionProvenance, error: LuaExecutionError, started: Instant) -> Self {
        Self {
            script_id: provenance.script_id,
            script_version: provenance.script_version,
            source_sha256: provenance.source_sha256,
            status: error.status(),
            error: Some(error),
            output: String::new(),
            return_value: None,
            execution_time_ms: elapsed_ms(started),
        }
    }
}

#[derive(Clone)]
struct ExecutionProvenance {
    script_id: String,
    script_version: String,
    source_sha256: String,
}

impl From<&LuaScript> for ExecutionProvenance {
    fn from(script: &LuaScript) -> Self {
        Self {
            script_id: script.id(),
            script_version: script.version.clone(),
            source_sha256: hex_digest(&script.source_digest),
        }
    }
}

/// Bounded, privacy-minimized execution metadata retained by the registry.
///
/// Script identity, source provenance, status, error, and timing remain sensitive
/// operational metadata. The receipt never contains Lua output, return values,
/// context, source text, or filesystem paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LuaExecutionReceipt {
    script_id: String,
    script_version: String,
    source_sha256: String,
    status: LuaExecutionStatus,
    error: Option<LuaExecutionError>,
    execution_time_ms: u64,
}

impl LuaExecutionReceipt {
    #[must_use]
    pub fn script_id(&self) -> &str {
        &self.script_id
    }

    #[must_use]
    pub fn script_version(&self) -> &str {
        &self.script_version
    }

    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    #[must_use]
    pub fn status(&self) -> LuaExecutionStatus {
        self.status
    }

    #[must_use]
    pub fn error(&self) -> Option<LuaExecutionError> {
        self.error
    }

    #[must_use]
    pub fn execution_time_ms(&self) -> u64 {
        self.execution_time_ms
    }

    fn from_result(result: &LuaExecutionResult) -> Self {
        Self {
            script_id: result.script_id.clone(),
            script_version: result.script_version.clone(),
            source_sha256: result.source_sha256.clone(),
            status: result.status,
            error: result.error,
            execution_time_ms: result.execution_time_ms,
        }
    }

    fn retained_bytes(&self) -> usize {
        256usize
            .saturating_add(self.script_id.capacity())
            .saturating_add(self.script_version.capacity())
            .saturating_add(self.source_sha256.capacity())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaRegistryError {
    InvalidConfig(LuaConfigError),
    DuplicateId,
    DuplicateName,
    ScriptCapacity,
    SourceLimit,
    TotalSourceCapacity,
    ScriptNotFound,
    ScriptInUse,
    InvocationLimit,
    RegistrationGenerationExhausted,
    HistorySequenceExhausted,
    StateUnavailable,
}

impl fmt::Display for LuaRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig(_) => "invalid Lua registry configuration",
            Self::DuplicateId => "Lua script ID is already registered",
            Self::DuplicateName => "Lua script name is already registered",
            Self::ScriptCapacity => "Lua script registry capacity reached",
            Self::SourceLimit => "Lua script exceeds this registry source limit",
            Self::TotalSourceCapacity => "Lua registry source-byte capacity reached",
            Self::ScriptNotFound => "Lua script not found",
            Self::ScriptInUse => "Lua script has an active invocation",
            Self::InvocationLimit => "Lua script invocation counter exhausted",
            Self::RegistrationGenerationExhausted => "Lua registry generation sequence exhausted",
            Self::HistorySequenceExhausted => "Lua history sequence exhausted",
            Self::StateUnavailable => "Lua registry state unavailable",
        })
    }
}

impl std::error::Error for LuaRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(error) => Some(error),
            _ => None,
        }
    }
}

struct HistoryEntry {
    sequence: u64,
    retained_bytes: usize,
    receipt: LuaExecutionReceipt,
}

struct BoundedExecutionHistory {
    entries: VecDeque<HistoryEntry>,
    retained_bytes: usize,
}

impl BoundedExecutionHistory {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            retained_bytes: 0,
        }
    }

    fn pop_front(&mut self) -> Option<HistoryEntry> {
        let entry = self.entries.pop_front()?;
        self.retained_bytes = self.retained_bytes.saturating_sub(entry.retained_bytes);
        Some(entry)
    }

    fn push(
        &mut self,
        sequence: u64,
        receipt: LuaExecutionReceipt,
        max_entries: usize,
        max_bytes: usize,
    ) -> bool {
        let retained_bytes = receipt.retained_bytes();
        if retained_bytes > max_bytes {
            return false;
        }
        while self.entries.len() >= max_entries
            || self.retained_bytes.saturating_add(retained_bytes) > max_bytes
        {
            if self.pop_front().is_none() {
                return false;
            }
        }
        self.retained_bytes = self.retained_bytes.saturating_add(retained_bytes);
        self.entries.push_back(HistoryEntry {
            sequence,
            retained_bytes,
            receipt,
        });
        true
    }
}

struct RegisteredScript {
    script: LuaScript,
    enabled: bool,
    active_invocations: usize,
    generation: u64,
}

struct RegistryState {
    scripts: BTreeMap<String, RegisteredScript>,
    names: BTreeMap<String, String>,
    histories: BTreeMap<String, BoundedExecutionHistory>,
    history_bytes: usize,
    next_sequence: u64,
    next_generation: u64,
    total_source_bytes: usize,
}

impl RegistryState {
    fn new() -> Self {
        Self {
            scripts: BTreeMap::new(),
            names: BTreeMap::new(),
            histories: BTreeMap::new(),
            history_bytes: 0,
            next_sequence: 0,
            next_generation: 0,
            total_source_bytes: 0,
        }
    }

    fn allocate_sequence(&mut self) -> Result<u64, LuaRegistryError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(LuaRegistryError::HistorySequenceExhausted)?;
        Ok(sequence)
    }

    fn allocate_generation(&mut self) -> Result<u64, LuaRegistryError> {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(LuaRegistryError::RegistrationGenerationExhausted)?;
        Ok(generation)
    }

    fn evict_global_oldest(&mut self) -> bool {
        let oldest = self
            .histories
            .iter()
            .filter_map(|(script_id, history)| {
                history
                    .entries
                    .front()
                    .map(|entry| (entry.sequence, script_id.clone()))
            })
            .min();
        let Some((_, script_id)) = oldest else {
            return false;
        };
        let Some(history) = self.histories.get_mut(&script_id) else {
            return false;
        };
        if let Some(entry) = history.pop_front() {
            self.history_bytes = self.history_bytes.saturating_sub(entry.retained_bytes);
        }
        if history.entries.is_empty() {
            self.histories.remove(&script_id);
        }
        true
    }
}

struct InvocationLease {
    state: Arc<Mutex<RegistryState>>,
    script_id: String,
    generation: u64,
}

impl Drop for InvocationLease {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Some(entry) = state.scripts.get_mut(&self.script_id) else {
            return;
        };
        if entry.generation == self.generation {
            entry.active_invocations = entry.active_invocations.saturating_sub(1);
        }
    }
}

struct RegisteredSnapshot {
    script: LuaScript,
    enabled: bool,
    generation: u64,
}

pub struct LuaScriptRegistry {
    state: Arc<Mutex<RegistryState>>,
    config: LuaEngineConfig,
    execution_permits: Arc<Semaphore>,
}

impl fmt::Debug for LuaScriptRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LuaScriptRegistry")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LuaScriptRegistry {
    pub fn new() -> Result<Self, LuaRegistryError> {
        Self::from_config(&LuaEngineConfig::default())
    }

    pub fn from_config(config: &LuaEngineConfig) -> Result<Self, LuaRegistryError> {
        config.validate().map_err(LuaRegistryError::InvalidConfig)?;
        Ok(Self {
            state: Arc::new(Mutex::new(RegistryState::new())),
            config: config.clone(),
            execution_permits: Arc::new(Semaphore::new(config.max_concurrent_executions)),
        })
    }

    pub fn register(&self, script: LuaScript) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let id = script.id();
        if state.scripts.contains_key(&id) {
            return Err(LuaRegistryError::DuplicateId);
        }
        if state.names.contains_key(&script.name) {
            return Err(LuaRegistryError::DuplicateName);
        }
        if state.scripts.len() >= self.config.max_scripts {
            return Err(LuaRegistryError::ScriptCapacity);
        }
        if script.source.len() > self.config.max_source_bytes {
            return Err(LuaRegistryError::SourceLimit);
        }
        let total_source_bytes = state
            .total_source_bytes
            .checked_add(script.source.len())
            .ok_or(LuaRegistryError::TotalSourceCapacity)?;
        if total_source_bytes > self.config.max_total_source_bytes {
            return Err(LuaRegistryError::TotalSourceCapacity);
        }
        let generation = state.allocate_generation()?;
        state.names.insert(script.name.clone(), id.clone());
        state.scripts.insert(
            id,
            RegisteredScript {
                enabled: script.enabled,
                script,
                active_invocations: 0,
                generation,
            },
        );
        state.total_source_bytes = total_source_bytes;
        Ok(())
    }

    pub fn get(&self, script_id: &str) -> Result<Option<LuaScriptManifest>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .scripts
            .get(script_id)
            .map(|entry| entry.script.manifest_with_enabled(entry.enabled)))
    }

    pub fn list_all(&self) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let mut manifests: Vec<_> = state
            .scripts
            .values()
            .map(|entry| entry.script.manifest_with_enabled(entry.enabled))
            .collect();
        manifests.sort_by(|left, right| {
            (&left.name, &left.version, &left.id).cmp(&(&right.name, &right.version, &right.id))
        });
        Ok(manifests)
    }

    pub fn list_enabled(&self) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(LuaScriptManifest::enabled)
            .collect())
    }

    pub fn list_by_category(
        &self,
        category: ScriptCategory,
    ) -> Result<Vec<LuaScriptManifest>, LuaRegistryError> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(|manifest| manifest.categories.contains(&category))
            .collect())
    }

    pub async fn execute(
        &self,
        script_id: &str,
        context: LuaContext,
    ) -> Result<LuaExecutionResult, LuaRegistryError> {
        self.execute_with_cancellation(script_id, context, LuaCancellationToken::new())
            .await
    }

    pub async fn execute_with_cancellation(
        &self,
        script_id: &str,
        context: LuaContext,
        cancellation: LuaCancellationToken,
    ) -> Result<LuaExecutionResult, LuaRegistryError> {
        let snapshot = {
            let state = self
                .state
                .lock()
                .map_err(|_| LuaRegistryError::StateUnavailable)?;
            let entry = state
                .scripts
                .get(script_id)
                .ok_or(LuaRegistryError::ScriptNotFound)?;
            RegisteredSnapshot {
                script: entry.script.clone(),
                enabled: entry.enabled,
                generation: entry.generation,
            }
        };
        let started = Instant::now();
        if !snapshot.enabled {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                LuaExecutionError::ScriptDisabled,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        if let Err(error) = context.validate(&self.config) {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                error,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        if cancellation.is_cancelled() {
            let result = LuaExecutionResult::failed(
                ExecutionProvenance::from(&snapshot.script),
                LuaExecutionError::Cancelled,
                started,
            );
            self.record_result(snapshot.generation, &result)?;
            return Ok(result);
        }
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    ExecutionProvenance::from(&snapshot.script),
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(snapshot.generation, &result)?;
                return Ok(result);
            },
        };
        let permit = match Arc::clone(&self.execution_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    ExecutionProvenance::from(&snapshot.script),
                    LuaExecutionError::ConcurrencyLimit,
                    started,
                );
                self.record_result(snapshot.generation, &result)?;
                return Ok(result);
            },
        };
        let (script, lease, generation) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| LuaRegistryError::StateUnavailable)?;
            let entry = state
                .scripts
                .get_mut(script_id)
                .ok_or(LuaRegistryError::ScriptNotFound)?;
            if !entry.enabled {
                let provenance = ExecutionProvenance::from(&entry.script);
                let generation = entry.generation;
                drop(state);
                drop(permit);
                let result = LuaExecutionResult::failed(
                    provenance,
                    LuaExecutionError::ScriptDisabled,
                    started,
                );
                self.record_result(generation, &result)?;
                return Ok(result);
            }
            entry.active_invocations = entry
                .active_invocations
                .checked_add(1)
                .ok_or(LuaRegistryError::InvocationLimit)?;
            let script = entry.script.clone();
            let generation = entry.generation;
            let lease = InvocationLease {
                state: Arc::clone(&self.state),
                script_id: script.id(),
                generation,
            };
            (script, lease, generation)
        };
        let config = self.config.clone();
        let fallback_provenance = ExecutionProvenance::from(&script);
        let worker = match catch_unwind(AssertUnwindSafe(|| {
            runtime.spawn_blocking(move || {
                let _permit = permit;
                let result = execute_snapshot(script, context, config, cancellation, started);
                (result, lease)
            })
        })) {
            Ok(worker) => worker,
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    fallback_provenance,
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(generation, &result)?;
                return Ok(result);
            },
        };
        let result = match await_worker(worker).await {
            Ok((result, lease)) => {
                self.record_result(generation, &result)?;
                drop(lease);
                result
            },
            Err(_) => {
                let result = LuaExecutionResult::failed(
                    fallback_provenance,
                    LuaExecutionError::HostFailure,
                    started,
                );
                self.record_result(generation, &result)?;
                result
            },
        };
        Ok(result)
    }

    pub fn get_history(
        &self,
        script_id: &str,
    ) -> Result<Vec<LuaExecutionReceipt>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .histories
            .get(script_id)
            .map(|history| {
                history
                    .entries
                    .iter()
                    .map(|entry| entry.receipt.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn get_recent_history(
        &self,
        script_id: &str,
        count: usize,
    ) -> Result<Vec<LuaExecutionReceipt>, LuaRegistryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        Ok(state
            .histories
            .get(script_id)
            .map(|history| {
                history
                    .entries
                    .iter()
                    .rev()
                    .take(count)
                    .map(|entry| entry.receipt.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn count(&self) -> Result<usize, LuaRegistryError> {
        self.state
            .lock()
            .map(|state| state.scripts.len())
            .map_err(|_| LuaRegistryError::StateUnavailable)
    }

    pub fn enabled_count(&self) -> Result<usize, LuaRegistryError> {
        self.state
            .lock()
            .map(|state| state.scripts.values().filter(|entry| entry.enabled).count())
            .map_err(|_| LuaRegistryError::StateUnavailable)
    }

    pub fn set_enabled(&self, script_id: &str, enabled: bool) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .get_mut(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        entry.enabled = enabled;
        Ok(())
    }

    pub fn unregister(&self, script_id: &str) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .get(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        if entry.active_invocations != 0 {
            return Err(LuaRegistryError::ScriptInUse);
        }
        let total_source_bytes = state
            .total_source_bytes
            .checked_sub(entry.script.source.len())
            .ok_or(LuaRegistryError::StateUnavailable)?;
        let removed_history_bytes = state
            .histories
            .get(script_id)
            .map_or(0, |history| history.retained_bytes);
        let history_bytes = state
            .history_bytes
            .checked_sub(removed_history_bytes)
            .ok_or(LuaRegistryError::StateUnavailable)?;
        let entry = state
            .scripts
            .remove(script_id)
            .ok_or(LuaRegistryError::ScriptNotFound)?;
        state.names.remove(&entry.script.name);
        state.total_source_bytes = total_source_bytes;
        state.histories.remove(script_id);
        state.history_bytes = history_bytes;
        Ok(())
    }

    fn record_result(
        &self,
        generation: u64,
        result: &LuaExecutionResult,
    ) -> Result<(), LuaRegistryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LuaRegistryError::StateUnavailable)?;
        if !state
            .scripts
            .get(result.script_id())
            .is_some_and(|entry| entry.generation == generation)
        {
            return Ok(());
        }
        let receipt = LuaExecutionReceipt::from_result(result);
        let receipt_bytes = receipt.retained_bytes();
        if receipt_bytes > self.config.max_history_bytes_per_script
            || receipt_bytes > self.config.max_history_bytes_total
        {
            return Ok(());
        }
        let sequence = state.allocate_sequence()?;
        while state.history_bytes.saturating_add(receipt_bytes)
            > self.config.max_history_bytes_total
        {
            if !state.evict_global_oldest() {
                return Ok(());
            }
        }
        let history = state
            .histories
            .entry(result.script_id().to_owned())
            .or_insert_with(BoundedExecutionHistory::new);
        let before = history.retained_bytes;
        let inserted = history.push(
            sequence,
            receipt,
            self.config.history_size,
            self.config.max_history_bytes_per_script,
        );
        let after = history.retained_bytes;
        if inserted {
            state.history_bytes = state
                .history_bytes
                .saturating_sub(before)
                .saturating_add(after);
        }
        Ok(())
    }
}

async fn await_worker<T>(mut worker: tokio::task::JoinHandle<T>) -> Result<T, ()> {
    poll_fn(|context| {
        match catch_unwind(AssertUnwindSafe(|| Pin::new(&mut worker).poll(context))) {
            Ok(Poll::Ready(result)) => Poll::Ready(result.map_err(|_| ())),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                worker.abort();
                Poll::Ready(Err(()))
            },
        }
    })
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StickyAbort {
    Cancelled,
    Deadline,
    Instruction,
    Output,
    OutputEncoding,
    UnsupportedOutput,
    NonFiniteOutput,
}

fn execute_snapshot(
    script: LuaScript,
    context: LuaContext,
    config: LuaEngineConfig,
    cancellation: LuaCancellationToken,
    started: Instant,
) -> LuaExecutionResult {
    let provenance = ExecutionProvenance::from(&script);
    let deadline = started
        .checked_add(Duration::from_millis(config.default_timeout_ms))
        .unwrap_or(started);
    if cancellation.is_cancelled() {
        return LuaExecutionResult::failed(provenance, LuaExecutionError::Cancelled, started);
    }
    if Instant::now() >= deadline {
        return LuaExecutionResult::failed(
            provenance,
            LuaExecutionError::DeadlineExceeded,
            started,
        );
    }
    let abort = Rc::new(Cell::new(None));
    let output = Rc::new(RefCell::new(String::new()));
    let lua = match Lua::new_with(StdLib::NONE, LuaOptions::default()) {
        Ok(lua) => lua,
        Err(_) => {
            return LuaExecutionResult::failed(provenance, LuaExecutionError::HostFailure, started);
        },
    };
    if lua.set_memory_limit(config.max_memory_bytes).is_err() {
        return LuaExecutionResult::failed(provenance, LuaExecutionError::HostFailure, started);
    }
    let instruction_count = Rc::new(Cell::new(0u64));
    let hook_abort = Rc::clone(&abort);
    let hook_count = Rc::clone(&instruction_count);
    let hook_cancellation = cancellation.clone();
    let hook_interval = config.hook_interval;
    let instruction_limit = config.instruction_limit;
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(hook_interval),
        move |_, _| {
            if let Some(reason) = hook_abort.get() {
                return Err(sticky_abort_error(reason));
            }
            if hook_cancellation.is_cancelled() {
                hook_abort.set(Some(StickyAbort::Cancelled));
                return Err(MluaError::RuntimeError(ABORT_CANCELLED.to_owned()));
            }
            if Instant::now() >= deadline {
                hook_abort.set(Some(StickyAbort::Deadline));
                return Err(MluaError::RuntimeError(ABORT_DEADLINE.to_owned()));
            }
            let (next, exhausted) =
                instruction_quantum_status(hook_count.get(), hook_interval, instruction_limit);
            hook_count.set(next);
            if exhausted {
                hook_abort.set(Some(StickyAbort::Instruction));
                return Err(MluaError::RuntimeError(ABORT_INSTRUCTION.to_owned()));
            }
            Ok(())
        },
    );
    let environment = match build_environment(
        &lua,
        &context,
        Rc::clone(&output),
        Rc::clone(&abort),
        config.max_output_bytes,
    ) {
        Ok(environment) => environment,
        Err(error) => {
            let code = classify_mlua_error(&error, abort.get());
            return LuaExecutionResult::failed(provenance, code, started);
        },
    };
    if let Some(error) = terminal_control_error(
        abort.get(),
        cancellation.is_cancelled(),
        Instant::now() >= deadline,
    ) {
        return LuaExecutionResult::failed(provenance, error, started);
    }
    let return_value = {
        let execution = lua
            .load(script.source.as_bytes())
            .set_name(REGISTERED_CHUNK_NAME)
            .set_mode(ChunkMode::Text)
            .set_environment(environment)
            .call::<_, MultiValue>(());
        if let Some(error) = terminal_control_error(
            abort.get(),
            cancellation.is_cancelled(),
            Instant::now() >= deadline,
        ) {
            return LuaExecutionResult::failed(provenance, error, started);
        }
        match execution {
            Ok(values) => match project_return_values(values, config.max_return_bytes) {
                Ok(value) => value,
                Err(error) => return LuaExecutionResult::failed(provenance, error, started),
            },
            Err(error) => {
                return LuaExecutionResult::failed(
                    provenance,
                    classify_mlua_error(&error, abort.get()),
                    started,
                );
            },
        }
    };
    drop(lua);
    let output =
        Rc::try_unwrap(output).map_or_else(|shared| shared.borrow().clone(), RefCell::into_inner);
    if let Some(error) = terminal_control_error(
        abort.get(),
        cancellation.is_cancelled(),
        Instant::now() >= deadline,
    ) {
        return LuaExecutionResult::failed(provenance, error, started);
    }
    LuaExecutionResult::completed(provenance, output, return_value, started)
}

fn build_environment<'lua>(
    lua: &'lua Lua,
    context: &LuaContext,
    output: Rc<RefCell<String>>,
    abort: Rc<Cell<Option<StickyAbort>>>,
    max_output_bytes: usize,
) -> mlua::Result<mlua::Table<'lua>> {
    let allowed = lua.create_table()?;
    let type_function = lua.create_function(|_, value: Value| Ok(value.type_name()))?;
    allowed.raw_set("type", type_function)?;
    let emit_output = output;
    let emit_abort = abort;
    let emit = lua.create_function(move |_, value: Value| {
        let mut buffer = emit_output.borrow_mut();
        let appended = match value {
            Value::Boolean(true) => append_emitted(&mut buffer, "true", max_output_bytes),
            Value::Boolean(false) => append_emitted(&mut buffer, "false", max_output_bytes),
            Value::Integer(value) => {
                append_emitted(&mut buffer, &value.to_string(), max_output_bytes)
            },
            Value::Number(value) if value.is_finite() => {
                append_emitted(&mut buffer, &value.to_string(), max_output_bytes)
            },
            Value::Number(_) => {
                emit_abort.set(Some(StickyAbort::NonFiniteOutput));
                return Err(MluaError::RuntimeError(ABORT_OUTPUT_NUMBER.to_owned()));
            },
            Value::String(value) => match value.to_str() {
                Ok(value) => append_emitted(&mut buffer, value, max_output_bytes),
                Err(_) => {
                    emit_abort.set(Some(StickyAbort::OutputEncoding));
                    return Err(MluaError::RuntimeError(ABORT_OUTPUT_ENCODING.to_owned()));
                },
            },
            _ => {
                emit_abort.set(Some(StickyAbort::UnsupportedOutput));
                return Err(MluaError::RuntimeError(ABORT_OUTPUT_TYPE.to_owned()));
            },
        };
        if appended.is_err() {
            emit_abort.set(Some(StickyAbort::Output));
            return Err(MluaError::RuntimeError(ABORT_OUTPUT.to_owned()));
        }
        Ok(())
    })?;
    allowed.raw_set("emit", emit)?;
    allowed.raw_set("context", build_context_proxy(lua, context)?)?;
    readonly_proxy(lua, allowed)
}

fn append_emitted(buffer: &mut String, value: &str, max_output_bytes: usize) -> Result<(), ()> {
    let next_len = buffer.len().checked_add(value.len()).ok_or(())?;
    if next_len > max_output_bytes {
        return Err(());
    }
    buffer.push_str(value);
    Ok(())
}

fn build_context_proxy<'lua>(
    lua: &'lua Lua,
    context: &LuaContext,
) -> mlua::Result<mlua::Table<'lua>> {
    let values = lua.create_table()?;
    values.raw_set("target", context.target.clone())?;
    values.raw_set("payload", context.payload.clone())?;
    values.raw_set("parameter_count", context.parameters.len())?;
    let parameters = Arc::new(context.parameters.clone());
    let lookup_parameters = Arc::clone(&parameters);
    let parameter = lua.create_function(move |_, key: mlua::String| {
        let Ok(key) = key.to_str() else {
            return Ok(None::<String>);
        };
        Ok(lookup_parameters.get(key).cloned())
    })?;
    values.raw_set("parameter", parameter)?;
    let ordered_parameters: Arc<Vec<(String, String)>> = Arc::new(
        parameters
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let parameter_at = lua.create_function(move |_, index: usize| {
        let value = index
            .checked_sub(1)
            .and_then(|index| ordered_parameters.get(index));
        Ok(match value {
            Some((key, value)) => (Some(key.clone()), Some(value.clone())),
            None => (None::<String>, None::<String>),
        })
    })?;
    values.raw_set("parameter_at", parameter_at)?;
    readonly_proxy(lua, values)
}

fn readonly_proxy<'lua>(
    lua: &'lua Lua,
    values: mlua::Table<'lua>,
) -> mlua::Result<mlua::Table<'lua>> {
    let proxy = lua.create_table()?;
    let metatable = lua.create_table()?;
    metatable.raw_set("__index", values)?;
    metatable.raw_set(
        "__newindex",
        lua.create_function(|_, _: (Value, Value, Value)| -> mlua::Result<()> {
            Err(MluaError::RuntimeError(IMMUTABLE_CONTEXT.to_owned()))
        })?,
    )?;
    metatable.raw_set("__metatable", "locked")?;
    proxy.set_metatable(Some(metatable));
    Ok(proxy)
}

fn project_return_values(
    mut values: MultiValue<'_>,
    max_return_bytes: usize,
) -> Result<Option<LuaReturnValue>, LuaExecutionError> {
    // mlua must collect LUA_MULTRET to distinguish zero, one, and many values.
    // The source, VM-memory, and concurrency caps jointly bound this temporary
    // Rust-side container; there is no lower-level one-slot API that preserves
    // the number of returned values.
    if values.len() > 1 {
        return Err(LuaExecutionError::MultipleReturnValues);
    }
    project_return_value(values.pop_front().unwrap_or(Value::Nil), max_return_bytes)
}

fn project_return_value(
    value: Value<'_>,
    max_return_bytes: usize,
) -> Result<Option<LuaReturnValue>, LuaExecutionError> {
    match value {
        Value::Nil => Ok(None),
        Value::Boolean(value) => Ok(Some(LuaReturnValue::Boolean(value))),
        Value::Integer(value) => Ok(Some(LuaReturnValue::Integer(value))),
        Value::Number(value) if value.is_finite() => Ok(Some(LuaReturnValue::Number(value))),
        Value::Number(_) => Err(LuaExecutionError::NonFiniteReturnNumber),
        Value::String(value) => {
            let value = value
                .to_str()
                .map_err(|_| LuaExecutionError::ReturnNotUtf8)?;
            if value.len() > max_return_bytes {
                return Err(LuaExecutionError::ReturnLimit);
            }
            Ok(Some(LuaReturnValue::String(value.to_owned())))
        },
        _ => Err(LuaExecutionError::UnsupportedReturnType),
    }
}

fn classify_mlua_error(error: &MluaError, sticky_abort: Option<StickyAbort>) -> LuaExecutionError {
    if let Some(reason) = sticky_abort {
        return sticky_abort_code(reason);
    }
    match error {
        MluaError::SyntaxError { .. } => LuaExecutionError::Syntax,
        MluaError::MemoryError(_) => LuaExecutionError::MemoryLimit,
        MluaError::CallbackError { cause, .. } | MluaError::WithContext { cause, .. } => {
            classify_mlua_error(cause, sticky_abort)
        },
        _ => LuaExecutionError::Runtime,
    }
}

fn sticky_abort_error(reason: StickyAbort) -> MluaError {
    MluaError::RuntimeError(
        match reason {
            StickyAbort::Cancelled => ABORT_CANCELLED,
            StickyAbort::Deadline => ABORT_DEADLINE,
            StickyAbort::Instruction => ABORT_INSTRUCTION,
            StickyAbort::Output => ABORT_OUTPUT,
            StickyAbort::OutputEncoding => ABORT_OUTPUT_ENCODING,
            StickyAbort::UnsupportedOutput => ABORT_OUTPUT_TYPE,
            StickyAbort::NonFiniteOutput => ABORT_OUTPUT_NUMBER,
        }
        .to_owned(),
    )
}

fn sticky_abort_code(reason: StickyAbort) -> LuaExecutionError {
    match reason {
        StickyAbort::Cancelled => LuaExecutionError::Cancelled,
        StickyAbort::Deadline => LuaExecutionError::DeadlineExceeded,
        StickyAbort::Instruction => LuaExecutionError::InstructionLimit,
        StickyAbort::Output => LuaExecutionError::OutputLimit,
        StickyAbort::OutputEncoding => LuaExecutionError::OutputNotUtf8,
        StickyAbort::UnsupportedOutput => LuaExecutionError::UnsupportedOutputType,
        StickyAbort::NonFiniteOutput => LuaExecutionError::NonFiniteOutputNumber,
    }
}

fn terminal_control_error(
    sticky_abort: Option<StickyAbort>,
    cancelled: bool,
    deadline_exceeded: bool,
) -> Option<LuaExecutionError> {
    if let Some(reason) = sticky_abort {
        Some(sticky_abort_code(reason))
    } else if cancelled {
        Some(LuaExecutionError::Cancelled)
    } else if deadline_exceeded {
        Some(LuaExecutionError::DeadlineExceeded)
    } else {
        None
    }
}

fn instruction_quantum_status(current: u64, interval: u32, limit: u64) -> (u64, bool) {
    let quantum = u64::from(interval);
    let next = current.saturating_add(quantum);
    let following_exceeds = match next.checked_add(quantum) {
        Some(following) => following > limit,
        None => true,
    };
    (next, next >= limit || following_exceeds)
}

fn read_registered_source(
    script_path: &Path,
    approved_root: &Path,
    max_source_bytes: usize,
) -> Result<String, LuaRegistrationError> {
    let absolute_root =
        std::path::absolute(approved_root).map_err(|_| LuaRegistrationError::InvalidPath)?;
    let absolute_candidate = if script_path.is_absolute() {
        std::path::absolute(script_path).map_err(|_| LuaRegistrationError::InvalidPath)?
    } else {
        absolute_root.join(script_path)
    };
    let relative = absolute_candidate
        .strip_prefix(&absolute_root)
        .map_err(|_| LuaRegistrationError::OutsideApprovedRoot)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(LuaRegistrationError::InvalidPath);
    }
    if absolute_candidate
        .extension()
        .and_then(|value| value.to_str())
        != Some("lua")
    {
        return Err(LuaRegistrationError::InvalidPath);
    }
    reject_symlink_components(&absolute_root, relative)?;
    let canonical_root = absolute_root
        .canonicalize()
        .map_err(|_| LuaRegistrationError::InvalidPath)?;
    let canonical_candidate = absolute_candidate
        .canonicalize()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(LuaRegistrationError::OutsideApprovedRoot);
    }
    let path_metadata = canonical_candidate
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if !path_metadata.is_file() {
        return Err(LuaRegistrationError::NotRegularFile);
    }
    if path_metadata.len() > max_source_bytes as u64 {
        return Err(LuaRegistrationError::SourceTooLarge);
    }
    let mut file =
        File::open(&canonical_candidate).map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let before = file
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let read_limit = u64::try_from(max_source_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(LuaRegistrationError::SourceTooLarge)?;
    let initial_capacity =
        usize::try_from(path_metadata.len()).map_err(|_| LuaRegistrationError::SourceTooLarge)?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    if bytes.len() > max_source_bytes {
        return Err(LuaRegistrationError::SourceTooLarge);
    }
    let after = file
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
    let canonical_after = absolute_candidate
        .canonicalize()
        .map_err(|_| LuaRegistrationError::SourceChangedDuringRegistration)?;
    reject_symlink_components(&absolute_root, relative)?;
    let path_after = canonical_after
        .metadata()
        .map_err(|_| LuaRegistrationError::SourceChangedDuringRegistration)?;
    if canonical_after != canonical_candidate
        || !same_file_metadata(&before, &after)
        || !same_file_metadata(&after, &path_after)
        || after.len() != bytes.len() as u64
    {
        return Err(LuaRegistrationError::SourceChangedDuringRegistration);
    }
    String::from_utf8(bytes).map_err(|_| LuaRegistrationError::SourceNotUtf8)
}

fn reject_symlink_components(
    absolute_root: &Path,
    relative: &Path,
) -> Result<(), LuaRegistrationError> {
    let root_metadata = absolute_root
        .symlink_metadata()
        .map_err(|_| LuaRegistrationError::InvalidPath)?;
    if root_metadata.file_type().is_symlink() {
        return Err(LuaRegistrationError::SymlinkRejected);
    }
    let mut current = PathBuf::from(absolute_root);
    for component in relative.components() {
        if let Component::Normal(component) = component {
            current.push(component);
            let metadata = current
                .symlink_metadata()
                .map_err(|_| LuaRegistrationError::SourceReadFailed)?;
            if metadata.file_type().is_symlink() {
                return Err(LuaRegistrationError::SymlinkRejected);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn validate_identifier(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(());
    }
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn stable_script_id(name: &str, version: &str, source_digest: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"venom-lua-script/v1\0");
    digest.update(name.as_bytes());
    digest.update(b"\0");
    digest.update(version.as_bytes());
    digest.update(b"\0");
    digest.update(source_digest);
    let digest: [u8; 32] = digest.finalize().into();
    let mut id = String::with_capacity(68);
    id.push_str("lua:");
    id.push_str(&hex_digest(&digest));
    id
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn test_config() -> LuaEngineConfig {
        let mut config = LuaEngineConfig::minimal();
        config.default_timeout_ms = 250;
        config.instruction_limit = 50_000;
        config.hook_interval = 100;
        config.max_memory_bytes = 2 * 1_024 * 1_024;
        config.max_source_bytes = 8 * 1_024;
        config.max_context_bytes = 8 * 1_024;
        config.max_target_bytes = 2 * 1_024;
        config.max_payload_bytes = 2 * 1_024;
        config.max_parameter_key_bytes = 256;
        config.max_parameter_value_bytes = 2 * 1_024;
        config.max_output_bytes = 1_024;
        config.max_return_bytes = 1_024;
        config
    }

    fn fixture_with_config(source: &[u8], config: &LuaEngineConfig) -> (TempDir, LuaScript) {
        let root = tempfile::tempdir().expect("temporary script root");
        let path = root.path().join("fixture.lua");
        fs::write(&path, source).expect("fixture source");
        let script = LuaScript::new_safe_with_config("fixture", &path, root.path(), config)
            .expect("registered fixture");
        (root, script)
    }

    fn fixture(source: &str) -> (TempDir, LuaScript) {
        fixture_with_config(source.as_bytes(), &test_config())
    }

    async fn run(source: &str, context: LuaContext) -> LuaExecutionResult {
        let config = test_config();
        let (_root, script) = fixture_with_config(source.as_bytes(), &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("registration");
        registry.execute(&id, context).await.expect("execution")
    }

    #[tokio::test]
    async fn executes_registered_snapshot_and_projects_scalar_return() {
        let result = run(
            "emit(context.target); return context.parameter('mode')",
            LuaContext::new("fixture-target").with_parameter("mode", "safe"),
        )
        .await;
        assert_eq!(result.status(), LuaExecutionStatus::Completed);
        assert_eq!(result.output(), "fixture-target");
        assert_eq!(
            result.return_value(),
            Some(&LuaReturnValue::String("safe".to_owned()))
        );
    }

    #[tokio::test]
    async fn supported_scalar_return_domain_is_exact() {
        let boolean = run("return true", LuaContext::new("target")).await;
        assert_eq!(boolean.return_value(), Some(&LuaReturnValue::Boolean(true)));
        let integer = run("return 42", LuaContext::new("target")).await;
        assert_eq!(integer.return_value(), Some(&LuaReturnValue::Integer(42)));
        let number = run("return 1.5", LuaContext::new("target")).await;
        assert_eq!(number.return_value(), Some(&LuaReturnValue::Number(1.5)));
        let nil = run("return nil", LuaContext::new("target")).await;
        assert_eq!(nil.return_value(), None);
        let table = run("return {}", LuaContext::new("target")).await;
        assert_eq!(
            table.error(),
            Some(LuaExecutionError::UnsupportedReturnType)
        );
        let non_finite = run("return 0 / 0", LuaContext::new("target")).await;
        assert_eq!(
            non_finite.error(),
            Some(LuaExecutionError::NonFiniteReturnNumber)
        );
        let multiple = run("return true, false", LuaContext::new("target")).await;
        assert_eq!(
            multiple.error(),
            Some(LuaExecutionError::MultipleReturnValues)
        );
    }

    #[tokio::test]
    async fn syntax_and_runtime_errors_are_typed_and_sanitized() {
        let syntax = run("local =", LuaContext::new("secret-target")).await;
        assert_eq!(syntax.error(), Some(LuaExecutionError::Syntax));
        assert!(!format!("{syntax:?}").contains("secret-target"));

        let runtime = run(
            "local missing = nil; return missing.field",
            LuaContext::new("secret-target"),
        )
        .await;
        assert_eq!(runtime.error(), Some(LuaExecutionError::Runtime));
        assert!(!format!("{runtime:?}").contains("secret-target"));

        let forged_abort = run(
            "return context['venom:cancelled']()",
            LuaContext::new("target"),
        )
        .await;
        assert_eq!(forged_abort.error(), Some(LuaExecutionError::Runtime));
        assert_eq!(forged_abort.status(), LuaExecutionStatus::Failed);
    }

    #[tokio::test]
    async fn result_and_context_debug_redact_sensitive_values() {
        let context = LuaContext::new("target-secret")
            .with_payload("payload-secret")
            .with_parameter("token", "parameter-secret");
        let context_debug = format!("{context:?}");
        for secret in ["target-secret", "payload-secret", "parameter-secret"] {
            assert!(!context_debug.contains(secret));
        }

        let result = run("emit(context.target); return context.payload", context).await;
        let result_debug = format!("{result:?}");
        for secret in ["target-secret", "payload-secret"] {
            assert!(!result_debug.contains(secret));
        }
        assert_eq!(
            format!("{:?}", LuaReturnValue::Boolean(true)),
            "Boolean(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", LuaReturnValue::Integer(42)),
            "Integer(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", LuaReturnValue::Number(1.5)),
            "Number(<redacted>)"
        );
    }

    #[tokio::test]
    async fn infinite_loop_is_actually_interrupted_by_instruction_hook() {
        let result = run("while true do end", LuaContext::new("target")).await;
        assert_eq!(result.error(), Some(LuaExecutionError::InstructionLimit));
        assert_eq!(result.status(), LuaExecutionStatus::TimedOut);
    }

    #[test]
    fn non_divisible_instruction_quantum_stops_before_the_next_over_limit_hook() {
        assert_eq!(instruction_quantum_status(0, 100, 250), (100, false));
        let (aborted_at, exhausted) = instruction_quantum_status(100, 100, 250);
        assert_eq!(aborted_at, 200);
        assert!(exhausted);
        assert!(aborted_at <= 250);

        assert_eq!(instruction_quantum_status(0, 100, 200), (100, false));
        assert_eq!(instruction_quantum_status(100, 100, 200), (200, true));
        assert_eq!(
            instruction_quantum_status(u64::MAX - 50, 100, u64::MAX),
            (u64::MAX, true)
        );
        assert_eq!(
            instruction_quantum_status(u64::MAX - 150, 100, u64::MAX),
            (u64::MAX - 50, true)
        );
    }

    #[tokio::test]
    async fn non_divisible_instruction_ceiling_allows_finite_and_interrupts_over_ceiling_code() {
        let mut config = test_config();
        config.instruction_limit = 250;
        config.hook_interval = 100;
        let (_finite_root, finite) =
            fixture_with_config(b"local value = 1; value = value + 1; return value", &config);
        let finite_id = finite.id();
        let finite_registry = LuaScriptRegistry::from_config(&config).expect("finite registry");
        finite_registry
            .register(finite)
            .expect("finite registration");
        let completed = finite_registry
            .execute(&finite_id, LuaContext::new("target"))
            .await
            .expect("finite execution");
        assert_eq!(completed.status(), LuaExecutionStatus::Completed);
        assert_eq!(completed.return_value(), Some(&LuaReturnValue::Integer(2)));

        let (_infinite_root, infinite) = fixture_with_config(b"while true do end", &config);
        let infinite_id = infinite.id();
        let infinite_registry = LuaScriptRegistry::from_config(&config).expect("infinite registry");
        infinite_registry
            .register(infinite)
            .expect("infinite registration");
        let interrupted = infinite_registry
            .execute(&infinite_id, LuaContext::new("target"))
            .await
            .expect("infinite execution");
        assert_eq!(
            interrupted.error(),
            Some(LuaExecutionError::InstructionLimit)
        );
    }

    #[tokio::test]
    async fn monotonic_deadline_is_distinct_from_instruction_limit() {
        let mut config = test_config();
        config.default_timeout_ms = 1;
        config.instruction_limit = 100_000_000;
        config.hook_interval = 100;
        let (_root, script) = fixture_with_config(b"while true do end", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        let result = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(result.error(), Some(LuaExecutionError::DeadlineExceeded));
    }

    #[tokio::test]
    async fn cancellation_interrupts_running_lua_on_a_blocking_worker() {
        let mut config = test_config();
        config.default_timeout_ms = 5_000;
        config.instruction_limit = 100_000_000;
        config.hook_interval = 100;
        let (_root, script) = fixture_with_config(b"while true do end", &config);
        let id = script.id();
        let registry = Arc::new(LuaScriptRegistry::from_config(&config).expect("registry"));
        registry.register(script).expect("register");
        let cancellation = LuaCancellationToken::new();
        let worker_registry = Arc::clone(&registry);
        let worker_id = id.clone();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::spawn(async move {
            worker_registry
                .execute_with_cancellation(
                    &worker_id,
                    LuaContext::new("target"),
                    worker_cancellation,
                )
                .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        let result = worker.await.expect("worker").expect("execute");
        assert_eq!(result.error(), Some(LuaExecutionError::Cancelled));
    }

    #[test]
    fn single_concurrency_permit_rejects_second_vm_and_is_reusable() {
        let mut config = test_config();
        config.max_concurrent_executions = 1;
        config.default_timeout_ms = 5_000;
        config.instruction_limit = 100_000_000;
        config.hook_interval = 10_000;
        let root = tempfile::tempdir().expect("root");
        let holding_path = root.path().join("holding.lua");
        let finite_path = root.path().join("finite.lua");
        fs::write(&holding_path, "while true do end").expect("holding source");
        fs::write(&finite_path, "return true").expect("finite source");
        let holding =
            LuaScript::new_safe_with_config("holding", &holding_path, root.path(), &config)
                .expect("holding script");
        let finite = LuaScript::new_safe_with_config("finite", &finite_path, root.path(), &config)
            .expect("finite script");
        let holding_id = holding.id();
        let finite_id = finite.id();
        let registry = Arc::new(LuaScriptRegistry::from_config(&config).expect("registry"));
        registry.register(holding).expect("holding registration");
        registry.register(finite).expect("finite registration");

        let blocking_gate = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("test runtime");
        let worker_gate = Arc::clone(&blocking_gate);
        let blocking_worker = runtime.spawn_blocking(move || {
            let (state, condition) = &*worker_gate;
            let mut state = state.lock().expect("blocking gate");
            state.0 = true;
            condition.notify_all();
            while !state.1 {
                state = condition.wait(state).expect("blocking gate");
            }
        });
        {
            let (state, condition) = &*blocking_gate;
            let mut state = state.lock().expect("blocking gate");
            while !state.0 {
                state = condition.wait(state).expect("blocking gate");
            }
        }

        runtime.block_on(async {
            let cancellation = LuaCancellationToken::new();
            let worker_registry = Arc::clone(&registry);
            let worker_id = holding_id.clone();
            let worker_cancellation = cancellation.clone();
            let worker = tokio::spawn(async move {
                worker_registry
                    .execute_with_cancellation(
                        &worker_id,
                        LuaContext::new("holding"),
                        worker_cancellation,
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let active = registry
                        .state
                        .lock()
                        .expect("registry state")
                        .scripts
                        .get(&holding_id)
                        .expect("holding script")
                        .active_invocations;
                    if active == 1 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("holding invocation acquired its lease");

            let rejected = registry
                .execute(&finite_id, LuaContext::new("second"))
                .await
                .expect("typed concurrency rejection");
            assert_eq!(rejected.error(), Some(LuaExecutionError::ConcurrencyLimit));
            assert_eq!(
                registry
                    .state
                    .lock()
                    .expect("registry state")
                    .scripts
                    .get(&finite_id)
                    .expect("finite script")
                    .active_invocations,
                0
            );

            cancellation.cancel();
            {
                let (state, condition) = &*blocking_gate;
                let mut state = state.lock().expect("blocking gate");
                state.1 = true;
                condition.notify_all();
            }
            blocking_worker.await.expect("blocking worker");
            let cancelled = worker.await.expect("worker").expect("holding execution");
            assert_eq!(cancelled.error(), Some(LuaExecutionError::Cancelled));
            assert_eq!(
                registry
                    .state
                    .lock()
                    .expect("registry state")
                    .scripts
                    .get(&holding_id)
                    .expect("holding script")
                    .active_invocations,
                0
            );

            let reused = registry
                .execute(&finite_id, LuaContext::new("reused"))
                .await
                .expect("reused permit");
            assert_eq!(reused.status(), LuaExecutionStatus::Completed);
            assert_eq!(reused.return_value(), Some(&LuaReturnValue::Boolean(true)));
        });
    }

    #[test]
    fn blocking_worker_preflight_checks_cancel_and_queue_deadline_before_vm_creation() {
        let config = test_config();
        let (_root, script) = fixture_with_config(b"return true", &config);
        let stale_start = Instant::now()
            .checked_sub(Duration::from_millis(config.default_timeout_ms + 1))
            .expect("stale start");
        let expired = execute_snapshot(
            script.clone(),
            LuaContext::new("target"),
            config.clone(),
            LuaCancellationToken::new(),
            stale_start,
        );
        assert_eq!(expired.error(), Some(LuaExecutionError::DeadlineExceeded));

        let cancellation = LuaCancellationToken::new();
        cancellation.cancel();
        let cancelled = execute_snapshot(
            script,
            LuaContext::new("target"),
            config,
            cancellation,
            stale_start,
        );
        assert_eq!(cancelled.error(), Some(LuaExecutionError::Cancelled));
    }

    #[tokio::test]
    async fn pcall_coroutines_and_all_standard_libraries_are_absent() {
        let result = run(
            "return pcall == nil and xpcall == nil and coroutine == nil and os == nil and io == nil and debug == nil and package == nil and load == nil and dofile == nil and loadfile == nil and require == nil and print == nil and warn == nil and collectgarbage == nil and math == nil and string == nil and table == nil and utf8 == nil",
            LuaContext::new("target"),
        )
        .await;
        assert_eq!(result.return_value(), Some(&LuaReturnValue::Boolean(true)));

        let method = run("return ('x'):match('x')", LuaContext::new("target")).await;
        assert_eq!(method.error(), Some(LuaExecutionError::Runtime));
    }

    #[tokio::test]
    async fn memory_bomb_fails_with_fixed_memory_code() {
        let result = run(
            "local value = 'xxxxxxxx'; while true do value = value .. value end",
            LuaContext::new("target"),
        )
        .await;
        assert_eq!(result.error(), Some(LuaExecutionError::MemoryLimit));
    }

    #[tokio::test]
    async fn context_is_immutable_and_parameter_order_is_stable() {
        let result = run(
            "context.target = 'changed'; return context.target",
            LuaContext::new("original"),
        )
        .await;
        assert_eq!(result.error(), Some(LuaExecutionError::Runtime));

        let result = run(
            "local a, av = context.parameter_at(1); local b, bv = context.parameter_at(2); emit(a .. '=' .. av .. ',' .. b .. '=' .. bv)",
            LuaContext::new("target")
                .with_parameter("z", "last")
                .with_parameter("a", "first"),
        )
        .await;
        assert_eq!(result.output(), "a=first,z=last");
    }

    #[tokio::test]
    async fn output_cap_enforces_exact_boundary_plus_one() {
        let mut config = test_config();
        config.max_output_bytes = 4;
        let root = tempfile::tempdir().expect("root");
        let exact_path = root.path().join("exact.lua");
        fs::write(&exact_path, "emit('1234')").expect("source");
        let exact_script =
            LuaScript::new_safe_with_config("exact", &exact_path, root.path(), &config)
                .expect("script");
        let exact_id = exact_script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(exact_script).expect("register");
        let exact = registry
            .execute(&exact_id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert!(exact.success());
        assert_eq!(exact.output(), "1234");

        let plus_path = root.path().join("plus.lua");
        fs::write(&plus_path, "emit('12345')").expect("source");
        let plus_script = LuaScript::new_safe_with_config("plus", &plus_path, root.path(), &config)
            .expect("script");
        let plus_id = plus_script.id();
        registry.register(plus_script).expect("register");
        let plus = registry
            .execute(&plus_id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(plus.error(), Some(LuaExecutionError::OutputLimit));
        assert!(plus.output().is_empty());
    }

    #[tokio::test]
    async fn oversized_vm_string_is_rejected_before_any_rust_heap_clone() {
        let mut config = test_config();
        config.max_output_bytes = 4;
        let (_root, script) = fixture_with_config(
            b"local value = '12345678'; for _ = 1, 8 do value = value .. value end; emit(value)",
            &config,
        );
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        let result = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(result.error(), Some(LuaExecutionError::OutputLimit));
        assert!(result.output().is_empty());
    }

    #[tokio::test]
    async fn unsupported_nonfinite_and_non_utf8_output_are_distinct() {
        let unsupported = run("emit({})", LuaContext::new("target")).await;
        assert_eq!(
            unsupported.error(),
            Some(LuaExecutionError::UnsupportedOutputType)
        );

        let nonfinite = run("emit(0 / 0)", LuaContext::new("target")).await;
        assert_eq!(
            nonfinite.error(),
            Some(LuaExecutionError::NonFiniteOutputNumber)
        );

        let invalid_utf8 = run("emit('\\255')", LuaContext::new("target")).await;
        assert_eq!(invalid_utf8.error(), Some(LuaExecutionError::OutputNotUtf8));
    }

    #[tokio::test]
    async fn return_cap_enforces_exact_boundary_plus_one() {
        let mut config = test_config();
        config.max_return_bytes = 4;
        let root = tempfile::tempdir().expect("root");
        let exact_path = root.path().join("exact.lua");
        fs::write(&exact_path, "return '1234'").expect("source");
        let exact_script =
            LuaScript::new_safe_with_config("exact", &exact_path, root.path(), &config)
                .expect("script");
        let exact_id = exact_script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(exact_script).expect("register");
        let exact = registry
            .execute(&exact_id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(
            exact.return_value(),
            Some(&LuaReturnValue::String("1234".to_owned()))
        );

        let plus_path = root.path().join("plus.lua");
        fs::write(&plus_path, "return '12345'").expect("source");
        let plus_script = LuaScript::new_safe_with_config("plus", &plus_path, root.path(), &config)
            .expect("script");
        let plus_id = plus_script.id();
        registry.register(plus_script).expect("register");
        let plus = registry
            .execute(&plus_id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(plus.error(), Some(LuaExecutionError::ReturnLimit));
    }

    #[tokio::test]
    async fn each_context_limit_is_checked_before_vm_creation() {
        let mut config = test_config();
        config.max_target_bytes = 4;
        config.max_payload_bytes = 4;
        config.max_parameters = 1;
        config.max_parameter_key_bytes = 4;
        config.max_parameter_value_bytes = 4;
        config.max_context_bytes = 8;
        let (_root, script) = fixture_with_config(b"return true", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");

        for (context, expected) in [
            (
                LuaContext::new("12345"),
                LuaExecutionError::ContextTargetLimit,
            ),
            (
                LuaContext::new("").with_payload("12345"),
                LuaExecutionError::ContextPayloadLimit,
            ),
            (
                LuaContext::new("")
                    .with_parameter("a", "")
                    .with_parameter("b", ""),
                LuaExecutionError::ContextParameterCountLimit,
            ),
            (
                LuaContext::new("").with_parameter("12345", ""),
                LuaExecutionError::ContextParameterKeyLimit,
            ),
            (
                LuaContext::new("").with_parameter("a", "12345"),
                LuaExecutionError::ContextParameterValueLimit,
            ),
            (
                LuaContext::new("1234")
                    .with_payload("1234")
                    .with_parameter("a", ""),
                LuaExecutionError::ContextTotalLimit,
            ),
        ] {
            let result = registry.execute(&id, context).await.expect("execute");
            assert_eq!(result.error(), Some(expected));
            assert_eq!(result.status(), LuaExecutionStatus::Rejected);
        }
    }

    #[tokio::test]
    async fn source_snapshot_survives_later_file_replacement() {
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("fixture.lua");
        fs::write(&path, "return 'original'").expect("source");
        let script = LuaScript::new_safe_with_config("snapshot", &path, root.path(), &config)
            .expect("script");
        fs::write(&path, "return 'replacement'").expect("replacement");
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        let result = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(
            result.return_value(),
            Some(&LuaReturnValue::String("original".to_owned()))
        );
    }

    #[test]
    fn source_size_enforces_exact_boundary_plus_one() {
        let mut config = test_config();
        config.max_source_bytes = 4;
        let root = tempfile::tempdir().expect("root");
        let exact = root.path().join("exact.lua");
        fs::write(&exact, "true").expect("source");
        assert!(LuaScript::new_safe_with_config("exact", &exact, root.path(), &config).is_ok());
        let plus = root.path().join("plus.lua");
        fs::write(&plus, "false").expect("source");
        assert_eq!(
            LuaScript::new_safe_with_config("plus", &plus, root.path(), &config).unwrap_err(),
            LuaRegistrationError::SourceTooLarge
        );
    }

    #[test]
    fn traversal_and_non_lua_paths_are_rejected() {
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let outside_path = outside.path().join("outside.lua");
        fs::write(&outside_path, "return true").expect("source");
        assert_eq!(
            LuaScript::new_safe_with_config("escape", &outside_path, root.path(), &config)
                .unwrap_err(),
            LuaRegistrationError::OutsideApprovedRoot
        );
        let text = root.path().join("source.txt");
        fs::write(&text, "return true").expect("source");
        assert_eq!(
            LuaScript::new_safe_with_config("text", &text, root.path(), &config).unwrap_err(),
            LuaRegistrationError::InvalidPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_is_rejected() {
        use std::os::unix::fs::symlink;
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("source.lua");
        let link = root.path().join("link.lua");
        fs::write(&source, "return true").expect("source");
        symlink(&source, &link).expect("symlink");
        assert_eq!(
            LuaScript::new_safe_with_config("link", &link, root.path(), &config).unwrap_err(),
            LuaRegistrationError::SymlinkRejected
        );
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_directory_symlink_component_is_rejected() {
        use std::os::unix::fs::symlink;
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let actual = root.path().join("actual");
        let linked = root.path().join("linked");
        fs::create_dir(&actual).expect("actual directory");
        fs::write(actual.join("source.lua"), "return true").expect("source");
        symlink(&actual, &linked).expect("directory symlink");
        assert_eq!(
            LuaScript::new_safe_with_config(
                "linked-directory",
                linked.join("source.lua"),
                root.path(),
                &config,
            )
            .unwrap_err(),
            LuaRegistrationError::SymlinkRejected
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_symlink_source_is_rejected_when_host_can_create_it() {
        use std::os::windows::fs::symlink_file;
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("source.lua");
        let link = root.path().join("link.lua");
        fs::write(&source, "return true").expect("source");
        if symlink_file(&source, &link).is_ok() {
            assert_eq!(
                LuaScript::new_safe_with_config("link", &link, root.path(), &config).unwrap_err(),
                LuaRegistrationError::SymlinkRejected
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_intermediate_directory_symlink_is_rejected_when_host_can_create_it() {
        use std::os::windows::fs::symlink_dir;
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let actual = root.path().join("actual");
        let linked = root.path().join("linked");
        fs::create_dir(&actual).expect("actual directory");
        fs::write(actual.join("source.lua"), "return true").expect("source");
        if symlink_dir(&actual, &linked).is_ok() {
            assert_eq!(
                LuaScript::new_safe_with_config(
                    "linked-directory",
                    linked.join("source.lua"),
                    root.path(),
                    &config,
                )
                .unwrap_err(),
                LuaRegistrationError::SymlinkRejected
            );
        }
    }

    #[tokio::test]
    async fn text_only_mode_rejects_lua_binary_signature() {
        let config = test_config();
        let (_root, script) = fixture_with_config(b"Lua", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        let result = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(result.error(), Some(LuaExecutionError::Syntax));
    }

    #[tokio::test]
    async fn disabled_and_pre_cancelled_scripts_fail_before_vm_execution() {
        let config = test_config();
        let (_root, script) = fixture("return true");
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        registry.set_enabled(&id, false).expect("disable");
        let disabled = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("execute");
        assert_eq!(disabled.error(), Some(LuaExecutionError::ScriptDisabled));

        registry.set_enabled(&id, true).expect("enable");
        let cancellation = LuaCancellationToken::new();
        cancellation.cancel();
        let cancelled = registry
            .execute_with_cancellation(&id, LuaContext::new("target"), cancellation)
            .await
            .expect("execute");
        assert_eq!(cancelled.error(), Some(LuaExecutionError::Cancelled));
    }

    #[test]
    fn execution_without_tokio_runtime_is_typed_and_releases_registry_state() {
        let config = test_config();
        let (_root, script) = fixture_with_config(b"return true", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");

        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let execution = registry.execute(&id, LuaContext::new("target"));
        let mut execution = std::pin::pin!(execution);
        let result = match std::future::Future::poll(execution.as_mut(), &mut context) {
            Poll::Ready(result) => result.expect("typed execution result"),
            Poll::Pending => panic!("no-runtime preflight must not suspend"),
        };

        assert_eq!(result.error(), Some(LuaExecutionError::HostFailure));
        assert_eq!(registry.get_history(&id).expect("history").len(), 1);
        registry
            .unregister(&id)
            .expect("no invocation lease was retained");
    }

    #[tokio::test]
    async fn history_is_entry_and_byte_bounded_and_newest_ordered() {
        let mut config = test_config();
        config.history_size = 2;
        config.max_history_bytes_per_script = 1_024;
        config.max_history_bytes_total = 1_024;
        let (_root, script) = fixture_with_config(b"return context.target", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        registry
            .execute(&id, LuaContext::new("one"))
            .await
            .expect("execute");
        registry.set_enabled(&id, false).expect("disable");
        registry
            .execute(&id, LuaContext::new("two"))
            .await
            .expect("execute");
        registry.set_enabled(&id, true).expect("enable");
        registry
            .execute(&id, LuaContext::new("three"))
            .await
            .expect("execute");
        let history = registry.get_history(&id).expect("history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].status(), LuaExecutionStatus::Rejected);
        assert_eq!(history[0].error(), Some(LuaExecutionError::ScriptDisabled));
        assert_eq!(history[1].status(), LuaExecutionStatus::Completed);
        let recent = registry.get_recent_history(&id, 1).expect("recent");
        assert_eq!(recent[0].status(), LuaExecutionStatus::Completed);
    }

    #[tokio::test]
    async fn history_receipts_never_retain_output_return_or_context() {
        let config = test_config();
        let (_root, script) =
            fixture_with_config(b"emit(context.target); return context.payload", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        let result = registry
            .execute(
                &id,
                LuaContext::new("output-secret").with_payload("return-secret"),
            )
            .await
            .expect("execute");
        assert_eq!(result.output(), "output-secret");
        let history = registry.get_history(&id).expect("history");
        let wire = serde_json::to_string(&history).expect("serialize receipt");
        assert!(!wire.contains("output-secret"));
        assert!(!wire.contains("return-secret"));
        assert_eq!(history[0].source_sha256(), result.source_sha256());
        assert_eq!(history[0].script_version(), result.script_version());
    }

    #[tokio::test]
    async fn global_history_byte_cap_evicts_the_stable_oldest_receipt() {
        let mut config = test_config();
        config.max_history_bytes_per_script = 512;
        config.max_history_bytes_total = 512;
        let root = tempfile::tempdir().expect("root");
        let first_path = root.path().join("first.lua");
        let second_path = root.path().join("second.lua");
        fs::write(&first_path, "return true").expect("first source");
        fs::write(&second_path, "return false").expect("second source");
        let first = LuaScript::new_safe_with_config("first", &first_path, root.path(), &config)
            .expect("first");
        let second = LuaScript::new_safe_with_config("second", &second_path, root.path(), &config)
            .expect("second");
        let first_id = first.id();
        let second_id = second.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(first).expect("first registration");
        registry.register(second).expect("second registration");

        registry
            .execute(&first_id, LuaContext::new("first"))
            .await
            .expect("first execution");
        registry
            .execute(&second_id, LuaContext::new("second"))
            .await
            .expect("second execution");

        assert!(registry
            .get_history(&first_id)
            .expect("first history")
            .is_empty());
        assert_eq!(
            registry
                .get_history(&second_id)
                .expect("second history")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn disabling_affects_new_calls_and_unregister_rejects_active_invocation() {
        let mut config = test_config();
        config.default_timeout_ms = 5_000;
        config.instruction_limit = 100_000_000;
        config.hook_interval = 100;
        let (_root, script) = fixture_with_config(b"while true do end", &config);
        let retained = script.clone();
        let id = script.id();
        let registry = Arc::new(LuaScriptRegistry::from_config(&config).expect("registry"));
        registry.register(script).expect("register");
        let cancellation = LuaCancellationToken::new();
        let worker_registry = Arc::clone(&registry);
        let worker_id = id.clone();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::spawn(async move {
            worker_registry
                .execute_with_cancellation(
                    &worker_id,
                    LuaContext::new("target"),
                    worker_cancellation,
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(registry.unregister(&id), Err(LuaRegistryError::ScriptInUse));
        registry.set_enabled(&id, false).expect("disable");
        let rejected = registry
            .execute(&id, LuaContext::new("target"))
            .await
            .expect("new invocation");
        assert_eq!(rejected.error(), Some(LuaExecutionError::ScriptDisabled));
        cancellation.cancel();
        let active = worker.await.expect("worker").expect("active invocation");
        assert_eq!(active.error(), Some(LuaExecutionError::Cancelled));
        registry.unregister(&id).expect("unregister after finish");
        registry
            .register(retained)
            .expect("same stable identity may register again");
        assert_eq!(registry.count(), Ok(1));
    }

    #[test]
    fn public_script_clones_cannot_mutate_registered_enabled_state() {
        let (_root, script) = fixture("return true");
        let disabled_clone = script.clone().with_enabled(false);
        assert!(script.manifest().enabled());
        assert!(!disabled_clone.manifest().enabled());
        let registry = LuaScriptRegistry::from_config(&test_config()).expect("registry");
        registry.register(script).expect("register");
        assert_eq!(registry.enabled_count(), Ok(1));
        let _ = disabled_clone.with_enabled(true);
        assert_eq!(registry.enabled_count(), Ok(1));
    }

    #[test]
    fn total_source_byte_capacity_is_accounted_and_released() {
        let mut config = test_config();
        config.max_source_bytes = 4;
        config.max_total_source_bytes = 6;
        let root = tempfile::tempdir().expect("root");
        let first_path = root.path().join("first.lua");
        let second_path = root.path().join("second.lua");
        fs::write(&first_path, "a=1\n").expect("source");
        fs::write(&second_path, "b=2\n").expect("source");
        let first = LuaScript::new_safe_with_config("first", &first_path, root.path(), &config)
            .expect("first");
        let second = LuaScript::new_safe_with_config("second", &second_path, root.path(), &config)
            .expect("second");
        let first_id = first.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(first).expect("register");
        assert_eq!(
            registry.register(second.clone()),
            Err(LuaRegistryError::TotalSourceCapacity)
        );
        registry.unregister(&first_id).expect("unregister");
        registry.register(second).expect("capacity released");
    }

    #[tokio::test]
    async fn checked_history_sequence_overflow_does_not_mutate_history() {
        let config = test_config();
        let (_root, script) = fixture_with_config(b"return true", &config);
        let id = script.id();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        registry
            .execute(&id, LuaContext::new("first"))
            .await
            .expect("first");
        let before = registry.get_history(&id).expect("history");
        registry.state.lock().expect("state").next_sequence = u64::MAX;
        assert!(matches!(
            registry.execute(&id, LuaContext::new("second")).await,
            Err(LuaRegistryError::HistorySequenceExhausted)
        ));
        let after = registry.get_history(&id).expect("history");
        assert_eq!(before, after);
    }

    #[test]
    fn terminal_control_precedence_is_sticky_then_cancel_then_deadline() {
        assert_eq!(
            terminal_control_error(Some(StickyAbort::Output), true, true),
            Some(LuaExecutionError::OutputLimit)
        );
        assert_eq!(
            terminal_control_error(None, true, true),
            Some(LuaExecutionError::Cancelled)
        );
        assert_eq!(
            terminal_control_error(None, false, true),
            Some(LuaExecutionError::DeadlineExceeded)
        );
        assert_eq!(terminal_control_error(None, false, false), None);
    }

    #[tokio::test]
    async fn fresh_vm_prevents_cross_run_global_state() {
        let first = run("state = 1; return state", LuaContext::new("target")).await;
        assert_eq!(first.error(), Some(LuaExecutionError::Runtime));
        let second = run("return state == nil", LuaContext::new("target")).await;
        assert_eq!(second.return_value(), Some(&LuaReturnValue::Boolean(true)));
    }

    #[test]
    fn manifests_are_inert_sorted_and_hide_source_path() {
        let config = test_config();
        let root = tempfile::tempdir().expect("root");
        let first_path = root.path().join("first.lua");
        let second_path = root.path().join("second.lua");
        fs::write(&first_path, "return true").expect("source");
        fs::write(&second_path, "return false").expect("source");
        let first = LuaScript::new_safe_with_config("zeta", &first_path, root.path(), &config)
            .expect("one");
        let second = LuaScript::new_safe_with_config("alpha", &second_path, root.path(), &config)
            .expect("two");
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(first).expect("register");
        registry.register(second).expect("register");
        let manifests = registry.list_all().expect("manifests");
        assert_eq!(manifests[0].name(), "alpha");
        let serialized = serde_json::to_string(&manifests).expect("serialize manifests");
        assert!(!serialized.contains(root.path().to_string_lossy().as_ref()));
        assert!(!serialized.contains("return true"));
    }

    #[test]
    fn registry_rejects_duplicate_identity_name_and_capacity() {
        let mut config = test_config();
        config.max_scripts = 2;
        let (root, script) = fixture_with_config(b"return true", &config);
        let duplicate = script.clone();
        let registry = LuaScriptRegistry::from_config(&config).expect("registry");
        registry.register(script).expect("register");
        assert_eq!(
            registry.register(duplicate),
            Err(LuaRegistryError::DuplicateId)
        );

        let same_name_path = root.path().join("same-name.lua");
        fs::write(&same_name_path, "return false").expect("source");
        let same_name =
            LuaScript::new_safe_with_config("fixture", &same_name_path, root.path(), &config)
                .expect("same name");
        assert_eq!(
            registry.register(same_name),
            Err(LuaRegistryError::DuplicateName)
        );

        let second_path = root.path().join("second.lua");
        let third_path = root.path().join("third.lua");
        fs::write(&second_path, "return 2").expect("source");
        fs::write(&third_path, "return 3").expect("source");
        let second = LuaScript::new_safe_with_config("second", &second_path, root.path(), &config)
            .expect("second");
        let third = LuaScript::new_safe_with_config("third", &third_path, root.path(), &config)
            .expect("third");
        registry.register(second).expect("second registration");
        assert_eq!(
            registry.register(third),
            Err(LuaRegistryError::ScriptCapacity)
        );
    }
}
