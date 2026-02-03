//! Extension protocol, policy, and runtime scaffolding.
//!
//! This module defines the versioned extension protocol and provides
//! validation utilities plus a minimal WASM host scaffold.

use crate::agent::AgentEvent;
use crate::error::{Error, Result};
use crate::session::SessionMessage;
use asupersync::Cx;
use asupersync::channel::{mpsc, oneshot};
use asupersync::time::{timeout, wall_now};
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "1.0";
pub const LOG_SCHEMA_VERSION: &str = "pi.ext.log.v1";

// ============================================================================
// Policy
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionPolicyMode {
    Strict,
    Prompt,
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionPolicy {
    pub mode: ExtensionPolicyMode,
    pub max_memory_mb: u32,
    pub default_caps: Vec<String>,
    pub deny_caps: Vec<String>,
}

impl Default for ExtensionPolicy {
    fn default() -> Self {
        Self {
            mode: ExtensionPolicyMode::Prompt,
            max_memory_mb: 256,
            default_caps: vec!["read".to_string(), "write".to_string(), "http".to_string()],
            deny_caps: vec!["exec".to_string(), "env".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Prompt,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub decision: PolicyDecision,
    pub capability: String,
    pub reason: String,
}

impl ExtensionPolicy {
    pub fn evaluate(&self, capability: &str) -> PolicyCheck {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return PolicyCheck {
                decision: PolicyDecision::Deny,
                capability: String::new(),
                reason: "empty_capability".to_string(),
            };
        }

        if self
            .deny_caps
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case(&normalized))
        {
            return PolicyCheck {
                decision: PolicyDecision::Deny,
                capability: normalized,
                reason: "deny_caps".to_string(),
            };
        }

        let in_default_caps = self
            .default_caps
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case(&normalized));

        match self.mode {
            ExtensionPolicyMode::Strict => PolicyCheck {
                decision: if in_default_caps {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny
                },
                capability: normalized,
                reason: if in_default_caps {
                    "default_caps".to_string()
                } else {
                    "not_in_default_caps".to_string()
                },
            },
            ExtensionPolicyMode::Prompt => PolicyCheck {
                decision: if in_default_caps {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Prompt
                },
                capability: normalized,
                reason: if in_default_caps {
                    "default_caps".to_string()
                } else {
                    "prompt_required".to_string()
                },
            },
            ExtensionPolicyMode::Permissive => PolicyCheck {
                decision: PolicyDecision::Allow,
                capability: normalized,
                reason: "permissive".to_string(),
            },
        }
    }
}

pub fn required_capability_for_host_call(call: &HostCallPayload) -> Option<String> {
    let method = call.method.trim().to_ascii_lowercase();
    if method.is_empty() {
        return None;
    }

    match method.as_str() {
        "fs" => {
            let op = call
                .params
                .get("op")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            let op = FsOp::parse(op)?;
            Some(op.required_capability().to_string())
        }
        "tool" => {
            let tool_name = call
                .params
                .get("name")
                .and_then(Value::as_str)
                .map(|name| name.trim().to_ascii_lowercase())?;
            if tool_name.is_empty() {
                return None;
            }
            match tool_name.as_str() {
                "read" | "grep" | "find" | "ls" => Some("read".to_string()),
                "write" | "edit" => Some("write".to_string()),
                "bash" => Some("exec".to_string()),
                _ => Some("tool".to_string()),
            }
        }
        "exec" => Some("exec".to_string()),
        "http" => Some("http".to_string()),
        "session" => Some("session".to_string()),
        "ui" => Some("ui".to_string()),
        "log" => Some("log".to_string()),
        _ => None,
    }
}

// ============================================================================
// Connectors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    Read,
    Write,
    List,
    Stat,
    Mkdir,
    Delete,
}

impl FsOp {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "list" | "readdir" => Some(Self::List),
            "stat" => Some(Self::Stat),
            "mkdir" => Some(Self::Mkdir),
            "delete" | "remove" | "rm" => Some(Self::Delete),
            _ => None,
        }
    }

    const fn required_capability(self) -> &'static str {
        match self {
            Self::Read | Self::List | Self::Stat => "read",
            Self::Write | Self::Mkdir | Self::Delete => "write",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsScopes {
    read_declared: bool,
    write_declared: bool,
    read_roots: Vec<PathBuf>,
    write_roots: Vec<PathBuf>,
}

impl FsScopes {
    pub fn for_cwd(cwd: &Path) -> Result<Self> {
        let root = canonicalize_root(cwd)?;
        Ok(Self {
            read_declared: true,
            write_declared: true,
            read_roots: vec![root.clone()],
            write_roots: vec![root],
        })
    }

    pub fn from_manifest(manifest: Option<&CapabilityManifest>, cwd: &Path) -> Result<Self> {
        let Some(manifest) = manifest else {
            return Self::for_cwd(cwd);
        };

        let mut read_declared = false;
        let mut write_declared = false;
        let mut read_roots = Vec::new();
        let mut write_roots = Vec::new();

        for req in &manifest.capabilities {
            let cap = req.capability.trim().to_ascii_lowercase();
            if cap != "read" && cap != "write" {
                continue;
            }
            if cap == "read" {
                read_declared = true;
            } else {
                write_declared = true;
            }
            let Some(scope) = &req.scope else {
                continue;
            };
            let Some(paths) = &scope.paths else {
                continue;
            };

            for raw in paths {
                let root = resolve_scoped_root(raw, cwd)?;
                if cap == "read" {
                    read_roots.push(root);
                } else {
                    write_roots.push(root);
                }
            }
        }

        let fallback = canonicalize_root(cwd)?;
        if read_declared && read_roots.is_empty() {
            read_roots.push(fallback.clone());
        }
        if write_declared && write_roots.is_empty() {
            write_roots.push(fallback);
        }

        Ok(Self {
            read_declared,
            write_declared,
            read_roots,
            write_roots,
        })
    }

    fn roots_for_capability(&self, capability: &str) -> &[PathBuf] {
        if capability.eq_ignore_ascii_case("read") {
            if self.read_declared {
                &self.read_roots
            } else {
                &[]
            }
        } else if self.write_declared {
            &self.write_roots
        } else {
            &[]
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsConnector {
    cwd: PathBuf,
    policy: ExtensionPolicy,
    scopes: FsScopes,
}

impl FsConnector {
    pub fn new(cwd: impl AsRef<Path>, policy: ExtensionPolicy, scopes: FsScopes) -> Result<Self> {
        let cwd = canonicalize_root(cwd.as_ref())?;
        Ok(Self {
            cwd,
            policy,
            scopes,
        })
    }

    pub fn handle_host_call(&self, call: &HostCallPayload) -> HostResultPayload {
        if !call.method.trim().eq_ignore_ascii_case("fs") {
            return HostResultPayload {
                call_id: call.call_id.clone(),
                output: json!({}),
                is_error: true,
                error: Some(HostCallError {
                    code: HostCallErrorCode::InvalidRequest,
                    message: "Unsupported hostcall method for FsConnector".to_string(),
                    details: Some(json!({ "method": call.method })),
                    retryable: None,
                }),
                chunk: None,
            };
        }

        let result = self.handle_fs_params(&call.params);
        match result {
            Ok(output) => HostResultPayload {
                call_id: call.call_id.clone(),
                output,
                is_error: false,
                error: None,
                chunk: None,
            },
            Err(error) => HostResultPayload {
                call_id: call.call_id.clone(),
                output: json!({}),
                is_error: true,
                error: Some(error),
                chunk: None,
            },
        }
    }

    fn handle_fs_params(&self, params: &Value) -> std::result::Result<Value, HostCallError> {
        let op = params
            .get("op")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let op = FsOp::parse(op).ok_or_else(|| HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Invalid fs op".to_string(),
            details: Some(json!({ "op": op })),
            retryable: None,
        })?;

        let capability = op.required_capability();
        let policy_check = self.policy.evaluate(capability);
        if policy_check.decision != PolicyDecision::Allow {
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Capability denied by policy".to_string(),
                details: Some(json!({
                    "capability": policy_check.capability,
                    "decision": format!("{:?}", policy_check.decision),
                    "reason": policy_check.reason,
                })),
                retryable: None,
            });
        }

        let roots = self.scopes.roots_for_capability(capability);
        if roots.is_empty() {
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "No allowed roots configured".to_string(),
                details: Some(json!({ "capability": capability })),
                retryable: None,
            });
        }

        let path_str = params
            .get("path")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or_else(|| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Missing fs path".to_string(),
                details: None,
                retryable: None,
            })?;

        let target = resolve_target_path(&self.cwd, path_str)?;

        let canonical_target = match op {
            FsOp::Read | FsOp::List | FsOp::Stat | FsOp::Delete => canonicalize_existing(&target),
            FsOp::Write | FsOp::Mkdir => canonicalize_for_create(&target),
        }?;

        let matched_root = roots.iter().find(|root| canonical_target.starts_with(root));

        if matched_root.is_none() {
            let root_hashes = roots.iter().map(|root| hash_path(root)).collect::<Vec<_>>();
            tracing::warn!(
                event = "ext.fs.denied",
                op = ?op,
                capability = capability,
                path_hash = %hash_path(&canonical_target),
                scope_roots = ?root_hashes,
                "Denied fs operation outside allowlist",
            );
            return Err(HostCallError {
                code: HostCallErrorCode::Denied,
                message: "Path outside allowed scope".to_string(),
                details: Some(json!({
                    "capability": capability,
                    "path_hash": hash_path(&canonical_target),
                    "scope_roots": root_hashes,
                })),
                retryable: None,
            });
        }

        let matched_root_hash = matched_root.map(|root| hash_path(root)).unwrap_or_default();
        tracing::info!(
            event = "ext.fs.call",
            op = ?op,
            capability = capability,
            path_hash = %hash_path(&canonical_target),
            scope_root = %matched_root_hash,
            "Executing fs operation",
        );

        match op {
            FsOp::Read => fs_op_read(params, &canonical_target),
            FsOp::Write => fs_op_write(params, &canonical_target),
            FsOp::List => fs_op_list(&canonical_target),
            FsOp::Stat => fs_op_stat(params, &canonical_target),
            FsOp::Mkdir => fs_op_mkdir(&canonical_target),
            FsOp::Delete => fs_op_delete(params, &canonical_target),
        }
    }
}

fn resolve_target_path(cwd: &Path, raw: &str) -> std::result::Result<PathBuf, HostCallError> {
    if raw.is_empty() {
        return Err(HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Path is empty".to_string(),
            details: None,
            retryable: None,
        });
    }

    let path = Path::new(raw);
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    })
}

fn canonicalize_root(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).map_err(|err| Error::extension(format!("canonicalize: {err}")))
}

fn resolve_scoped_root(raw: &str, cwd: &Path) -> Result<PathBuf> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::validation("Capability scope path is empty"));
    }

    let path = Path::new(raw);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    canonicalize_root(&resolved)
}

fn canonicalize_existing(path: &Path) -> std::result::Result<PathBuf, HostCallError> {
    std::fs::canonicalize(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("canonicalize: {err}"),
        details: Some(json!({ "path": path.display().to_string() })),
        retryable: None,
    })
}

fn canonicalize_for_create(path: &Path) -> std::result::Result<PathBuf, HostCallError> {
    // For non-existing paths, canonicalize the nearest existing ancestor and re-append suffix.
    let mut ancestor = path.to_path_buf();
    while !ancestor.exists() {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Path has no existing ancestor".to_string(),
                details: Some(json!({ "path": path.display().to_string() })),
                retryable: None,
            })?
            .to_path_buf();
    }

    let canonical_ancestor = std::fs::canonicalize(&ancestor).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("canonicalize: {err}"),
        details: Some(json!({ "path": ancestor.display().to_string() })),
        retryable: None,
    })?;

    let suffix = path.strip_prefix(&ancestor).map_err(|_| HostCallError {
        code: HostCallErrorCode::Internal,
        message: "Failed to compute path suffix".to_string(),
        details: Some(json!({
            "path": path.display().to_string(),
            "ancestor": ancestor.display().to_string(),
        })),
        retryable: None,
    })?;

    Ok(canonical_ancestor.join(suffix))
}

fn hash_path(path: &Path) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

fn fs_op_read(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let encoding = params
        .get("encoding")
        .and_then(Value::as_str)
        .map_or("utf8", str::trim);

    let bytes = fs::read(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("read: {err}"),
        details: None,
        retryable: None,
    })?;

    match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => {
            let text = String::from_utf8(bytes).map_err(|_| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "File is not valid UTF-8; use base64 encoding".to_string(),
                details: Some(json!({ "encoding": "base64" })),
                retryable: None,
            })?;
            Ok(json!({ "encoding": "utf8", "text": text }))
        }
        "base64" => {
            let data = base64::engine::general_purpose::STANDARD.encode(bytes);
            Ok(json!({ "encoding": "base64", "data": data }))
        }
        other => Err(HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Invalid encoding".to_string(),
            details: Some(json!({ "encoding": other })),
            retryable: None,
        }),
    }
}

fn fs_op_write(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let encoding = params
        .get("encoding")
        .and_then(Value::as_str)
        .map_or("utf8", str::trim);

    let data = params
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| HostCallError {
            code: HostCallErrorCode::InvalidRequest,
            message: "Missing write data".to_string(),
            details: None,
            retryable: None,
        })?;

    let bytes = match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" => data.as_bytes().to_vec(),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|err| HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: format!("Invalid base64: {err}"),
                details: None,
                retryable: None,
            })?,
        other => {
            return Err(HostCallError {
                code: HostCallErrorCode::InvalidRequest,
                message: "Invalid encoding".to_string(),
                details: Some(json!({ "encoding": other })),
                retryable: None,
            });
        }
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("mkdir parent: {err}"),
            details: None,
            retryable: None,
        })?;
    }

    fs::write(path, &bytes).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("write: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({ "bytes_written": bytes.len() }))
}

fn fs_op_list(path: &Path) -> std::result::Result<Value, HostCallError> {
    let read_dir = fs::read_dir(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("read_dir: {err}"),
        details: None,
        retryable: None,
    })?;

    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("read_dir entry: {err}"),
            details: None,
            retryable: None,
        })?;
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = fs::symlink_metadata(entry.path()).map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("metadata: {err}"),
            details: None,
            retryable: None,
        })?;
        let kind = if meta.file_type().is_symlink() {
            "symlink"
        } else if meta.is_dir() {
            "dir"
        } else if meta.is_file() {
            "file"
        } else {
            "other"
        };
        entries.push(json!({ "name": name, "kind": kind }));
    }

    Ok(json!({ "entries": entries }))
}

fn fs_op_stat(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let follow = params
        .get("follow_symlinks")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let meta = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    }
    .map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("stat: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({
        "is_file": meta.is_file(),
        "is_dir": meta.is_dir(),
        "len": meta.len(),
    }))
}

fn fs_op_mkdir(path: &Path) -> std::result::Result<Value, HostCallError> {
    fs::create_dir_all(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("mkdir: {err}"),
        details: None,
        retryable: None,
    })?;
    Ok(json!({ "created": true }))
}

fn fs_op_delete(params: &Value, path: &Path) -> std::result::Result<Value, HostCallError> {
    let recursive = params
        .get("recursive")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let meta = fs::symlink_metadata(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("stat: {err}"),
        details: None,
        retryable: None,
    })?;

    if meta.is_dir() && !meta.file_type().is_symlink() {
        if recursive {
            fs::remove_dir_all(path)
        } else {
            fs::remove_dir(path)
        }
        .map_err(|err| HostCallError {
            code: HostCallErrorCode::Io,
            message: format!("remove_dir: {err}"),
            details: None,
            retryable: None,
        })?;
        return Ok(json!({ "deleted": true, "kind": "dir" }));
    }

    fs::remove_file(path).map_err(|err| HostCallError {
        code: HostCallErrorCode::Io,
        message: format!("remove_file: {err}"),
        details: None,
        retryable: None,
    })?;

    Ok(json!({ "deleted": true, "kind": "file" }))
}

// ============================================================================
// Protocol (v1)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionMessage {
    pub id: String,
    pub version: String,
    #[serde(flatten)]
    pub body: ExtensionBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ExtensionBody {
    Register(RegisterPayload),
    ToolCall(ToolCallPayload),
    ToolResult(ToolResultPayload),
    SlashCommand(SlashCommandPayload),
    SlashResult(SlashResultPayload),
    EventHook(EventHookPayload),
    HostCall(HostCallPayload),
    HostResult(HostResultPayload),
    Log(Box<LogPayload>),
    Error(ErrorPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub version: String,
    pub api_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_manifest: Option<CapabilityManifest>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(default)]
    pub slash_commands: Vec<Value>,
    #[serde(default)]
    pub event_hooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub schema: String,
    pub capabilities: Vec<CapabilityRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub capability: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<CapabilityScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallPayload {
    pub call_id: String,
    pub name: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallPayload {
    pub call_id: String,
    pub capability: String,
    pub method: String,
    pub params: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostCallErrorCode {
    Timeout,
    Denied,
    Io,
    InvalidRequest,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallError {
    pub code: HostCallErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStreamChunk {
    pub index: u64,
    pub is_last: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backpressure: Option<HostStreamBackpressure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStreamBackpressure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResultPayload {
    pub call_id: String,
    pub output: Value,
    pub is_error: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<HostCallError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk: Option<HostStreamChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommandPayload {
    pub name: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashResultPayload {
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventHookPayload {
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogPayload {
    pub schema: String,
    pub ts: String,
    pub level: LogLevel,
    pub event: String,
    pub message: String,
    pub correlation: LogCorrelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<LogSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCorrelation {
    pub extension_id: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub component: LogComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogComponent {
    Capture,
    Harness,
    Runtime,
    Extension,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

// ============================================================================
// Extension UI + Session Bridge
// ============================================================================

/// Extension UI request payload (host -> UI surface).
#[derive(Debug, Clone)]
pub struct ExtensionUiRequest {
    pub id: String,
    pub method: String,
    pub payload: Value,
    pub timeout_ms: Option<u64>,
}

impl ExtensionUiRequest {
    pub fn new(id: impl Into<String>, method: impl Into<String>, payload: Value) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            payload,
            timeout_ms: None,
        }
    }

    pub fn expects_response(&self) -> bool {
        matches!(
            self.method.as_str(),
            "select" | "confirm" | "input" | "editor"
        )
    }

    pub fn effective_timeout_ms(&self) -> Option<u64> {
        self.timeout_ms.or_else(|| {
            self.payload
                .get("timeout")
                .and_then(serde_json::Value::as_u64)
        })
    }

    pub fn to_rpc_event(&self) -> Value {
        let mut map = serde_json::Map::new();
        map.insert(
            "type".to_string(),
            Value::String("extension_ui_request".to_string()),
        );
        map.insert("id".to_string(), Value::String(self.id.clone()));
        map.insert("method".to_string(), Value::String(self.method.clone()));

        match &self.payload {
            Value::Object(obj) => {
                for (key, value) in obj {
                    map.insert(key.clone(), value.clone());
                }
            }
            other => {
                map.insert("payload".to_string(), other.clone());
            }
        }

        Value::Object(map)
    }
}

/// Extension UI response payload (UI surface -> host).
#[derive(Debug, Clone)]
pub struct ExtensionUiResponse {
    pub id: String,
    pub value: Option<Value>,
    pub cancelled: bool,
}

/// Minimal session access for extensions (hostcalls).
#[async_trait]
pub trait ExtensionSession: Send + Sync {
    async fn get_state(&self) -> Value;
    async fn get_messages(&self) -> Vec<SessionMessage>;
    async fn set_name(&self, name: String) -> Result<()>;
}

impl ExtensionMessage {
    pub fn parse_and_validate(json: &str) -> Result<Self> {
        let msg: Self = serde_json::from_str(json)?;
        msg.validate()?;
        Ok(msg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(Error::validation("Extension message id is empty"));
        }
        if self.version != PROTOCOL_VERSION {
            return Err(Error::validation(format!(
                "Unsupported extension protocol version: {}",
                self.version
            )));
        }

        match &self.body {
            ExtensionBody::Register(payload) => validate_register(payload),
            ExtensionBody::ToolCall(payload) => validate_tool_call(payload),
            ExtensionBody::ToolResult(payload) => validate_tool_result(payload),
            ExtensionBody::SlashCommand(payload) => validate_slash_command(payload),
            ExtensionBody::SlashResult(_) => Ok(()),
            ExtensionBody::EventHook(payload) => validate_event_hook(payload),
            ExtensionBody::HostCall(payload) => validate_host_call(payload),
            ExtensionBody::HostResult(payload) => validate_host_result(payload),
            ExtensionBody::Log(payload) => validate_log(payload),
            ExtensionBody::Error(payload) => validate_error(payload),
        }
    }
}

fn validate_register(payload: &RegisterPayload) -> Result<()> {
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Extension name is empty"));
    }
    if payload.version.trim().is_empty() {
        return Err(Error::validation("Extension version is empty"));
    }
    if payload.api_version.trim().is_empty() {
        return Err(Error::validation("Extension api_version is empty"));
    }

    if let Some(manifest) = &payload.capability_manifest {
        if manifest.schema != "pi.ext.cap.v1" {
            return Err(Error::validation(format!(
                "Unsupported capability manifest schema: {}",
                manifest.schema
            )));
        }

        for req in &manifest.capabilities {
            if req.capability.trim().is_empty() {
                return Err(Error::validation(
                    "Capability manifest includes empty capability",
                ));
            }
        }
    }
    Ok(())
}

fn validate_tool_call(payload: &ToolCallPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Tool call_id is empty"));
    }
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Tool name is empty"));
    }
    Ok(())
}

fn validate_tool_result(payload: &ToolResultPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Tool result call_id is empty"));
    }
    Ok(())
}

fn validate_host_call(payload: &HostCallPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Host call_id is empty"));
    }

    if !payload.params.is_object() {
        return Err(Error::validation("Host call params must be an object"));
    }

    let declared_capability = payload.capability.trim().to_ascii_lowercase();
    if declared_capability.is_empty() {
        return Err(Error::validation("Host call capability is empty"));
    }

    if payload.method.trim().is_empty() {
        return Err(Error::validation("Host call method is empty"));
    }

    let required = required_capability_for_host_call(payload).ok_or_else(|| {
        Error::validation(format!(
            "Unknown or invalid host call method: {}",
            payload.method
        ))
    })?;

    if declared_capability != required {
        return Err(Error::validation(format!(
            "Host call capability mismatch: declared {declared_capability}, required {required}"
        )));
    }
    Ok(())
}

fn validate_host_result(payload: &HostResultPayload) -> Result<()> {
    if payload.call_id.trim().is_empty() {
        return Err(Error::validation("Host result call_id is empty"));
    }
    if !payload.output.is_object() {
        return Err(Error::validation("Host result output must be an object"));
    }
    if payload.is_error {
        if payload.error.is_none() {
            return Err(Error::validation(
                "Host result marked is_error=true but error payload is missing",
            ));
        }
    } else if payload.error.is_some() {
        return Err(Error::validation(
            "Host result includes error payload but is_error=false",
        ));
    }
    Ok(())
}

fn validate_slash_command(payload: &SlashCommandPayload) -> Result<()> {
    if payload.name.trim().is_empty() {
        return Err(Error::validation("Slash command name is empty"));
    }
    Ok(())
}

fn validate_event_hook(payload: &EventHookPayload) -> Result<()> {
    if payload.event.trim().is_empty() {
        return Err(Error::validation("Event hook name is empty"));
    }
    Ok(())
}

fn validate_log(payload: &LogPayload) -> Result<()> {
    if payload.schema != LOG_SCHEMA_VERSION {
        return Err(Error::validation(format!(
            "Unsupported log schema: {}",
            payload.schema
        )));
    }
    if payload.ts.trim().is_empty() {
        return Err(Error::validation("Log timestamp is empty"));
    }
    if payload.event.trim().is_empty() {
        return Err(Error::validation("Log event is empty"));
    }
    if payload.message.trim().is_empty() {
        return Err(Error::validation("Log message is empty"));
    }
    if payload.correlation.extension_id.trim().is_empty() {
        return Err(Error::validation("Log correlation extension_id is empty"));
    }
    if payload.correlation.scenario_id.trim().is_empty() {
        return Err(Error::validation("Log correlation scenario_id is empty"));
    }
    Ok(())
}

fn validate_error(payload: &ErrorPayload) -> Result<()> {
    if payload.code.trim().is_empty() {
        return Err(Error::validation("Error code is empty"));
    }
    if payload.message.trim().is_empty() {
        return Err(Error::validation("Error message is empty"));
    }
    Ok(())
}

// ============================================================================
// WASM Host Scaffold (minimal)
// ============================================================================

#[derive(Debug, Clone)]
pub struct WasmExtension {
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WasmExtensionHost {
    policy: ExtensionPolicy,
}

impl WasmExtensionHost {
    pub const fn new(policy: ExtensionPolicy) -> Self {
        Self { policy }
    }

    pub const fn policy(&self) -> &ExtensionPolicy {
        &self.policy
    }

    pub fn load_from_path(&self, path: &Path) -> Result<WasmExtension> {
        if !path.exists() {
            return Err(Error::validation(format!(
                "Extension artifact not found: {}",
                path.display()
            )));
        }
        Ok(WasmExtension {
            path: path.to_path_buf(),
        })
    }

    pub fn instantiate(&self, _extension: &WasmExtension) -> Result<()> {
        Err(Error::validation(
            "WASM host not enabled yet. Scaffold only.",
        ))
    }
}

// ============================================================================
// Extension Event System
// ============================================================================

/// Timeout for extension events in milliseconds.
pub const EXTENSION_EVENT_TIMEOUT_MS: u64 = 5000;

/// Event names for the extension lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionEventName {
    /// Input from the user.
    Input,
    /// Before the agent starts processing.
    BeforeAgentStart,
    /// Agent started processing.
    AgentStart,
    /// Agent ended processing.
    AgentEnd,
    /// Session before switch.
    SessionBeforeSwitch,
    /// Session switched.
    SessionSwitch,
    /// Session before fork.
    SessionBeforeFork,
    /// Session forked.
    SessionFork,
    /// Session before compact.
    SessionBeforeCompact,
    /// Session compacted.
    SessionCompact,
}

impl std::fmt::Display for ExtensionEventName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Input => "input",
            Self::BeforeAgentStart => "before_agent_start",
            Self::AgentStart => "agent_start",
            Self::AgentEnd => "agent_end",
            Self::SessionBeforeSwitch => "session_before_switch",
            Self::SessionSwitch => "session_switch",
            Self::SessionBeforeFork => "session_before_fork",
            Self::SessionFork => "session_fork",
            Self::SessionBeforeCompact => "session_before_compact",
            Self::SessionCompact => "session_compact",
        };
        write!(f, "{name}")
    }
}

/// Extension manager for handling loaded extensions.
#[derive(Clone)]
pub struct ExtensionManager {
    inner: Arc<Mutex<ExtensionManagerInner>>,
}

#[derive(Default)]
struct ExtensionManagerInner {
    extensions: Vec<RegisterPayload>,
    ui_sender: Option<mpsc::Sender<ExtensionUiRequest>>,
    pending_ui: HashMap<String, oneshot::Sender<ExtensionUiResponse>>,
    session: Option<Arc<dyn ExtensionSession>>,
}

impl std::fmt::Debug for ExtensionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionManager").finish_non_exhaustive()
    }
}

impl Default for ExtensionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionManager {
    /// Create a new extension manager.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExtensionManagerInner::default())),
        }
    }

    pub fn set_ui_sender(&self, sender: mpsc::Sender<ExtensionUiRequest>) {
        let mut guard = self.inner.lock().unwrap();
        guard.ui_sender = Some(sender);
    }

    pub fn set_session(&self, session: Arc<dyn ExtensionSession>) {
        let mut guard = self.inner.lock().unwrap();
        guard.session = Some(session);
    }

    pub fn register(&self, payload: RegisterPayload) {
        let mut guard = self.inner.lock().unwrap();
        guard.extensions.push(payload);
    }

    pub fn has_command(&self, name: &str) -> bool {
        let needle = normalize_command(name);
        let guard = self.inner.lock().unwrap();
        guard
            .extensions
            .iter()
            .flat_map(|ext| ext.slash_commands.iter())
            .filter_map(extract_slash_command_name)
            .any(|cmd| normalize_command(&cmd) == needle)
    }

    pub fn list_commands(&self) -> Vec<Value> {
        let guard = self.inner.lock().unwrap();
        let mut commands = Vec::new();

        for ext in &guard.extensions {
            for cmd in &ext.slash_commands {
                let Some(name) = extract_slash_command_name(cmd) else {
                    continue;
                };
                let description = cmd.get("description").and_then(Value::as_str);
                commands.push(json!({
                    "name": name,
                    "description": description,
                    "source": "extension",
                }));
            }
        }

        drop(guard);
        commands
    }

    pub async fn request_ui(
        &self,
        mut request: ExtensionUiRequest,
    ) -> Result<Option<ExtensionUiResponse>> {
        let cx = Cx::for_request();
        if request.id.trim().is_empty() {
            request.id = Uuid::new_v4().to_string();
        }

        let (ui_sender, expects_response) = {
            let guard = self.inner.lock().unwrap();
            (guard.ui_sender.clone(), request.expects_response())
        };

        let Some(ui_sender) = ui_sender else {
            return Err(Error::extension("Extension UI sender not configured"));
        };

        if !expects_response {
            ui_sender
                .send(&cx, request)
                .await
                .map_err(|_| Error::extension("Extension UI channel closed"))?;
            return Ok(None);
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.inner.lock().unwrap();
            guard.pending_ui.insert(request.id.clone(), tx);
        }

        if ui_sender.send(&cx, request.clone()).await.is_err() {
            self.inner.lock().unwrap().pending_ui.remove(&request.id);
            return Err(Error::extension("Extension UI channel closed"));
        }

        let response = if let Some(timeout_ms) = request.effective_timeout_ms() {
            match timeout(wall_now(), Duration::from_millis(timeout_ms), rx.recv(&cx)).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err(Error::extension("Extension UI response dropped")),
                Err(_) => Err(Error::extension("Extension UI request timed out")),
            }
        } else {
            rx.recv(&cx)
                .await
                .map_err(|_| Error::extension("Extension UI response dropped"))
        };

        match response {
            Ok(resp) => Ok(Some(resp)),
            Err(err) => {
                self.inner.lock().unwrap().pending_ui.remove(&request.id);
                Err(err)
            }
        }
    }

    pub fn respond_ui(&self, response: ExtensionUiResponse) -> bool {
        let cx = Cx::for_request();
        let tx = {
            let mut guard = self.inner.lock().unwrap();
            guard.pending_ui.remove(&response.id)
        };
        tx.is_some_and(|sender| sender.send(&cx, response).is_ok())
    }

    /// Dispatch an event to all registered extensions.
    pub async fn dispatch_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
    ) -> Result<()> {
        let _ = (event, data); // Stub - extension runtime not yet implemented
        Ok(())
    }

    /// Dispatch a cancellable event to all registered extensions.
    pub async fn dispatch_cancellable_event(
        &self,
        event: ExtensionEventName,
        data: Option<Value>,
        _timeout_ms: u64,
    ) -> Result<bool> {
        let _ = (event, data); // Stub - extension runtime not yet implemented
        Ok(false) // Not cancelled
    }
}

/// Extract extension event information from an agent event.
pub const fn extension_event_from_agent(
    event: &AgentEvent,
) -> Option<(ExtensionEventName, Option<Value>)> {
    match event {
        AgentEvent::AgentStart => Some((ExtensionEventName::AgentStart, None)),
        AgentEvent::AgentEnd { .. } => Some((ExtensionEventName::AgentEnd, None)),
        _ => None,
    }
}

fn extract_slash_command_name(value: &Value) -> Option<String> {
    value
        .get("name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn normalize_command(name: &str) -> String {
    name.trim_start_matches('/').trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::Validator;
    use tempfile::tempdir;

    fn compiled_extension_protocol_schema() -> Validator {
        let schema_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs/schema/extension_protocol.json");
        let raw = std::fs::read_to_string(&schema_path)
            .map_err(|err| {
                format!(
                    "Failed to read extension protocol schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap();
        let schema: Value = serde_json::from_str(&raw)
            .map_err(|err| {
                format!(
                    "Failed to parse extension protocol schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap();

        jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|err| {
                format!(
                    "Failed to compile JSON schema {}: {err}",
                    schema_path.display()
                )
            })
            .unwrap()
    }

    #[allow(clippy::too_many_lines)]
    fn sample_protocol_messages() -> Vec<(&'static str, ExtensionMessage)> {
        vec![
            (
                "register",
                ExtensionMessage {
                    id: "msg-register".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Register(RegisterPayload {
                        name: "demo".to_string(),
                        version: "0.1.0".to_string(),
                        api_version: "1.0".to_string(),
                        capabilities: vec!["read".to_string()],
                        capability_manifest: None,
                        tools: Vec::new(),
                        slash_commands: Vec::new(),
                        event_hooks: Vec::new(),
                    }),
                },
            ),
            (
                "tool_call",
                ExtensionMessage {
                    id: "msg-tool-call".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::ToolCall(ToolCallPayload {
                        call_id: "call-1".to_string(),
                        name: "read".to_string(),
                        input: json!({ "path": "README.md" }),
                        context: None,
                    }),
                },
            ),
            (
                "tool_result",
                ExtensionMessage {
                    id: "msg-tool-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::ToolResult(ToolResultPayload {
                        call_id: "call-1".to_string(),
                        output: json!({ "ok": true }),
                        is_error: false,
                    }),
                },
            ),
            (
                "slash_command",
                ExtensionMessage {
                    id: "msg-slash-command".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::SlashCommand(SlashCommandPayload {
                        name: "/hello".to_string(),
                        args: vec!["world".to_string()],
                        input: None,
                    }),
                },
            ),
            (
                "slash_result",
                ExtensionMessage {
                    id: "msg-slash-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::SlashResult(SlashResultPayload {
                        output: json!({ "text": "ok" }),
                        is_error: false,
                    }),
                },
            ),
            (
                "event_hook",
                ExtensionMessage {
                    id: "msg-event-hook".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::EventHook(EventHookPayload {
                        event: "agent_start".to_string(),
                        data: Some(json!({ "note": "hello" })),
                    }),
                },
            ),
            (
                "host_call",
                ExtensionMessage {
                    id: "msg-host-call".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostCall(HostCallPayload {
                        call_id: "host-1".to_string(),
                        capability: "read".to_string(),
                        method: "tool".to_string(),
                        params: json!({ "name": "read", "input": { "path": "README.md" } }),
                        timeout_ms: Some(2500),
                        cancel_token: None,
                        context: None,
                    }),
                },
            ),
            (
                "host_result",
                ExtensionMessage {
                    id: "msg-host-result".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::HostResult(HostResultPayload {
                        call_id: "host-1".to_string(),
                        output: json!({ "content": [] }),
                        is_error: false,
                        error: None,
                        chunk: None,
                    }),
                },
            ),
            (
                "log",
                ExtensionMessage {
                    id: "msg-log".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Log(Box::new(LogPayload {
                        schema: LOG_SCHEMA_VERSION.to_string(),
                        ts: "2026-02-03T03:01:02.123Z".to_string(),
                        level: LogLevel::Info,
                        event: "tool_call.start".to_string(),
                        message: "tool call dispatched".to_string(),
                        correlation: LogCorrelation {
                            extension_id: "ext.demo".to_string(),
                            scenario_id: "scn-001".to_string(),
                            session_id: None,
                            run_id: None,
                            artifact_id: None,
                            tool_call_id: None,
                            slash_command_id: None,
                            event_id: None,
                            host_call_id: None,
                            rpc_id: None,
                            trace_id: None,
                            span_id: None,
                        },
                        source: None,
                        data: None,
                    })),
                },
            ),
            (
                "error",
                ExtensionMessage {
                    id: "msg-error".to_string(),
                    version: PROTOCOL_VERSION.to_string(),
                    body: ExtensionBody::Error(ErrorPayload {
                        code: "E_DEMO".to_string(),
                        message: "Something went wrong".to_string(),
                        details: Some(json!({ "hint": "check config" })),
                    }),
                },
            ),
        ]
    }

    #[test]
    fn parse_register_message() {
        let json = r#"
        {
          "id": "msg-1",
          "version": "1.0",
          "type": "register",
          "payload": {
            "name": "demo",
            "version": "0.1.0",
            "api_version": "1.0",
            "capabilities": ["read"]
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::Register(_)));
    }

    #[test]
    fn reject_invalid_version() {
        let json = r#"
        {
          "id": "msg-2",
          "version": "2.0",
          "type": "log",
          "payload": {
            "schema": "pi.ext.log.v1",
            "ts": "2026-02-03T03:01:02.123Z",
            "level": "info",
            "event": "tool_call.start",
            "message": "hi",
            "correlation": {
              "extension_id": "ext.demo",
              "scenario_id": "scn-001"
            }
          }
        }
        "#;
        let err = ExtensionMessage::parse_and_validate(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Unsupported extension protocol version"));
    }

    #[test]
    fn parse_host_call_message() {
        let json = r#"
        {
          "id": "msg-3",
          "version": "1.0",
          "type": "host_call",
          "payload": {
            "call_id": "call-1",
            "capability": "read",
            "method": "tool",
            "params": { "name": "read", "input": { "path": "README.md" } },
            "timeout_ms": 1000
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::HostCall(_)));
    }

    #[test]
    fn parse_log_message() {
        let json = r#"
        {
          "id": "msg-4",
          "version": "1.0",
          "type": "log",
          "payload": {
            "schema": "pi.ext.log.v1",
            "ts": "2026-02-03T03:01:02.123Z",
            "level": "info",
            "event": "tool_call.start",
            "message": "tool call dispatched",
            "correlation": {
              "extension_id": "ext.demo",
              "scenario_id": "scn-001"
            }
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::Log(_)));
    }

    #[test]
    fn extension_ui_rpc_event_format() {
        let request = ExtensionUiRequest::new(
            "req-1",
            "notify",
            json!({ "title": "Hello", "message": "World" }),
        );
        let event = request.to_rpc_event();
        assert_eq!(event["type"], "extension_ui_request");
        assert_eq!(event["id"], "req-1");
        assert_eq!(event["method"], "notify");
        assert_eq!(event["title"], "Hello");
        assert_eq!(event["message"], "World");
    }

    #[test]
    fn extension_ui_request_roundtrip() {
        let manager = ExtensionManager::new();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let handle = runtime.handle();

        runtime.block_on(async move {
            let (ui_tx, ui_rx) = mpsc::channel(16);
            manager.set_ui_sender(ui_tx);

            let responder = manager.clone();
            handle.spawn(async move {
                let cx = Cx::for_request();
                if let Ok(req) = ui_rx.recv(&cx).await {
                    responder.respond_ui(ExtensionUiResponse {
                        id: req.id,
                        value: Some(json!(true)),
                        cancelled: false,
                    });
                }
            });

            let request = ExtensionUiRequest::new("", "confirm", json!({ "title": "Confirm" }));
            let response = manager.request_ui(request).await.unwrap();
            assert_eq!(response.unwrap().value, Some(json!(true)));
        });
    }

    #[test]
    fn extension_protocol_schema_accepts_all_variants() {
        let schema = compiled_extension_protocol_schema();
        for (label, message) in sample_protocol_messages() {
            let instance = serde_json::to_value(&message)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();

            let errors = schema
                .iter_errors(&instance)
                .map(|err| err.to_string())
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "{label}: schema validation failed:\n{}",
                errors.join("\n")
            );

            let json = serde_json::to_string(&message)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();
            let parsed = ExtensionMessage::parse_and_validate(&json)
                .map_err(|err| format!("{label}: parse_and_validate failed: {err}"))
                .unwrap();
            let parsed_json = serde_json::to_value(&parsed)
                .map_err(|err| format!("{label}: {err}"))
                .unwrap();
            assert_eq!(
                instance, parsed_json,
                "{label}: JSON changed after roundtrip"
            );
        }
    }

    #[test]
    fn extension_protocol_schema_rejects_missing_required_fields() {
        let schema = compiled_extension_protocol_schema();

        let (_, message) = sample_protocol_messages()
            .into_iter()
            .find(|(label, _)| *label == "register")
            .expect("register sample");
        let mut instance = serde_json::to_value(&message).expect("serialize");

        // Missing "id"
        instance
            .as_object_mut()
            .expect("object")
            .remove("id")
            .expect("id present");
        assert!(
            schema.validate(&instance).is_err(),
            "schema should reject missing id"
        );
    }

    #[test]
    fn parse_and_validate_rejects_unknown_type() {
        let json = r#"
        {
          "id": "msg-unknown",
          "version": "1.0",
          "type": "not_a_real_type",
          "payload": { "x": 1 }
        }
        "#;
        assert!(ExtensionMessage::parse_and_validate(json).is_err());
    }

    #[test]
    fn parse_fs_host_call_message() {
        let json = r#"
        {
          "id": "msg-fs",
          "version": "1.0",
          "type": "host_call",
          "payload": {
            "call_id": "call-1",
            "capability": "read",
            "method": "fs",
            "params": { "op": "read", "path": "README.md" }
          }
        }
        "#;
        let msg = ExtensionMessage::parse_and_validate(json).unwrap();
        assert!(matches!(msg.body, ExtensionBody::HostCall(_)));
    }

    #[test]
    fn fs_connector_denies_path_traversal_outside_cwd() {
        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let inside = project.join("inside.txt");
        std::fs::write(&inside, "hello").expect("write inside");

        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "secret").expect("write outside");

        let policy = ExtensionPolicy::default();
        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(project, policy, scopes).expect("connector");

        let ok_call = HostCallPayload {
            call_id: "call-ok".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "inside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let ok_result = connector.handle_host_call(&ok_call);
        assert!(!ok_result.is_error);

        let denied_call = HostCallPayload {
            call_id: "call-deny".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "../outside.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let denied = connector.handle_host_call(&denied_call);
        assert!(denied.is_error);
        assert_eq!(
            denied.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }

    #[cfg(unix)]
    #[test]
    fn fs_connector_denies_symlink_escape() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).expect("create project dir");

        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, "secret").expect("write outside");

        let link = project.join("link.txt");
        symlink(&outside, &link).expect("symlink");

        let policy = ExtensionPolicy::default();
        let scopes = FsScopes::for_cwd(&project).expect("scopes");
        let connector = FsConnector::new(project, policy, scopes).expect("connector");

        let call = HostCallPayload {
            call_id: "call-link".to_string(),
            capability: "read".to_string(),
            method: "fs".to_string(),
            params: json!({ "op": "read", "path": "link.txt" }),
            timeout_ms: None,
            cancel_token: None,
            context: None,
        };
        let result = connector.handle_host_call(&call);
        assert!(result.is_error);
        assert_eq!(
            result.error.as_ref().expect("error").code,
            HostCallErrorCode::Denied
        );
    }
}
