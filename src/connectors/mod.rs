//! Connectors for extension hostcalls.
//!
//! Connectors provide capability-gated access to host resources (HTTP, filesystem, etc.)
//! for extensions. Each connector validates requests against policy before execution.
//!
//! Types are defined locally to avoid coupling with the extensions module.

pub mod http;

use crate::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ============================================================================
// Hostcall protocol types (defined locally to avoid coupling with extensions)
// ============================================================================

/// Hostcall request payload from extension.
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

/// Error codes for hostcall failures.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostCallErrorCode {
    Timeout,
    Denied,
    Io,
    InvalidRequest,
    Internal,
}

/// Structured error information for hostcall failures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallError {
    pub code: HostCallErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

/// Optional streaming chunk metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostStreamChunk {
    pub index: u64,
    pub is_last: bool,
}

/// Hostcall result payload returned to extension.
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

/// Trait for connectors that handle hostcalls from extensions.
#[async_trait]
pub trait Connector: Send + Sync {
    /// The capability name this connector handles (e.g., "http", "fs").
    fn capability(&self) -> &'static str;

    /// Dispatch a hostcall to this connector.
    ///
    /// Returns `HostResultPayload` with either success output or error details.
    async fn dispatch(&self, call: &HostCallPayload) -> Result<HostResultPayload>;
}

/// Helper to create a successful host result.
pub fn host_result_ok(call_id: &str, output: Value) -> HostResultPayload {
    HostResultPayload {
        call_id: call_id.to_string(),
        output,
        is_error: false,
        error: None,
        chunk: None,
    }
}

/// Helper to create an error host result.
pub fn host_result_err(
    call_id: &str,
    code: HostCallErrorCode,
    message: impl Into<String>,
    retryable: Option<bool>,
) -> HostResultPayload {
    HostResultPayload {
        call_id: call_id.to_string(),
        output: Value::Null,
        is_error: true,
        error: Some(HostCallError {
            code,
            message: message.into(),
            details: None,
            retryable,
        }),
        chunk: None,
    }
}

/// Helper to create an error host result with details.
pub fn host_result_err_with_details(
    call_id: &str,
    code: HostCallErrorCode,
    message: impl Into<String>,
    details: Value,
    retryable: Option<bool>,
) -> HostResultPayload {
    HostResultPayload {
        call_id: call_id.to_string(),
        output: Value::Null,
        is_error: true,
        error: Some(HostCallError {
            code,
            message: message.into(),
            details: Some(details),
            retryable,
        }),
        chunk: None,
    }
}
