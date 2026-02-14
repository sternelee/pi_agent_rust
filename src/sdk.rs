//! Stable SDK-facing API surface for embedding Pi as a library.
//!
//! This module is the supported entry point for external library consumers.
//! Prefer importing from `pi::sdk` instead of deep internal modules.
//!
//! # Examples
//!
//! ```rust
//! use pi::sdk::{AgentEvent, Message, ToolDefinition};
//!
//! let _events: Vec<AgentEvent> = Vec::new();
//! let _messages: Vec<Message> = Vec::new();
//! let _tools: Vec<ToolDefinition> = Vec::new();
//! ```
//!
//! Internal implementation types are intentionally not part of this surface.
//!
//! ```compile_fail
//! use pi::sdk::RpcSharedState;
//! ```

pub use crate::agent::{
    AbortHandle, AbortSignal, Agent, AgentConfig, AgentEvent, AgentSession, QueueMode,
};
pub use crate::config::Config;
pub use crate::error::{Error, Result};
pub use crate::model::{
    AssistantMessage, ContentBlock, Cost, CustomMessage, ImageContent, Message, StopReason,
    StreamEvent, TextContent, ThinkingContent, ToolCall, ToolResultMessage, Usage, UserContent,
    UserMessage,
};
pub use crate::models::{ModelEntry, ModelRegistry};
pub use crate::provider::{
    Context as ProviderContext, InputType, Model, ModelCost, Provider, StreamOptions,
    ThinkingBudgets as ProviderThinkingBudgets, ToolDef,
};
pub use crate::session::Session;
pub use crate::tools::{Tool, ToolOutput, ToolRegistry, ToolUpdate};

/// Stable alias for model-exposed tool schema definitions.
pub type ToolDefinition = ToolDef;
