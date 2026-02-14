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

use crate::app;
use crate::auth::AuthStorage;
use crate::cli::Cli;
use crate::compaction::ResolvedCompactionSettings;
use crate::models::default_models_path;
use crate::provider::ThinkingBudgets;
use crate::providers;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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

/// SDK session construction options.
///
/// These options provide the programmatic equivalent of the core CLI startup
/// path used in `src/main.rs`.
#[derive(Clone)]
pub struct SessionOptions {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub api_key: Option<String>,
    pub thinking: Option<crate::model::ThinkingLevel>,
    pub system_prompt: Option<String>,
    pub append_system_prompt: Option<String>,
    pub enabled_tools: Option<Vec<String>>,
    pub working_directory: Option<PathBuf>,
    pub no_session: bool,
    pub session_path: Option<PathBuf>,
    pub session_dir: Option<PathBuf>,
    pub extension_paths: Vec<PathBuf>,
    pub extension_policy: Option<String>,
    pub repair_policy: Option<String>,
    pub max_tool_iterations: usize,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            provider: None,
            model: None,
            api_key: None,
            thinking: None,
            system_prompt: None,
            append_system_prompt: None,
            enabled_tools: None,
            working_directory: None,
            no_session: true,
            session_path: None,
            session_dir: None,
            extension_paths: Vec::new(),
            extension_policy: None,
            repair_policy: None,
            max_tool_iterations: 50,
        }
    }
}

/// Lightweight handle for programmatic embedding.
///
/// This wraps `AgentSession` and exposes high-level request methods while still
/// allowing access to the underlying session when needed.
pub struct AgentSessionHandle {
    session: AgentSession,
}

/// Snapshot of the current agent session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionState {
    pub session_id: Option<String>,
    pub provider: String,
    pub model_id: String,
    pub thinking_level: Option<crate::model::ThinkingLevel>,
    pub save_enabled: bool,
    pub message_count: usize,
}

impl AgentSessionHandle {
    /// Send one user prompt through the agent loop.
    pub async fn prompt(
        &mut self,
        input: impl Into<String>,
        on_event: impl Fn(AgentEvent) + Send + Sync + 'static,
    ) -> Result<AssistantMessage> {
        self.session.run_text(input.into(), on_event).await
    }

    /// Send one user prompt through the agent loop with an explicit abort signal.
    pub async fn prompt_with_abort(
        &mut self,
        input: impl Into<String>,
        abort_signal: AbortSignal,
        on_event: impl Fn(AgentEvent) + Send + Sync + 'static,
    ) -> Result<AssistantMessage> {
        self.session
            .run_text_with_abort(input.into(), Some(abort_signal), on_event)
            .await
    }

    /// Create a new abort handle/signal pair for prompt cancellation.
    pub fn new_abort_handle() -> (AbortHandle, AbortSignal) {
        AbortHandle::new()
    }

    /// Return the active provider/model pair.
    pub fn model(&self) -> (String, String) {
        let provider = self.session.agent.provider();
        (provider.name().to_string(), provider.model_id().to_string())
    }

    /// Update the active provider/model pair and persist it to session metadata.
    pub async fn set_model(&mut self, provider: &str, model_id: &str) -> Result<()> {
        self.session.set_provider_model(provider, model_id).await
    }

    /// Return the currently configured thinking level.
    pub const fn thinking_level(&self) -> Option<crate::model::ThinkingLevel> {
        self.session.agent.stream_options().thinking_level
    }

    /// Alias for thinking level access, matching the SDK naming style.
    pub const fn thinking(&self) -> Option<crate::model::ThinkingLevel> {
        self.thinking_level()
    }

    /// Update thinking level and persist it to session metadata.
    pub async fn set_thinking_level(&mut self, level: crate::model::ThinkingLevel) -> Result<()> {
        let level_string = level.to_string();
        let cx = crate::agent_cx::AgentCx::for_request();
        {
            let mut guard = self
                .session
                .session
                .lock(cx.cx())
                .await
                .map_err(|e| Error::session(e.to_string()))?;
            guard.set_model_header(None, None, Some(level_string.clone()));
            guard.append_thinking_level_change(level_string);
        }
        self.session.agent.stream_options_mut().thinking_level = Some(level);
        self.session.persist_session().await
    }

    /// Return all model messages for the current session path.
    pub async fn messages(&self) -> Result<Vec<Message>> {
        let cx = crate::agent_cx::AgentCx::for_request();
        let guard = self
            .session
            .session
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(e.to_string()))?;
        Ok(guard.to_messages_for_current_path())
    }

    /// Return a lightweight state snapshot.
    pub async fn state(&self) -> Result<AgentSessionState> {
        let (provider, model_id) = self.model();
        let thinking_level = self.thinking_level();
        let save_enabled = self.session.save_enabled();
        let cx = crate::agent_cx::AgentCx::for_request();
        let guard = self
            .session
            .session
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(e.to_string()))?;
        let session_id = Some(guard.header.id.clone());
        let message_count = guard.to_messages_for_current_path().len();

        Ok(AgentSessionState {
            session_id,
            provider,
            model_id,
            thinking_level,
            save_enabled,
            message_count,
        })
    }

    /// Trigger an immediate compaction pass (if compaction is enabled).
    pub async fn compact(
        &mut self,
        on_event: impl Fn(AgentEvent) + Send + Sync + 'static,
    ) -> Result<()> {
        self.session.compact_now(on_event).await
    }

    /// Access the underlying `AgentSession`.
    pub const fn session(&self) -> &AgentSession {
        &self.session
    }

    /// Mutable access to the underlying `AgentSession`.
    pub const fn session_mut(&mut self) -> &mut AgentSession {
        &mut self.session
    }

    /// Consume the handle and return the inner `AgentSession`.
    pub fn into_inner(self) -> AgentSession {
        self.session
    }
}

fn resolve_path_for_cwd(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn build_stream_options_with_optional_key(
    config: &Config,
    api_key: Option<String>,
    selection: &app::ModelSelection,
    session: &Session,
) -> StreamOptions {
    let mut options = StreamOptions {
        api_key,
        headers: selection.model_entry.headers.clone(),
        session_id: Some(session.header.id.clone()),
        thinking_level: Some(selection.thinking_level),
        ..Default::default()
    };

    if let Some(budgets) = &config.thinking_budgets {
        let defaults = ThinkingBudgets::default();
        options.thinking_budgets = Some(ThinkingBudgets {
            minimal: budgets.minimal.unwrap_or(defaults.minimal),
            low: budgets.low.unwrap_or(defaults.low),
            medium: budgets.medium.unwrap_or(defaults.medium),
            high: budgets.high.unwrap_or(defaults.high),
            xhigh: budgets.xhigh.unwrap_or(defaults.xhigh),
        });
    }

    options
}

/// Create a fully configured embeddable agent session.
///
/// This is the programmatic entrypoint for non-CLI consumers that want to run
/// Pi sessions in-process.
#[allow(clippy::too_many_lines)]
pub async fn create_agent_session(options: SessionOptions) -> Result<AgentSessionHandle> {
    let process_cwd =
        std::env::current_dir().map_err(|e| Error::config(format!("cwd lookup failed: {e}")))?;
    let cwd = options.working_directory.as_deref().map_or_else(
        || process_cwd.clone(),
        |path| resolve_path_for_cwd(path, &process_cwd),
    );

    let mut cli = Cli::try_parse_from(["pi"])
        .map_err(|e| Error::validation(format!("CLI init failed: {e}")))?;
    cli.no_session = options.no_session;
    cli.provider = options.provider.clone();
    cli.model = options.model.clone();
    cli.api_key = options.api_key.clone();
    cli.system_prompt = options.system_prompt.clone();
    cli.append_system_prompt = options.append_system_prompt.clone();
    cli.thinking = options.thinking.map(|t| t.to_string());
    cli.session = options
        .session_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    cli.session_dir = options
        .session_dir
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    if let Some(enabled_tools) = &options.enabled_tools {
        if enabled_tools.is_empty() {
            cli.no_tools = true;
        } else {
            cli.no_tools = false;
            cli.tools = enabled_tools.join(",");
        }
    }

    let config = Config::load()?;

    let mut auth = AuthStorage::load_async(Config::auth_path()).await?;
    auth.refresh_expired_oauth_tokens().await?;

    let global_dir = Config::global_dir();
    let package_dir = Config::package_dir();
    let models_path = default_models_path(&global_dir);
    let model_registry = ModelRegistry::load(&auth, Some(models_path));

    let mut session = Session::new(&cli, &config).await?;
    let scoped_patterns = if let Some(models_arg) = &cli.models {
        app::parse_models_arg(models_arg)
    } else {
        config.enabled_models.clone().unwrap_or_default()
    };
    let scoped_models = if scoped_patterns.is_empty() {
        Vec::new()
    } else {
        app::resolve_model_scope(&scoped_patterns, &model_registry, cli.api_key.is_some())
    };

    let selection = app::select_model_and_thinking(
        &cli,
        &config,
        &session,
        &model_registry,
        &scoped_models,
        &global_dir,
    )
    .map_err(|err| Error::validation(err.to_string()))?;
    app::update_session_for_selection(&mut session, &selection);

    let enabled_tools_owned = cli
        .enabled_tools()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let enabled_tools = enabled_tools_owned
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();

    let system_prompt = app::build_system_prompt(
        &cli,
        &cwd,
        &enabled_tools,
        None,
        &global_dir,
        &package_dir,
        std::env::var_os("PI_TEST_MODE").is_some(),
    );

    let provider = providers::create_provider(&selection.model_entry, None)
        .map_err(|e| Error::provider("sdk", e.to_string()))?;

    let api_key = auth
        .resolve_api_key(
            &selection.model_entry.model.provider,
            cli.api_key.as_deref(),
        )
        .or_else(|| selection.model_entry.api_key.clone());

    let stream_options =
        build_stream_options_with_optional_key(&config, api_key, &selection, &session);

    let agent_config = AgentConfig {
        system_prompt: Some(system_prompt),
        max_tool_iterations: options.max_tool_iterations,
        stream_options,
    };

    let tools = ToolRegistry::new(&enabled_tools, &cwd, Some(&config));
    let session_arc = Arc::new(asupersync::sync::Mutex::new(session));

    let context_window_tokens = if selection.model_entry.model.context_window == 0 {
        ResolvedCompactionSettings::default().context_window_tokens
    } else {
        selection.model_entry.model.context_window
    };
    let compaction_settings = ResolvedCompactionSettings {
        enabled: config.compaction_enabled(),
        reserve_tokens: config.compaction_reserve_tokens(),
        keep_recent_tokens: config.compaction_keep_recent_tokens(),
        context_window_tokens,
    };

    let mut agent_session = AgentSession::new(
        Agent::new(provider, tools, agent_config),
        Arc::clone(&session_arc),
        !cli.no_session,
        compaction_settings,
    );

    if !options.extension_paths.is_empty() {
        let extension_paths = options
            .extension_paths
            .iter()
            .map(|path| resolve_path_for_cwd(path, &cwd))
            .collect::<Vec<_>>();
        let resolved_ext_policy =
            config.resolve_extension_policy_with_metadata(options.extension_policy.as_deref());
        let resolved_repair_policy =
            config.resolve_repair_policy_with_metadata(options.repair_policy.as_deref());

        agent_session
            .enable_extensions_with_policy(
                &enabled_tools,
                &cwd,
                Some(&config),
                &extension_paths,
                Some(resolved_ext_policy.policy),
                Some(resolved_repair_policy.effective_mode),
            )
            .await?;
    }

    agent_session.set_model_registry(model_registry);
    agent_session.set_auth_storage(auth);

    let history = {
        let cx = crate::agent_cx::AgentCx::for_request();
        let guard = session_arc
            .lock(cx.cx())
            .await
            .map_err(|e| Error::session(e.to_string()))?;
        guard.to_messages_for_current_path()
    };
    if !history.is_empty() {
        agent_session.agent.replace_messages(history);
    }

    Ok(AgentSessionHandle {
        session: agent_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::runtime::reactor::create_reactor;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn run_async<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        let reactor = create_reactor().expect("create reactor");
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("build runtime");
        runtime.block_on(future)
    }

    #[test]
    fn create_agent_session_default_succeeds() {
        let tmp = tempdir().expect("tempdir");
        let options = SessionOptions {
            working_directory: Some(tmp.path().to_path_buf()),
            no_session: true,
            ..SessionOptions::default()
        };

        let handle = run_async(create_agent_session(options)).expect("create session");
        let provider = handle.session().agent.provider();
        assert_eq!(provider.name(), "anthropic");
        assert_eq!(provider.model_id(), "claude-sonnet-4-20250514");
    }

    #[test]
    fn create_agent_session_respects_provider_model_and_thinking() {
        let tmp = tempdir().expect("tempdir");
        let options = SessionOptions {
            provider: Some("openai".to_string()),
            model: Some("gpt-4o".to_string()),
            thinking: Some(crate::model::ThinkingLevel::Low),
            working_directory: Some(tmp.path().to_path_buf()),
            no_session: true,
            ..SessionOptions::default()
        };

        let handle = run_async(create_agent_session(options)).expect("create session");
        let provider = handle.session().agent.provider();
        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.model_id(), "gpt-4o");
        assert_eq!(
            handle.session().agent.stream_options().thinking_level,
            Some(crate::model::ThinkingLevel::Low)
        );
    }

    #[test]
    fn create_agent_session_no_session_keeps_ephemeral_state() {
        let tmp = tempdir().expect("tempdir");
        let options = SessionOptions {
            working_directory: Some(tmp.path().to_path_buf()),
            no_session: true,
            ..SessionOptions::default()
        };

        let handle = run_async(create_agent_session(options)).expect("create session");
        assert!(!handle.session().save_enabled());

        let path_is_none = run_async(async {
            let cx = crate::agent_cx::AgentCx::for_request();
            let guard = handle
                .session()
                .session
                .lock(cx.cx())
                .await
                .expect("lock session");
            guard.path.is_none()
        });
        assert!(path_is_none);
    }

    #[test]
    fn create_agent_session_set_model_switches_provider_model() {
        let tmp = tempdir().expect("tempdir");
        let options = SessionOptions {
            working_directory: Some(tmp.path().to_path_buf()),
            no_session: true,
            ..SessionOptions::default()
        };

        let mut handle = run_async(create_agent_session(options)).expect("create session");
        run_async(handle.set_model("openai", "gpt-4o")).expect("set model");
        let provider = handle.session().agent.provider();
        assert_eq!(provider.name(), "openai");
        assert_eq!(provider.model_id(), "gpt-4o");
    }

    #[test]
    fn compact_without_history_is_noop() {
        let tmp = tempdir().expect("tempdir");
        let options = SessionOptions {
            working_directory: Some(tmp.path().to_path_buf()),
            no_session: true,
            ..SessionOptions::default()
        };

        let mut handle = run_async(create_agent_session(options)).expect("create session");
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_for_callback = Arc::clone(&events);
        run_async(handle.compact(move |event| {
            events_for_callback
                .lock()
                .expect("compact callback lock")
                .push(event);
        }))
        .expect("compact");

        assert!(
            events.lock().expect("events lock").is_empty(),
            "expected no compaction lifecycle events for empty session"
        );
    }

    #[test]
    fn resolve_path_for_cwd_uses_cwd_for_relative_paths() {
        let cwd = Path::new("/tmp/pi-sdk-cwd");
        assert_eq!(
            resolve_path_for_cwd(Path::new("relative/file.txt"), cwd),
            PathBuf::from("/tmp/pi-sdk-cwd/relative/file.txt")
        );
        assert_eq!(
            resolve_path_for_cwd(Path::new("/etc/hosts"), cwd),
            PathBuf::from("/etc/hosts")
        );
    }
}
