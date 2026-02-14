use super::*;

use crate::models::ModelEntry;

/// Available slash commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashCommand {
    Help,
    Login,
    Logout,
    Clear,
    Model,
    Thinking,
    ScopedModels,
    Exit,
    History,
    Export,
    Session,
    Settings,
    Theme,
    Resume,
    New,
    Copy,
    Name,
    Hotkeys,
    Changelog,
    Tree,
    Fork,
    Compact,
    Reload,
    Share,
}

impl SlashCommand {
    /// Parse a slash command from input.
    pub fn parse(input: &str) -> Option<(Self, &str)> {
        let input = input.trim();
        if !input.starts_with('/') {
            return None;
        }

        let (cmd, args) = input.split_once(char::is_whitespace).unwrap_or((input, ""));

        let command = match cmd.to_lowercase().as_str() {
            "/help" | "/h" | "/?" => Self::Help,
            "/login" => Self::Login,
            "/logout" => Self::Logout,
            "/clear" | "/cls" => Self::Clear,
            "/model" | "/m" => Self::Model,
            "/thinking" | "/think" | "/t" => Self::Thinking,
            "/scoped-models" | "/scoped" => Self::ScopedModels,
            "/exit" | "/quit" | "/q" => Self::Exit,
            "/history" | "/hist" => Self::History,
            "/export" => Self::Export,
            "/session" | "/info" => Self::Session,
            "/settings" => Self::Settings,
            "/theme" => Self::Theme,
            "/resume" | "/r" => Self::Resume,
            "/new" => Self::New,
            "/copy" | "/cp" => Self::Copy,
            "/name" => Self::Name,
            "/hotkeys" | "/keys" | "/keybindings" => Self::Hotkeys,
            "/changelog" => Self::Changelog,
            "/tree" => Self::Tree,
            "/fork" => Self::Fork,
            "/compact" => Self::Compact,
            "/reload" => Self::Reload,
            "/share" => Self::Share,
            _ => return None,
        };

        Some((command, args.trim()))
    }

    /// Get help text for all commands.
    pub const fn help_text() -> &'static str {
        r"Available commands:
  /help, /h, /?      - Show this help message
  /login [provider]  - Login/setup credentials; without provider shows status table
  /logout [provider] - Remove stored credentials
  /clear, /cls       - Clear conversation history
  /model, /m [id|provider/id] - Show or change the current model
  /thinking, /t [level] - Set thinking level (off/minimal/low/medium/high/xhigh)
  /scoped-models [patterns|clear] - Show or set scoped models for cycling
  /history, /hist    - Show input history
  /export [path]     - Export conversation to HTML
  /session, /info    - Show session info (path, tokens, cost)
  /settings          - Open settings selector
  /theme [name]      - List or switch themes (dark/light/custom)
  /resume, /r        - Pick and resume a previous session
  /new               - Start a new session
  /copy, /cp         - Copy last assistant message to clipboard
  /name <name>       - Set session display name
  /hotkeys, /keys    - Show keyboard shortcuts
  /changelog         - Show changelog entries
  /tree              - Show session branch tree summary
  /fork [id|index]   - Fork from a user message (default: last on current path)
  /compact [notes]   - Compact older context with optional instructions
  /reload            - Reload skills/prompts from disk
  /share             - Upload session HTML to a secret GitHub gist and show URL
  /exit, /quit, /q   - Exit Pi

  Tips:
    • Use ↑/↓ arrows to navigate input history
    • Use Ctrl+L to open model selector
    • Use Ctrl+P to cycle scoped models
    • Use Shift+Enter (Ctrl+Enter on Windows) to insert a newline
    • Use PageUp/PageDown to scroll conversation history
    • Use Escape to cancel current input
    • Use /skill:name or /template to expand resources"
    }
}

pub(super) fn parse_extension_command(input: &str) -> Option<(String, Vec<String>)> {
    let input = input.trim();
    if !input.starts_with('/') {
        return None;
    }

    // Built-in slash commands are handled elsewhere.
    if SlashCommand::parse(input).is_some() {
        return None;
    }

    let (cmd, rest) = input.split_once(char::is_whitespace).unwrap_or((input, ""));
    let cmd = cmd.trim_start_matches('/').trim();
    if cmd.is_empty() {
        return None;
    }
    let args = rest
        .split_whitespace()
        .map(std::string::ToString::to_string)
        .collect();
    Some((cmd.to_string(), args))
}

pub(super) fn parse_bash_command(input: &str) -> Option<(String, bool)> {
    let trimmed = input.trim_start();
    let (rest, force) = trimmed
        .strip_prefix("!!")
        .map(|r| (r, true))
        .or_else(|| trimmed.strip_prefix('!').map(|r| (r, false)))?;
    let command = rest.trim();
    if command.is_empty() {
        return None;
    }
    Some((command.to_string(), force))
}

pub(super) fn normalize_api_key_input(raw: &str) -> std::result::Result<String, String> {
    let key = raw.trim();
    if key.is_empty() {
        return Err("API key cannot be empty".to_string());
    }
    if key.chars().any(char::is_whitespace) {
        return Err("API key must not contain whitespace".to_string());
    }
    Ok(key.to_string())
}

pub(super) fn normalize_auth_provider_input(raw: &str) -> String {
    let provider = raw.trim().to_ascii_lowercase();
    crate::provider_metadata::canonical_provider_id(&provider)
        .unwrap_or(provider.as_str())
        .to_string()
}

pub(super) fn api_key_login_prompt(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some(
            "API key login: openai\n\n\
Paste your OpenAI API key to save it in auth.json.\n\
Get a key from platform.openai.com/api-keys.\n\
Rotate/revoke keys from that dashboard if compromised.\n\n\
Your input will be treated as sensitive and is not added to message history.",
        ),
        "google" => Some(
            "API key login: google/gemini\n\n\
Paste your Google Gemini API key to save it in auth.json under google.\n\
Get a key from ai.google.dev/gemini-api/docs/api-key.\n\
Rotate/revoke keys from Google AI Studio if compromised.\n\n\
Your input will be treated as sensitive and is not added to message history.",
        ),
        _ => None,
    }
}

pub(super) fn save_provider_credential(
    auth: &mut crate::auth::AuthStorage,
    provider: &str,
    credential: crate::auth::AuthCredential,
) {
    let requested = provider.trim().to_ascii_lowercase();
    let canonical = normalize_auth_provider_input(&requested);
    auth.set(canonical.clone(), credential);
    if canonical == "google" {
        let _ = auth.remove("gemini");
    } else if requested != canonical {
        let _ = auth.remove(&requested);
    }
}

pub(super) fn remove_provider_credentials(
    auth: &mut crate::auth::AuthStorage,
    requested_provider: &str,
) -> bool {
    let requested = requested_provider.trim().to_ascii_lowercase();
    let canonical = normalize_auth_provider_input(&requested);

    let mut removed = auth.remove(&canonical);
    if requested != canonical {
        removed |= auth.remove(&requested);
    }
    if canonical == "google" {
        removed |= auth.remove("gemini");
    }
    removed
}

const BUILTIN_LOGIN_PROVIDERS: [(&str, &str); 3] = [
    ("anthropic", "OAuth"),
    ("openai", "API key"),
    ("google", "API key"),
];

fn format_compact_duration(ms: i64) -> String {
    let seconds = (ms.max(0) / 1000).max(1);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 60 * 60 {
        format!("{}m", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h", seconds / (60 * 60))
    } else {
        format!("{}d", seconds / (24 * 60 * 60))
    }
}

fn format_credential_status(status: &crate::auth::CredentialStatus) -> String {
    match status {
        crate::auth::CredentialStatus::Missing => "Not authenticated".to_string(),
        crate::auth::CredentialStatus::ApiKey
        | crate::auth::CredentialStatus::BearerToken
        | crate::auth::CredentialStatus::AwsCredentials
        | crate::auth::CredentialStatus::ServiceKey => "Authenticated".to_string(),
        crate::auth::CredentialStatus::OAuthValid { expires_in_ms } => {
            format!(
                "Authenticated (expires in {})",
                format_compact_duration(*expires_in_ms)
            )
        }
        crate::auth::CredentialStatus::OAuthExpired { expired_by_ms } => {
            format!(
                "Authenticated (expired {} ago)",
                format_compact_duration(*expired_by_ms)
            )
        }
    }
}

fn collect_extension_oauth_providers(available_models: &[ModelEntry]) -> Vec<String> {
    let mut providers: Vec<String> = available_models
        .iter()
        .filter(|entry| entry.oauth_config.is_some())
        .map(|entry| {
            let provider = entry.model.provider.as_str();
            crate::provider_metadata::canonical_provider_id(provider)
                .unwrap_or(provider)
                .to_string()
        })
        .collect();

    providers.retain(|provider| {
        !BUILTIN_LOGIN_PROVIDERS
            .iter()
            .any(|(builtin, _)| provider == builtin)
    });
    providers.sort_unstable();
    providers.dedup();
    providers
}

fn append_provider_rows(output: &mut String, heading: &str, rows: &[(String, String, String)]) {
    let provider_width = rows
        .iter()
        .map(|(provider, _, _)| provider.len())
        .max()
        .unwrap_or("provider".len())
        .max("provider".len());
    let method_width = rows
        .iter()
        .map(|(_, method, _)| method.len())
        .max()
        .unwrap_or("method".len())
        .max("method".len());

    let _ = writeln!(output, "{heading}:");
    let _ = writeln!(
        output,
        "  {:<provider_width$}  {:<method_width$}  status",
        "provider", "method"
    );
    for (provider, method, status) in rows {
        let _ = writeln!(
            output,
            "  {provider:<provider_width$}  {method:<method_width$}  {status}"
        );
    }
}

pub(super) fn format_login_provider_listing(
    auth: &crate::auth::AuthStorage,
    available_models: &[ModelEntry],
) -> String {
    let mut output = String::from("Available login providers:\n\n");

    let built_in_rows: Vec<(String, String, String)> = BUILTIN_LOGIN_PROVIDERS
        .iter()
        .map(|(provider, method)| {
            let status = auth.credential_status(provider);
            (
                (*provider).to_string(),
                (*method).to_string(),
                format_credential_status(&status),
            )
        })
        .collect();
    append_provider_rows(&mut output, "Built-in", &built_in_rows);

    let extension_providers = collect_extension_oauth_providers(available_models);
    if !extension_providers.is_empty() {
        let extension_rows: Vec<(String, String, String)> = extension_providers
            .iter()
            .map(|provider| {
                let status = auth.credential_status(provider);
                (
                    provider.clone(),
                    "OAuth".to_string(),
                    format_credential_status(&status),
                )
            })
            .collect();
        output.push('\n');
        append_provider_rows(&mut output, "Extension providers", &extension_rows);
    }

    output.push_str("\nUsage: /login <provider>");
    output
}

pub fn strip_thinking_level_suffix(pattern: &str) -> &str {
    let Some((prefix, suffix)) = pattern.rsplit_once(':') else {
        return pattern;
    };
    match suffix.to_ascii_lowercase().as_str() {
        "off" | "minimal" | "low" | "medium" | "high" | "xhigh" => prefix,
        _ => pattern,
    }
}

pub fn parse_scoped_model_patterns(args: &str) -> Vec<String> {
    args.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub fn model_entry_matches(left: &ModelEntry, right: &ModelEntry) -> bool {
    left.model
        .provider
        .eq_ignore_ascii_case(&right.model.provider)
        && left.model.id.eq_ignore_ascii_case(&right.model.id)
}

pub fn resolve_scoped_model_entries(
    patterns: &[String],
    available_models: &[ModelEntry],
) -> Result<Vec<ModelEntry>, String> {
    let mut resolved: Vec<ModelEntry> = Vec::new();

    for pattern in patterns {
        let raw_pattern = strip_thinking_level_suffix(pattern);
        let is_glob =
            raw_pattern.contains('*') || raw_pattern.contains('?') || raw_pattern.contains('[');

        if is_glob {
            let glob = Pattern::new(&raw_pattern.to_lowercase())
                .map_err(|err| format!("Invalid model pattern \"{pattern}\": {err}"))?;

            for entry in available_models {
                let full_id = format!("{}/{}", entry.model.provider, entry.model.id);
                let full_id_lower = full_id.to_lowercase();
                let id_lower = entry.model.id.to_lowercase();

                if (glob.matches(&full_id_lower) || glob.matches(&id_lower))
                    && !resolved
                        .iter()
                        .any(|existing| model_entry_matches(existing, entry))
                {
                    resolved.push(entry.clone());
                }
            }
            continue;
        }

        for entry in available_models {
            let full_id = format!("{}/{}", entry.model.provider, entry.model.id);
            if raw_pattern.eq_ignore_ascii_case(&full_id)
                || raw_pattern.eq_ignore_ascii_case(&entry.model.id)
            {
                if !resolved
                    .iter()
                    .any(|existing| model_entry_matches(existing, entry))
                {
                    resolved.push(entry.clone());
                }
                break;
            }
        }
    }

    resolved.sort_by(|a, b| {
        let left = format!("{}/{}", a.model.provider, a.model.id);
        let right = format!("{}/{}", b.model.provider, b.model.id);
        left.cmp(&right)
    });

    Ok(resolved)
}

#[derive(Debug, Clone)]
pub(super) struct ForkCandidate {
    pub id: String,
    pub summary: String,
}

pub(super) fn fork_candidates(session: &Session) -> Vec<ForkCandidate> {
    let mut out = Vec::new();

    for entry in session.entries_for_current_path() {
        let SessionEntry::Message(message_entry) = entry else {
            continue;
        };

        let Some(id) = message_entry.base.id.as_ref() else {
            continue;
        };

        let SessionMessage::User { content, .. } = &message_entry.message else {
            continue;
        };

        let text = user_content_to_text(content);
        let first_line = text
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("")
            .trim();
        let summary = if first_line.is_empty() {
            "(empty)".to_string()
        } else {
            truncate(first_line, 80)
        };

        out.push(ForkCandidate {
            id: id.clone(),
            summary,
        });
    }

    out
}

impl PiApp {
    pub(super) fn submit_oauth_code(
        &mut self,
        code_input: &str,
        pending: PendingOAuth,
    ) -> Option<Cmd> {
        // Do not store OAuth codes in history or session.
        self.input.reset();
        self.input_mode = InputMode::SingleLine;
        self.set_input_height(3);

        self.agent_state = AgentState::Processing;
        self.scroll_to_bottom();

        let event_tx = self.event_tx.clone();
        let PendingOAuth {
            provider,
            kind,
            verifier,
            oauth_config,
        } = pending;
        let code_input = code_input.to_string();

        let runtime_handle = self.runtime_handle.clone();
        runtime_handle.spawn(async move {
            let auth_path = crate::config::Config::auth_path();
            let mut auth = match crate::auth::AuthStorage::load_async(auth_path).await {
                Ok(a) => a,
                Err(e) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(e.to_string()));
                    return;
                }
            };

            let credential = match kind {
                PendingLoginKind::ApiKey => normalize_api_key_input(&code_input)
                    .map(|key| crate::auth::AuthCredential::ApiKey { key })
                    .map_err(crate::error::Error::auth),
                PendingLoginKind::OAuth => {
                    if provider == "anthropic" {
                        Box::pin(crate::auth::complete_anthropic_oauth(
                            &code_input,
                            &verifier,
                        ))
                        .await
                    } else if let Some(config) = &oauth_config {
                        Box::pin(crate::auth::complete_extension_oauth(
                            config,
                            &code_input,
                            &verifier,
                        ))
                        .await
                    } else {
                        Err(crate::error::Error::auth(format!(
                            "OAuth provider not supported: {provider}"
                        )))
                    }
                }
            };

            let credential = match credential {
                Ok(c) => c,
                Err(e) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(e.to_string()));
                    return;
                }
            };

            save_provider_credential(&mut auth, &provider, credential);
            if let Err(e) = auth.save_async().await {
                let _ = event_tx.try_send(PiMsg::AgentError(e.to_string()));
                return;
            }

            let status = match kind {
                PendingLoginKind::ApiKey => {
                    format!("API key saved for {provider}. Credentials saved to auth.json.")
                }
                PendingLoginKind::OAuth => {
                    format!(
                        "OAuth login successful for {provider}. Credentials saved to auth.json."
                    )
                }
            };
            let _ = event_tx.try_send(PiMsg::System(status));
        });

        None
    }

    pub(super) fn submit_bash_command(
        &mut self,
        raw_message: &str,
        command: String,
        exclude_from_context: bool,
    ) -> Option<Cmd> {
        if self.bash_running {
            self.status_message = Some("A bash command is already running.".to_string());
            return None;
        }

        self.bash_running = true;
        self.agent_state = AgentState::ToolRunning;
        self.current_tool = Some("bash".to_string());
        self.history.push(raw_message.to_string());

        self.input.reset();
        self.input_mode = InputMode::SingleLine;
        self.set_input_height(3);

        let event_tx = self.event_tx.clone();
        let session = Arc::clone(&self.session);
        let save_enabled = self.save_enabled;
        let cwd = self.cwd.clone();
        let shell_path = self.config.shell_path.clone();
        let command_prefix = self.config.shell_command_prefix.clone();
        let runtime_handle = self.runtime_handle.clone();

        runtime_handle.spawn(async move {
            let cx = Cx::for_request();
            let result = crate::tools::run_bash_command(
                &cwd,
                shell_path.as_deref(),
                command_prefix.as_deref(),
                &command,
                None,
                None,
            )
            .await;

            match result {
                Ok(result) => {
                    let display =
                        bash_execution_to_text(&command, &result.output, 0, false, false, None);

                    if exclude_from_context {
                        let mut extra = HashMap::new();
                        extra.insert("excludeFromContext".to_string(), Value::Bool(true));

                        let bash_message = SessionMessage::BashExecution {
                            command: command.clone(),
                            output: result.output.clone(),
                            exit_code: result.exit_code,
                            cancelled: Some(result.cancelled),
                            truncated: Some(result.truncated),
                            full_output_path: result.full_output_path.clone(),
                            timestamp: Some(Utc::now().timestamp_millis()),
                            extra,
                        };

                        if let Ok(mut session_guard) = session.lock(&cx).await {
                            session_guard.append_message(bash_message);
                            if save_enabled {
                                let _ = session_guard.save().await;
                            }
                        }

                        let mut display = display;
                        display.push_str("\n\n[Output excluded from model context]");
                        let _ = event_tx.try_send(PiMsg::BashResult {
                            display,
                            content_for_agent: None,
                        });
                    } else {
                        let content_for_agent =
                            vec![ContentBlock::Text(TextContent::new(display.clone()))];
                        let _ = event_tx.try_send(PiMsg::BashResult {
                            display,
                            content_for_agent: Some(content_for_agent),
                        });
                    }
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::BashResult {
                        display: format!("Bash command failed: {err}"),
                        content_for_agent: None,
                    });
                }
            }
        });

        None
    }

    pub(super) fn format_themes_list(&self) -> String {
        let mut names = Vec::new();
        names.push("dark".to_string());
        names.push("light".to_string());
        names.push("solarized".to_string());

        for path in Theme::discover_themes(&self.cwd) {
            if let Ok(theme) = Theme::load(&path) {
                names.push(theme.name);
            }
        }

        names.sort_by_key(|a| a.to_ascii_lowercase());
        names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

        let mut output = String::from("Available themes:\n");
        for name in names {
            let marker = if name.eq_ignore_ascii_case(&self.theme.name) {
                "* "
            } else {
                "  "
            };
            let _ = writeln!(output, "{marker}{name}");
        }
        output.push_str("\nUse /theme <name> to switch");
        output
    }

    pub(super) fn format_scoped_models_status(&self) -> String {
        let patterns = self.config.enabled_models.as_deref().unwrap_or(&[]);
        let scope_configured = !patterns.is_empty();

        let mut output = String::new();
        let current = format!(
            "{}/{}",
            self.model_entry.model.provider, self.model_entry.model.id
        );
        let _ = writeln!(output, "Current model: {current}");
        let _ = writeln!(output);

        if !scope_configured {
            let _ = writeln!(output, "Scoped models: (all models)");
            let _ = writeln!(output);
            output.push_str("Use /scoped-models <patterns> to scope Ctrl+P cycling.\n");
            output.push_str("Use /scoped-models clear to clear scope.\n");
            return output;
        }

        output.push_str("Scoped model patterns:\n");
        for pattern in patterns {
            let _ = writeln!(output, "  - {pattern}");
        }
        let _ = writeln!(output);

        output.push_str("Scoped models (matched):\n");
        if self.model_scope.is_empty() {
            output.push_str("  (none)\n");
        } else {
            let mut models = self
                .model_scope
                .iter()
                .map(|entry| format!("{}/{}", entry.model.provider, entry.model.id))
                .collect::<Vec<_>>();
            models.sort_by_key(|value| value.to_ascii_lowercase());
            models.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
            for model in models {
                let _ = writeln!(output, "  - {model}");
            }
        }
        let _ = writeln!(output);

        output.push_str("Use /scoped-models clear to cycle all models.\n");
        output
    }

    pub(super) fn format_input_history(&self) -> String {
        let entries = self.history.entries();
        if entries.is_empty() {
            return "No input history yet.".to_string();
        }

        let mut output = String::from("Input history (most recent first):\n");
        for (idx, entry) in entries.iter().rev().take(50).enumerate() {
            let trimmed = entry.value.trim();
            if trimmed.is_empty() {
                continue;
            }
            let preview = trimmed.replace('\n', "\\n");
            let preview = preview.chars().take(120).collect::<String>();
            let _ = writeln!(output, "  {}. {preview}", idx + 1);
        }
        output
    }

    pub(super) fn format_session_info(&self, session: &Session) -> String {
        let file = session.path.as_ref().map_or_else(
            || "(not saved yet)".to_string(),
            |p| p.display().to_string(),
        );
        let name = session.get_name().unwrap_or_else(|| "-".to_string());
        let thinking = session
            .header
            .thinking_level
            .as_deref()
            .unwrap_or("off")
            .to_string();

        let message_count = session
            .entries_for_current_path()
            .iter()
            .filter(|entry| matches!(entry, SessionEntry::Message(_)))
            .count();

        let total_tokens = self.total_usage.total_tokens;
        let total_cost = self.total_usage.cost.total;
        let cost_str = if total_cost > 0.0 {
            format!("${total_cost:.4}")
        } else {
            "$0.0000".to_string()
        };

        let mut info = format!(
            "Session info:\n  file: {file}\n  id: {id}\n  name: {name}\n  model: {model}\n  thinking: {thinking}\n  messageCount: {message_count}\n  tokens: {total_tokens}\n  cost: {cost_str}",
            id = session.header.id,
            model = self.model,
        );
        info.push_str("\n\n");
        info.push_str(&self.frame_timing.summary());
        info.push_str("\n\n");
        info.push_str(&self.memory_monitor.summary());
        info
    }

    /// Handle a slash command.
    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_slash_command(&mut self, cmd: SlashCommand, args: &str) -> Option<Cmd> {
        // Clear input
        self.input.reset();

        match cmd {
            SlashCommand::Help => {
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: SlashCommand::help_text().to_string(),
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_last_match("Available commands:");
                None
            }
            SlashCommand::Login => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot login while processing".to_string());
                    return None;
                }

                let args = args.trim();
                if args.is_empty() {
                    let auth_path = crate::config::Config::auth_path();
                    match crate::auth::AuthStorage::load(auth_path) {
                        Ok(auth) => {
                            let listing =
                                format_login_provider_listing(&auth, &self.available_models);
                            self.messages.push(ConversationMessage {
                                role: MessageRole::System,
                                content: listing,
                                thinking: None,
                                collapsed: false,
                            });
                            self.scroll_to_last_match("Available login providers:");
                        }
                        Err(err) => {
                            self.status_message =
                                Some(format!("Unable to load auth status: {err}"));
                        }
                    }
                    return None;
                }

                let requested_provider = args.split_whitespace().next().unwrap_or(args).to_string();
                let provider = normalize_auth_provider_input(&requested_provider);

                if let Some(prompt) = api_key_login_prompt(&provider) {
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: prompt.to_string(),
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_bottom();
                    self.pending_oauth = Some(PendingOAuth {
                        provider,
                        kind: PendingLoginKind::ApiKey,
                        verifier: String::new(),
                        oauth_config: None,
                    });
                    self.input_mode = InputMode::SingleLine;
                    self.set_input_height(3);
                    self.input.focus();
                    return None;
                }

                // Look up OAuth config: built-in (anthropic) or extension-registered.
                let oauth_result = if provider == "anthropic" {
                    crate::auth::start_anthropic_oauth().map(|info| (info, None))
                } else {
                    // Check extension providers for OAuth config.
                    let ext_oauth = self
                        .available_models
                        .iter()
                        .find(|m| {
                            let model_provider = m.model.provider.as_str();
                            let canonical =
                                crate::provider_metadata::canonical_provider_id(model_provider)
                                    .unwrap_or(model_provider);
                            canonical == provider
                        })
                        .and_then(|m| m.oauth_config.clone());
                    if let Some(config) = ext_oauth {
                        crate::auth::start_extension_oauth(&provider, &config)
                            .map(|info| (info, Some(config)))
                    } else {
                        self.status_message = Some(format!(
                            "Login not supported for {provider} (no built-in flow or OAuth config)"
                        ));
                        return None;
                    }
                };

                match oauth_result {
                    Ok((info, ext_config)) => {
                        let mut message = format!(
                            "OAuth login: {}\n\nOpen this URL:\n{}\n",
                            info.provider, info.url
                        );
                        if let Some(instructions) = info.instructions {
                            message.push('\n');
                            message.push_str(&instructions);
                            message.push('\n');
                        }
                        message.push_str(
                            "\nPaste the callback URL or authorization code into Pi to continue.",
                        );

                        self.messages.push(ConversationMessage {
                            role: MessageRole::System,
                            content: message,
                            thinking: None,
                            collapsed: false,
                        });
                        self.scroll_to_bottom();
                        self.pending_oauth = Some(PendingOAuth {
                            provider: info.provider,
                            kind: PendingLoginKind::OAuth,
                            verifier: info.verifier,
                            oauth_config: ext_config,
                        });
                        self.input_mode = InputMode::SingleLine;
                        self.set_input_height(3);
                        self.input.focus();
                        None
                    }
                    Err(err) => {
                        self.status_message = Some(format!("OAuth login failed: {err}"));
                        None
                    }
                }
            }
            SlashCommand::Logout => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot logout while processing".to_string());
                    return None;
                }

                let requested_provider = if args.is_empty() {
                    self.model_entry.model.provider.clone()
                } else {
                    args.split_whitespace().next().unwrap_or(args).to_string()
                };
                let requested_provider = requested_provider.trim().to_ascii_lowercase();
                let provider = normalize_auth_provider_input(&requested_provider);

                let auth_path = crate::config::Config::auth_path();
                match crate::auth::AuthStorage::load(auth_path) {
                    Ok(mut auth) => {
                        let removed = remove_provider_credentials(&mut auth, &requested_provider);
                        if let Err(err) = auth.save() {
                            self.status_message = Some(err.to_string());
                            return None;
                        }
                        if removed {
                            self.status_message =
                                Some(format!("Removed stored credentials for {provider}."));
                        } else {
                            self.status_message =
                                Some(format!("No stored credentials for {provider}."));
                        }
                    }
                    Err(err) => {
                        self.status_message = Some(err.to_string());
                    }
                }
                None
            }
            SlashCommand::Clear => {
                self.messages.clear();
                self.current_response.clear();
                self.current_thinking.clear();
                self.current_tool = None;
                self.pending_tool_output = None;
                self.abort_handle = None;
                self.autocomplete.close();
                self.status_message = Some("Conversation cleared".to_string());
                self.scroll_to_bottom();
                None
            }
            SlashCommand::Model => {
                if args.trim().is_empty() {
                    self.status_message = Some(format!("Current model: {}", self.model));
                    return None;
                }

                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot switch models while processing".to_string());
                    return None;
                }

                let pattern = args.trim();
                let pattern_lower = pattern.to_ascii_lowercase();

                let mut exact_matches = Vec::new();
                for entry in &self.available_models {
                    let full = format!("{}/{}", entry.model.provider, entry.model.id);
                    if full.eq_ignore_ascii_case(pattern)
                        || entry.model.id.eq_ignore_ascii_case(pattern)
                    {
                        exact_matches.push(entry.clone());
                    }
                }

                let mut matches = if exact_matches.is_empty() {
                    let mut fuzzy = Vec::new();
                    for entry in &self.available_models {
                        let full = format!("{}/{}", entry.model.provider, entry.model.id);
                        let full_lower = full.to_ascii_lowercase();
                        if full_lower.contains(&pattern_lower)
                            || entry.model.id.to_ascii_lowercase().contains(&pattern_lower)
                        {
                            fuzzy.push(entry.clone());
                        }
                    }
                    fuzzy
                } else {
                    exact_matches
                };

                matches.sort_by(|a, b| {
                    let left = format!("{}/{}", a.model.provider, a.model.id);
                    let right = format!("{}/{}", b.model.provider, b.model.id);
                    left.cmp(&right)
                });
                matches.dedup_by(|a, b| {
                    a.model.provider.eq_ignore_ascii_case(&b.model.provider)
                        && a.model.id.eq_ignore_ascii_case(&b.model.id)
                });

                if matches.is_empty() {
                    if let Some((provider, model_id)) = pattern.split_once('/') {
                        let provider = provider.trim().to_ascii_lowercase();
                        let model_id = model_id.trim();
                        if !provider.is_empty() && !model_id.is_empty() {
                            if let Some(entry) =
                                crate::models::ad_hoc_model_entry(&provider, model_id)
                            {
                                matches.push(entry);
                            }
                        }
                    }
                }

                if matches.is_empty() {
                    self.status_message = Some(format!("Model not found: {pattern}"));
                    return None;
                }
                if matches.len() > 1 {
                    let preview = matches
                        .iter()
                        .take(8)
                        .map(|m| format!("  - {}/{}", m.model.provider, m.model.id))
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: format!(
                            "Ambiguous model pattern \"{pattern}\". Matches:\n{preview}\n\nUse /model provider/id for an exact match."
                        ),
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_bottom();
                    return None;
                }

                let next = matches.into_iter().next().expect("matches is non-empty");

                let resolved_key_opt = if next.api_key.is_some() {
                    next.api_key.clone()
                } else {
                    let auth_path = crate::config::Config::auth_path();
                    crate::auth::AuthStorage::load(auth_path)
                        .ok()
                        .and_then(|auth| auth.resolve_api_key(&next.model.provider, None))
                };
                if resolved_key_opt.is_none() {
                    self.status_message = Some(format!(
                        "Missing API key for provider {}",
                        next.model.provider
                    ));
                    return None;
                }

                if next.model.provider == self.model_entry.model.provider
                    && next.model.id == self.model_entry.model.id
                {
                    self.status_message = Some(format!("Current model: {}", self.model));
                    return None;
                }

                let provider_impl =
                    match providers::create_provider(&next, self.extensions.as_ref()) {
                        Ok(provider_impl) => provider_impl,
                        Err(err) => {
                            self.status_message = Some(err.to_string());
                            return None;
                        }
                    };

                let Ok(mut agent_guard) = self.agent.try_lock() else {
                    self.status_message = Some("Agent busy; try again".to_string());
                    return None;
                };
                agent_guard.set_provider(provider_impl);
                agent_guard
                    .stream_options_mut()
                    .api_key
                    .clone_from(&resolved_key_opt);
                agent_guard
                    .stream_options_mut()
                    .headers
                    .clone_from(&next.headers);
                drop(agent_guard);

                let Ok(mut session_guard) = self.session.try_lock() else {
                    self.status_message = Some("Session busy; try again".to_string());
                    return None;
                };
                session_guard.header.provider = Some(next.model.provider.clone());
                session_guard.header.model_id = Some(next.model.id.clone());
                session_guard
                    .append_model_change(next.model.provider.clone(), next.model.id.clone());
                drop(session_guard);
                self.spawn_save_session();

                if !self
                    .available_models
                    .iter()
                    .any(|entry| model_entry_matches(entry, &next))
                {
                    self.available_models.push(next.clone());
                }
                self.model_entry = next.clone();
                if let Ok(mut guard) = self.model_entry_shared.lock() {
                    *guard = next.clone();
                }
                self.model = format!("{}/{}", next.model.provider, next.model.id);

                self.status_message = Some(format!("Switched model: {}", self.model));
                None
            }
            SlashCommand::Thinking => {
                let value = args.trim();
                if value.is_empty() {
                    let current = self
                        .session
                        .try_lock()
                        .ok()
                        .and_then(|guard| guard.header.thinking_level.clone())
                        .unwrap_or_else(|| ThinkingLevel::Off.to_string());
                    self.status_message = Some(format!("Thinking level: {current}"));
                    return None;
                }

                let level: ThinkingLevel = match value.parse() {
                    Ok(level) => level,
                    Err(err) => {
                        self.status_message = Some(err);
                        return None;
                    }
                };

                let Ok(mut session_guard) = self.session.try_lock() else {
                    self.status_message = Some("Session busy; try again".to_string());
                    return None;
                };
                session_guard.header.thinking_level = Some(level.to_string());
                session_guard.append_thinking_level_change(level.to_string());
                drop(session_guard);
                self.spawn_save_session();

                if let Ok(mut agent_guard) = self.agent.try_lock() {
                    agent_guard.stream_options_mut().thinking_level = Some(level);
                }

                self.status_message = Some(format!("Thinking level: {level}"));
                None
            }
            SlashCommand::ScopedModels => {
                let value = args.trim();
                if value.is_empty() {
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: self.format_scoped_models_status(),
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_last_match("Scoped models");
                    return None;
                }

                if value.eq_ignore_ascii_case("clear") {
                    let previous_patterns = self
                        .config
                        .enabled_models
                        .as_deref()
                        .unwrap_or(&[])
                        .to_vec();
                    self.config.enabled_models = Some(Vec::new());
                    self.model_scope.clear();

                    let global_dir = Config::global_dir();
                    let patch = json!({ "enabled_models": [] });
                    let cleared_msg = if previous_patterns.is_empty() {
                        "Scoped models cleared (was: all models)".to_string()
                    } else {
                        format!(
                            "Cleared {} pattern(s) (was: {})",
                            previous_patterns.len(),
                            previous_patterns.join(", ")
                        )
                    };
                    if let Err(err) = Config::patch_settings_with_roots(
                        SettingsScope::Project,
                        &global_dir,
                        &self.cwd,
                        patch,
                    ) {
                        tracing::warn!("Failed to persist enabled_models: {err}");
                        self.status_message = Some(format!("{cleared_msg} (not saved: {err})"));
                    } else {
                        self.status_message = Some(cleared_msg);
                    }
                    return None;
                }

                let patterns = parse_scoped_model_patterns(value);
                if patterns.is_empty() {
                    self.status_message =
                        Some("Usage: /scoped-models [patterns|clear]".to_string());
                    return None;
                }

                let resolved = match resolve_scoped_model_entries(&patterns, &self.available_models)
                {
                    Ok(resolved) => resolved,
                    Err(err) => {
                        self.status_message =
                            Some(format!("{err}\n  Example: /scoped-models gpt-4*,claude-3*"));
                        return None;
                    }
                };

                self.model_scope = resolved;
                self.config.enabled_models = Some(patterns.clone());

                let match_count = self.model_scope.len();

                // Build a preview of matched models for the conversation pane.
                let mut preview = String::new();
                if match_count == 0 {
                    let _ = writeln!(
                        preview,
                        "Warning: No models matched patterns: {}",
                        patterns.join(", ")
                    );
                    let _ = writeln!(preview, "Ctrl+P cycling will use all available models.");
                } else {
                    let _ = writeln!(preview, "Matching {match_count} model(s):");
                    let mut model_names: Vec<String> = self
                        .model_scope
                        .iter()
                        .map(|e| format!("{}/{}", e.model.provider, e.model.id))
                        .collect();
                    model_names.sort_by_key(|s| s.to_ascii_lowercase());
                    model_names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
                    for name in &model_names {
                        let _ = writeln!(preview, "  {name}");
                    }
                }
                let _ = writeln!(
                    preview,
                    "Patterns saved. Press Ctrl+P to cycle through matched models."
                );

                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: preview,
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();

                let status = if match_count == 0 {
                    format!(
                        "Scoped models: 0 matched for {}; cycling all available",
                        patterns.join(", ")
                    )
                } else {
                    format!("Scoped models: {match_count} matched")
                };
                let global_dir = Config::global_dir();
                let patch = json!({ "enabled_models": patterns });
                if let Err(err) = Config::patch_settings_with_roots(
                    SettingsScope::Project,
                    &global_dir,
                    &self.cwd,
                    patch,
                ) {
                    tracing::warn!("Failed to persist enabled_models: {err}");
                    self.status_message = Some(format!("{status} (not saved: {err})"));
                } else {
                    self.status_message = Some(status);
                }
                None
            }
            SlashCommand::Exit => Some(self.quit_cmd()),
            SlashCommand::History => {
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: self.format_input_history(),
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_last_match("Input history");
                None
            }
            SlashCommand::Export => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot export while processing".to_string());
                    return None;
                }

                let (output_path, html) = {
                    let Ok(session_guard) = self.session.try_lock() else {
                        self.status_message = Some("Session busy; try again".to_string());
                        return None;
                    };
                    let output_path = if args.trim().is_empty() {
                        self.default_export_path(&session_guard)
                    } else {
                        self.resolve_output_path(args)
                    };
                    let html = session_guard.to_html();
                    (output_path, html)
                };

                if let Some(parent) = output_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(err) = std::fs::create_dir_all(parent) {
                            self.status_message = Some(format!("Failed to create dir: {err}"));
                            return None;
                        }
                    }
                }
                if let Err(err) = std::fs::write(&output_path, html) {
                    self.status_message = Some(format!("Failed to write export: {err}"));
                    return None;
                }

                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: format!("Exported HTML: {}", output_path.display()),
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
                self.status_message = Some(format!("Exported: {}", output_path.display()));
                None
            }
            SlashCommand::Session => {
                let Ok(session_guard) = self.session.try_lock() else {
                    self.status_message = Some("Session busy; try again".to_string());
                    return None;
                };
                let info = self.format_session_info(&session_guard);
                drop(session_guard);
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: info,
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
                None
            }
            SlashCommand::Settings => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot open settings while processing".to_string());
                    return None;
                }

                self.settings_ui = Some(SettingsUiState::new());
                self.session_picker = None;
                self.autocomplete.close();
                None
            }
            SlashCommand::Theme => {
                let name = args.trim();
                if name.is_empty() {
                    self.messages.push(ConversationMessage {
                        role: MessageRole::System,
                        content: self.format_themes_list(),
                        thinking: None,
                        collapsed: false,
                    });
                    self.scroll_to_last_match("Available themes:");
                    return None;
                }

                let theme = if name.eq_ignore_ascii_case("dark") {
                    Theme::dark()
                } else if name.eq_ignore_ascii_case("light") {
                    Theme::light()
                } else if name.eq_ignore_ascii_case("solarized") {
                    Theme::solarized()
                } else {
                    match Theme::load_by_name(name, &self.cwd) {
                        Ok(theme) => theme,
                        Err(err) => {
                            self.status_message = Some(err.to_string());
                            return None;
                        }
                    }
                };

                let theme_name = theme.name.clone();
                self.apply_theme(theme);
                self.config.theme = Some(theme_name.clone());

                if let Err(err) = self.persist_project_theme(&theme_name) {
                    tracing::warn!("Failed to persist theme preference: {err}");
                    self.status_message = Some(format!(
                        "Switched to theme: {theme_name} (not saved: {err})"
                    ));
                } else {
                    self.status_message = Some(format!("Switched to theme: {theme_name}"));
                }

                None
            }
            SlashCommand::Resume => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot resume while processing".to_string());
                    return None;
                }

                let override_dir = self
                    .session
                    .try_lock()
                    .ok()
                    .and_then(|guard| guard.session_dir.clone());
                let base_dir = override_dir.clone().unwrap_or_else(Config::sessions_dir);
                let sessions = crate::session_picker::list_sessions_for_project(
                    &self.cwd,
                    override_dir.as_deref(),
                );
                if sessions.is_empty() {
                    self.status_message = Some("No sessions found for this project".to_string());
                    return None;
                }

                self.session_picker = Some(SessionPickerOverlay::new_with_root(
                    sessions,
                    Some(base_dir),
                ));
                self.autocomplete.close();
                None
            }
            SlashCommand::New => {
                if self.agent_state != AgentState::Idle {
                    self.status_message =
                        Some("Cannot start a new session while processing".to_string());
                    return None;
                }

                let Some(extensions) = self.extensions.clone() else {
                    let Ok(mut session_guard) = self.session.try_lock() else {
                        self.status_message = Some("Session busy; try again".to_string());
                        return None;
                    };
                    let session_dir = session_guard.session_dir.clone();
                    *session_guard = Session::create_with_dir(session_dir);
                    session_guard.header.provider = Some(self.model_entry.model.provider.clone());
                    session_guard.header.model_id = Some(self.model_entry.model.id.clone());
                    session_guard.header.thinking_level = Some(ThinkingLevel::Off.to_string());
                    drop(session_guard);

                    if let Ok(mut agent_guard) = self.agent.try_lock() {
                        agent_guard.replace_messages(Vec::new());
                        agent_guard.stream_options_mut().thinking_level = Some(ThinkingLevel::Off);
                    }

                    self.messages.clear();
                    self.total_usage = Usage::default();
                    self.current_response.clear();
                    self.current_thinking.clear();
                    self.current_tool = None;
                    self.pending_tool_output = None;
                    self.abort_handle = None;
                    self.pending_oauth = None;
                    self.session_picker = None;
                    self.tree_ui = None;
                    self.autocomplete.close();

                    self.status_message = Some(format!(
                        "Started new session\nModel set to {}\nThinking level: off",
                        self.model
                    ));
                    self.scroll_to_bottom();
                    self.input.focus();
                    return None;
                };

                let model_provider = self.model_entry.model.provider.clone();
                let model_id = self.model_entry.model.id.clone();
                let model_label = self.model.clone();
                let event_tx = self.event_tx.clone();
                let session = Arc::clone(&self.session);
                let agent = Arc::clone(&self.agent);
                let runtime_handle = self.runtime_handle.clone();

                let previous_session_file = self
                    .session
                    .try_lock()
                    .ok()
                    .and_then(|guard| guard.path.as_ref().map(|p| p.display().to_string()));

                self.agent_state = AgentState::Processing;
                self.status_message = Some("Starting new session...".to_string());

                runtime_handle.spawn(async move {
                    let cx = Cx::for_request();

                    let cancelled = extensions
                        .dispatch_cancellable_event(
                            ExtensionEventName::SessionBeforeSwitch,
                            Some(json!({ "reason": "new" })),
                            EXTENSION_EVENT_TIMEOUT_MS,
                        )
                        .await
                        .unwrap_or(false);
                    if cancelled {
                        let _ = event_tx.try_send(PiMsg::System(
                            "Session switch cancelled by extension".to_string(),
                        ));
                        return;
                    }

                    let new_session_id = {
                        let mut guard = match session.lock(&cx).await {
                            Ok(guard) => guard,
                            Err(err) => {
                                let _ = event_tx.try_send(PiMsg::AgentError(format!(
                                    "Failed to lock session: {err}"
                                )));
                                return;
                            }
                        };
                        let session_dir = guard.session_dir.clone();
                        let mut new_session = Session::create_with_dir(session_dir);
                        new_session.header.provider = Some(model_provider);
                        new_session.header.model_id = Some(model_id);
                        new_session.header.thinking_level = Some(ThinkingLevel::Off.to_string());
                        let new_id = new_session.header.id.clone();
                        *guard = new_session;
                        new_id
                    };

                    {
                        let mut agent_guard = match agent.lock(&cx).await {
                            Ok(guard) => guard,
                            Err(err) => {
                                let _ = event_tx.try_send(PiMsg::AgentError(format!(
                                    "Failed to lock agent: {err}"
                                )));
                                return;
                            }
                        };
                        agent_guard.replace_messages(Vec::new());
                        agent_guard.stream_options_mut().thinking_level = Some(ThinkingLevel::Off);
                    }

                    let _ = event_tx.try_send(PiMsg::ConversationReset {
                        messages: Vec::new(),
                        usage: Usage::default(),
                        status: Some(format!(
                            "Started new session\nModel set to {model_label}\nThinking level: off"
                        )),
                    });

                    let _ = extensions
                        .dispatch_event(
                            ExtensionEventName::SessionSwitch,
                            Some(json!({
                                "reason": "new",
                                "previousSessionFile": previous_session_file,
                                "sessionId": new_session_id,
                            })),
                        )
                        .await;
                });

                None
            }
            SlashCommand::Copy => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot copy while processing".to_string());
                    return None;
                }

                let text = self
                    .messages
                    .iter()
                    .rev()
                    .find(|m| m.role == MessageRole::Assistant && !m.content.trim().is_empty())
                    .map(|m| m.content.clone());

                let Some(text) = text else {
                    self.status_message = Some("No agent messages to copy yet.".to_string());
                    return None;
                };

                let write_fallback = |text: &str| -> std::io::Result<std::path::PathBuf> {
                    let dir = std::env::temp_dir();
                    let filename = format!("pi_copy_{}.txt", Utc::now().timestamp_millis());
                    let path = dir.join(filename);
                    std::fs::write(&path, text)?;
                    Ok(path)
                };

                #[cfg(feature = "clipboard")]
                {
                    match ClipboardProvider::new()
                        .and_then(|mut ctx: ClipboardContext| ctx.set_contents(text.clone()))
                    {
                        Ok(()) => self.status_message = Some("Copied to clipboard".to_string()),
                        Err(err) => match write_fallback(&text) {
                            Ok(path) => {
                                self.status_message = Some(format!(
                                    "Clipboard support is disabled or unavailable ({err}). Wrote to {}",
                                    path.display()
                                ));
                            }
                            Err(io_err) => {
                                self.status_message = Some(format!(
                                    "Clipboard support is disabled or unavailable ({err}); also failed to write fallback file: {io_err}"
                                ));
                            }
                        },
                    }
                }

                #[cfg(not(feature = "clipboard"))]
                {
                    match write_fallback(&text) {
                        Ok(path) => {
                            self.status_message = Some(format!(
                                "Clipboard support is disabled. Wrote to {}",
                                path.display()
                            ));
                        }
                        Err(err) => {
                            self.status_message = Some(format!(
                                "Clipboard support is disabled; failed to write fallback file: {err}"
                            ));
                        }
                    }
                }

                None
            }
            SlashCommand::Name => {
                let name = args.trim();
                if name.is_empty() {
                    self.status_message = Some("Usage: /name <name>".to_string());
                    return None;
                }

                let Ok(mut session_guard) = self.session.try_lock() else {
                    self.status_message = Some("Session busy; try again".to_string());
                    return None;
                };
                session_guard.append_session_info(Some(name.to_string()));
                drop(session_guard);
                self.spawn_save_session();

                self.status_message = Some(format!("Session name: {name}"));
                None
            }
            SlashCommand::Hotkeys => {
                self.messages.push(ConversationMessage {
                    role: MessageRole::System,
                    content: self.format_hotkeys(),
                    thinking: None,
                    collapsed: false,
                });
                self.scroll_to_bottom();
                None
            }
            SlashCommand::Changelog => {
                let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("CHANGELOG.md");
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        self.messages.push(ConversationMessage {
                            role: MessageRole::System,
                            content,
                            thinking: None,
                            collapsed: false,
                        });
                        self.scroll_to_last_match("# ");
                    }
                    Err(err) => {
                        self.status_message = Some(format!(
                            "Failed to read changelog {}: {err}",
                            path.display()
                        ));
                    }
                }
                None
            }
            SlashCommand::Tree => {
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot open tree while processing".to_string());
                    return None;
                }

                let Ok(session_guard) = self.session.try_lock() else {
                    self.status_message = Some("Session busy; try again".to_string());
                    return None;
                };
                let initial_selected_id = resolve_tree_selector_initial_id(&session_guard, args);
                let selector = TreeSelectorState::new(
                    &session_guard,
                    self.term_height,
                    initial_selected_id.as_deref(),
                );
                drop(session_guard);
                self.tree_ui = Some(TreeUiState::Selector(selector));
                None
            }
            SlashCommand::Fork => self.handle_slash_fork(args),
            SlashCommand::Compact => self.handle_slash_compact(args),
            SlashCommand::Reload => self.handle_slash_reload(),
            SlashCommand::Share => self.handle_slash_share(args),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_slash_fork(&mut self, args: &str) -> Option<Cmd> {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot fork while processing a request".to_string());
            return None;
        }

        let candidates = if let Ok(mut session_guard) = self.session.try_lock() {
            session_guard.ensure_entry_ids();
            fork_candidates(&session_guard)
        } else {
            self.status_message = Some("Session busy; try again".to_string());
            return None;
        };
        if candidates.is_empty() {
            self.status_message = Some("No user messages to fork from".to_string());
            return None;
        }

        if args.eq_ignore_ascii_case("list") || args.eq_ignore_ascii_case("ls") {
            let list = candidates
                .iter()
                .enumerate()
                .map(|(i, c)| format!("  {}. {} - {}", i + 1, c.id, c.summary))
                .collect::<Vec<_>>()
                .join("\n");
            self.messages.push(ConversationMessage {
                role: MessageRole::System,
                content: format!("Forkable user messages (use /fork <id|index>):\n{list}"),
                thinking: None,
                collapsed: false,
            });
            self.scroll_to_bottom();
            return None;
        }

        let selection = if args.is_empty() {
            candidates.last().expect("candidates is non-empty").clone()
        } else if let Ok(index) = args.parse::<usize>() {
            if index == 0 || index > candidates.len() {
                self.status_message =
                    Some(format!("Invalid index: {index} (1-{})", candidates.len()));
                return None;
            }
            candidates[index - 1].clone()
        } else {
            let matches = candidates
                .iter()
                .filter(|c| c.id == args || c.id.starts_with(args))
                .cloned()
                .collect::<Vec<_>>();
            if matches.is_empty() {
                self.status_message = Some(format!("No user message id matches \"{args}\""));
                return None;
            }
            if matches.len() > 1 {
                self.status_message = Some(format!(
                    "Ambiguous id \"{args}\" (matches {})",
                    matches.len()
                ));
                return None;
            }
            matches[0].clone()
        };

        let event_tx = self.event_tx.clone();
        let session = Arc::clone(&self.session);
        let agent = Arc::clone(&self.agent);
        let extensions = self.extensions.clone();
        let model_provider = self.model_entry.model.provider.clone();
        let model_id = self.model_entry.model.id.clone();
        let (thinking_level, session_id) = if let Ok(guard) = self.session.try_lock() {
            (guard.header.thinking_level.clone(), guard.header.id.clone())
        } else {
            self.status_message = Some("Session busy; try again".to_string());
            return None;
        };

        self.agent_state = AgentState::Processing;
        self.status_message = Some("Forking session...".to_string());

        let runtime_handle = self.runtime_handle.clone();
        runtime_handle.spawn(async move {
            let cx = Cx::for_request();
            if let Some(manager) = extensions.clone() {
                let cancelled = manager
                    .dispatch_cancellable_event(
                        ExtensionEventName::SessionBeforeFork,
                        Some(json!({
                            "entryId": selection.id.clone(),
                            "summary": selection.summary.clone(),
                            "sessionId": session_id.clone(),
                        })),
                        EXTENSION_EVENT_TIMEOUT_MS,
                    )
                    .await
                    .unwrap_or(false);
                if cancelled {
                    let _ =
                        event_tx.try_send(PiMsg::System("Fork cancelled by extension".to_string()));
                    return;
                }
            }

            let (fork_plan, parent_path, session_dir) = {
                let guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
                let fork_plan = match guard.plan_fork_from_user_message(&selection.id) {
                    Ok(plan) => plan,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to build fork: {err}")));
                        return;
                    }
                };
                let parent_path = guard.path.as_ref().map(|p| p.display().to_string());
                let session_dir = guard.session_dir.clone();
                drop(guard);
                (fork_plan, parent_path, session_dir)
            };

            let crate::session::ForkPlan {
                entries,
                leaf_id,
                selected_text,
            } = fork_plan;

            let mut new_session = Session::create_with_dir(session_dir);
            new_session.header.provider = Some(model_provider);
            new_session.header.model_id = Some(model_id);
            new_session.header.thinking_level = thinking_level;
            if let Some(parent_path) = parent_path {
                new_session.set_branched_from(Some(parent_path));
            }
            new_session.entries = entries;
            new_session.leaf_id = leaf_id;
            new_session.ensure_entry_ids();
            let new_session_id = new_session.header.id.clone();

            if let Err(err) = new_session.save().await {
                let _ = event_tx.try_send(PiMsg::AgentError(format!("Failed to save fork: {err}")));
                return;
            }

            let messages_for_agent = new_session.to_messages_for_current_path();
            {
                let mut agent_guard = match agent.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock agent: {err}")));
                        return;
                    }
                };
                agent_guard.replace_messages(messages_for_agent);
            }

            {
                let mut guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
                *guard = new_session;
            }

            let (messages, usage) = {
                let guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
                conversation_from_session(&guard)
            };

            let _ = event_tx.try_send(PiMsg::ConversationReset {
                messages,
                usage,
                status: Some(format!("Forked new session from {}", selection.summary)),
            });

            let _ = event_tx.try_send(PiMsg::SetEditorText(selected_text));

            if let Some(manager) = extensions {
                let _ = manager
                    .dispatch_event(
                        ExtensionEventName::SessionFork,
                        Some(json!({
                            "entryId": selection.id,
                            "summary": selection.summary,
                            "sessionId": session_id,
                            "newSessionId": new_session_id,
                        })),
                    )
                    .await;
            }
        });
        None
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_slash_compact(&mut self, args: &str) -> Option<Cmd> {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot compact while processing".to_string());
            return None;
        }

        let Ok(agent_guard) = self.agent.try_lock() else {
            self.status_message = Some("Agent busy; try again".to_string());
            return None;
        };
        let provider = agent_guard.provider();
        let api_key_opt = agent_guard.stream_options().api_key.clone();
        drop(agent_guard);

        let Some(api_key) = api_key_opt else {
            self.status_message = Some("No API key configured; cannot run compaction".to_string());
            return None;
        };

        let event_tx = self.event_tx.clone();
        let session = Arc::clone(&self.session);
        let agent = Arc::clone(&self.agent);
        let extensions = self.extensions.clone();
        let runtime_handle = self.runtime_handle.clone();
        let reserve_tokens = self.config.compaction_reserve_tokens();
        let keep_recent_tokens = self.config.compaction_keep_recent_tokens();
        let custom_instructions = args.trim().to_string();
        let custom_instructions = if custom_instructions.is_empty() {
            None
        } else {
            Some(custom_instructions)
        };
        let is_compacting = Arc::clone(&self.extension_compacting);

        self.agent_state = AgentState::Processing;
        self.status_message = Some("Compacting session...".to_string());
        self.extension_compacting.store(true, Ordering::SeqCst);

        runtime_handle.spawn(async move {
            let cx = Cx::for_request();

            let (session_id, path_entries) = {
                let mut guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        is_compacting.store(false, Ordering::SeqCst);
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
                guard.ensure_entry_ids();
                let session_id = guard.header.id.clone();
                let entries = guard
                    .entries_for_current_path()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
                (session_id, entries)
            };

            if let Some(manager) = extensions.clone() {
                let cancelled = manager
                    .dispatch_cancellable_event(
                        ExtensionEventName::SessionBeforeCompact,
                        Some(json!({
                            "sessionId": session_id,
                            "notes": custom_instructions.as_deref(),
                        })),
                        EXTENSION_EVENT_TIMEOUT_MS,
                    )
                    .await
                    .unwrap_or(false);
                if cancelled {
                    is_compacting.store(false, Ordering::SeqCst);
                    let _ = event_tx.try_send(PiMsg::System(
                        "Compaction cancelled by extension".to_string(),
                    ));
                    return;
                }
            }

            let settings = crate::compaction::ResolvedCompactionSettings {
                enabled: true,
                reserve_tokens,
                keep_recent_tokens,
                ..Default::default()
            };
            let Some(prep) = crate::compaction::prepare_compaction(&path_entries, settings) else {
                is_compacting.store(false, Ordering::SeqCst);
                let _ = event_tx.try_send(PiMsg::System(
                    "Nothing to compact (already compacted or too little history)".to_string(),
                ));
                return;
            };

            let result = match crate::compaction::compact(
                prep,
                Arc::clone(&provider),
                &api_key,
                custom_instructions.as_deref(),
            )
            .await
            {
                Ok(result) => result,
                Err(err) => {
                    is_compacting.store(false, Ordering::SeqCst);
                    let _ =
                        event_tx.try_send(PiMsg::AgentError(format!("Compaction failed: {err}")));
                    return;
                }
            };

            let details = crate::compaction::compaction_details_to_value(&result.details).ok();

            let messages_for_agent = {
                let mut guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        is_compacting.store(false, Ordering::SeqCst);
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };

                guard.append_compaction(
                    result.summary.clone(),
                    result.first_kept_entry_id.clone(),
                    result.tokens_before,
                    details,
                    None,
                );
                let _ = guard.save().await;
                guard.to_messages_for_current_path()
            };

            {
                let mut agent_guard = match agent.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        is_compacting.store(false, Ordering::SeqCst);
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock agent: {err}")));
                        return;
                    }
                };
                agent_guard.replace_messages(messages_for_agent);
            }

            let (messages, usage) = {
                let guard = match session.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(err) => {
                        is_compacting.store(false, Ordering::SeqCst);
                        let _ = event_tx
                            .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                        return;
                    }
                };
                conversation_from_session(&guard)
            };

            is_compacting.store(false, Ordering::SeqCst);
            let _ = event_tx.try_send(PiMsg::ConversationReset {
                messages,
                usage,
                status: Some("Compaction complete".to_string()),
            });

            if let Some(manager) = extensions {
                let _ = manager
                    .dispatch_event(
                        ExtensionEventName::SessionCompact,
                        Some(json!({
                            "tokensBefore": result.tokens_before,
                            "firstKeptEntryId": result.first_kept_entry_id,
                        })),
                    )
                    .await;
            }
        });
        None
    }

    pub(super) fn handle_slash_reload(&mut self) -> Option<Cmd> {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot reload while processing".to_string());
            return None;
        }

        let config = self.config.clone();
        let cli = self.resource_cli.clone();
        let cwd = self.cwd.clone();
        let event_tx = self.event_tx.clone();
        let runtime_handle = self.runtime_handle.clone();

        runtime_handle.spawn(async move {
            let manager = PackageManager::new(cwd.clone());
            match ResourceLoader::load(&manager, &cwd, &config, &cli).await {
                Ok(resources) => {
                    let models_error =
                        match crate::auth::AuthStorage::load_async(Config::auth_path()).await {
                            Ok(auth) => {
                                let models_path = default_models_path(&Config::global_dir());
                                let registry = ModelRegistry::load(&auth, Some(models_path));
                                registry.error().map(ToString::to_string)
                            }
                            Err(err) => Some(format!("Failed to load auth.json: {err}")),
                        };

                    let (diagnostics, diag_count) =
                        build_reload_diagnostics(models_error, &resources);

                    let mut status = format!(
                        "Reloaded resources: {} skills, {} prompts, {} themes",
                        resources.skills().len(),
                        resources.prompts().len(),
                        resources.themes().len()
                    );
                    if diag_count > 0 {
                        let _ = write!(status, " ({diag_count} diagnostics)");
                    }

                    let _ = event_tx.try_send(PiMsg::ResourcesReloaded {
                        resources,
                        status,
                        diagnostics,
                    });
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(format!(
                        "Failed to reload resources: {err}"
                    )));
                }
            }
        });

        self.status_message = Some("Reloading resources...".to_string());
        None
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_slash_share(&mut self, args: &str) -> Option<Cmd> {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot share while processing".to_string());
            return None;
        }

        let is_public = parse_share_is_public(args);

        self.agent_state = AgentState::Processing;
        self.status_message = Some("Sharing session... (Esc to cancel)".to_string());

        let (abort_handle, abort_signal) = AbortHandle::new();
        self.abort_handle = Some(abort_handle);

        let event_tx = self.event_tx.clone();
        let runtime_handle = self.runtime_handle.clone();
        let session = Arc::clone(&self.session);
        let cwd = self.cwd.clone();
        let gh_path_override = self.config.gh_path.clone();

        runtime_handle.spawn(async move {
            let gh = gh_path_override
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "gh".to_string());

            let auth_args = vec![OsString::from("auth"), OsString::from("status")];
            match run_command_output(&gh, &auth_args, &cwd, &abort_signal) {
                Ok(output) => {
                    if !output.status.success() {
                        let details = format_command_output(&output);
                        let message = format!(
                            "`gh` is not authenticated.\n\
                             Run `gh auth login` to authenticate, then retry `/share`.\n\n\
                             {details}"
                        );
                        let _ = event_tx.try_send(PiMsg::AgentError(message));
                        return;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    let message = "GitHub CLI `gh` not found.\n\
                             Install it from https://cli.github.com, then run `gh auth login`."
                        .to_string();
                    let _ = event_tx.try_send(PiMsg::AgentError(message));
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    let _ = event_tx.try_send(PiMsg::System("Share cancelled".to_string()));
                    return;
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(format!(
                        "Failed to run `gh auth status`: {err}"
                    )));
                    return;
                }
            }

            if abort_signal.is_aborted() {
                let _ = event_tx.try_send(PiMsg::System("Share cancelled".to_string()));
                return;
            }

            let cx = Cx::for_request();
            let (html, session_name) = match session.lock(&cx).await {
                Ok(guard) => (guard.to_html(), guard.get_name()),
                Err(err) => {
                    let _ = event_tx
                        .try_send(PiMsg::AgentError(format!("Failed to lock session: {err}")));
                    return;
                }
            };

            if abort_signal.is_aborted() {
                let _ = event_tx.try_send(PiMsg::System("Share cancelled".to_string()));
                return;
            }

            let gist_desc = share_gist_description(session_name.as_deref());

            let temp_file = match tempfile::Builder::new()
                .prefix("pi-share-")
                .suffix(".html")
                .tempfile()
            {
                Ok(file) => file,
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(format!(
                        "Failed to create temp file: {err}"
                    )));
                    return;
                }
            };
            let temp_path = temp_file.into_temp_path();
            if let Err(err) = std::fs::write(&temp_path, html.as_bytes()) {
                let _ = event_tx.try_send(PiMsg::AgentError(format!(
                    "Failed to write temp file: {err}"
                )));
                return;
            }

            let gist_args = vec![
                OsString::from("gist"),
                OsString::from("create"),
                OsString::from(format!("--public={is_public}")),
                OsString::from("--desc"),
                OsString::from(&gist_desc),
                temp_path.as_os_str().to_os_string(),
            ];
            let output = match run_command_output(&gh, &gist_args, &cwd, &abort_signal) {
                Ok(output) => output,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    let message = "GitHub CLI `gh` not found.\n\
                             Install it from https://cli.github.com, then run `gh auth login`."
                        .to_string();
                    let _ = event_tx.try_send(PiMsg::AgentError(message));
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    let _ = event_tx.try_send(PiMsg::System("Share cancelled".to_string()));
                    return;
                }
                Err(err) => {
                    let _ = event_tx.try_send(PiMsg::AgentError(format!(
                        "Failed to run `gh gist create`: {err}"
                    )));
                    return;
                }
            };

            if !output.status.success() {
                let details = format_command_output(&output);
                let _ = event_tx.try_send(PiMsg::AgentError(format!(
                    "`gh gist create` failed.\n\n{details}"
                )));
                return;
            }

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let Some((gist_url, gist_id)) = parse_gist_url_and_id(&stdout) else {
                let details = format_command_output(&output);
                let _ = event_tx.try_send(PiMsg::AgentError(format!(
                    "Failed to parse gist URL from `gh gist create` output.\n\n{details}"
                )));
                return;
            };

            let share_url = crate::session::get_share_viewer_url(&gist_id);
            drop(temp_path);

            // Copy viewer URL to clipboard (best-effort).
            #[cfg(feature = "clipboard")]
            {
                let _ = ClipboardProvider::new()
                    .and_then(|mut ctx: ClipboardContext| ctx.set_contents(share_url.clone()));
            }

            let privacy = if is_public { "public" } else { "private" };
            let message =
                format!("Created {privacy} gist\nShare URL: {share_url}\nGist: {gist_url}");
            let _ = event_tx.try_send(PiMsg::System(message));
        });
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bash_command, parse_extension_command};

    #[test]
    fn parse_ext_cmd_basic() {
        let result = parse_extension_command("/deploy");
        assert_eq!(result, Some(("deploy".to_string(), vec![])));
    }

    #[test]
    fn parse_ext_cmd_with_args() {
        let result = parse_extension_command("/deploy staging fast");
        assert_eq!(
            result,
            Some((
                "deploy".to_string(),
                vec!["staging".to_string(), "fast".to_string()]
            ))
        );
    }

    #[test]
    fn parse_ext_cmd_builtin_filtered() {
        assert!(parse_extension_command("/help").is_none());
        assert!(parse_extension_command("/clear").is_none());
        assert!(parse_extension_command("/model").is_none());
        assert!(parse_extension_command("/exit").is_none());
        assert!(parse_extension_command("/compact").is_none());
    }

    #[test]
    fn parse_ext_cmd_no_slash() {
        assert!(parse_extension_command("deploy").is_none());
        assert!(parse_extension_command("hello world").is_none());
    }

    #[test]
    fn parse_ext_cmd_empty_slash() {
        assert!(parse_extension_command("/").is_none());
        assert!(parse_extension_command("/  ").is_none());
    }

    #[test]
    fn parse_ext_cmd_whitespace_trimming() {
        let result = parse_extension_command("  /deploy  arg1  arg2  ");
        assert_eq!(
            result,
            Some((
                "deploy".to_string(),
                vec!["arg1".to_string(), "arg2".to_string()]
            ))
        );
    }

    #[test]
    fn parse_ext_cmd_single_arg() {
        let result = parse_extension_command("/greet world");
        assert_eq!(
            result,
            Some(("greet".to_string(), vec!["world".to_string()]))
        );
    }

    #[test]
    fn parse_bash_command_distinguishes_exclusion() {
        let (command, exclude) = parse_bash_command("! ls -la").expect("bang command");
        assert_eq!(command, "ls -la");
        assert!(!exclude);

        let (command, exclude) = parse_bash_command("!! ls -la").expect("double bang command");
        assert_eq!(command, "ls -la");
        assert!(exclude);
    }

    #[test]
    fn parse_bash_command_empty_bang() {
        assert!(parse_bash_command("!").is_none());
        assert!(parse_bash_command("!!").is_none());
        assert!(parse_bash_command("!  ").is_none());
    }

    #[test]
    fn parse_bash_command_no_bang() {
        assert!(parse_bash_command("ls -la").is_none());
        assert!(parse_bash_command("").is_none());
    }

    #[test]
    fn parse_bash_command_leading_whitespace() {
        let (cmd, exclude) = parse_bash_command("  ! echo hi").expect("should parse");
        assert_eq!(cmd, "echo hi");
        assert!(!exclude);
    }
}
