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
                    let models_error = match crate::auth::AuthStorage::load_async(Config::auth_path())
                        .await
                    {
                        Ok(auth) => {
                            let models_path = default_models_path(&Config::global_dir());
                            let registry = ModelRegistry::load(&auth, Some(models_path));
                            registry.error().map(ToString::to_string)
                        }
                        Err(err) => Some(format!("Failed to load auth.json: {err}")),
                    };

                    let (diagnostics, diag_count) = build_reload_diagnostics(models_error, &resources);

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
                    let _ = event_tx
                        .try_send(PiMsg::AgentError(format!("Failed to reload resources: {err}")));
                }
            }
        });

        self.status_message = Some("Reloading resources...".to_string());
        None
    }

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
                    let _ = event_tx
                        .try_send(PiMsg::AgentError(format!("Failed to run `gh auth status`: {err}")));
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
                    let _ = event_tx
                        .try_send(PiMsg::AgentError(format!("Failed to create temp file: {err}")));
                    return;
                }
            };
            let temp_path = temp_file.into_temp_path();
            if let Err(err) = std::fs::write(&temp_path, html.as_bytes()) {
                let _ = event_tx
                    .try_send(PiMsg::AgentError(format!("Failed to write temp file: {err}")));
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
                    let _ = event_tx
                        .try_send(PiMsg::AgentError(format!("Failed to run `gh gist create`: {err}")));
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
            let message = format!("Created {privacy} gist\nShare URL: {share_url}\nGist: {gist_url}");
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
