use super::commands::model_entry_matches;
use super::*;

impl PiApp {
    fn available_models_with_credentials(&self) -> Vec<ModelEntry> {
        let auth = crate::auth::AuthStorage::load(crate::config::Config::auth_path()).ok();
        let mut filtered = self
            .available_models
            .iter()
            .filter(|entry| {
                entry
                    .api_key
                    .as_ref()
                    .is_some_and(|key| !key.trim().is_empty())
                    || auth
                        .as_ref()
                        .and_then(|storage| storage.resolve_api_key(&entry.model.provider, None))
                        .is_some()
            })
            .cloned()
            .collect::<Vec<_>>();

        filtered.sort_by(|a, b| {
            a.model
                .provider
                .cmp(&b.model.provider)
                .then_with(|| a.model.id.cmp(&b.model.id))
        });
        filtered.dedup_by(|left, right| model_entry_matches(left, right));
        filtered
    }

    /// Open the model selector overlay.
    pub fn open_model_selector(&mut self) {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot switch models while processing".to_string());
            return;
        }

        if self.available_models.is_empty() {
            self.status_message = Some("No models available".to_string());
            return;
        }

        self.model_selector = Some(crate::model_selector::ModelSelectorOverlay::new(
            &self.available_models,
        ));
    }

    pub(super) fn open_model_selector_configured_only(&mut self) {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot switch models while processing".to_string());
            return;
        }

        if self.available_models.is_empty() {
            self.status_message = Some("No models available".to_string());
            return;
        }

        let filtered = self.available_models_with_credentials();
        if filtered.is_empty() {
            self.status_message = Some(
                "No models with configured API keys. Use /login <provider> to configure credentials."
                    .to_string(),
            );
            return;
        }

        let mut overlay = crate::model_selector::ModelSelectorOverlay::new(&filtered);
        overlay.set_configured_only_scope(self.available_models.len());
        self.model_selector = Some(overlay);
    }

    /// Handle keyboard input while the model selector is open.
    pub fn handle_model_selector_key(&mut self, key: &KeyMsg) -> Option<Cmd> {
        let selector = self.model_selector.as_mut()?;

        match key.key_type {
            KeyType::Up => selector.select_prev(),
            KeyType::Down => selector.select_next(),
            KeyType::Runes if key.runes == ['k'] => selector.select_prev(),
            KeyType::Runes if key.runes == ['j'] => selector.select_next(),
            KeyType::PgDown => selector.select_page_down(),
            KeyType::PgUp => selector.select_page_up(),
            KeyType::Backspace => selector.pop_char(),
            KeyType::Runes => selector.push_chars(key.runes.iter().copied()),
            KeyType::Enter => {
                let selected = selector.selected_item().cloned();
                self.model_selector = None;
                if let Some(selected) = selected {
                    self.apply_model_selection(&selected);
                } else {
                    self.status_message = Some("No model selected".to_string());
                }
                return None;
            }
            KeyType::Esc | KeyType::CtrlC => {
                self.model_selector = None;
                self.status_message = Some("Model selector cancelled".to_string());
            }
            _ => {} // consume all other input while selector is open
        }

        None
    }

    /// Apply a model selection from the model selector overlay.
    fn apply_model_selection(&mut self, selected: &crate::model_selector::ModelKey) {
        // Find the matching ModelEntry from available_models
        let entry = self
            .available_models
            .iter()
            .find(|e| {
                e.model.provider.eq_ignore_ascii_case(&selected.provider)
                    && e.model.id.eq_ignore_ascii_case(&selected.id)
            })
            .cloned();

        let Some(next) = entry else {
            self.status_message = Some(format!("Model {} not found", selected.full_id()));
            return;
        };

        if model_entry_matches(&next, &self.model_entry) {
            self.status_message = Some(format!("Already using {}", selected.full_id()));
            return;
        }

        let provider_impl = match providers::create_provider(&next, self.extensions.as_ref()) {
            Ok(p) => p,
            Err(err) => {
                self.status_message = Some(err.to_string());
                return;
            }
        };

        let Ok(mut agent_guard) = self.agent.try_lock() else {
            self.status_message = Some("Agent busy; try again".to_string());
            return;
        };
        agent_guard.set_provider(provider_impl);
        drop(agent_guard);

        let Ok(mut session_guard) = self.session.try_lock() else {
            self.status_message = Some("Session busy; try again".to_string());
            return;
        };
        session_guard.header.provider = Some(next.model.provider.clone());
        session_guard.header.model_id = Some(next.model.id.clone());
        session_guard.append_model_change(next.model.provider.clone(), next.model.id.clone());
        drop(session_guard);
        self.spawn_save_session();

        self.model_entry = next.clone();
        if let Ok(mut guard) = self.model_entry_shared.lock() {
            *guard = next;
        }
        self.model = format!(
            "{}/{}",
            self.model_entry.model.provider, self.model_entry.model.id
        );
        self.status_message = Some(format!("Switched model: {}", self.model));
    }

    /// Render the model selector overlay.
    pub(super) fn render_model_selector(
        &self,
        selector: &crate::model_selector::ModelSelectorOverlay,
    ) -> String {
        use std::fmt::Write;
        let mut output = String::new();

        let _ = writeln!(output, "\n  {}", self.styles.title.render("Select a model"));
        if selector.configured_only() {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.muted.render(
                    "Only showing models with configured API keys (see README for details)"
                )
            );
        }

        // Search field
        let query = selector.query();
        let search_line = if query.is_empty() {
            if selector.configured_only() {
                "  >".to_string()
            } else {
                "  > (type to filter)".to_string()
            }
        } else {
            format!("  > {query}")
        };
        let _ = writeln!(output, "{}", self.styles.muted.render(&search_line));

        let _ = writeln!(
            output,
            "  {}",
            self.styles.muted.render("─".repeat(50).as_str())
        );

        if selector.filtered_len() == 0 {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.muted_italic.render("No matching models.")
            );
        } else {
            let offset = selector.scroll_offset();
            let visible_count = selector.max_visible().min(selector.filtered_len());
            let end = (offset + visible_count).min(selector.filtered_len());

            let current_full = format!(
                "{}/{}",
                self.model_entry.model.provider, self.model_entry.model.id
            );

            for idx in offset..end {
                let is_selected = idx == selector.selected_index();
                let prefix = if is_selected { ">" } else { " " };

                if let Some(key) = selector.item_at(idx) {
                    let full = key.full_id();
                    let is_current = full.eq_ignore_ascii_case(&current_full);
                    let marker = if is_current { " *" } else { "" };
                    let row = format!("{prefix} {full}{marker}");
                    let rendered = if is_selected {
                        self.styles.accent_bold.render(&row)
                    } else if is_current {
                        self.styles.accent.render(&row)
                    } else {
                        self.styles.muted.render(&row)
                    };
                    let _ = writeln!(output, "  {rendered}");
                }
            }

            if selector.filtered_len() > visible_count {
                let _ = writeln!(
                    output,
                    "  {}",
                    self.styles.muted.render(&format!(
                        "({}-{} of {})",
                        offset + 1,
                        end,
                        selector.filtered_len()
                    ))
                );
            }

            if selector.configured_only() {
                let _ = writeln!(
                    output,
                    "  {}",
                    self.styles.muted.render(&format!(
                        "({}/{})",
                        selector.filtered_len(),
                        selector.source_total()
                    ))
                );
            }

            if let Some(selected) = selector.selected_item()
                && let Some(entry) = self.available_models.iter().find(|entry| {
                    entry
                        .model
                        .provider
                        .eq_ignore_ascii_case(&selected.provider)
                        && entry.model.id.eq_ignore_ascii_case(&selected.id)
                })
            {
                let _ = writeln!(
                    output,
                    "\n  {}",
                    self.styles
                        .muted
                        .render(&format!("Model Name: {}", entry.model.name))
                );
            }
        }

        let _ = writeln!(
            output,
            "\n  {}",
            self.styles
                .muted_italic
                .render("↑/↓/j/k: navigate  Enter: select  Esc: cancel  * = current")
        );
        output
    }
}
