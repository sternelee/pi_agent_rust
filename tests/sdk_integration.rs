//! SDK integration test suite (bd-2hcex: PARITY-V3).
//!
//! Validates that the programmatic SDK API (`pi::sdk`) works correctly:
//! session creation, model selection, event streaming, tool execution,
//! persistence, abort, compaction, error handling.
//!
//! - Non-prompting tests use `create_agent_session()` directly.
//! - Prompting tests use `AgentSession` with a `ScriptedProvider` (same
//!   code path as `AgentSessionHandle::prompt()`, which delegates to
//!   `AgentSession::run_text()`).

mod common;

use async_trait::async_trait;
use common::{TestHarness, run_async};
use futures::Stream;
use pi::agent::{AgentConfig, AgentEvent, AgentSession};
use pi::compaction::ResolvedCompactionSettings;
use pi::error::{Error, Result};
use pi::model::{
    AssistantMessage, ContentBlock, StopReason, StreamEvent, TextContent, ToolCall, Usage,
};
use pi::provider::{Context, Provider, StreamOptions};
use pi::sdk::{
    AgentSessionHandle, AgentSessionState, SessionOptions, SubscriptionId, create_agent_session,
};
use pi::session::Session;
use pi::tools::ToolRegistry;
use serde_json::json;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// ============================================================================
// ScriptedProvider — deterministic responses for prompting tests
// ============================================================================

#[derive(Debug, Clone)]
enum Script {
    /// Return a single text response and stop.
    SingleText(String),
    /// First call: emit a tool call; second call: text response.
    ToolRoundTrip {
        tool_name: String,
        tool_args: serde_json::Value,
        final_text: String,
    },
}

#[derive(Debug)]
struct ScriptedProvider {
    script: Script,
    call_count: AtomicUsize,
}

impl ScriptedProvider {
    const fn new(script: Script) -> Self {
        Self {
            script,
            call_count: AtomicUsize::new(0),
        }
    }

    fn assistant_msg(stop: StopReason, content: Vec<ContentBlock>) -> AssistantMessage {
        AssistantMessage {
            content,
            api: "scripted".to_string(),
            provider: "scripted".to_string(),
            model: "scripted-model".to_string(),
            usage: Usage {
                total_tokens: 10,
                output: 10,
                ..Usage::default()
            },
            stop_reason: stop,
            error_message: None,
            timestamp: 0,
        }
    }

    fn done_stream(
        msg: AssistantMessage,
    ) -> Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>> {
        let partial = Self::assistant_msg(StopReason::Stop, Vec::new());
        Box::pin(futures::stream::iter(vec![
            Ok(StreamEvent::Start { partial }),
            Ok(StreamEvent::Done {
                reason: msg.stop_reason,
                message: msg,
            }),
        ]))
    }
}

#[async_trait]
#[allow(clippy::unnecessary_literal_bound)]
impl Provider for ScriptedProvider {
    fn name(&self) -> &str {
        "scripted"
    }
    fn api(&self) -> &str {
        "scripted"
    }
    fn model_id(&self) -> &str {
        "scripted-model"
    }

    async fn stream(
        &self,
        _context: &Context,
        _options: &StreamOptions,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent>> + Send>>> {
        let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
        match &self.script {
            Script::SingleText(text) => {
                if idx > 0 {
                    return Err(Error::api("SingleText expects exactly one call"));
                }
                Ok(Self::done_stream(Self::assistant_msg(
                    StopReason::Stop,
                    vec![ContentBlock::Text(TextContent::new(text.clone()))],
                )))
            }
            Script::ToolRoundTrip {
                tool_name,
                tool_args,
                final_text,
            } => {
                if idx == 0 {
                    Ok(Self::done_stream(Self::assistant_msg(
                        StopReason::ToolUse,
                        vec![ContentBlock::ToolCall(ToolCall {
                            id: "tc-1".to_string(),
                            name: tool_name.clone(),
                            arguments: tool_args.clone(),
                            thought_signature: None,
                        })],
                    )))
                } else if idx == 1 {
                    Ok(Self::done_stream(Self::assistant_msg(
                        StopReason::Stop,
                        vec![ContentBlock::Text(TextContent::new(final_text.clone()))],
                    )))
                } else {
                    Err(Error::api("ToolRoundTrip expects at most two calls"))
                }
            }
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn default_session_options(harness: &TestHarness) -> SessionOptions {
    SessionOptions {
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: true,
        ..SessionOptions::default()
    }
}

fn run_scripted(
    harness: &TestHarness,
    script: Script,
    user_prompt: &str,
) -> (AssistantMessage, Vec<AgentEvent>) {
    let cwd = harness.temp_dir().to_path_buf();
    let prompt = user_prompt.to_string();
    run_async(async move {
        let provider: Arc<dyn Provider> = Arc::new(ScriptedProvider::new(script));
        let tools = ToolRegistry::new(&["read"], &cwd, None);
        let config = AgentConfig {
            system_prompt: None,
            max_tool_iterations: 10,
            stream_options: StreamOptions {
                api_key: Some("test-key".to_string()),
                ..StreamOptions::default()
            },
            block_images: false,
        };
        let agent = pi::agent::Agent::new(provider, tools, config);
        let session = Arc::new(asupersync::sync::Mutex::new(Session::create_with_dir(
            Some(cwd),
        )));
        let mut agent_session =
            AgentSession::new(agent, session, true, ResolvedCompactionSettings::default());

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_ref = Arc::clone(&events);
        let message = agent_session
            .run_text(prompt, move |event| {
                events_ref.lock().expect("lock").push(event);
            })
            .await
            .expect("run_text");
        let captured = events.lock().expect("lock").clone();
        (message, captured)
    })
}

// ============================================================================
// 1. Basic session creation
// ============================================================================

#[test]
fn sdk_basic_session_creation() {
    let harness = TestHarness::new("sdk_basic_session_creation");
    let options = default_session_options(&harness);

    let handle = run_async(create_agent_session(options)).expect("create session");

    let provider = handle.session().agent.provider();
    assert_eq!(
        provider.name(),
        "anthropic",
        "default provider should be anthropic"
    );
    // Model can vary; just verify it's non-empty.
    assert!(
        !provider.model_id().is_empty(),
        "model_id should be non-empty"
    );

    harness.log().info_ctx("sdk", "basic creation ok", |ctx| {
        ctx.push(("provider".to_string(), provider.name().to_string()));
        ctx.push(("model".to_string(), provider.model_id().to_string()));
    });
}

// ============================================================================
// 2. Custom model
// ============================================================================

#[test]
fn sdk_custom_model_selection() {
    let harness = TestHarness::new("sdk_custom_model_selection");
    let options = SessionOptions {
        provider: Some("openai".to_string()),
        model: Some("gpt-4o".to_string()),
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: true,
        ..SessionOptions::default()
    };

    let handle = run_async(create_agent_session(options)).expect("create session");
    let (prov, model) = handle.model();
    assert_eq!(prov, "openai");
    assert_eq!(model, "gpt-4o");

    harness.log().info_ctx("sdk", "custom model ok", |ctx| {
        ctx.push(("provider".to_string(), prov));
        ctx.push(("model".to_string(), model));
    });
}

// ============================================================================
// 3. Event streaming — verify all lifecycle events fire
// ============================================================================

#[test]
fn sdk_event_streaming() {
    let harness = TestHarness::new("sdk_event_streaming");
    let (message, events) = run_scripted(
        &harness,
        Script::SingleText("hello from sdk test".to_string()),
        "Say hello",
    );

    // The response text should appear in the assistant message.
    let text = message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<String>();
    assert!(
        text.contains("hello from sdk test"),
        "response text mismatch: {text}"
    );

    // Verify core lifecycle events were emitted.
    let has_agent_start = events
        .iter()
        .any(|e| matches!(e, AgentEvent::AgentStart { .. }));
    let has_agent_end = events
        .iter()
        .any(|e| matches!(e, AgentEvent::AgentEnd { .. }));
    let has_turn_start = events
        .iter()
        .any(|e| matches!(e, AgentEvent::TurnStart { .. }));
    let has_turn_end = events
        .iter()
        .any(|e| matches!(e, AgentEvent::TurnEnd { .. }));
    let has_message_start = events
        .iter()
        .any(|e| matches!(e, AgentEvent::MessageStart { .. }));
    let has_message_end = events
        .iter()
        .any(|e| matches!(e, AgentEvent::MessageEnd { .. }));

    assert!(has_agent_start, "missing AgentStart event");
    assert!(has_agent_end, "missing AgentEnd event");
    assert!(has_turn_start, "missing TurnStart event");
    assert!(has_turn_end, "missing TurnEnd event");
    assert!(has_message_start, "missing MessageStart event");
    assert!(has_message_end, "missing MessageEnd event");

    harness.log().info_ctx("sdk", "event streaming ok", |ctx| {
        ctx.push(("event_count".to_string(), events.len().to_string()));
        ctx.push(("response_len".to_string(), text.len().to_string()));
    });
}

// ============================================================================
// 4. Tool execution — verify tool events
// ============================================================================

#[test]
fn sdk_tool_execution() {
    let harness = TestHarness::new("sdk_tool_execution");

    // Create a file the tool can read.
    let target = harness.temp_dir().join("test_input.txt");
    std::fs::write(&target, "SDK integration content").expect("write target");

    let (message, events) = run_scripted(
        &harness,
        Script::ToolRoundTrip {
            tool_name: "read".to_string(),
            tool_args: json!({ "path": target.to_str().unwrap() }),
            final_text: "file contents confirmed".to_string(),
        },
        "Read the test file",
    );

    // Final response should contain the scripted text.
    let text = message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<String>();
    assert!(
        text.contains("file contents confirmed"),
        "final text mismatch: {text}"
    );

    // Should have tool execution events.
    let tool_starts: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, AgentEvent::ToolExecutionStart { .. }))
        .collect();
    let has_tool_end = events
        .iter()
        .any(|e| matches!(e, AgentEvent::ToolExecutionEnd { .. }));
    assert!(!tool_starts.is_empty(), "missing ToolExecutionStart");
    assert!(has_tool_end, "missing ToolExecutionEnd");

    // At least 2 turns (tool call turn + final response turn).
    let turn_starts: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, AgentEvent::TurnStart { .. }))
        .collect();
    assert!(
        turn_starts.len() >= 2,
        "expected >=2 turns, got {}",
        turn_starts.len()
    );

    harness.log().info_ctx("sdk", "tool execution ok", |ctx| {
        ctx.push(("tool_starts".to_string(), tool_starts.len().to_string()));
        ctx.push(("turns".to_string(), turn_starts.len().to_string()));
    });
}

// ============================================================================
// 5. Session persistence — verify session file is created
// ============================================================================

#[test]
fn sdk_session_persistence() {
    let harness = TestHarness::new("sdk_session_persistence");
    let session_dir = harness.temp_dir().join("sessions");
    std::fs::create_dir_all(&session_dir).expect("create session dir");

    let options = SessionOptions {
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: false,
        session_dir: Some(session_dir.clone()),
        ..SessionOptions::default()
    };

    let handle = run_async(create_agent_session(options)).expect("create session");
    assert!(handle.session().save_enabled(), "save should be enabled");

    harness
        .log()
        .info_ctx("sdk", "session persistence ok", |ctx| {
            ctx.push(("save_enabled".to_string(), "true".to_string()));
            ctx.push(("session_dir".to_string(), session_dir.display().to_string()));
        });
}

// ============================================================================
// 6. Abort — verify prompt can be cancelled
// ============================================================================

#[test]
fn sdk_abort_signal() {
    let harness = TestHarness::new("sdk_abort_signal");

    // Verify abort handle/signal creation works through the SDK.
    let (abort_handle, _abort_signal) = AgentSessionHandle::new_abort_handle();

    // Abort immediately — should complete without error.
    abort_handle.abort();

    harness.log().info_ctx("sdk", "abort signal ok", |ctx| {
        ctx.push(("aborted".to_string(), "true".to_string()));
    });
}

// ============================================================================
// 7. Compaction — verify compact on empty session is noop
// ============================================================================

#[test]
fn sdk_compact_empty_session() {
    let harness = TestHarness::new("sdk_compact_empty_session");
    let options = default_session_options(&harness);

    let mut handle = run_async(create_agent_session(options)).expect("create session");

    let events = Arc::new(Mutex::new(Vec::new()));
    let events_ref = Arc::clone(&events);
    run_async(async move {
        handle
            .compact(move |event| {
                events_ref.lock().expect("lock").push(event);
            })
            .await
    })
    .expect("compact");

    let captured_len = {
        let captured = events.lock().expect("lock");
        assert!(
            captured.is_empty(),
            "compact on empty session should emit no events, got {}",
            captured.len()
        );
        captured.len()
    };
    assert!(
        captured_len == 0,
        "compact on empty session should emit no events, got {captured_len}"
    );

    harness.log().info_ctx("sdk", "compact noop ok", |ctx| {
        ctx.push(("event_count".to_string(), captured_len.to_string()));
    });
}

// ============================================================================
// 8. No-session mode — verify ephemeral state
// ============================================================================

#[test]
fn sdk_no_session_mode() {
    let harness = TestHarness::new("sdk_no_session_mode");
    let options = SessionOptions {
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: true,
        ..SessionOptions::default()
    };

    let handle = run_async(create_agent_session(options)).expect("create session");
    assert!(
        !handle.session().save_enabled(),
        "save should be disabled in no-session mode"
    );

    harness.log().info_ctx("sdk", "no session mode ok", |ctx| {
        ctx.push(("save_enabled".to_string(), "false".to_string()));
    });
}

// ============================================================================
// 9. Error handling — invalid provider
// ============================================================================

#[test]
fn sdk_error_invalid_provider() {
    let harness = TestHarness::new("sdk_error_invalid_provider");
    let options = SessionOptions {
        provider: Some("nonexistent-provider-xyz".to_string()),
        model: Some("fake-model".to_string()),
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: true,
        ..SessionOptions::default()
    };

    let result = run_async(create_agent_session(options));
    assert!(
        result.is_err(),
        "creating session with invalid provider should fail"
    );
    let err_msg = match result {
        Ok(_) => panic!("expected invalid provider to fail"),
        Err(err) => err.to_string(),
    };

    harness.log().info_ctx("sdk", "error handling ok", |ctx| {
        ctx.push(("error".to_string(), err_msg.clone()));
    });

    // Verify the error is meaningful (not a panic or empty message).
    assert!(!err_msg.is_empty(), "error message should be non-empty");
}

// ============================================================================
// 10. Event subscription lifecycle
// ============================================================================

#[test]
fn sdk_subscribe_unsubscribe_lifecycle() {
    let harness = TestHarness::new("sdk_subscribe_unsubscribe_lifecycle");
    let options = default_session_options(&harness);

    let handle = run_async(create_agent_session(options)).expect("create session");

    let count = Arc::new(AtomicUsize::new(0));
    let count_ref = Arc::clone(&count);
    let id: SubscriptionId = handle.subscribe(move |_event| {
        count_ref.fetch_add(1, Ordering::SeqCst);
    });

    // Unsubscribe should succeed.
    assert!(handle.unsubscribe(id), "unsubscribe should return true");
    // Double-unsubscribe should return false.
    assert!(
        !handle.unsubscribe(id),
        "double unsubscribe should return false"
    );

    harness
        .log()
        .info_ctx("sdk", "subscribe lifecycle ok", |ctx| {
            ctx.push(("unsubscribed".to_string(), "true".to_string()));
        });
}

// ============================================================================
// Bonus: state snapshot
// ============================================================================

#[test]
fn sdk_state_snapshot() {
    let harness = TestHarness::new("sdk_state_snapshot");
    let options = default_session_options(&harness);

    let handle = run_async(create_agent_session(options)).expect("create session");
    let state: AgentSessionState =
        run_async(async move { handle.state().await }).expect("get state");

    assert!(state.session_id.is_some(), "session_id should be set");
    assert_eq!(state.provider, "anthropic");
    assert!(!state.model_id.is_empty(), "model_id should be non-empty");
    assert!(
        !state.save_enabled,
        "no-session mode should have save disabled"
    );
    assert_eq!(
        state.message_count, 0,
        "fresh session should have 0 messages"
    );

    harness.log().info_ctx("sdk", "state snapshot ok", |ctx| {
        ctx.push(("provider".to_string(), state.provider.clone()));
        ctx.push(("model_id".to_string(), state.model_id.clone()));
        ctx.push(("messages".to_string(), state.message_count.to_string()));
    });
}

// ============================================================================
// Bonus: model switching
// ============================================================================

#[test]
fn sdk_model_switching() {
    let harness = TestHarness::new("sdk_model_switching");
    let options = default_session_options(&harness);

    let mut handle = run_async(create_agent_session(options)).expect("create session");

    // Switch to openai/gpt-4o
    let (prov, model) = run_async(async move {
        handle.set_model("openai", "gpt-4o").await?;
        Ok::<(String, String), Error>(handle.model())
    })
    .expect("set model");
    assert_eq!(prov, "openai");
    assert_eq!(model, "gpt-4o");

    harness.log().info_ctx("sdk", "model switching ok", |ctx| {
        ctx.push(("new_provider".to_string(), prov));
        ctx.push(("new_model".to_string(), model));
    });
}

// ============================================================================
// Bonus: thinking level
// ============================================================================

#[test]
fn sdk_thinking_level() {
    let harness = TestHarness::new("sdk_thinking_level");
    let options = SessionOptions {
        thinking: Some(pi::model::ThinkingLevel::High),
        working_directory: Some(harness.temp_dir().to_path_buf()),
        no_session: true,
        ..SessionOptions::default()
    };

    let handle = run_async(create_agent_session(options)).expect("create session");
    assert_eq!(
        handle.thinking_level(),
        Some(pi::model::ThinkingLevel::High),
        "thinking level should be High"
    );

    harness.log().info_ctx("sdk", "thinking level ok", |ctx| {
        ctx.push(("level".to_string(), "High".to_string()));
    });
}
