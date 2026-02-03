//! Provider streaming tests backed by VCR cassettes.
//!
//! Recording (run locally with real API keys):
//! ```bash
//! ANTHROPIC_API_KEY=sk-ant-... VCR_MODE=record \
//!   cargo test provider_streaming::anthropic_
//! ```
//!
//! Playback (default in CI):
//! ```bash
//! VCR_MODE=playback VCR_CASSETTE_DIR=tests/fixtures/vcr \
//!   cargo test provider_streaming::anthropic_
//! ```
mod common;

use common::TestHarness;
use futures::{Stream, StreamExt};
use pi::model::{
    AssistantMessage, ContentBlock, Message, StopReason, StreamEvent, ToolCall, ToolResultMessage,
    Usage, UserContent, UserMessage,
};
use pi::vcr::VcrMode;
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::path::PathBuf;

#[path = "provider_streaming/anthropic.rs"]
mod anthropic;
#[path = "provider_streaming/azure.rs"]
mod azure;
#[path = "provider_streaming/gemini.rs"]
mod gemini;
#[path = "provider_streaming/openai.rs"]
mod openai;

pub(crate) fn cassette_root() -> PathBuf {
    env::var("VCR_CASSETTE_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vcr"),
        PathBuf::from,
    )
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .is_ok_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

pub(crate) fn vcr_mode() -> VcrMode {
    match env::var("VCR_MODE")
        .ok()
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("record") => VcrMode::Record,
        Some("auto") => VcrMode::Auto,
        _ => VcrMode::Playback,
    }
}

pub(crate) fn vcr_strict() -> bool {
    env_truthy("VCR_STRICT")
}

pub(crate) struct StreamOutcome {
    pub events: Vec<StreamEvent>,
    pub stream_error: Option<String>,
}

pub(crate) async fn collect_events<S>(mut stream: S) -> StreamOutcome
where
    S: Stream<Item = pi::PiResult<StreamEvent>> + Unpin,
{
    let mut events = Vec::new();
    let mut stream_error = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(event) => events.push(event),
            Err(err) => {
                stream_error = Some(err.to_string());
                break;
            }
        }
    }
    StreamOutcome {
        events,
        stream_error,
    }
}

pub(crate) struct StreamSummary {
    pub timeline: Vec<String>,
    pub event_count: usize,
    pub has_start: bool,
    pub has_done: bool,
    pub has_error_event: bool,
    pub text: String,
    pub thinking: String,
    pub tool_calls: Vec<ToolCall>,
    pub text_deltas: usize,
    pub thinking_deltas: usize,
    pub tool_call_deltas: usize,
    pub stop_reason: Option<StopReason>,
    pub stream_error: Option<String>,
}

pub(crate) fn summarize_events(outcome: &StreamOutcome) -> StreamSummary {
    let mut summary = StreamSummary {
        timeline: Vec::new(),
        event_count: outcome.events.len(),
        has_start: false,
        has_done: false,
        has_error_event: false,
        text: String::new(),
        thinking: String::new(),
        tool_calls: Vec::new(),
        text_deltas: 0,
        thinking_deltas: 0,
        tool_call_deltas: 0,
        stop_reason: None,
        stream_error: outcome.stream_error.clone(),
    };

    for event in &outcome.events {
        match event {
            StreamEvent::Start { .. } => {
                summary.has_start = true;
                summary.timeline.push("start".to_string());
            }
            StreamEvent::TextStart { .. } => {
                summary.timeline.push("text_start".to_string());
            }
            StreamEvent::TextDelta { delta, .. } => {
                summary.text_deltas += 1;
                summary.text.push_str(delta);
                summary.timeline.push("text_delta".to_string());
            }
            StreamEvent::TextEnd { content, .. } => {
                summary.text.clone_from(content);
                summary.timeline.push("text_end".to_string());
            }
            StreamEvent::ThinkingStart { .. } => {
                summary.timeline.push("thinking_start".to_string());
            }
            StreamEvent::ThinkingDelta { delta, .. } => {
                summary.thinking_deltas += 1;
                summary.thinking.push_str(delta);
                summary.timeline.push("thinking_delta".to_string());
            }
            StreamEvent::ThinkingEnd { content, .. } => {
                summary.thinking.clone_from(content);
                summary.timeline.push("thinking_end".to_string());
            }
            StreamEvent::ToolCallStart { .. } => {
                summary.timeline.push("tool_call_start".to_string());
            }
            StreamEvent::ToolCallDelta { .. } => {
                summary.tool_call_deltas += 1;
                summary.timeline.push("tool_call_delta".to_string());
            }
            StreamEvent::ToolCallEnd { tool_call, .. } => {
                summary.tool_calls.push(tool_call.clone());
                summary.timeline.push("tool_call_end".to_string());
            }
            StreamEvent::Done { reason, .. } => {
                summary.has_done = true;
                summary.stop_reason = Some(*reason);
                summary.timeline.push("done".to_string());
            }
            StreamEvent::Error { reason, .. } => {
                summary.has_error_event = true;
                summary.stop_reason = Some(*reason);
                summary.timeline.push("error".to_string());
            }
        }
    }

    summary
}

pub(crate) fn log_summary(harness: &TestHarness, scenario: &str, summary: &StreamSummary) {
    harness.log().info_ctx("stream", "Stream summary", |ctx| {
        ctx.push(("scenario".into(), scenario.to_string()));
        ctx.push(("events".into(), summary.event_count.to_string()));
        ctx.push(("text_deltas".into(), summary.text_deltas.to_string()));
        ctx.push((
            "thinking_deltas".into(),
            summary.thinking_deltas.to_string(),
        ));
        ctx.push(("tool_calls".into(), summary.tool_calls.len().to_string()));
        if let Some(reason) = summary.stop_reason {
            ctx.push(("stop_reason".into(), format!("{reason:?}")));
        }
        if let Some(error) = &summary.stream_error {
            ctx.push(("stream_error".into(), error.clone()));
        }
    });
    if !summary.timeline.is_empty() {
        harness.log().info(
            "timeline",
            format!("{scenario}: {}", summary.timeline.join(" -> ")),
        );
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StreamExpectations {
    pub min_text_deltas: usize,
    pub min_thinking_deltas: usize,
    pub min_tool_calls: usize,
    pub allowed_stop_reasons: Option<Vec<StopReason>>,
    pub require_blank_line: bool,
    pub require_unicode: bool,
    pub min_tool_args_bytes: Option<usize>,
    pub allow_stream_error: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ErrorExpectation {
    pub status: u16,
    pub contains: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScenarioExpectation {
    Stream(StreamExpectations),
    Error(ErrorExpectation),
}

pub(crate) fn assert_stream_expectations(
    harness: &TestHarness,
    scenario: &str,
    summary: &StreamSummary,
    expectations: &StreamExpectations,
) {
    if !expectations.allow_stream_error {
        harness.assert_log("assert no stream error");
        assert!(
            summary.stream_error.is_none(),
            "{scenario}: unexpected stream error {:?}",
            summary.stream_error
        );
    }

    if summary.event_count > 0 {
        harness.assert_log("assert stream start");
        assert!(summary.has_start, "{scenario}: missing start event");
    }

    if expectations.min_text_deltas > 0 {
        harness.assert_log("assert text deltas");
        assert!(
            summary.text_deltas >= expectations.min_text_deltas,
            "{scenario}: expected >= {} text deltas, got {}",
            expectations.min_text_deltas,
            summary.text_deltas
        );
    }

    if expectations.min_thinking_deltas > 0 {
        harness.assert_log("assert thinking deltas");
        assert!(
            summary.thinking_deltas >= expectations.min_thinking_deltas,
            "{scenario}: expected >= {} thinking deltas, got {}",
            expectations.min_thinking_deltas,
            summary.thinking_deltas
        );
    }

    if expectations.min_tool_calls > 0 {
        harness.assert_log("assert tool calls");
        assert!(
            summary.tool_calls.len() >= expectations.min_tool_calls,
            "{scenario}: expected >= {} tool calls, got {}",
            expectations.min_tool_calls,
            summary.tool_calls.len()
        );
    }

    if let Some(min_bytes) = expectations.min_tool_args_bytes {
        harness.assert_log("assert tool args size");
        let max_args = summary
            .tool_calls
            .iter()
            .filter_map(|call| serde_json::to_vec(&call.arguments).ok().map(|v| v.len()))
            .max()
            .unwrap_or(0);
        assert!(
            max_args >= min_bytes,
            "{scenario}: expected tool args >= {min_bytes} bytes, got {max_args}"
        );
    }

    if expectations.require_blank_line {
        harness.assert_log("assert blank line");
        assert!(
            summary.text.contains("\n\n"),
            "{scenario}: expected blank line in text"
        );
    }

    if expectations.require_unicode {
        harness.assert_log("assert unicode");
        let has_unicode = !summary.text.is_ascii();
        assert!(has_unicode, "{scenario}: expected unicode in text");
    }

    if let Some(allowed) = &expectations.allowed_stop_reasons {
        harness.assert_log("assert stop reason");
        let Some(reason) = summary.stop_reason else {
            panic!("{scenario}: missing stop reason");
        };
        assert!(
            allowed.contains(&reason),
            "{scenario}: expected stop reason in {allowed:?}, got {reason:?}"
        );
    }
}

pub(crate) fn user_text(text: &str) -> Message {
    Message::User(UserMessage {
        content: UserContent::Text(text.to_string()),
        timestamp: 0,
    })
}

pub(crate) fn assistant_tool_call_message(
    api: &str,
    provider: &str,
    model: &str,
    id: &str,
    name: &str,
    arguments: serde_json::Value,
) -> Message {
    Message::Assistant(AssistantMessage {
        content: vec![ContentBlock::ToolCall(ToolCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
            thought_signature: None,
        })],
        api: api.to_string(),
        provider: provider.to_string(),
        model: model.to_string(),
        usage: Usage::default(),
        stop_reason: StopReason::ToolUse,
        error_message: None,
        timestamp: 0,
    })
}

pub(crate) fn tool_result_message(
    tool_call_id: &str,
    tool_name: &str,
    content: &str,
    is_error: bool,
) -> Message {
    Message::ToolResult(ToolResultMessage {
        tool_call_id: tool_call_id.to_string(),
        tool_name: tool_name.to_string(),
        content: vec![ContentBlock::Text(pi::model::TextContent::new(
            content.to_string(),
        ))],
        details: None,
        is_error,
        timestamp: 0,
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
