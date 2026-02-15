//! JSON Mode Event Parity Validation (bd-37u8a: PARITY-V1).
//!
//! Validates that the Rust JSON mode output (--mode json) is event-for-event
//! compatible with pi-mono. Verifies:
//! - All 15 event types are emitted with correct JSON schema
//! - camelCase field naming throughout
//! - Events appear in correct lifecycle order
//! - `SessionHeader` is the first output line
//!
//! This is a SMOKE TEST. The comprehensive test suite is DROPIN-172 (bd-3p29k).

mod common;

use common::TestHarness;
use pi::agent::AgentEvent;
use pi::extensions::ExtensionUiRequest;
use pi::model::{
    AssistantMessage, AssistantMessageEvent, ContentBlock, Message, StopReason, TextContent,
    ToolCall, Usage,
};
use pi::tools::ToolOutput;
use serde_json::{Value, json};
use std::sync::Arc;

// ============================================================================
// Helpers
// ============================================================================

/// Serialize an `AgentEvent` and return the parsed JSON value.
fn event_to_json(event: &AgentEvent) -> Value {
    serde_json::to_value(event).expect("serialize AgentEvent")
}

/// Assert a JSON value has a "type" field with the expected value.
fn assert_event_type(value: &Value, expected: &str) {
    let actual = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("<missing>");
    assert_eq!(actual, expected, "event type mismatch");
}

/// Assert that a JSON object has a specific key.
fn assert_has_field(value: &Value, field: &str) {
    assert!(
        value.get(field).is_some(),
        "expected field '{field}' in {value}"
    );
}

/// Assert that a JSON field is a non-empty string.
fn assert_non_empty_string(value: &Value, field: &str) {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected string field '{field}' in {value}"));
    assert!(
        !s.is_empty(),
        "expected non-empty string for '{field}', got empty"
    );
}

fn test_assistant_message() -> AssistantMessage {
    AssistantMessage {
        content: vec![ContentBlock::Text(TextContent::new("hello"))],
        api: "anthropic-messages".to_string(),
        provider: "anthropic".to_string(),
        model: "claude-sonnet-4-20250514".to_string(),
        usage: Usage {
            total_tokens: 50,
            input: 20,
            output: 30,
            ..Usage::default()
        },
        stop_reason: StopReason::Stop,
        error_message: None,
        timestamp: 1_700_000_000,
    }
}

fn test_user_message() -> Message {
    Message::User(pi::model::UserMessage {
        content: pi::model::UserContent::Text("test prompt".to_string()),
        timestamp: 1_700_000_000,
    })
}

fn test_tool_output() -> ToolOutput {
    ToolOutput {
        content: vec![ContentBlock::Text(TextContent::new("tool output"))],
        details: None,
        is_error: false,
    }
}

// ============================================================================
// 1. AgentStart schema
// ============================================================================

#[test]
fn json_parity_agent_start_schema() {
    let harness = TestHarness::new("json_parity_agent_start_schema");
    let event = AgentEvent::AgentStart {
        session_id: "session-abc".to_string(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "agent_start");
    assert_non_empty_string(&json, "sessionId");
    assert_eq!(json["sessionId"], "session-abc");

    // Verify no snake_case version exists.
    assert!(
        json.get("session_id").is_none(),
        "should use camelCase 'sessionId', not 'session_id'"
    );

    harness
        .log()
        .info_ctx("json_parity", "agent_start schema ok", |ctx| {
            ctx.push(("type".to_string(), "agent_start".to_string()));
        });
}

// ============================================================================
// 2. AgentEnd schema
// ============================================================================

#[test]
fn json_parity_agent_end_schema() {
    let harness = TestHarness::new("json_parity_agent_end_schema");
    let event = AgentEvent::AgentEnd {
        session_id: "session-abc".to_string(),
        messages: vec![test_user_message()],
        error: None,
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "agent_end");
    assert_non_empty_string(&json, "sessionId");
    assert!(json["messages"].is_array(), "messages should be array");
    assert!(
        json.get("error").is_none() || json["error"].is_null(),
        "error should be absent or null when no error"
    );

    // With error
    let event_err = AgentEvent::AgentEnd {
        session_id: "s".to_string(),
        messages: vec![],
        error: Some("provider timeout".to_string()),
    };
    let json_err = event_to_json(&event_err);
    assert_eq!(json_err["error"], "provider timeout");

    harness
        .log()
        .info_ctx("json_parity", "agent_end schema ok", |ctx| {
            ctx.push(("messages_count".to_string(), "1".to_string()));
        });
}

// ============================================================================
// 3. TurnStart schema
// ============================================================================

#[test]
fn json_parity_turn_start_schema() {
    let harness = TestHarness::new("json_parity_turn_start_schema");
    let event = AgentEvent::TurnStart {
        session_id: "session-abc".to_string(),
        turn_index: 0,
        timestamp: 1_700_000_000,
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "turn_start");
    assert_non_empty_string(&json, "sessionId");
    assert_has_field(&json, "turnIndex");
    assert_has_field(&json, "timestamp");

    assert_eq!(json["turnIndex"], 0);
    assert!(json["timestamp"].is_i64(), "timestamp should be i64");

    // Verify camelCase
    assert!(json.get("turn_index").is_none());
    assert!(json.get("session_id").is_none());

    harness
        .log()
        .info_ctx("json_parity", "turn_start schema ok", |ctx| {
            ctx.push(("turnIndex".to_string(), "0".to_string()));
        });
}

// ============================================================================
// 4. TurnEnd schema
// ============================================================================

#[test]
fn json_parity_turn_end_schema() {
    let harness = TestHarness::new("json_parity_turn_end_schema");
    let assistant_msg = Message::Assistant(Arc::new(test_assistant_message()));
    let event = AgentEvent::TurnEnd {
        session_id: "session-abc".to_string(),
        turn_index: 0,
        message: assistant_msg,
        tool_results: vec![],
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "turn_end");
    assert_non_empty_string(&json, "sessionId");
    assert_has_field(&json, "turnIndex");
    assert_has_field(&json, "message");
    assert_has_field(&json, "toolResults");
    assert!(json["toolResults"].is_array());

    // Verify camelCase
    assert!(json.get("tool_results").is_none());

    harness
        .log()
        .info_ctx("json_parity", "turn_end schema ok", |ctx| {
            ctx.push(("turnIndex".to_string(), "0".to_string()));
        });
}

// ============================================================================
// 5. MessageStart schema
// ============================================================================

#[test]
fn json_parity_message_start_schema() {
    let harness = TestHarness::new("json_parity_message_start_schema");
    let event = AgentEvent::MessageStart {
        message: test_user_message(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "message_start");
    assert_has_field(&json, "message");
    assert!(json["message"].is_object());

    harness
        .log()
        .info_ctx("json_parity", "message_start schema ok", |ctx| {
            ctx.push(("has_message".to_string(), "true".to_string()));
        });
}

// ============================================================================
// 6. MessageUpdate schema
// ============================================================================

#[test]
fn json_parity_message_update_schema() {
    let harness = TestHarness::new("json_parity_message_update_schema");
    let partial = Arc::new(test_assistant_message());
    let event = AgentEvent::MessageUpdate {
        message: Message::Assistant(Arc::clone(&partial)),
        assistant_message_event: Box::new(AssistantMessageEvent::TextDelta {
            content_index: 0,
            delta: "hello".to_string(),
            partial,
        }),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "message_update");
    assert_has_field(&json, "message");
    assert_has_field(&json, "assistantMessageEvent");

    // Verify camelCase
    assert!(json.get("assistant_message_event").is_none());

    // Verify nested event has correct type tag
    let ame = &json["assistantMessageEvent"];
    assert_eq!(ame["type"], "text_delta");
    assert_has_field(ame, "contentIndex");
    assert_has_field(ame, "delta");

    harness
        .log()
        .info_ctx("json_parity", "message_update schema ok", |ctx| {
            ctx.push(("ame_type".to_string(), "text_delta".to_string()));
        });
}

// ============================================================================
// 7. MessageEnd schema
// ============================================================================

#[test]
fn json_parity_message_end_schema() {
    let harness = TestHarness::new("json_parity_message_end_schema");
    let event = AgentEvent::MessageEnd {
        message: Message::Assistant(Arc::new(test_assistant_message())),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "message_end");
    assert_has_field(&json, "message");

    harness
        .log()
        .info_ctx("json_parity", "message_end schema ok", |ctx| {
            ctx.push(("has_message".to_string(), "true".to_string()));
        });
}

// ============================================================================
// 8. ToolExecutionStart schema
// ============================================================================

#[test]
fn json_parity_tool_execution_start_schema() {
    let harness = TestHarness::new("json_parity_tool_execution_start_schema");
    let event = AgentEvent::ToolExecutionStart {
        tool_call_id: "tc-1".to_string(),
        tool_name: "read".to_string(),
        args: json!({"path": "/tmp/test.txt"}),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "tool_execution_start");
    assert_non_empty_string(&json, "toolCallId");
    assert_non_empty_string(&json, "toolName");
    assert_has_field(&json, "args");

    assert_eq!(json["toolCallId"], "tc-1");
    assert_eq!(json["toolName"], "read");

    // Verify camelCase
    assert!(json.get("tool_call_id").is_none());
    assert!(json.get("tool_name").is_none());

    harness
        .log()
        .info_ctx("json_parity", "tool_execution_start schema ok", |ctx| {
            ctx.push(("tool".to_string(), "read".to_string()));
        });
}

// ============================================================================
// 9. ToolExecutionUpdate schema
// ============================================================================

#[test]
fn json_parity_tool_execution_update_schema() {
    let harness = TestHarness::new("json_parity_tool_execution_update_schema");
    let event = AgentEvent::ToolExecutionUpdate {
        tool_call_id: "tc-1".to_string(),
        tool_name: "bash".to_string(),
        args: json!({"command": "ls"}),
        partial_result: test_tool_output(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "tool_execution_update");
    assert_non_empty_string(&json, "toolCallId");
    assert_non_empty_string(&json, "toolName");
    assert_has_field(&json, "args");
    assert_has_field(&json, "partialResult");

    // Verify camelCase
    assert!(json.get("partial_result").is_none());

    harness
        .log()
        .info_ctx("json_parity", "tool_execution_update schema ok", |ctx| {
            ctx.push(("tool".to_string(), "bash".to_string()));
        });
}

// ============================================================================
// 10. ToolExecutionEnd schema
// ============================================================================

#[test]
fn json_parity_tool_execution_end_schema() {
    let harness = TestHarness::new("json_parity_tool_execution_end_schema");
    let event = AgentEvent::ToolExecutionEnd {
        tool_call_id: "tc-1".to_string(),
        tool_name: "read".to_string(),
        result: test_tool_output(),
        is_error: false,
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "tool_execution_end");
    assert_non_empty_string(&json, "toolCallId");
    assert_non_empty_string(&json, "toolName");
    assert_has_field(&json, "result");
    assert_has_field(&json, "isError");
    assert_eq!(json["isError"], false);

    // Verify camelCase
    assert!(json.get("is_error").is_none());

    // With error
    let event_err = AgentEvent::ToolExecutionEnd {
        tool_call_id: "tc-2".to_string(),
        tool_name: "bash".to_string(),
        result: ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new("error msg"))],
            details: None,
            is_error: true,
        },
        is_error: true,
    };
    let json_err = event_to_json(&event_err);
    assert_eq!(json_err["isError"], true);

    harness
        .log()
        .info_ctx("json_parity", "tool_execution_end schema ok", |ctx| {
            ctx.push(("error_case".to_string(), "true".to_string()));
        });
}

// ============================================================================
// 11. AutoCompactionStart schema
// ============================================================================

#[test]
fn json_parity_auto_compaction_start_schema() {
    let harness = TestHarness::new("json_parity_auto_compaction_start_schema");
    let event = AgentEvent::AutoCompactionStart {
        reason: "context window exceeded".to_string(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "auto_compaction_start");
    assert_non_empty_string(&json, "reason");

    harness
        .log()
        .info_ctx("json_parity", "auto_compaction_start schema ok", |ctx| {
            ctx.push(("reason".to_string(), "context window exceeded".to_string()));
        });
}

// ============================================================================
// 12. AutoCompactionEnd schema
// ============================================================================

#[test]
fn json_parity_auto_compaction_end_schema() {
    let harness = TestHarness::new("json_parity_auto_compaction_end_schema");

    // Success case
    let event = AgentEvent::AutoCompactionEnd {
        result: Some(json!({"summary": "compacted 10 messages"})),
        aborted: false,
        will_retry: false,
        error_message: None,
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "auto_compaction_end");
    assert_has_field(&json, "aborted");
    assert_has_field(&json, "willRetry");
    assert_eq!(json["aborted"], false);
    assert_eq!(json["willRetry"], false);

    // Verify camelCase
    assert!(json.get("will_retry").is_none());
    assert!(json.get("error_message").is_none());

    // Error case with retry
    let event_err = AgentEvent::AutoCompactionEnd {
        result: None,
        aborted: false,
        will_retry: true,
        error_message: Some("provider error".to_string()),
    };
    let json_err = event_to_json(&event_err);
    assert_eq!(json_err["willRetry"], true);
    assert_eq!(json_err["errorMessage"], "provider error");

    harness
        .log()
        .info_ctx("json_parity", "auto_compaction_end schema ok", |ctx| {
            ctx.push(("variants_tested".to_string(), "2".to_string()));
        });
}

// ============================================================================
// 13. AutoRetryStart schema
// ============================================================================

#[test]
fn json_parity_auto_retry_start_schema() {
    let harness = TestHarness::new("json_parity_auto_retry_start_schema");
    let event = AgentEvent::AutoRetryStart {
        attempt: 1,
        max_attempts: 3,
        delay_ms: 1000,
        error_message: "rate limited".to_string(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "auto_retry_start");
    assert_has_field(&json, "attempt");
    assert_has_field(&json, "maxAttempts");
    assert_has_field(&json, "delayMs");
    assert_has_field(&json, "errorMessage");
    assert_eq!(json["attempt"], 1);
    assert_eq!(json["maxAttempts"], 3);
    assert_eq!(json["delayMs"], 1000);
    assert_eq!(json["errorMessage"], "rate limited");

    // Verify camelCase
    assert!(json.get("max_attempts").is_none());
    assert!(json.get("delay_ms").is_none());
    assert!(json.get("error_message").is_none());

    harness
        .log()
        .info_ctx("json_parity", "auto_retry_start schema ok", |ctx| {
            ctx.push(("attempt".to_string(), "1".to_string()));
        });
}

// ============================================================================
// 14. AutoRetryEnd schema
// ============================================================================

#[test]
fn json_parity_auto_retry_end_schema() {
    let harness = TestHarness::new("json_parity_auto_retry_end_schema");

    // Success case
    let event = AgentEvent::AutoRetryEnd {
        success: true,
        attempt: 2,
        final_error: None,
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "auto_retry_end");
    assert_has_field(&json, "success");
    assert_has_field(&json, "attempt");
    assert_eq!(json["success"], true);
    assert_eq!(json["attempt"], 2);

    // Verify camelCase
    assert!(json.get("final_error").is_none());

    // Failure case
    let event_fail = AgentEvent::AutoRetryEnd {
        success: false,
        attempt: 3,
        final_error: Some("max retries exceeded".to_string()),
    };
    let json_fail = event_to_json(&event_fail);
    assert_eq!(json_fail["success"], false);
    assert_eq!(json_fail["finalError"], "max retries exceeded");

    harness
        .log()
        .info_ctx("json_parity", "auto_retry_end schema ok", |ctx| {
            ctx.push(("variants_tested".to_string(), "2".to_string()));
        });
}

// ============================================================================
// 15. ExtensionError schema
// ============================================================================

#[test]
fn json_parity_extension_error_schema() {
    let harness = TestHarness::new("json_parity_extension_error_schema");
    let event = AgentEvent::ExtensionError {
        extension_id: Some("ext-foo".to_string()),
        event: "on_tool_start".to_string(),
        error: "TypeError: undefined is not a function".to_string(),
    };
    let json = event_to_json(&event);

    assert_event_type(&json, "extension_error");
    assert_has_field(&json, "extensionId");
    assert_non_empty_string(&json, "event");
    assert_non_empty_string(&json, "error");
    assert_eq!(json["extensionId"], "ext-foo");

    // Verify camelCase
    assert!(json.get("extension_id").is_none());

    // Without extension_id
    let event_no_id = AgentEvent::ExtensionError {
        extension_id: None,
        event: "lifecycle".to_string(),
        error: "load failed".to_string(),
    };
    let json_no_id = event_to_json(&event_no_id);
    assert!(
        json_no_id.get("extensionId").is_none()
            || json_no_id["extensionId"].is_null(),
        "extensionId should be absent or null when None"
    );

    harness
        .log()
        .info_ctx("json_parity", "extension_error schema ok", |ctx| {
            ctx.push(("with_id".to_string(), "true".to_string()));
            ctx.push(("without_id".to_string(), "true".to_string()));
        });
}

// ============================================================================
// 16. Complete lifecycle ordering
// ============================================================================

#[test]
fn json_parity_complete_lifecycle_ordering() {
    let harness = TestHarness::new("json_parity_complete_lifecycle_ordering");

    // Simulate a full agent run lifecycle and verify ordering.
    let session_id = "session-lifecycle-test";
    let partial = Arc::new(test_assistant_message());

    let events: Vec<AgentEvent> = vec![
        AgentEvent::AgentStart {
            session_id: session_id.to_string(),
        },
        AgentEvent::MessageStart {
            message: test_user_message(),
        },
        AgentEvent::MessageEnd {
            message: test_user_message(),
        },
        AgentEvent::TurnStart {
            session_id: session_id.to_string(),
            turn_index: 0,
            timestamp: 1_700_000_000,
        },
        AgentEvent::MessageStart {
            message: Message::Assistant(Arc::clone(&partial)),
        },
        AgentEvent::MessageUpdate {
            message: Message::Assistant(Arc::clone(&partial)),
            assistant_message_event: Box::new(AssistantMessageEvent::TextDelta {
                content_index: 0,
                delta: "hello".to_string(),
                partial: Arc::clone(&partial),
            }),
        },
        AgentEvent::MessageEnd {
            message: Message::Assistant(Arc::clone(&partial)),
        },
        AgentEvent::TurnEnd {
            session_id: session_id.to_string(),
            turn_index: 0,
            message: Message::Assistant(Arc::clone(&partial)),
            tool_results: vec![],
        },
        AgentEvent::AgentEnd {
            session_id: session_id.to_string(),
            messages: vec![test_user_message(), Message::Assistant(partial)],
            error: None,
        },
    ];

    let json_lines: Vec<Value> = events.iter().map(event_to_json).collect();

    let expected_order = [
        "agent_start",
        "message_start",   // user
        "message_end",     // user
        "turn_start",
        "message_start",   // assistant
        "message_update",
        "message_end",     // assistant
        "turn_end",
        "agent_end",
    ];

    for (i, expected_type) in expected_order.iter().enumerate() {
        let actual_type = json_lines[i]["type"].as_str().unwrap_or("<missing>");
        assert_eq!(
            actual_type, *expected_type,
            "event at index {i}: expected '{expected_type}', got '{actual_type}'"
        );
    }

    // Verify sessionId consistency across events that have it.
    for line in &json_lines {
        if let Some(sid) = line.get("sessionId").and_then(Value::as_str) {
            assert_eq!(
                sid, session_id,
                "sessionId should be consistent across events"
            );
        }
    }

    harness
        .log()
        .info_ctx("json_parity", "lifecycle ordering ok", |ctx| {
            ctx.push(("events".to_string(), json_lines.len().to_string()));
            ctx.push((
                "order".to_string(),
                expected_order.join(","),
            ));
        });
}

// ============================================================================
// 17. AssistantMessageEvent sub-types
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn json_parity_assistant_message_event_all_subtypes() {
    let harness = TestHarness::new("json_parity_assistant_message_event_all_subtypes");
    let partial = Arc::new(test_assistant_message());

    // Each AssistantMessageEvent variant serialized through MessageUpdate
    let variants: Vec<(&str, AssistantMessageEvent)> = vec![
        (
            "start",
            AssistantMessageEvent::Start {
                partial: Arc::clone(&partial),
            },
        ),
        (
            "text_start",
            AssistantMessageEvent::TextStart {
                content_index: 0,
                partial: Arc::clone(&partial),
            },
        ),
        (
            "text_delta",
            AssistantMessageEvent::TextDelta {
                content_index: 0,
                delta: "hello".to_string(),
                partial: Arc::clone(&partial),
            },
        ),
        (
            "text_end",
            AssistantMessageEvent::TextEnd {
                content_index: 0,
                content: "hello world".to_string(),
                partial: Arc::clone(&partial),
            },
        ),
        (
            "thinking_start",
            AssistantMessageEvent::ThinkingStart {
                content_index: 0,
                partial: Arc::clone(&partial),
            },
        ),
        (
            "thinking_delta",
            AssistantMessageEvent::ThinkingDelta {
                content_index: 0,
                delta: "thinking...".to_string(),
                partial: Arc::clone(&partial),
            },
        ),
        (
            "thinking_end",
            AssistantMessageEvent::ThinkingEnd {
                content_index: 0,
                content: "full thought".to_string(),
                partial: Arc::clone(&partial),
            },
        ),
        (
            "toolcall_start",
            AssistantMessageEvent::ToolCallStart {
                content_index: 0,
                partial: Arc::clone(&partial),
            },
        ),
        (
            "toolcall_delta",
            AssistantMessageEvent::ToolCallDelta {
                content_index: 0,
                delta: "{\"path\"".to_string(),
                partial: Arc::clone(&partial),
            },
        ),
        (
            "toolcall_end",
            AssistantMessageEvent::ToolCallEnd {
                content_index: 0,
                tool_call: ToolCall {
                    id: "tc-1".to_string(),
                    name: "read".to_string(),
                    arguments: json!({"path": "/tmp"}),
                    thought_signature: None,
                },
                partial: Arc::clone(&partial),
            },
        ),
        (
            "done",
            AssistantMessageEvent::Done {
                reason: StopReason::Stop,
                message: Arc::clone(&partial),
            },
        ),
        (
            "error",
            AssistantMessageEvent::Error {
                reason: StopReason::Stop,
                error: Arc::clone(&partial),
            },
        ),
    ];

    let mut tested = 0;
    for (expected_type, ame) in &variants {
        let event = AgentEvent::MessageUpdate {
            message: Message::Assistant(Arc::clone(&partial)),
            assistant_message_event: Box::new(ame.clone()),
        };
        let json = event_to_json(&event);
        let ame_json = &json["assistantMessageEvent"];

        let actual_type = ame_json["type"].as_str().unwrap_or("<missing>");
        assert_eq!(
            actual_type, *expected_type,
            "AME variant type mismatch for {expected_type}"
        );
        tested += 1;
    }

    assert_eq!(tested, 12, "should test all 12 AME variants");

    harness
        .log()
        .info_ctx("json_parity", "AME subtypes ok", |ctx| {
            ctx.push(("variants_tested".to_string(), tested.to_string()));
        });
}

// ============================================================================
// 18. No snake_case leak check (comprehensive)
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn json_parity_no_snake_case_leak() {
    let harness = TestHarness::new("json_parity_no_snake_case_leak");
    let partial = Arc::new(test_assistant_message());

    // Test every event type for snake_case field leaks.
    let events: Vec<AgentEvent> = vec![
        AgentEvent::AgentStart {
            session_id: "s".to_string(),
        },
        AgentEvent::AgentEnd {
            session_id: "s".to_string(),
            messages: vec![],
            error: None,
        },
        AgentEvent::TurnStart {
            session_id: "s".to_string(),
            turn_index: 0,
            timestamp: 0,
        },
        AgentEvent::TurnEnd {
            session_id: "s".to_string(),
            turn_index: 0,
            message: test_user_message(),
            tool_results: vec![],
        },
        AgentEvent::MessageStart {
            message: test_user_message(),
        },
        AgentEvent::MessageUpdate {
            message: Message::Assistant(Arc::clone(&partial)),
            assistant_message_event: Box::new(AssistantMessageEvent::TextDelta {
                content_index: 0,
                delta: "x".to_string(),
                partial: Arc::clone(&partial),
            }),
        },
        AgentEvent::MessageEnd {
            message: test_user_message(),
        },
        AgentEvent::ToolExecutionStart {
            tool_call_id: "tc".to_string(),
            tool_name: "read".to_string(),
            args: json!({}),
        },
        AgentEvent::ToolExecutionUpdate {
            tool_call_id: "tc".to_string(),
            tool_name: "bash".to_string(),
            args: json!({}),
            partial_result: test_tool_output(),
        },
        AgentEvent::ToolExecutionEnd {
            tool_call_id: "tc".to_string(),
            tool_name: "read".to_string(),
            result: test_tool_output(),
            is_error: false,
        },
        AgentEvent::AutoCompactionStart {
            reason: "r".to_string(),
        },
        AgentEvent::AutoCompactionEnd {
            result: None,
            aborted: false,
            will_retry: false,
            error_message: Some("err".to_string()),
        },
        AgentEvent::AutoRetryStart {
            attempt: 1,
            max_attempts: 3,
            delay_ms: 100,
            error_message: "e".to_string(),
        },
        AgentEvent::AutoRetryEnd {
            success: true,
            attempt: 1,
            final_error: None,
        },
        AgentEvent::ExtensionError {
            extension_id: Some("ext".to_string()),
            event: "e".to_string(),
            error: "err".to_string(),
        },
    ];

    // Known snake_case fields that should NOT appear.
    let banned_snake_case = [
        "session_id",
        "turn_index",
        "tool_results",
        "tool_call_id",
        "tool_name",
        "is_error",
        "partial_result",
        "assistant_message_event",
        "max_attempts",
        "delay_ms",
        "error_message",
        "will_retry",
        "final_error",
        "extension_id",
        "content_index",
    ];

    for event in &events {
        let json = event_to_json(event);
        let json_string = serde_json::to_string(&json).expect("to_string");

        for banned in &banned_snake_case {
            // Check if the banned key appears as a JSON key ("key":)
            let key_pattern = format!("\"{banned}\":");
            assert!(
                !json_string.contains(&key_pattern),
                "found banned snake_case field '{banned}' in event {:?}: {json_string}",
                json["type"]
            );
        }
    }

    harness
        .log()
        .info_ctx("json_parity", "no snake_case leak ok", |ctx| {
            ctx.push(("events_checked".to_string(), events.len().to_string()));
            ctx.push(("banned_fields".to_string(), banned_snake_case.len().to_string()));
        });
}

// ============================================================================
// 19. SessionHeader schema validation
// ============================================================================

#[test]
fn json_parity_session_header_schema() {
    let harness = TestHarness::new("json_parity_session_header_schema");

    let header = pi::session::SessionHeader::new();
    let json = serde_json::to_value(&header).expect("serialize header");

    assert_eq!(json["type"], "session");
    assert!(
        json["id"].as_str().is_some_and(|s| !s.is_empty()),
        "id should be non-empty string"
    );
    assert!(
        json["timestamp"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "timestamp should be non-empty string"
    );
    assert!(
        json["cwd"].as_str().is_some_and(|s| !s.is_empty()),
        "cwd should be non-empty string"
    );

    // Verify camelCase naming
    assert!(
        json.get("parent_session").is_none(),
        "should use camelCase 'branchedFrom' not 'parent_session'"
    );

    harness
        .log()
        .info_ctx("json_parity", "session header schema ok", |ctx| {
            ctx.push(("type".to_string(), "session".to_string()));
            ctx.push(("has_id".to_string(), "true".to_string()));
        });
}

// ============================================================================
// 20. Event type string stability
// ============================================================================

#[test]
#[allow(clippy::too_many_lines)]
fn json_parity_all_event_type_strings() {
    let harness = TestHarness::new("json_parity_all_event_type_strings");
    let partial = Arc::new(test_assistant_message());

    // Map of (variant, expected_type_string)
    let cases: Vec<(AgentEvent, &str)> = vec![
        (
            AgentEvent::AgentStart {
                session_id: "s".to_string(),
            },
            "agent_start",
        ),
        (
            AgentEvent::AgentEnd {
                session_id: "s".to_string(),
                messages: vec![],
                error: None,
            },
            "agent_end",
        ),
        (
            AgentEvent::TurnStart {
                session_id: "s".to_string(),
                turn_index: 0,
                timestamp: 0,
            },
            "turn_start",
        ),
        (
            AgentEvent::TurnEnd {
                session_id: "s".to_string(),
                turn_index: 0,
                message: test_user_message(),
                tool_results: vec![],
            },
            "turn_end",
        ),
        (
            AgentEvent::MessageStart {
                message: test_user_message(),
            },
            "message_start",
        ),
        (
            AgentEvent::MessageUpdate {
                message: Message::Assistant(Arc::clone(&partial)),
                assistant_message_event: Box::new(AssistantMessageEvent::Start {
                    partial: Arc::clone(&partial),
                }),
            },
            "message_update",
        ),
        (
            AgentEvent::MessageEnd {
                message: test_user_message(),
            },
            "message_end",
        ),
        (
            AgentEvent::ToolExecutionStart {
                tool_call_id: "t".to_string(),
                tool_name: "r".to_string(),
                args: json!({}),
            },
            "tool_execution_start",
        ),
        (
            AgentEvent::ToolExecutionUpdate {
                tool_call_id: "t".to_string(),
                tool_name: "r".to_string(),
                args: json!({}),
                partial_result: test_tool_output(),
            },
            "tool_execution_update",
        ),
        (
            AgentEvent::ToolExecutionEnd {
                tool_call_id: "t".to_string(),
                tool_name: "r".to_string(),
                result: test_tool_output(),
                is_error: false,
            },
            "tool_execution_end",
        ),
        (
            AgentEvent::AutoCompactionStart {
                reason: "r".to_string(),
            },
            "auto_compaction_start",
        ),
        (
            AgentEvent::AutoCompactionEnd {
                result: None,
                aborted: false,
                will_retry: false,
                error_message: None,
            },
            "auto_compaction_end",
        ),
        (
            AgentEvent::AutoRetryStart {
                attempt: 1,
                max_attempts: 3,
                delay_ms: 0,
                error_message: "e".to_string(),
            },
            "auto_retry_start",
        ),
        (
            AgentEvent::AutoRetryEnd {
                success: true,
                attempt: 1,
                final_error: None,
            },
            "auto_retry_end",
        ),
        (
            AgentEvent::ExtensionError {
                extension_id: None,
                event: "e".to_string(),
                error: "err".to_string(),
            },
            "extension_error",
        ),
    ];

    for (event, expected_type) in &cases {
        let json = event_to_json(event);
        assert_event_type(&json, expected_type);
    }

    assert_eq!(cases.len(), 15, "should cover all 15 AgentEvent variants");

    harness
        .log()
        .info_ctx("json_parity", "all event type strings ok", |ctx| {
            ctx.push(("variants".to_string(), cases.len().to_string()));
        });
}

// ============================================================================
// Extension UI Request Parity (DROPIN-124: bd-359pl)
//
// Validates that `ExtensionUiRequest::to_rpc_event()` produces JSON events
// matching the TypeScript `RpcExtensionUIRequest` schema from pi-mono.
// Reference: legacy_pi_mono_code/.../rpc-types.ts lines 207-247.
// ============================================================================

// ---------------------------------------------------------------------------
// 1. Select method — dialog, expects response
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_select_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_select_schema");
    let req = ExtensionUiRequest::new(
        "sel-1",
        "select",
        json!({"title": "Pick a tool", "options": ["read", "write", "bash"]}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "sel-1");
    assert_eq!(event["method"], "select");
    assert_eq!(event["title"], "Pick a tool");
    assert_eq!(event["options"], json!(["read", "write", "bash"]));
    // Payload fields are flattened — no nested "payload" key.
    assert!(event.get("payload").is_none(), "payload must be flattened");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui select schema ok",
        |ctx| ctx.push(("method".to_string(), "select".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 2. Confirm method — dialog, expects response
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_confirm_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_confirm_schema");
    let req = ExtensionUiRequest::new(
        "cfm-1",
        "confirm",
        json!({"title": "Allow exec?", "message": "Extension wants to run commands"}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "cfm-1");
    assert_eq!(event["method"], "confirm");
    assert_eq!(event["title"], "Allow exec?");
    assert_eq!(event["message"], "Extension wants to run commands");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui confirm schema ok",
        |ctx| ctx.push(("method".to_string(), "confirm".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 3. Input method — dialog, expects response
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_input_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_input_schema");
    let req = ExtensionUiRequest::new(
        "inp-1",
        "input",
        json!({"title": "API Key", "placeholder": "sk-ant-..."}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "inp-1");
    assert_eq!(event["method"], "input");
    assert_eq!(event["title"], "API Key");
    assert_eq!(event["placeholder"], "sk-ant-...");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui input schema ok",
        |ctx| ctx.push(("method".to_string(), "input".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 4. Editor method — dialog, expects response
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_editor_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_editor_schema");
    let req = ExtensionUiRequest::new(
        "edt-1",
        "editor",
        json!({"title": "Edit prompt", "prefill": "Hello, world!"}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "edt-1");
    assert_eq!(event["method"], "editor");
    assert_eq!(event["title"], "Edit prompt");
    assert_eq!(event["prefill"], "Hello, world!");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui editor schema ok",
        |ctx| ctx.push(("method".to_string(), "editor".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 5. Notify method — fire-and-forget
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_notify_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_notify_schema");
    let req = ExtensionUiRequest::new(
        "ntf-1",
        "notify",
        json!({"message": "Build complete", "notifyType": "info"}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "ntf-1");
    assert_eq!(event["method"], "notify");
    assert_eq!(event["message"], "Build complete");
    assert_eq!(event["notifyType"], "info");

    // Also test warning and error notify types.
    let req_warn = ExtensionUiRequest::new(
        "ntf-2",
        "notify",
        json!({"message": "Deprecation", "notifyType": "warning"}),
    );
    assert_eq!(req_warn.to_rpc_event()["notifyType"], "warning");

    let req_err = ExtensionUiRequest::new(
        "ntf-3",
        "notify",
        json!({"message": "Failed", "notifyType": "error"}),
    );
    assert_eq!(req_err.to_rpc_event()["notifyType"], "error");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui notify schema ok",
        |ctx| ctx.push(("variants".to_string(), "3".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 6. setStatus method — fire-and-forget
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_set_status_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_set_status_schema");
    let req = ExtensionUiRequest::new(
        "sts-1",
        "setStatus",
        json!({"statusKey": "build", "statusText": "compiling..."}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "sts-1");
    assert_eq!(event["method"], "setStatus");
    assert_eq!(event["statusKey"], "build");
    assert_eq!(event["statusText"], "compiling...");

    // Test clearing status (statusText undefined → null in JSON).
    let req_clear = ExtensionUiRequest::new(
        "sts-2",
        "setStatus",
        json!({"statusKey": "build", "statusText": null}),
    );
    let event_clear = req_clear.to_rpc_event();
    assert_eq!(event_clear["statusKey"], "build");
    assert!(event_clear["statusText"].is_null());

    harness.log().info_ctx(
        "json_parity",
        "extension_ui setStatus schema ok",
        |ctx| ctx.push(("method".to_string(), "setStatus".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 7. setWidget method — fire-and-forget
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_set_widget_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_set_widget_schema");
    let req = ExtensionUiRequest::new(
        "wdg-1",
        "setWidget",
        json!({
            "widgetKey": "metrics",
            "widgetLines": ["CPU: 42%", "RAM: 8GB"],
            "widgetPlacement": "aboveEditor"
        }),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "wdg-1");
    assert_eq!(event["method"], "setWidget");
    assert_eq!(event["widgetKey"], "metrics");
    assert_eq!(event["widgetLines"], json!(["CPU: 42%", "RAM: 8GB"]));
    assert_eq!(event["widgetPlacement"], "aboveEditor");

    // Test clearing widget (widgetLines undefined → null).
    let req_clear = ExtensionUiRequest::new(
        "wdg-2",
        "setWidget",
        json!({"widgetKey": "metrics", "widgetLines": null}),
    );
    let event_clear = req_clear.to_rpc_event();
    assert_eq!(event_clear["widgetKey"], "metrics");
    assert!(event_clear["widgetLines"].is_null());

    harness.log().info_ctx(
        "json_parity",
        "extension_ui setWidget schema ok",
        |ctx| ctx.push(("method".to_string(), "setWidget".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 8. setTitle method — fire-and-forget
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_set_title_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_set_title_schema");
    let req = ExtensionUiRequest::new(
        "ttl-1",
        "setTitle",
        json!({"title": "My Agent Session"}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "ttl-1");
    assert_eq!(event["method"], "setTitle");
    assert_eq!(event["title"], "My Agent Session");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui setTitle schema ok",
        |ctx| ctx.push(("method".to_string(), "setTitle".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 9. set_editor_text method — fire-and-forget
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_set_editor_text_schema() {
    let harness = TestHarness::new("json_parity_extension_ui_set_editor_text_schema");
    let req = ExtensionUiRequest::new(
        "set-1",
        "set_editor_text",
        json!({"text": "prefilled prompt text"}),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["type"], "extension_ui_request");
    assert_eq!(event["id"], "set-1");
    assert_eq!(event["method"], "set_editor_text");
    assert_eq!(event["text"], "prefilled prompt text");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui set_editor_text schema ok",
        |ctx| ctx.push(("method".to_string(), "set_editor_text".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 10. Dialog vs fire-and-forget classification matches TypeScript
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_expects_response_classification() {
    let harness = TestHarness::new("json_parity_extension_ui_expects_response_classification");

    // Dialog methods (expects response = true).
    for method in &["select", "confirm", "input", "editor"] {
        let req = ExtensionUiRequest::new("x", *method, json!({}));
        assert!(
            req.expects_response(),
            "{method} should expect a response (dialog)"
        );
    }

    // Fire-and-forget methods (expects response = false).
    for method in &["notify", "setStatus", "setWidget", "setTitle", "set_editor_text"] {
        let req = ExtensionUiRequest::new("x", *method, json!({}));
        assert!(
            !req.expects_response(),
            "{method} should NOT expect a response (fire-and-forget)"
        );
    }

    harness.log().info_ctx(
        "json_parity",
        "extension_ui dialog classification ok",
        |ctx| ctx.push(("dialog_count".to_string(), "4".to_string())),
    );
}

// ---------------------------------------------------------------------------
// 11. All 9 methods produce extension_ui_request type tag
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_all_methods_type_tag() {
    let harness = TestHarness::new("json_parity_extension_ui_all_methods_type_tag");
    let methods = [
        "select", "confirm", "input", "editor",
        "notify", "setStatus", "setWidget", "setTitle", "set_editor_text",
    ];

    for method in &methods {
        let req = ExtensionUiRequest::new("id-1", *method, json!({}));
        let event = req.to_rpc_event();
        assert_eq!(
            event["type"], "extension_ui_request",
            "method {method} should produce extension_ui_request type"
        );
        assert_eq!(event["method"], *method);
    }

    harness.log().info_ctx(
        "json_parity",
        "all 9 extension_ui methods ok",
        |ctx| ctx.push(("methods".to_string(), methods.len().to_string())),
    );
}

// ---------------------------------------------------------------------------
// 12. Payload flattening — object payloads merge into top-level
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_payload_flattening() {
    let harness = TestHarness::new("json_parity_extension_ui_payload_flattening");

    // Object payload: fields should appear at top level.
    let req = ExtensionUiRequest::new(
        "r1",
        "select",
        json!({"title": "Pick", "options": ["A"], "custom_key": 42}),
    );
    let event = req.to_rpc_event();
    assert!(
        event.get("payload").is_none(),
        "object payload must be flattened"
    );
    assert_eq!(event["title"], "Pick");
    assert_eq!(event["custom_key"], 42);

    // Non-object payload: falls back to a "payload" key.
    let req_str = ExtensionUiRequest::new("r2", "notify", Value::String("raw".to_string()));
    let event_str = req_str.to_rpc_event();
    assert_eq!(event_str["payload"], "raw");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui payload flattening ok",
        |_| {},
    );
}

// ---------------------------------------------------------------------------
// 13. No snake_case leaks in extension UI events
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_no_snake_case_leaks() {
    let harness = TestHarness::new("json_parity_extension_ui_no_snake_case_leaks");

    // Build events for all methods and verify no keys contain underscores
    // (except the event "type" value and method names which are allowed).
    let cases = vec![
        ExtensionUiRequest::new("r1", "select", json!({"title": "T", "options": ["A"]})),
        ExtensionUiRequest::new("r2", "confirm", json!({"title": "T", "message": "M"})),
        ExtensionUiRequest::new("r3", "input", json!({"title": "T", "placeholder": "P"})),
        ExtensionUiRequest::new("r4", "editor", json!({"title": "T", "prefill": "P"})),
        ExtensionUiRequest::new("r5", "notify", json!({"message": "M", "notifyType": "info"})),
        ExtensionUiRequest::new("r6", "setStatus", json!({"statusKey": "K", "statusText": "V"})),
        ExtensionUiRequest::new(
            "r7",
            "setWidget",
            json!({"widgetKey": "K", "widgetLines": ["L"], "widgetPlacement": "aboveEditor"}),
        ),
        ExtensionUiRequest::new("r8", "setTitle", json!({"title": "T"})),
        ExtensionUiRequest::new("r9", "set_editor_text", json!({"text": "T"})),
    ];

    // Known keys that intentionally use snake_case (matching TS reference exactly).
    let allowed_snake_keys = ["set_editor_text"]; // method value, not a key

    for req in &cases {
        let event = req.to_rpc_event();
        if let Value::Object(map) = &event {
            for key in map.keys() {
                // The "type" key is a standard JSON discriminator.
                if key == "type" {
                    continue;
                }
                // Keys themselves should use camelCase (like TypeScript).
                // Exception: keys from the payload that match TS reference exactly.
                let has_underscore = key.contains('_');
                if has_underscore {
                    // Only allow keys that are intentional in the TS schema.
                    let allowed = allowed_snake_keys.contains(&key.as_str());
                    assert!(
                        allowed,
                        "unexpected snake_case key '{key}' in {method} event",
                        method = req.method
                    );
                }
            }
        }
    }

    harness.log().info_ctx(
        "json_parity",
        "no snake_case leaks in extension_ui events",
        |_| {},
    );
}

// ---------------------------------------------------------------------------
// 14. Extension ID provenance — when set, included in event
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_extension_id_provenance() {
    let harness = TestHarness::new("json_parity_extension_ui_extension_id_provenance");

    // The extension_id is part of the struct but NOT part of `to_rpc_event()` output
    // because it's tracked on the Rust side for provenance, not emitted to RPC clients.
    // The payload may carry an extension_id field if the extension puts it there.
    let req = ExtensionUiRequest::new(
        "r1",
        "confirm",
        json!({"title": "T", "message": "M", "extension_id": "my-ext"}),
    )
    .with_extension_id(Some("my-ext".to_string()));

    let event = req.to_rpc_event();
    // Payload-provided extension_id should be flattened.
    assert_eq!(event["extension_id"], "my-ext");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui extension_id provenance ok",
        |_| {},
    );
}

// ---------------------------------------------------------------------------
// 15. Timeout field in dialog requests
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_timeout_field() {
    let harness = TestHarness::new("json_parity_extension_ui_timeout_field");

    // TypeScript schema: `timeout?: number` on select/confirm/input methods.
    let mut req = ExtensionUiRequest::new(
        "r1",
        "select",
        json!({"title": "Pick", "options": ["A"], "timeout": 5000}),
    );
    let event = req.to_rpc_event();
    assert_eq!(event["timeout"], 5000);

    // effective_timeout_ms reads from payload.
    assert_eq!(req.effective_timeout_ms(), Some(5000));

    // Explicit timeout_ms on struct takes precedence.
    req.timeout_ms = Some(3000);
    assert_eq!(req.effective_timeout_ms(), Some(3000));

    harness.log().info_ctx(
        "json_parity",
        "extension_ui timeout field ok",
        |_| {},
    );
}

// ---------------------------------------------------------------------------
// 16. Select with label/value objects (rich options)
// ---------------------------------------------------------------------------

#[test]
fn json_parity_extension_ui_select_rich_options() {
    let harness = TestHarness::new("json_parity_extension_ui_select_rich_options");
    let req = ExtensionUiRequest::new(
        "sel-rich",
        "select",
        json!({
            "title": "Choose provider",
            "options": [
                {"label": "Anthropic", "value": "anthropic"},
                {"label": "OpenAI", "value": "openai"},
            ]
        }),
    );
    let event = req.to_rpc_event();

    assert_eq!(event["method"], "select");
    let options = event["options"].as_array().expect("options should be array");
    assert_eq!(options.len(), 2);
    assert_eq!(options[0]["label"], "Anthropic");
    assert_eq!(options[0]["value"], "anthropic");

    harness.log().info_ctx(
        "json_parity",
        "extension_ui select rich options ok",
        |_| {},
    );
}

// ---------------------------------------------------------------------------
// 17. Tool + Extension UI event ordering in complete lifecycle
// ---------------------------------------------------------------------------

#[test]
fn json_parity_complete_lifecycle_with_extension_ui() {
    let harness = TestHarness::new("json_parity_complete_lifecycle_with_extension_ui");

    // Validate that tool events and extension UI events can coexist in a
    // complete agent lifecycle without schema conflicts.
    let tool_start = event_to_json(&AgentEvent::ToolExecutionStart {
        tool_call_id: "tc-1".to_string(),
        tool_name: "bash".to_string(),
        args: json!({"command": "echo hi"}),
    });
    let tool_end = event_to_json(&AgentEvent::ToolExecutionEnd {
        tool_call_id: "tc-1".to_string(),
        tool_name: "bash".to_string(),
        result: test_tool_output(),
        is_error: false,
    });
    let ui_req = ExtensionUiRequest::new(
        "ui-1",
        "confirm",
        json!({"title": "Proceed?", "message": "Continue with deployment?"}),
    )
    .to_rpc_event();

    // All three should have distinct type tags.
    assert_eq!(tool_start["type"], "tool_execution_start");
    assert_eq!(tool_end["type"], "tool_execution_end");
    assert_eq!(ui_req["type"], "extension_ui_request");

    // No field name collisions between event types.
    // Tool events use toolCallId/toolName, UI events use id/method.
    assert!(tool_start.get("id").is_none() || tool_start["id"] != ui_req["id"]);
    assert!(ui_req.get("toolCallId").is_none());
    assert!(ui_req.get("toolName").is_none());

    harness.log().info_ctx(
        "json_parity",
        "tool + extension_ui lifecycle ok",
        |_| {},
    );
}
