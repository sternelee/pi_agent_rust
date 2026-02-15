use pi::sdk;
use serde_json::json;

const fn assert_clone_debug_send_sync<T: Clone + std::fmt::Debug + Send + Sync>() {}

#[test]
fn sdk_surface_exports_core_types() {
    let _: Option<sdk::ModelRegistry> = None;
    let _: Option<sdk::Config> = None;
    let _: Option<sdk::Session> = None;
    let _: Option<sdk::Agent> = None;
    let _: Option<sdk::AgentSession> = None;
    let _: sdk::ProviderContext = sdk::ProviderContext::default();
    let _: sdk::StreamOptions = sdk::StreamOptions::default();

    let _: sdk::ToolDefinition = sdk::ToolDef {
        name: "read".to_string(),
        description: "Read file".to_string(),
        parameters: json!({"type": "object"}),
    };
}

#[test]
fn sdk_public_types_have_expected_traits() {
    assert_clone_debug_send_sync::<sdk::Message>();
    assert_clone_debug_send_sync::<sdk::ContentBlock>();
    assert_clone_debug_send_sync::<sdk::ToolCall>();
    assert_clone_debug_send_sync::<sdk::ToolDefinition>();
    assert_clone_debug_send_sync::<sdk::AgentEvent>();
    assert_clone_debug_send_sync::<sdk::RpcModelInfo>();
    assert_clone_debug_send_sync::<sdk::RpcSessionState>();
    assert_clone_debug_send_sync::<sdk::RpcSessionStats>();
    assert_clone_debug_send_sync::<sdk::RpcCommandInfo>();
}

#[test]
fn sdk_message_round_trips_via_serde() {
    let message = sdk::Message::User(sdk::UserMessage {
        content: sdk::UserContent::Text("hello".to_string()),
        timestamp: 1234,
    });

    let encoded = serde_json::to_value(&message).expect("serialize sdk::Message");
    let decoded: sdk::Message = serde_json::from_value(encoded.clone()).expect("deserialize");
    let reencoded = serde_json::to_value(decoded).expect("re-serialize");

    assert_eq!(reencoded, encoded);
}

#[test]
fn sdk_rpc_state_round_trips_via_serde() {
    let value = json!({
        "model": {
            "id": "claude-sonnet-4-20250514",
            "name": "Claude Sonnet 4",
            "api": "anthropic-messages",
            "provider": "anthropic",
            "baseUrl": "https://api.anthropic.com",
            "reasoning": true,
            "input": ["text", "image"],
            "contextWindow": 200_000,
            "maxTokens": 8192,
            "cost": {
                "input": 3.0,
                "output": 15.0,
                "cacheRead": 0.3,
                "cacheWrite": 3.75
            }
        },
        "thinkingLevel": "low",
        "isStreaming": false,
        "isCompacting": false,
        "steeringMode": "all",
        "followUpMode": "one-at-a-time",
        "sessionFile": null,
        "sessionId": "session-123",
        "sessionName": "demo",
        "autoCompactionEnabled": true,
        "messageCount": 2,
        "pendingMessageCount": 0
    });

    let state: sdk::RpcSessionState =
        serde_json::from_value(value.clone()).expect("deserialize RpcSessionState");
    let reencoded = serde_json::to_value(state).expect("serialize RpcSessionState");
    assert_eq!(reencoded, value);
}
