//! Provider factory and base URL normalization tests (no network).

mod common;

use common::TestHarness;
use pi::Error;
use pi::models::ModelEntry;
use pi::provider::{InputType, Model, ModelCost};
use pi::providers::{create_provider, normalize_openai_base};
use std::collections::HashMap;

fn make_model_entry(provider: &str, model_id: &str, base_url: &str) -> ModelEntry {
    ModelEntry {
        model: Model {
            id: model_id.to_string(),
            name: format!("{provider} {model_id}"),
            api: "test-api".to_string(),
            provider: provider.to_string(),
            base_url: base_url.to_string(),
            reasoning: false,
            input: vec![InputType::Text],
            cost: ModelCost {
                input: 0.0,
                output: 0.0,
                cache_read: 0.0,
                cache_write: 0.0,
            },
            context_window: 8192,
            max_tokens: 4096,
            headers: HashMap::new(),
        },
        api_key: None,
        headers: HashMap::new(),
        auth_header: false,
        compat: None,
    }
}

#[test]
fn normalize_openai_base_appends_for_plain_host() {
    let harness = TestHarness::new("normalize_openai_base_appends_for_plain_host");
    let input = "https://api.openai.com";
    let expected = "https://api.openai.com/chat/completions";
    harness.log().info_ctx("normalize", "plain host", |ctx| {
        ctx.push(("input".to_string(), input.to_string()));
        ctx.push(("expected".to_string(), expected.to_string()));
    });
    let normalized = normalize_openai_base(input);
    assert_eq!(normalized, expected);
}

#[test]
fn normalize_openai_base_appends_for_v1() {
    let harness = TestHarness::new("normalize_openai_base_appends_for_v1");
    let input = "https://api.openai.com/v1";
    let expected = "https://api.openai.com/v1/chat/completions";
    harness.log().info_ctx("normalize", "v1 host", |ctx| {
        ctx.push(("input".to_string(), input.to_string()));
        ctx.push(("expected".to_string(), expected.to_string()));
    });
    let normalized = normalize_openai_base(input);
    assert_eq!(normalized, expected);
}

#[test]
fn normalize_openai_base_trims_trailing_slash() {
    let harness = TestHarness::new("normalize_openai_base_trims_trailing_slash");
    let input = "https://api.openai.com/v1/";
    let expected = "https://api.openai.com/v1/chat/completions";
    harness
        .log()
        .info_ctx("normalize", "trailing slash", |ctx| {
            ctx.push(("input".to_string(), input.to_string()));
            ctx.push(("expected".to_string(), expected.to_string()));
        });
    let normalized = normalize_openai_base(input);
    assert_eq!(normalized, expected);
}

#[test]
fn normalize_openai_base_preserves_chat_completions() {
    let harness = TestHarness::new("normalize_openai_base_preserves_chat_completions");
    let input = "https://api.openai.com/v1/chat/completions";
    let expected = "https://api.openai.com/v1/chat/completions";
    harness
        .log()
        .info_ctx("normalize", "chat completions", |ctx| {
            ctx.push(("input".to_string(), input.to_string()));
            ctx.push(("expected".to_string(), expected.to_string()));
        });
    let normalized = normalize_openai_base(input);
    assert_eq!(normalized, expected);
}

#[test]
fn normalize_openai_base_preserves_responses() {
    let harness = TestHarness::new("normalize_openai_base_preserves_responses");
    let input = "https://api.openai.com/v1/responses";
    let expected = "https://api.openai.com/v1/responses";
    harness
        .log()
        .info_ctx("normalize", "responses endpoint", |ctx| {
            ctx.push(("input".to_string(), input.to_string()));
            ctx.push(("expected".to_string(), expected.to_string()));
        });
    let normalized = normalize_openai_base(input);
    assert_eq!(normalized, expected);
}

#[test]
fn create_provider_for_anthropic() {
    let harness = TestHarness::new("create_provider_for_anthropic");
    let entry = make_model_entry(
        "anthropic",
        "claude-test",
        "https://api.anthropic.com/v1/messages",
    );
    let provider = create_provider(&entry).expect("create anthropic provider");
    harness
        .log()
        .info_ctx("provider", "created provider", |ctx| {
            ctx.push(("name".to_string(), provider.name().to_string()));
            ctx.push(("api".to_string(), provider.api().to_string()));
            ctx.push(("model".to_string(), provider.model_id().to_string()));
        });

    assert_eq!(provider.name(), "anthropic");
    assert_eq!(provider.api(), "anthropic-messages");
    assert_eq!(provider.model_id(), "claude-test");
}

#[test]
fn create_provider_for_openai() {
    let harness = TestHarness::new("create_provider_for_openai");
    let entry = make_model_entry("openai", "gpt-test", "https://api.openai.com/v1");
    let provider = create_provider(&entry).expect("create openai provider");
    harness
        .log()
        .info_ctx("provider", "created provider", |ctx| {
            ctx.push(("name".to_string(), provider.name().to_string()));
            ctx.push(("api".to_string(), provider.api().to_string()));
            ctx.push(("model".to_string(), provider.model_id().to_string()));
        });

    assert_eq!(provider.name(), "openai");
    assert_eq!(provider.api(), "openai-completions");
    assert_eq!(provider.model_id(), "gpt-test");
}

#[test]
fn create_provider_for_gemini() {
    let harness = TestHarness::new("create_provider_for_gemini");
    let entry = make_model_entry(
        "google",
        "gemini-test",
        "https://generativelanguage.googleapis.com/v1beta",
    );
    let provider = create_provider(&entry).expect("create gemini provider");
    harness
        .log()
        .info_ctx("provider", "created provider", |ctx| {
            ctx.push(("name".to_string(), provider.name().to_string()));
            ctx.push(("api".to_string(), provider.api().to_string()));
            ctx.push(("model".to_string(), provider.model_id().to_string()));
        });

    assert_eq!(provider.name(), "google");
    assert_eq!(provider.api(), "gemini");
    assert_eq!(provider.model_id(), "gemini-test");
}

#[test]
fn create_provider_rejects_azure_without_deployment() {
    let harness = TestHarness::new("create_provider_rejects_azure_without_deployment");
    let entry = make_model_entry("azure-openai", "gpt-4o", "https://example.openai.azure.com");
    let Err(err) = create_provider(&entry) else {
        panic!("expected azure-openai error");
    };
    harness.log().info_ctx("provider", "azure error", |ctx| {
        ctx.push(("error".to_string(), err.to_string()));
    });

    match err {
        Error::Provider { provider, message } => {
            assert_eq!(provider, "azure-openai");
            assert!(message.contains("resource+deployment"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn create_provider_rejects_unknown_provider() {
    let harness = TestHarness::new("create_provider_rejects_unknown_provider");
    let entry = make_model_entry("mystery", "mystery-model", "https://example.com/v1");
    let Err(err) = create_provider(&entry) else {
        panic!("expected unknown provider error");
    };
    harness.log().info_ctx("provider", "unknown error", |ctx| {
        ctx.push(("error".to_string(), err.to_string()));
    });

    match err {
        Error::Provider { provider, message } => {
            assert_eq!(provider, "mystery");
            assert!(message.contains("not implemented"));
        }
        other => panic!("unexpected error: {other}"),
    }
}
