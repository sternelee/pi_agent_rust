//! Canonical provider metadata shared across runtime surfaces.
//!
//! This module is intentionally data-first: it centralizes provider identifiers,
//! aliases, auth env keys, and default routing hints so models/auth/provider
//! selection paths don't drift independently.

use crate::provider::InputType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderOnboardingMode {
    BuiltInNative,
    OpenAICompatiblePreset,
    NativeAdapterRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ProviderTestObligations {
    pub unit: bool,
    pub contract: bool,
    pub conformance: bool,
    pub e2e: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderRoutingDefaults {
    pub api: &'static str,
    pub base_url: &'static str,
    pub auth_header: bool,
    pub reasoning: bool,
    pub input: &'static [InputType],
    pub context_window: u32,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderMetadata {
    pub canonical_id: &'static str,
    pub aliases: &'static [&'static str],
    pub auth_env_keys: &'static [&'static str],
    pub onboarding: ProviderOnboardingMode,
    pub routing_defaults: Option<ProviderRoutingDefaults>,
    pub test_obligations: ProviderTestObligations,
}

const INPUT_TEXT: [InputType; 1] = [InputType::Text];
const INPUT_TEXT_IMAGE: [InputType; 2] = [InputType::Text, InputType::Image];

const TEST_REQUIRED: ProviderTestObligations = ProviderTestObligations {
    unit: true,
    contract: true,
    conformance: true,
    e2e: true,
};

pub const PROVIDER_METADATA: &[ProviderMetadata] = &[
    ProviderMetadata {
        canonical_id: "anthropic",
        aliases: &[],
        auth_env_keys: &["ANTHROPIC_API_KEY"],
        onboarding: ProviderOnboardingMode::BuiltInNative,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "anthropic-messages",
            base_url: "https://api.anthropic.com/v1/messages",
            auth_header: false,
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 200_000,
            max_tokens: 8192,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "openai",
        aliases: &[],
        auth_env_keys: &["OPENAI_API_KEY"],
        onboarding: ProviderOnboardingMode::BuiltInNative,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-responses",
            base_url: "https://api.openai.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "google",
        aliases: &[],
        auth_env_keys: &["GOOGLE_API_KEY"],
        onboarding: ProviderOnboardingMode::BuiltInNative,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "google-generative-ai",
            base_url: "https://generativelanguage.googleapis.com/v1beta",
            auth_header: false,
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 128_000,
            max_tokens: 8192,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "cohere",
        aliases: &[],
        auth_env_keys: &["COHERE_API_KEY"],
        onboarding: ProviderOnboardingMode::BuiltInNative,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "cohere-chat",
            base_url: "https://api.cohere.com/v2",
            auth_header: false,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 8192,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "groq",
        aliases: &[],
        auth_env_keys: &["GROQ_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.groq.com/openai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "deepinfra",
        aliases: &[],
        auth_env_keys: &["DEEPINFRA_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.deepinfra.com/v1/openai",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "cerebras",
        aliases: &[],
        auth_env_keys: &["CEREBRAS_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.cerebras.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "openrouter",
        aliases: &[],
        auth_env_keys: &["OPENROUTER_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://openrouter.ai/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "mistral",
        aliases: &[],
        auth_env_keys: &["MISTRAL_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.mistral.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "moonshotai",
        aliases: &["moonshot", "kimi"],
        auth_env_keys: &["MOONSHOT_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.moonshot.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "alibaba",
        aliases: &["dashscope", "qwen"],
        auth_env_keys: &["DASHSCOPE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "deepseek",
        aliases: &[],
        auth_env_keys: &["DEEPSEEK_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.deepseek.com",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "fireworks",
        aliases: &[],
        auth_env_keys: &["FIREWORKS_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.fireworks.ai/inference/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "togetherai",
        aliases: &[],
        auth_env_keys: &["TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.together.xyz/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "perplexity",
        aliases: &[],
        auth_env_keys: &["PERPLEXITY_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.perplexity.ai",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "xai",
        aliases: &[],
        auth_env_keys: &["XAI_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.x.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "google-vertex",
        aliases: &[],
        auth_env_keys: &["GOOGLE_CLOUD_API_KEY"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "amazon-bedrock",
        aliases: &[],
        auth_env_keys: &["AWS_ACCESS_KEY_ID"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "azure-openai",
        aliases: &[],
        auth_env_keys: &["AZURE_OPENAI_API_KEY"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "github-copilot",
        aliases: &[],
        auth_env_keys: &["GITHUB_COPILOT_API_KEY"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
];

pub fn provider_metadata(provider_id: &str) -> Option<&'static ProviderMetadata> {
    if provider_id.is_empty() {
        return None;
    }

    PROVIDER_METADATA.iter().find(|meta| {
        meta.canonical_id.eq_ignore_ascii_case(provider_id)
            || meta
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(provider_id))
    })
}

pub fn canonical_provider_id(provider_id: &str) -> Option<&'static str> {
    provider_metadata(provider_id).map(|meta| meta.canonical_id)
}

pub fn provider_auth_env_keys(provider_id: &str) -> &'static [&'static str] {
    provider_metadata(provider_id).map_or(&[], |meta| meta.auth_env_keys)
}

pub fn provider_routing_defaults(provider_id: &str) -> Option<ProviderRoutingDefaults> {
    provider_metadata(provider_id).and_then(|meta| meta.routing_defaults)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_resolves_canonical_and_alias_names() {
        let canonical = provider_metadata("moonshotai").expect("moonshot metadata");
        assert_eq!(canonical.canonical_id, "moonshotai");
        let alias = provider_metadata("kimi").expect("alias metadata");
        assert_eq!(alias.canonical_id, "moonshotai");
    }

    #[test]
    fn provider_auth_env_keys_support_aliases() {
        assert_eq!(provider_auth_env_keys("dashscope"), &["DASHSCOPE_API_KEY"]);
        assert_eq!(
            provider_auth_env_keys("togetherai"),
            &["TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"]
        );
    }

    #[test]
    fn provider_routing_defaults_available_for_openai_compatible_providers() {
        let defaults = provider_routing_defaults("groq").expect("groq defaults");
        assert_eq!(defaults.api, "openai-completions");
        assert!(defaults.auth_header);
        assert!(defaults.base_url.contains("groq"));
    }

    #[test]
    fn provider_routing_defaults_absent_for_native_adapter_only_providers() {
        assert!(provider_routing_defaults("azure-openai").is_none());
    }
}
