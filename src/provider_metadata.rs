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
        aliases: &["gemini"],
        auth_env_keys: &["GOOGLE_API_KEY", "GEMINI_API_KEY"],
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
        aliases: &["fireworks-ai"],
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
    // ── Batch A1: OAI-compatible preset providers ──────────────────────
    ProviderMetadata {
        canonical_id: "302ai",
        aliases: &[],
        auth_env_keys: &["302AI_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.302.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "abacus",
        aliases: &[],
        auth_env_keys: &["ABACUS_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://routellm.abacus.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "aihubmix",
        aliases: &[],
        auth_env_keys: &["AIHUBMIX_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://aihubmix.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "bailing",
        aliases: &[],
        auth_env_keys: &["BAILING_API_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.tbox.cn/api/llm/v1",
            auth_header: true,
            reasoning: false,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "berget",
        aliases: &[],
        auth_env_keys: &["BERGET_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.berget.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "chutes",
        aliases: &[],
        auth_env_keys: &["CHUTES_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://llm.chutes.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "cortecs",
        aliases: &[],
        auth_env_keys: &["CORTECS_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.cortecs.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "fastrouter",
        aliases: &[],
        auth_env_keys: &["FASTROUTER_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://go.fastrouter.ai/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    // ── Batch A2: OAI-compatible preset providers ──────────────────────
    ProviderMetadata {
        canonical_id: "firmware",
        aliases: &[],
        auth_env_keys: &["FIRMWARE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://app.firmware.ai/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "friendli",
        aliases: &[],
        auth_env_keys: &["FRIENDLI_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.friendli.ai/serverless/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "github-models",
        aliases: &[],
        auth_env_keys: &["GITHUB_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://models.github.ai/inference",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "helicone",
        aliases: &[],
        auth_env_keys: &["HELICONE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://ai-gateway.helicone.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "huggingface",
        aliases: &[],
        auth_env_keys: &["HF_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://router.huggingface.co/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "iflowcn",
        aliases: &[],
        auth_env_keys: &["IFLOW_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://apis.iflow.cn/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "inception",
        aliases: &[],
        auth_env_keys: &["INCEPTION_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.inceptionlabs.ai/v1",
            auth_header: true,
            reasoning: false,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "inference",
        aliases: &[],
        auth_env_keys: &["INFERENCE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://inference.net/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    // ── Batch A3: OAI-compatible preset providers ──────────────────────
    ProviderMetadata {
        canonical_id: "io-net",
        aliases: &[],
        auth_env_keys: &["IOINTELLIGENCE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.intelligence.io.solutions/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "jiekou",
        aliases: &[],
        auth_env_keys: &["JIEKOU_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.jiekou.ai/openai",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "lucidquery",
        aliases: &[],
        auth_env_keys: &["LUCIDQUERY_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://lucidquery.com/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "moark",
        aliases: &[],
        auth_env_keys: &["MOARK_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://moark.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "morph",
        aliases: &[],
        auth_env_keys: &["MORPH_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.morphllm.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "nano-gpt",
        aliases: &[],
        auth_env_keys: &["NANO_GPT_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://nano-gpt.com/api/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "nova",
        aliases: &[],
        auth_env_keys: &["NOVA_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.nova.amazon.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "novita-ai",
        aliases: &[],
        auth_env_keys: &["NOVITA_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.novita.ai/openai",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "nvidia",
        aliases: &[],
        auth_env_keys: &["NVIDIA_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://integrate.api.nvidia.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    // ── Batch A4: OAI-compatible preset providers ──────────────────────
    ProviderMetadata {
        canonical_id: "poe",
        aliases: &[],
        auth_env_keys: &["POE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.poe.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "privatemode-ai",
        aliases: &[],
        auth_env_keys: &["PRIVATEMODE_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            // Default is localhost; users override via PRIVATEMODE_ENDPOINT env var.
            base_url: "http://localhost:8080/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "requesty",
        aliases: &[],
        auth_env_keys: &["REQUESTY_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://router.requesty.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "submodel",
        aliases: &[],
        auth_env_keys: &["SUBMODEL_INSTAGEN_ACCESS_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://llm.submodel.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "synthetic",
        aliases: &[],
        auth_env_keys: &["SYNTHETIC_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.synthetic.new/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "vivgrid",
        aliases: &[],
        auth_env_keys: &["VIVGRID_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.vivgrid.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "vultr",
        aliases: &[],
        auth_env_keys: &["VULTR_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.vultrinference.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "wandb",
        aliases: &[],
        auth_env_keys: &["WANDB_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.inference.wandb.ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "xiaomi",
        aliases: &[],
        auth_env_keys: &["XIAOMI_API_KEY"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.xiaomimimo.com/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    // ── Cloudflare provider IDs (gateway + workers-ai) ────────────────────
    ProviderMetadata {
        canonical_id: "cloudflare-ai-gateway",
        aliases: &[],
        auth_env_keys: &["CLOUDFLARE_API_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/openai",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "cloudflare-workers-ai",
        aliases: &[],
        auth_env_keys: &["CLOUDFLARE_API_TOKEN"],
        onboarding: ProviderOnboardingMode::OpenAICompatiblePreset,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "openai-completions",
            base_url: "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 128_000,
            max_tokens: 16_384,
        }),
        test_obligations: TEST_REQUIRED,
    },
    // ── Native adapter required providers ────────────────────────────────
    ProviderMetadata {
        canonical_id: "google-vertex",
        aliases: &["vertexai"],
        auth_env_keys: &["GOOGLE_CLOUD_API_KEY", "VERTEX_API_KEY"],
        onboarding: ProviderOnboardingMode::BuiltInNative,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "google-vertex",
            base_url: "",
            auth_header: true,
            reasoning: true,
            input: &INPUT_TEXT_IMAGE,
            context_window: 1_000_000,
            max_tokens: 8192,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "amazon-bedrock",
        aliases: &["bedrock"],
        auth_env_keys: &[
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_PROFILE",
            "AWS_REGION",
        ],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: Some(ProviderRoutingDefaults {
            api: "bedrock-converse-stream",
            base_url: "",
            auth_header: false,
            reasoning: true,
            input: &INPUT_TEXT,
            context_window: 200_000,
            max_tokens: 8192,
        }),
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "sap-ai-core",
        aliases: &["sap"],
        auth_env_keys: &[
            "AICORE_SERVICE_KEY",
            "SAP_AI_CORE_CLIENT_ID",
            "SAP_AI_CORE_CLIENT_SECRET",
            "SAP_AI_CORE_TOKEN_URL",
            "SAP_AI_CORE_SERVICE_URL",
        ],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "azure-openai",
        aliases: &["azure", "azure-cognitive-services"],
        auth_env_keys: &["AZURE_OPENAI_API_KEY"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "github-copilot",
        aliases: &["copilot"],
        auth_env_keys: &["GITHUB_COPILOT_API_KEY", "GITHUB_TOKEN"],
        onboarding: ProviderOnboardingMode::NativeAdapterRequired,
        routing_defaults: None,
        test_obligations: TEST_REQUIRED,
    },
    ProviderMetadata {
        canonical_id: "gitlab",
        aliases: &["gitlab-duo"],
        auth_env_keys: &["GITLAB_TOKEN", "GITLAB_API_KEY"],
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
        let google_alias = provider_metadata("gemini").expect("gemini alias metadata");
        assert_eq!(google_alias.canonical_id, "google");
        let azure_alias = provider_metadata("azure").expect("azure alias metadata");
        assert_eq!(azure_alias.canonical_id, "azure-openai");
        let azure_cognitive_alias =
            provider_metadata("azure-cognitive-services").expect("azure-cognitive alias metadata");
        assert_eq!(azure_cognitive_alias.canonical_id, "azure-openai");
    }

    #[test]
    fn provider_auth_env_keys_support_aliases() {
        assert_eq!(provider_auth_env_keys("dashscope"), &["DASHSCOPE_API_KEY"]);
        assert_eq!(
            provider_auth_env_keys("togetherai"),
            &["TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"]
        );
        assert_eq!(
            provider_auth_env_keys("fireworks-ai"),
            &["FIREWORKS_API_KEY"]
        );
        assert_eq!(
            provider_auth_env_keys("vertexai"),
            &["GOOGLE_CLOUD_API_KEY", "VERTEX_API_KEY"]
        );
        assert_eq!(
            provider_auth_env_keys("bedrock"),
            &[
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_BEARER_TOKEN_BEDROCK",
                "AWS_PROFILE",
                "AWS_REGION",
            ]
        );
        assert_eq!(provider_auth_env_keys("azure"), &["AZURE_OPENAI_API_KEY"]);
        assert_eq!(
            provider_auth_env_keys("azure-cognitive-services"),
            &["AZURE_OPENAI_API_KEY"]
        );
        assert_eq!(
            provider_auth_env_keys("copilot"),
            &["GITHUB_COPILOT_API_KEY", "GITHUB_TOKEN"]
        );
    }

    #[test]
    fn provider_auth_env_keys_support_shared_fallbacks() {
        assert_eq!(
            provider_auth_env_keys("google"),
            &["GOOGLE_API_KEY", "GEMINI_API_KEY"]
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

    #[test]
    fn provider_routing_defaults_present_for_bedrock_native_adapter() {
        let defaults = provider_routing_defaults("amazon-bedrock").expect("bedrock defaults");
        assert_eq!(defaults.api, "bedrock-converse-stream");
        assert_eq!(defaults.base_url, "");
        assert!(!defaults.auth_header);
    }

    #[test]
    fn cloudflare_metadata_registered_with_openai_compatible_defaults() {
        let gateway =
            provider_metadata("cloudflare-ai-gateway").expect("cloudflare-ai-gateway metadata");
        assert_eq!(
            gateway.onboarding,
            ProviderOnboardingMode::OpenAICompatiblePreset
        );
        let gateway_defaults =
            provider_routing_defaults("cloudflare-ai-gateway").expect("gateway defaults");
        assert_eq!(gateway_defaults.api, "openai-completions");
        assert!(
            gateway_defaults
                .base_url
                .contains("gateway.ai.cloudflare.com")
        );

        let workers =
            provider_metadata("cloudflare-workers-ai").expect("cloudflare-workers-ai metadata");
        assert_eq!(
            workers.onboarding,
            ProviderOnboardingMode::OpenAICompatiblePreset
        );
        let workers_defaults =
            provider_routing_defaults("cloudflare-workers-ai").expect("workers defaults");
        assert_eq!(workers_defaults.api, "openai-completions");
        assert!(
            workers_defaults
                .base_url
                .contains("api.cloudflare.com/client/v4/accounts")
        );

        assert_eq!(
            provider_auth_env_keys("cloudflare-ai-gateway"),
            &["CLOUDFLARE_API_TOKEN"]
        );
        assert_eq!(
            provider_auth_env_keys("cloudflare-workers-ai"),
            &["CLOUDFLARE_API_TOKEN"]
        );
    }

    #[test]
    fn batch_a1_metadata_resolves_all_eight_providers() {
        let ids = [
            "302ai",
            "abacus",
            "aihubmix",
            "bailing",
            "berget",
            "chutes",
            "cortecs",
            "fastrouter",
        ];
        for id in &ids {
            let meta = provider_metadata(id).unwrap_or_else(|| panic!("{id} metadata missing"));
            assert_eq!(meta.canonical_id, *id);
            assert_eq!(
                meta.onboarding,
                ProviderOnboardingMode::OpenAICompatiblePreset
            );
        }
    }

    #[test]
    fn batch_a1_env_keys_match_upstream_registry() {
        assert_eq!(provider_auth_env_keys("302ai"), &["302AI_API_KEY"]);
        assert_eq!(provider_auth_env_keys("abacus"), &["ABACUS_API_KEY"]);
        assert_eq!(provider_auth_env_keys("aihubmix"), &["AIHUBMIX_API_KEY"]);
        assert_eq!(provider_auth_env_keys("bailing"), &["BAILING_API_TOKEN"]);
        assert_eq!(provider_auth_env_keys("berget"), &["BERGET_API_KEY"]);
        assert_eq!(provider_auth_env_keys("chutes"), &["CHUTES_API_KEY"]);
        assert_eq!(provider_auth_env_keys("cortecs"), &["CORTECS_API_KEY"]);
        assert_eq!(
            provider_auth_env_keys("fastrouter"),
            &["FASTROUTER_API_KEY"]
        );
    }

    #[test]
    fn batch_a1_routing_defaults_use_openai_completions() {
        let ids = [
            "302ai",
            "abacus",
            "aihubmix",
            "bailing",
            "berget",
            "chutes",
            "cortecs",
            "fastrouter",
        ];
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert_eq!(defaults.api, "openai-completions", "{id} api mismatch");
            assert!(defaults.auth_header, "{id} must use auth header");
        }
    }

    #[test]
    fn batch_a1_base_urls_are_distinct_and_nonempty() {
        let ids = [
            "302ai",
            "abacus",
            "aihubmix",
            "bailing",
            "berget",
            "chutes",
            "cortecs",
            "fastrouter",
        ];
        let mut urls: Vec<&str> = Vec::new();
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert!(
                !defaults.base_url.is_empty(),
                "{id} base_url must not be empty"
            );
            assert!(
                defaults.base_url.starts_with("https://"),
                "{id} base_url must use HTTPS"
            );
            urls.push(defaults.base_url);
        }
        // All URLs must be unique.
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), ids.len(), "duplicate base URLs detected");
    }

    #[test]
    fn batch_a2_metadata_resolves_all_eight_providers() {
        let ids = [
            "firmware",
            "friendli",
            "github-models",
            "helicone",
            "huggingface",
            "iflowcn",
            "inception",
            "inference",
        ];
        for id in &ids {
            let meta = provider_metadata(id).unwrap_or_else(|| panic!("{id} metadata missing"));
            assert_eq!(meta.canonical_id, *id);
            assert_eq!(
                meta.onboarding,
                ProviderOnboardingMode::OpenAICompatiblePreset
            );
        }
    }

    #[test]
    fn batch_a2_env_keys_match_upstream_registry() {
        assert_eq!(provider_auth_env_keys("firmware"), &["FIRMWARE_API_KEY"]);
        assert_eq!(provider_auth_env_keys("friendli"), &["FRIENDLI_TOKEN"]);
        assert_eq!(provider_auth_env_keys("github-models"), &["GITHUB_TOKEN"]);
        assert_eq!(provider_auth_env_keys("helicone"), &["HELICONE_API_KEY"]);
        assert_eq!(provider_auth_env_keys("huggingface"), &["HF_TOKEN"]);
        assert_eq!(provider_auth_env_keys("iflowcn"), &["IFLOW_API_KEY"]);
        assert_eq!(provider_auth_env_keys("inception"), &["INCEPTION_API_KEY"]);
        assert_eq!(provider_auth_env_keys("inference"), &["INFERENCE_API_KEY"]);
    }

    #[test]
    fn batch_a2_routing_defaults_use_openai_completions() {
        let ids = [
            "firmware",
            "friendli",
            "github-models",
            "helicone",
            "huggingface",
            "iflowcn",
            "inception",
            "inference",
        ];
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert_eq!(defaults.api, "openai-completions", "{id} api mismatch");
            assert!(defaults.auth_header, "{id} must use auth header");
        }
    }

    #[test]
    fn batch_a2_base_urls_are_distinct_and_nonempty() {
        let ids = [
            "firmware",
            "friendli",
            "github-models",
            "helicone",
            "huggingface",
            "iflowcn",
            "inception",
            "inference",
        ];
        let mut urls: Vec<&str> = Vec::new();
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert!(
                !defaults.base_url.is_empty(),
                "{id} base_url must not be empty"
            );
            assert!(
                defaults.base_url.starts_with("https://"),
                "{id} base_url must use HTTPS"
            );
            urls.push(defaults.base_url);
        }
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), ids.len(), "duplicate base URLs detected");
    }

    // ── Batch A3 tests ────────────────────────────────────────────────

    #[test]
    fn batch_a3_metadata_resolves_all_nine_providers() {
        let ids = [
            "io-net",
            "jiekou",
            "lucidquery",
            "moark",
            "morph",
            "nano-gpt",
            "nova",
            "novita-ai",
            "nvidia",
        ];
        for id in &ids {
            let meta = provider_metadata(id).unwrap_or_else(|| panic!("{id} not found"));
            assert_eq!(meta.canonical_id, *id);
            assert_eq!(
                meta.onboarding,
                ProviderOnboardingMode::OpenAICompatiblePreset,
                "{id} onboarding mode mismatch"
            );
        }
    }

    #[test]
    fn batch_a3_env_keys_match_upstream_registry() {
        assert_eq!(
            provider_metadata("io-net").unwrap().auth_env_keys,
            &["IOINTELLIGENCE_API_KEY"]
        );
        assert_eq!(
            provider_metadata("jiekou").unwrap().auth_env_keys,
            &["JIEKOU_API_KEY"]
        );
        assert_eq!(
            provider_metadata("lucidquery").unwrap().auth_env_keys,
            &["LUCIDQUERY_API_KEY"]
        );
        assert_eq!(
            provider_metadata("moark").unwrap().auth_env_keys,
            &["MOARK_API_KEY"]
        );
        assert_eq!(
            provider_metadata("morph").unwrap().auth_env_keys,
            &["MORPH_API_KEY"]
        );
        assert_eq!(
            provider_metadata("nano-gpt").unwrap().auth_env_keys,
            &["NANO_GPT_API_KEY"]
        );
        assert_eq!(
            provider_metadata("nova").unwrap().auth_env_keys,
            &["NOVA_API_KEY"]
        );
        assert_eq!(
            provider_metadata("novita-ai").unwrap().auth_env_keys,
            &["NOVITA_API_KEY"]
        );
        assert_eq!(
            provider_metadata("nvidia").unwrap().auth_env_keys,
            &["NVIDIA_API_KEY"]
        );
    }

    #[test]
    fn batch_a3_routing_defaults_use_openai_completions() {
        let ids = [
            "io-net",
            "jiekou",
            "lucidquery",
            "moark",
            "morph",
            "nano-gpt",
            "nova",
            "novita-ai",
            "nvidia",
        ];
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert_eq!(
                defaults.api, "openai-completions",
                "{id} api should be openai-completions"
            );
            assert!(defaults.auth_header, "{id} auth_header should be true");
        }
    }

    #[test]
    fn batch_a3_base_urls_are_distinct_and_nonempty() {
        let ids = [
            "io-net",
            "jiekou",
            "lucidquery",
            "moark",
            "morph",
            "nano-gpt",
            "nova",
            "novita-ai",
            "nvidia",
        ];
        let mut urls: Vec<&str> = Vec::new();
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert!(
                !defaults.base_url.is_empty(),
                "{id} base_url must not be empty"
            );
            assert!(
                defaults.base_url.starts_with("https://"),
                "{id} base_url must use HTTPS"
            );
            urls.push(defaults.base_url);
        }
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), ids.len(), "duplicate base URLs detected");
    }

    #[test]
    fn fireworks_ai_alias_already_registered() {
        // fireworks-ai is listed in Batch A2 bead but already exists as alias
        // for the "fireworks" canonical entry from the initial metadata set.
        let meta = provider_metadata("fireworks-ai").expect("fireworks-ai alias");
        assert_eq!(meta.canonical_id, "fireworks");
    }

    // ── Batch A4 tests ────────────────────────────────────────────────

    #[test]
    fn batch_a4_metadata_resolves_all_nine_providers() {
        let ids = [
            "poe",
            "privatemode-ai",
            "requesty",
            "submodel",
            "synthetic",
            "vivgrid",
            "vultr",
            "wandb",
            "xiaomi",
        ];
        for id in &ids {
            let meta = provider_metadata(id).unwrap_or_else(|| panic!("{id} not found"));
            assert_eq!(meta.canonical_id, *id);
            assert_eq!(
                meta.onboarding,
                ProviderOnboardingMode::OpenAICompatiblePreset,
                "{id} onboarding mode mismatch"
            );
        }
    }

    #[test]
    fn batch_a4_env_keys_match_upstream_registry() {
        assert_eq!(
            provider_metadata("poe").unwrap().auth_env_keys,
            &["POE_API_KEY"]
        );
        assert_eq!(
            provider_metadata("privatemode-ai").unwrap().auth_env_keys,
            &["PRIVATEMODE_API_KEY"]
        );
        assert_eq!(
            provider_metadata("requesty").unwrap().auth_env_keys,
            &["REQUESTY_API_KEY"]
        );
        assert_eq!(
            provider_metadata("submodel").unwrap().auth_env_keys,
            &["SUBMODEL_INSTAGEN_ACCESS_KEY"]
        );
        assert_eq!(
            provider_metadata("synthetic").unwrap().auth_env_keys,
            &["SYNTHETIC_API_KEY"]
        );
        assert_eq!(
            provider_metadata("vivgrid").unwrap().auth_env_keys,
            &["VIVGRID_API_KEY"]
        );
        assert_eq!(
            provider_metadata("vultr").unwrap().auth_env_keys,
            &["VULTR_API_KEY"]
        );
        assert_eq!(
            provider_metadata("wandb").unwrap().auth_env_keys,
            &["WANDB_API_KEY"]
        );
        assert_eq!(
            provider_metadata("xiaomi").unwrap().auth_env_keys,
            &["XIAOMI_API_KEY"]
        );
    }

    #[test]
    fn batch_a4_routing_defaults_use_openai_completions() {
        let ids = [
            "poe",
            "privatemode-ai",
            "requesty",
            "submodel",
            "synthetic",
            "vivgrid",
            "vultr",
            "wandb",
            "xiaomi",
        ];
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert_eq!(
                defaults.api, "openai-completions",
                "{id} api should be openai-completions"
            );
            assert!(defaults.auth_header, "{id} auth_header should be true");
        }
    }

    #[test]
    fn batch_a4_base_urls_are_distinct_and_nonempty() {
        let ids = [
            "poe",
            "privatemode-ai",
            "requesty",
            "submodel",
            "synthetic",
            "vivgrid",
            "vultr",
            "wandb",
            "xiaomi",
        ];
        let mut urls: Vec<&str> = Vec::new();
        for id in &ids {
            let defaults =
                provider_routing_defaults(id).unwrap_or_else(|| panic!("{id} defaults missing"));
            assert!(
                !defaults.base_url.is_empty(),
                "{id} base_url must not be empty"
            );
            // privatemode-ai uses localhost (self-hosted); all others use HTTPS.
            if *id != "privatemode-ai" {
                assert!(
                    defaults.base_url.starts_with("https://"),
                    "{id} base_url must use HTTPS"
                );
            }
            urls.push(defaults.base_url);
        }
        urls.sort_unstable();
        urls.dedup();
        assert_eq!(urls.len(), ids.len(), "duplicate base URLs detected");
    }

    #[test]
    fn v0_not_onboarded_no_api_endpoint() {
        // v0 (Vercel) has no API endpoint in models.dev; deferred until endpoint is published.
        assert!(
            provider_metadata("v0").is_none(),
            "v0 should not be onboarded yet"
        );
    }
}
