# Provider Auth Troubleshooting Matrix (bd-3uqg.11.12.2)

Auth failure modes and exact remediation paths for each gap and longtail
provider, linked to test evidence and the error hint system in `src/error.rs`.

Generated: 2026-02-13

## Quick Reference

| Provider | Primary Env Var | Fallback Env Var | Get Key |
|---|---|---|---|
| groq | `GROQ_API_KEY` | - | console.groq.com |
| cerebras | `CEREBRAS_API_KEY` | - | cloud.cerebras.ai |
| openrouter | `OPENROUTER_API_KEY` | - | openrouter.ai/keys |
| moonshotai | `MOONSHOT_API_KEY` | `KIMI_API_KEY` | platform.moonshot.cn |
| alibaba | `DASHSCOPE_API_KEY` | `QWEN_API_KEY` | dashscope.console.aliyun.com |
| stackit | `STACKIT_API_KEY` | - | portal.stackit.cloud |
| mistral | `MISTRAL_API_KEY` | - | console.mistral.ai |
| deepinfra | `DEEPINFRA_API_KEY` | - | deepinfra.com/dash |
| togetherai | `TOGETHER_API_KEY` | - | api.together.xyz |
| nvidia | `NVIDIA_API_KEY` | - | build.nvidia.com |
| huggingface | `HF_TOKEN` | - | huggingface.co/settings/tokens |
| ollama-cloud | `OLLAMA_API_KEY` | - | ollama.com |

## Failure Mode Matrix

### 1. Missing API Key

**Symptom**: `Missing API key` or `No API key provided`

**Error hint summary**: "Provider API key is missing."

**Remediation by provider**:

| Provider | Fix |
|---|---|
| groq | `export GROQ_API_KEY=gsk_...` |
| cerebras | `export CEREBRAS_API_KEY=csk-...` |
| openrouter | `export OPENROUTER_API_KEY=sk-or-...` |
| moonshotai | `export MOONSHOT_API_KEY=sk-...` or `export KIMI_API_KEY=sk-...` |
| alibaba | `export DASHSCOPE_API_KEY=sk-...` or `export QWEN_API_KEY=sk-...` |
| stackit | `export STACKIT_API_KEY=...` |
| mistral | `export MISTRAL_API_KEY=...` |
| deepinfra | `export DEEPINFRA_API_KEY=...` |
| togetherai | `export TOGETHER_API_KEY=...` |
| nvidia | `export NVIDIA_API_KEY=nvapi-...` |
| huggingface | `export HF_TOKEN=hf_...` |
| ollama-cloud | `export OLLAMA_API_KEY=...` |

**Test evidence**: `cargo test --test provider_native_contract -- failure_taxonomy::all_providers_produce_hint_summary_for_missing_key`

### 2. Authentication Failure (HTTP 401)

**Symptom**: `401 Unauthorized`, `Invalid API key`, `API key expired`

**Error hint summary**: "Provider authentication failed."

**Common causes**:
- Typo in the API key
- Key was revoked or expired
- Wrong key for the provider (e.g., using Groq key with Cerebras)
- Key has restricted IP/referrer policies

**Remediation**:
1. Verify the key is set: `echo $GROQ_API_KEY` (or relevant var)
2. Test with curl: `curl -H "Authorization: Bearer $GROQ_API_KEY" https://api.groq.com/openai/v1/models`
3. Regenerate the key from the provider's dashboard
4. Check the key hasn't been restricted to specific IPs

**Test evidence**: `cargo test --test provider_native_contract -- failure_taxonomy::all_providers_produce_hint_for_auth_failure`

### 3. Rate Limiting (HTTP 429)

**Symptom**: `429 Too Many Requests`, `Rate limit exceeded`

**Error hint summary**: "Provider rate limited the request."

**Remediation**:
1. Wait and retry (providers typically have per-minute quotas)
2. Reduce `max_tokens` to lower compute per request
3. Check provider dashboard for current rate limits
4. Consider upgrading to a higher-tier plan

**Provider-specific rate limits**:

| Provider | Typical Limit | Notes |
|---|---|---|
| groq | 30 RPM (free tier) | Higher tiers available |
| cerebras | Varies by model | Check dashboard |
| openrouter | Depends on upstream provider | Rate limits cascade |
| moonshotai | Varies by plan | Regional limits may apply |
| alibaba | Varies by model | DashScope quota system |
| mistral | Varies by tier | API key dashboard shows limits |

**Test evidence**: `cargo test --test provider_native_contract -- failure_taxonomy::all_providers_produce_hint_for_rate_limit`

### 4. Forbidden (HTTP 403)

**Symptom**: `403 Forbidden`, `Access denied`

**Error hint summary**: "Provider access forbidden."

**Common causes**:
- Account doesn't have access to the requested model
- Organization/project restrictions
- Geographic restrictions

**Remediation**:
1. Verify the model ID is correct and available to your account
2. Check organization-level permissions
3. Contact the provider's support for access escalation

### 5. Quota Exceeded

**Symptom**: `insufficient_quota`, `billing hard limit`, `not enough credits`

**Error hint summary**: "Provider quota or billing limit reached."

**Remediation**:
1. Check billing status on the provider's dashboard
2. Add credits or update payment method
3. Review spending limits and adjust if needed

### 6. Overloaded (HTTP 529)

**Symptom**: `529 Overloaded`, `Service temporarily unavailable`

**Error hint summary**: "Provider is overloaded."

**Remediation**:
1. Wait and retry (typically resolves within minutes)
2. Consider switching to a less-loaded model
3. If persistent, check provider status page

## Env Var Precedence

For providers with multiple env vars, the precedence order is:

| Provider | Precedence (first found wins) |
|---|---|
| moonshotai | `MOONSHOT_API_KEY` > `KIMI_API_KEY` |
| alibaba | `DASHSCOPE_API_KEY` > `QWEN_API_KEY` |

All other providers have a single env var.

**Test evidence**: `cargo test --test provider_native_contract -- failure_taxonomy::provider_key_hints_reference_correct_env_var`

## Runtime Error Hint System

The error hint system in `src/error.rs` provides structured remediation:

```rust
// Example: creating a provider error
let err = Error::Provider {
    provider: "groq".to_string(),
    message: "401 Unauthorized".to_string(),
};
let hints = err.hints();
// hints.summary: "Provider authentication failed."
// hints.hints: ["Set `GROQ_API_KEY` for provider `groq`.", "If using OAuth, run `/login` again."]
// hints.context: [("provider", "groq"), ("details", "401 Unauthorized")]
```

The hint system is tested against all 12 providers across 7 failure categories:
`cargo test --test provider_native_contract -- failure_taxonomy`

## Related Artifacts

- Provider metadata: `src/provider_metadata.rs`
- Error hint system: `src/error.rs::provider_hints()`
- Contract tests: `tests/provider_native_contract.rs::failure_taxonomy`
- Provider gap test matrix: `docs/provider-gaps-test-matrix.json`
- Longtail evidence: `docs/provider-longtail-evidence.md`
