# Provider Configuration Examples (bd-3uqg.11.12.1)

Copy-paste-ready configuration examples for all gap and longtail providers.
Each example shows the minimal setup required to start using a provider, plus
advanced options for customization.

Generated: 2026-02-13

## Gap Providers

### Groq

```bash
# Minimal setup
export GROQ_API_KEY="gsk_..."

# Use with pi
pi --provider groq --model llama-3.3-70b-versatile
```

**Endpoint**: `https://api.groq.com/openai/v1/chat/completions`
**Auth**: Bearer token via `GROQ_API_KEY`
**API family**: `openai-completions`
**Models**: llama-3.3-70b-versatile, llama-3.1-8b-instant, mixtral-8x7b-32768

**Advanced**: Custom base URL for proxied access:
```bash
pi --provider groq --model llama-3.3-70b-versatile --base-url "https://my-proxy.example.com/groq/v1"
```

### Cerebras

```bash
# Minimal setup
export CEREBRAS_API_KEY="csk-..."

# Use with pi
pi --provider cerebras --model llama3.1-70b
```

**Endpoint**: `https://api.cerebras.ai/v1/chat/completions`
**Auth**: Bearer token via `CEREBRAS_API_KEY`
**API family**: `openai-completions`
**Models**: llama3.1-70b, llama3.1-8b

### OpenRouter

```bash
# Minimal setup
export OPENROUTER_API_KEY="sk-or-..."

# Use with pi
pi --provider openrouter --model anthropic/claude-3.5-sonnet
```

**Endpoint**: `https://openrouter.ai/api/v1/chat/completions`
**Auth**: Bearer token via `OPENROUTER_API_KEY`
**API family**: `openai-completions`
**Models**: Any model available on OpenRouter (use `provider/model` format)

**Caveats**:
- Model IDs use `provider/model` format (e.g., `anthropic/claude-3.5-sonnet`)
- Rate limits depend on the upstream provider
- Some models may have higher latency due to routing

### Moonshot AI (Kimi)

```bash
# Minimal setup (either env var works)
export MOONSHOT_API_KEY="sk-..."
# or
export KIMI_API_KEY="sk-..."

# Use with pi (either alias works)
pi --provider moonshotai --model moonshot-v1-8k
pi --provider kimi --model moonshot-v1-8k
```

**Endpoint**: `https://api.moonshot.ai/v1/chat/completions`
**Auth**: Bearer token via `MOONSHOT_API_KEY` (primary) or `KIMI_API_KEY` (fallback)
**API family**: `openai-completions`
**Models**: moonshot-v1-8k, moonshot-v1-32k, moonshot-v1-128k
**Aliases**: `moonshotai`, `moonshot`, `kimi`

### Alibaba (Qwen / DashScope)

```bash
# Minimal setup (either env var works)
export DASHSCOPE_API_KEY="sk-..."
# or
export QWEN_API_KEY="sk-..."

# Use with pi (either alias works)
pi --provider alibaba --model qwen-plus
pi --provider qwen --model qwen-plus
pi --provider dashscope --model qwen-turbo
```

**Endpoint**: `https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions`
**Auth**: Bearer token via `DASHSCOPE_API_KEY` (primary) or `QWEN_API_KEY` (fallback)
**API family**: `openai-completions`
**Models**: qwen-plus, qwen-turbo, qwen-max, qwen-long
**Aliases**: `alibaba`, `dashscope`, `qwen`

**Note**: China-region endpoint available via `alibaba-cn` provider ID.

## Longtail Quick-Win Providers

### Mistral

```bash
export MISTRAL_API_KEY="..."
pi --provider mistral --model mistral-large-latest
```

**Endpoint**: `https://api.mistral.ai/v1/chat/completions`

### NVIDIA

```bash
export NVIDIA_API_KEY="nvapi-..."
pi --provider nvidia --model meta/llama-3.1-70b-instruct
```

**Endpoint**: `https://integrate.api.nvidia.com/v1/chat/completions`

### Hugging Face

```bash
export HF_TOKEN="hf_..."
pi --provider huggingface --model meta-llama/Meta-Llama-3.1-70B-Instruct
```

**Endpoint**: `https://router.huggingface.co/v1/chat/completions`

### Together AI

```bash
export TOGETHER_API_KEY="..."
pi --provider togetherai --model meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo
```

**Endpoint**: `https://api.together.xyz/v1/chat/completions`

### DeepInfra

```bash
export DEEPINFRA_API_KEY="..."
pi --provider deepinfra --model meta-llama/Meta-Llama-3.1-70B-Instruct
```

**Endpoint**: `https://api.deepinfra.com/v1/openai/chat/completions`

### STACKIT (EU)

```bash
export STACKIT_API_KEY="..."
pi --provider stackit --model <model-id>
```

**Endpoint**: `https://api.openai-compat.model-serving.eu01.onstackit.cloud/v1/chat/completions`
**Note**: EU-hosted, data residency compliant.

### Ollama Cloud

```bash
export OLLAMA_API_KEY="..."
pi --provider ollama-cloud --model llama3.1:70b
```

**Endpoint**: `https://ollama.com/v1/chat/completions`

## Behavior Checks

After configuring a provider, verify it works:

```bash
# Quick verification (sends a minimal prompt)
pi --provider groq --model llama-3.3-70b-versatile -m "Hello, respond with just 'OK'"

# Expected: A response containing "OK" or similar acknowledgment
```

Common issues and their fixes are documented in
[provider-auth-troubleshooting.md](provider-auth-troubleshooting.md).

## Related Docs

- Auth troubleshooting: `docs/provider-auth-troubleshooting.md`
- Longtail evidence: `docs/provider-longtail-evidence.md`
- Provider metadata source: `src/provider_metadata.rs`
- Provider onboarding playbook: `docs/provider-onboarding-playbook.md`
