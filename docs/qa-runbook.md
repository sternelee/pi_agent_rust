# QA Runbook and Failure Triage Playbook

Reference for running the test suite, interpreting failures, and reproducing issues.

**Bead:** bd-1f42.7.4
**Policy:** [docs/testing-policy.md](testing-policy.md)
**Rubric:** [docs/non-mock-rubric.json](non-mock-rubric.json)
**Coverage baseline:** [docs/coverage-baseline-map.json](coverage-baseline-map.json)

---

## Quick Start

### Fast smoke check (< 60 seconds)

```bash
./scripts/smoke.sh                  # lint + unit + VCR smoke targets
./scripts/smoke.sh --skip-lint      # skip fmt/clippy (faster inner loop)
./scripts/smoke.sh --only unit      # unit smoke only
./scripts/smoke.sh --json           # machine-readable summary to stdout
```

Artifacts: `tests/smoke_results/<timestamp>/smoke_summary.json`

### Full verification

```bash
./scripts/e2e/run_all.sh                        # full: lint + lib + all targets
./scripts/e2e/run_all.sh --profile ci            # CI profile: deterministic
./scripts/e2e/run_all.sh --profile quick         # fast: lint + lib + unit only
```

Artifacts: `tests/e2e_results/<timestamp>/summary.json`

### Suite-specific runs

```bash
# Unit tests only (no mocks, no fixtures, no VCR)
cargo test --all-targets --lib

# VCR/fixture replay tests
VCR_MODE=playback cargo test --all-targets

# Single test file
cargo test --test provider_contract

# Single test function
cargo test --test non_mock_rubric_gate -- rubric_has_required_top_level_keys
```

---

## Test Suite Classification

Every test file belongs to exactly one suite. See `tests/suite_classification.toml` for the canonical mapping.

| Suite | What it tests | Execution command |
|-------|---------------|-------------------|
| **unit** | Pure logic, parsing, serialization, state machines. No mocks, fixtures, or VCR. | `cargo test --lib` + curated `--test` targets |
| **vcr** | Provider streaming, HTTP client, conformance against recorded data. | `VCR_MODE=playback cargo test` |
| **e2e** | Full system with real providers, network, or tmux. | `PI_E2E=1 cargo test --test e2e_*` |

---

## Artifact Locations

| Artifact | Location | Content |
|----------|----------|---------|
| Smoke summary | `tests/smoke_results/<ts>/smoke_summary.json` | Pass/fail per target, duration |
| Smoke event log | `tests/smoke_results/<ts>/smoke_log.jsonl` | Per-event structured log |
| E2E summary | `tests/e2e_results/<ts>/summary.json` | Full run summary |
| E2E evidence | `tests/e2e_results/<ts>/evidence_contract.json` | Evidence contract |
| Conformance report | `tests/ext_conformance/reports/conformance_summary.json` | Extension conformance |
| CI gate verdict | `tests/e2e_results/<ts>/ci_gate_promotion_v1.json` | Promotion gate result |
| Compliance report | `target/compliance-report.json` | Module compliance (set `COMPLIANCE_REPORT=1`) |
| Coverage baseline | `docs/coverage-baseline-map.json` | Line/function coverage per module |
| VCR cassettes | `tests/fixtures/vcr/` | Recorded HTTP interactions |
| Test failure log | `target/test-failures.jsonl` | Structured failure diagnostics (schema: `pi.test.failure_log.v1`) |

---

## Failure Triage Playbook

### Step 1: Identify the failure class

| Signature | Likely Class | Next Action |
|-----------|-------------|-------------|
| `assertion failed` in `provider_*` test | Provider regression | Check VCR cassette freshness; verify `api_key` is set in `StreamOptions` |
| `missing Start event` | Streaming auth failure | Ensure `api_key: Some("vcr-playback".to_string())` in `StreamOptions` for VCR tests |
| `request URL mismatch` in VCR | Model ID drift | VCR uses strict URL matching. Ensure model ID in test matches cassette URL path |
| `connection refused` | Missing test infrastructure | Check if mock server or VCR is configured; verify `VCR_MODE` env var |
| `DummyProvider` / `NullSession` in unit test | Policy violation | Move test to VCR suite or replace double with real implementation |
| `SIGSEGV` in `llvm-cov` | Known toolchain bug | Branch coverage unavailable; use line/function coverage only (see bd-1f42.1.5) |
| `thread panicked` in extension test | Extension dispatcher issue | Check `src/extension_dispatcher.rs`; review mock stub usage |
| Flaky: passes locally, fails on CI | Non-determinism | Classify per flake taxonomy (FLAKE-TIMING/ENV/NET/RES/EXT/LOGIC) |
| `No such file or directory` for cassette | Missing VCR fixture | Record new cassette or check cassette naming convention |
| `too many open files` | Resource exhaustion | Increase `ulimit -n`; check for leaked file descriptors |

### Step 2: Reproduce locally

```bash
# Run the specific failing test with output
cargo test --test <test_file> -- <test_name> --nocapture

# With VCR playback forced
VCR_MODE=playback cargo test --test <test_file> -- <test_name> --nocapture

# With debug logging
RUST_LOG=debug cargo test --test <test_file> -- <test_name> --nocapture

# With backtrace
RUST_BACKTRACE=1 cargo test --test <test_file> -- <test_name> --nocapture
```

### Step 3: Check VCR cassette integrity

If the failure involves provider/streaming tests:

```bash
# List cassettes for a provider
ls tests/fixtures/vcr/verify_<provider>_*.json

# Verify cassette is valid JSON
python3 -m json.tool tests/fixtures/vcr/<cassette>.json > /dev/null

# Check request URL in cassette matches test expectations
python3 -c "
import json
with open('tests/fixtures/vcr/<cassette>.json') as f:
    d = json.load(f)
    for i in d['interactions']:
        print(i['request']['url'])
"
```

### Step 4: Review compliance status

```bash
# Generate compliance report
COMPLIANCE_REPORT=1 cargo test --test non_mock_compliance_gate

# Check rubric integrity
cargo test --test non_mock_rubric_gate

# View module coverage status
python3 -c "
import json
with open('docs/coverage-baseline-map.json') as f:
    d = json.load(f)
    for cp in d['critical_paths']:
        print(f\"{cp['area']}: {cp['coverage']['line_pct']:.1f}% line, {cp['coverage']['function_pct']:.1f}% function\")
"
```

---

## Replay Workflow

The E2E harness supports deterministic replay for failure reproduction:

```bash
# Rerun only failed suites from a previous run
./scripts/e2e/run_all.sh --rerun-from tests/e2e_results/<ts>/summary.json

# Compare current run against a baseline
./scripts/e2e/run_all.sh --diff-from tests/e2e_results/<baseline>/summary.json
```

Replay artifacts include: seed, time-mode, environment snapshot, and per-step transcripts.

---

## Extension Failure Dossier Interpretation

When an extension fails conformance testing:

1. **Check conformance summary:**
   ```bash
   python3 -c "
   import json
   with open('tests/ext_conformance/reports/conformance_summary.json') as f:
       d = json.load(f)
       print(f\"Pass: {d.get('pass_count', '?')}, Fail: {d.get('fail_count', '?')}, N/A: {d.get('na_count', '?')}\")
   "
   ```

2. **Review the failure detail:** Failure dossiers (when available from bd-1f42.4.8) contain:
   - Extension ID and version
   - Input fixture used
   - Expected vs actual output
   - Provider compatibility notes
   - One-command reproduction

3. **Common extension failure patterns:**

   | Pattern | Cause | Fix |
   |---------|-------|-----|
   | Schema validation error | Extension output doesn't match expected shape | Update fixture or fix extension output normalization |
   | Timeout | Extension takes too long to execute | Check for blocking I/O or missing async boundaries |
   | Policy denial | Extension lacks required capability | Review capability policy in `src/extension_dispatcher.rs` |
   | Missing host call | Extension uses unsupported host call op | Check protocol method dispatch coverage |

---

## Smoke Suite Usage

The smoke suite (`scripts/smoke.sh`) is designed for pre-push validation:

**Targets covered:**

| Suite | Targets | What it catches |
|-------|---------|-----------------|
| Unit | `model_serialization`, `config_precedence`, `session_conformance`, `error_types`, `compaction`, `security_budgets` | Core data model regressions |
| VCR | `provider_streaming`, `error_handling`, `http_client`, `sse_strict_compliance`, `model_registry`, `provider_factory` | Provider/HTTP/SSE regressions |

**When to run:**
- Before every `git push`
- After modifying `src/model.rs`, `src/providers/`, `src/sse.rs`, `src/config.rs`
- After updating VCR cassettes

**Interpreting smoke output:**
- Exit code 0: all pass
- Exit code 1: at least one failure (check `smoke_summary.json`)
- `--json` flag outputs machine-readable summary for scripting

---

## CI Gate Thresholds

The CI promotion gate (`.github/workflows/ci.yml`) evaluates:

| Metric | Default | Override Variable |
|--------|---------|-------------------|
| Promotion mode | `strict` | `CI_GATE_PROMOTION_MODE` |
| Min pass rate | 80.0% | `CI_GATE_MIN_PASS_RATE_PCT` |
| Max failures | 36 | `CI_GATE_MAX_FAIL_COUNT` |
| Max N/A | 170 | `CI_GATE_MAX_NA_COUNT` |

Emergency rollback: Set `CI_GATE_PROMOTION_MODE=rollback` to emit warnings without blocking.

---

## Per-Module Coverage Thresholds

From `docs/non-mock-rubric.json`:

| Module | Criticality | Line Floor | Function Floor | Line Target | Function Target |
|--------|-------------|------------|----------------|-------------|-----------------|
| agent_loop | critical | 75% | 70% | 85% | 80% |
| tools | critical | 75% | 72% | 85% | 82% |
| providers | critical | 82% | 79% | 90% | 88% |
| extensions | critical | 80% | 69% | 88% | 80% |
| session | high | 76% | 74% | 85% | 82% |
| auth | high | 72% | 70% | 82% | 78% |
| error | high | 72% | 70% | 82% | 78% |
| model | high | 74% | 72% | 84% | 80% |
| sse | high | 76% | 74% | 86% | 82% |
| config | medium | 70% | 68% | 80% | 76% |
| compaction | medium | 70% | 68% | 80% | 76% |
| vcr | medium | 68% | 66% | 78% | 74% |
| rpc | medium | 70% | 68% | 80% | 76% |
| interactive | low | 60% | 58% | 72% | 68% |

**Floor** = CI fails below this. **Target** = aspirational goal.

---

## Quarantine Workflow

Flaky tests are quarantined in `tests/suite_classification.toml`:

1. **Detect**: Test fails on CI but passes on retry (same commit)
2. **Classify**: Assign a `FLAKE-*` category (TIMING/ENV/NET/RES/EXT/LOGIC)
3. **Quarantine**: Add entry to `[quarantine.<test_stem>]` with all 9 required fields
4. **Fix**: Land fix within the category's window (7 or 14 days)
5. **Restore**: Remove quarantine entry after 3 clean CI runs

Maximum quarantine window: 14 days. See `docs/testing-policy.md` for full escalation ladder.
