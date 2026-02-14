# Security Operator Quick Reference

Quick command and API reference for daily security operations.
For detailed procedures, see the Incident Response Runbook and Policy Tuning Guide.

## Environment Variables

```bash
# Master switches
PI_EXTENSION_RISK_ENABLED=true      # Enable runtime risk controller
PI_EXTENSION_RISK_ENFORCE=true       # Enable enforcement (false = shadow mode)
PI_EXTENSION_RISK_FAIL_CLOSED=true   # Deny on controller errors

# Tuning
PI_EXTENSION_RISK_ALPHA=0.01         # Type-I error budget (1e-6..0.5)
PI_EXTENSION_RISK_WINDOW=128         # Sliding window size (8..4096)
PI_EXTENSION_RISK_LEDGER_LIMIT=2048  # Max ledger entries (32..20000)
PI_EXTENSION_RISK_DECISION_TIMEOUT_MS=50  # Decision budget ms (1..2000)

# Policy profile
PI_EXTENSION_POLICY=standard         # safe | standard | permissive
```

## Rollout Phases

| Phase | `enforce` flag | Description |
|-------|---------------|-------------|
| `shadow` | `false` | Score + telemetry only, no blocking |
| `log_only` | `false` | Log would-be actions, no blocking |
| `enforce_new` | `true` | Enforce for newly loaded extensions |
| `enforce_all` | `true` | Full enforcement |

### Phase Operations (Programmatic API)

```rust
// Read current phase
let state: RolloutState = manager.rollout_state();
println!("Phase: {}, Enforce: {}", state.phase, state.enforce);

// Advance to next phase
let changed: bool = manager.advance_rollout();

// Set explicit phase (forward or backward)
manager.set_rollout_phase(RolloutPhase::Shadow);

// Configure rollback triggers
manager.set_rollback_trigger(RollbackTrigger {
    max_false_positive_rate: 0.05,
    max_error_rate: 0.10,
    window_size: 100,
    max_latency_ms: 200,
});

// Record a decision for rollback evaluation
let rollback_triggered: bool = manager.record_rollout_decision(
    latency_ms,    // decision latency
    was_error,     // controller error?
    was_fp,        // operator-flagged false positive?
);
```

## Enforcement States

```
Allow → Harden → Prompt → Deny → Terminate
  0        1        2       3        4
```

- **Allow:** Normal operation, no restrictions
- **Harden:** Dangerous capabilities blocked, safe ones allowed
- **Prompt:** User confirmation required before proceeding
- **Deny:** Call blocked entirely
- **Terminate:** Extension quarantined (3+ consecutive unsafe)

## Risk Ledger Operations

```rust
// Export ledger
let ledger = manager.runtime_risk_ledger_artifact();

// Verify hash chain integrity
let report = verify_runtime_risk_ledger_artifact(&ledger);
assert!(report.valid);

// Export telemetry
let telemetry = manager.runtime_hostcall_telemetry_artifact();
```

## Security Alerts

```rust
// Read alert stream
let alerts: Vec<SecurityAlert> = manager.security_alerts();

// Each alert contains:
// - schema, ts_ms, sequence_id
// - extension_id, capability, method
// - action_taken, reason, risk_score
```

## Kill-Switch Operations

```rust
// Activate kill-switch for an extension
manager.set_kill_switch("extension-id", true, "incident-2024-001");

// Deactivate
manager.set_kill_switch("extension-id", false, "cleared-after-investigation");

// Check trust state
let trust = manager.trust_state("extension-id");
```

## Score Band Thresholds (by profile)

| | Safe | Balanced | Permissive |
|---|------|----------|------------|
| Harden | 0.30 | 0.40 | 0.55 |
| Prompt | 0.50 | 0.60 | 0.70 |
| Deny | 0.65 | 0.75 | 0.85 |
| Terminate | 0.80 | 0.90 | 0.95 |

## Rollback Trigger Defaults

| Threshold | Value | Action when breached |
|-----------|-------|---------------------|
| FP rate | > 5% | Auto-rollback to Shadow |
| Error rate | > 10% | Auto-rollback to Shadow |
| Avg latency | > 200ms | Auto-rollback to Shadow |
| Min samples | 10 | No evaluation below this |

## Common Operations Cheatsheet

| Task | Method |
|------|--------|
| Enable risk controller | `PI_EXTENSION_RISK_ENABLED=true` |
| Start in shadow mode | `PI_EXTENSION_RISK_ENFORCE=false` |
| Check current phase | `manager.rollout_state()` |
| Advance rollout | `manager.advance_rollout()` |
| Emergency rollback | `manager.set_rollout_phase(RolloutPhase::Shadow)` |
| Kill extension | `manager.set_kill_switch(id, true, reason)` |
| Verify ledger | `verify_runtime_risk_ledger_artifact(&ledger)` |
| Export evidence | `manager.runtime_risk_ledger_artifact()` |
| Check FP rate | `manager.rollout_state().window_stats` |
