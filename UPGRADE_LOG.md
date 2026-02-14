# Dependency Upgrade Log

**Date:** 2026-02-14
**Project:** pi_agent_rust
**Language:** Rust
**Manifests:** `Cargo.toml`, `fuzz/Cargo.toml`

---

## Summary

| Metric | Count |
|--------|-------|
| **Total dependencies (direct, outdated)** | 18 |
| **Updated** | 0 |
| **Skipped** | 0 |
| **Failed (rolled back)** | 0 |
| **Requires attention** | 0 |

---

## Discovery

Detected manifests:
- `Cargo.toml`
- `fuzz/Cargo.toml`

Outdated direct dependencies detected (current -> latest stable):
- `anyhow` `1.0.100` -> `1.0.101`
- `clap` `4.5.56` -> `4.5.58`
- `clap_complete` `4.5.65` -> `4.5.66`
- `criterion` `0.7.0` -> `0.8.2`
- `ctrlc` `3.5.1` -> `3.5.2`
- `getrandom` `0.2.17` -> `0.4.1`
- `jsonschema` `0.40.2` -> `0.42.0`
- `memchr` `2.7.6` -> `2.8.0`
- `proptest` `1.9.0` -> `1.10.0`
- `regex` `1.12.2` -> `1.12.3`
- `sysinfo` `0.36.1` -> `0.38.1`
- `tempfile` `3.24.0` -> `3.25.0`
- `toml` `0.8.23` -> `1.0.1+spec-1.1.0`
- `uuid` `1.20.0` -> `1.21.0`
- `vergen` `9.0.6` -> `9.1.0` (fuzz)
- `vergen-gix` `1.0.9` -> `9.1.0`
- `wasmtime` `29.0.1` -> `41.0.3`
- `wat` `1.244.0` -> `1.245.1`

---

## Successfully Updated

_None yet._

---

## Skipped

_None yet._

---

## Failed Updates (Rolled Back)

_None yet._

---

## Requires Attention

_None yet._

---

## Commands Used

```bash
# Discovery
cargo metadata --format-version 1 --no-deps
cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps
cargo tree --depth 1 -e normal,build,dev --prefix none
cargo tree --manifest-path fuzz/Cargo.toml --depth 1 -e normal,build --prefix none
```
