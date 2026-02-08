#!/usr/bin/env bash
# scripts/ci_conformance_retry.sh — CI retry wrapper for conformance tests.
#
# Wraps a single conformance test command with automatic retry on
# transient failures (oracle timeouts, resource exhaustion, etc.).
#
# Usage:
#   ./scripts/ci_conformance_retry.sh <target_name> <test_command...>
#
# Example:
#   ./scripts/ci_conformance_retry.sh full-official \
#     cargo test --test ext_conformance_diff --features ext-conformance -- --nocapture
#
# Environment:
#   PI_CONFORMANCE_MAX_RETRIES   Max retries (default: 1)
#   PI_CONFORMANCE_RETRY_DELAY   Seconds between retries (default: 5)
#   PI_CONFORMANCE_CLASSIFY_ONLY Set to 1 to classify without retrying

set -euo pipefail

TARGET="${1:?Usage: ci_conformance_retry.sh <target> <command...>}"
shift
CMD=("$@")

MAX_RETRIES="${PI_CONFORMANCE_MAX_RETRIES:-1}"
RETRY_DELAY="${PI_CONFORMANCE_RETRY_DELAY:-5}"
CLASSIFY_ONLY="${PI_CONFORMANCE_CLASSIFY_ONLY:-0}"
FLAKE_LOG="${PI_CONFORMANCE_FLAKE_LOG:-flake_events.jsonl}"

# ─── Known flake patterns (must match src/flake_classifier.rs) ──────────────

is_transient_failure() {
    local output_lower
    output_lower="$(echo "$1" | tr '[:upper:]' '[:lower:]')"

    # Oracle timeout
    if echo "$output_lower" | grep -qE '(oracle|bun).*(timed out|timeout)'; then
        echo "oracle_timeout"
        return 0
    fi
    # Resource exhaustion
    if echo "$output_lower" | grep -qE 'out of memory|enomem|cannot allocate'; then
        if echo "$output_lower" | grep -qE 'quickjs|allocation failed'; then
            echo "js_gc_pressure"
        else
            echo "resource_exhaustion"
        fi
        return 0
    fi
    # Filesystem contention
    if echo "$output_lower" | grep -qE 'ebusy|etxtbsy|resource busy'; then
        echo "fs_contention"
        return 0
    fi
    # Port conflict
    if echo "$output_lower" | grep -qE 'eaddrinuse|address already in use'; then
        echo "port_conflict"
        return 0
    fi
    # Temp directory race
    if echo "$output_lower" | grep -qE '(no such file or directory|enoent).*tmp'; then
        echo "tmpdir_race"
        return 0
    fi

    echo "deterministic"
    return 1
}

log_flake_event() {
    local target="$1"
    local category="$2"
    local attempt="$3"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    printf '{"target":"%s","category":"%s","attempt":%d,"timestamp":"%s","retriable":true}\n' \
        "$target" "$category" "$attempt" "$timestamp" >> "$FLAKE_LOG"
}

# ─── Execute with retry logic ───────────────────────────────────────────────

attempt=0
while true; do
    attempt=$((attempt + 1))
    echo "=== [$TARGET] attempt $attempt ==="

    OUTPUT_FILE=$(mktemp)
    EXIT_CODE=0
    "${CMD[@]}" 2>&1 | tee "$OUTPUT_FILE" || EXIT_CODE=$?

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "=== [$TARGET] PASS (attempt $attempt) ==="
        rm -f "$OUTPUT_FILE"
        exit 0
    fi

    # Classify the failure.
    OUTPUT=$(cat "$OUTPUT_FILE")
    rm -f "$OUTPUT_FILE"

    CATEGORY=$(is_transient_failure "$OUTPUT" || true)

    if [[ "$CATEGORY" == "deterministic" ]]; then
        echo "=== [$TARGET] DETERMINISTIC FAILURE (attempt $attempt) ==="
        exit $EXIT_CODE
    fi

    echo "=== [$TARGET] TRANSIENT FAILURE: $CATEGORY (attempt $attempt) ==="
    log_flake_event "$TARGET" "$CATEGORY" "$attempt"

    if [[ "$CLASSIFY_ONLY" -eq 1 ]]; then
        echo "=== [$TARGET] CLASSIFY_ONLY mode — not retrying ==="
        exit $EXIT_CODE
    fi

    if [[ $attempt -gt $MAX_RETRIES ]]; then
        echo "=== [$TARGET] MAX RETRIES EXCEEDED ($MAX_RETRIES) ==="
        exit $EXIT_CODE
    fi

    echo "=== [$TARGET] Retrying in ${RETRY_DELAY}s... ==="
    sleep "$RETRY_DELAY"
done
