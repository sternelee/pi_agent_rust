#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "hyperfine not installed; install with: cargo install hyperfine" >&2
  exit 1
fi

BENCH_CARGO_PROFILE="${BENCH_CARGO_PROFILE:-perf}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BENCH_ALLOCATORS_CSV="${BENCH_ALLOCATORS_CSV:-system,jemalloc}"
BENCH_ALLOCATOR_FALLBACK="${BENCH_ALLOCATOR_FALLBACK:-system}"

BIN="$TARGET_DIR/$BENCH_CARGO_PROFILE/pijs_workload"
ITERATIONS="${ITERATIONS:-200}"
TOOL_CALLS_CSV="${TOOL_CALLS_CSV:-1,10}"
HYPERFINE_WARMUP="${HYPERFINE_WARMUP:-3}"
HYPERFINE_RUNS="${HYPERFINE_RUNS:-10}"
OUT_DIR="${OUT_DIR:-$TARGET_DIR/perf/$BENCH_CARGO_PROFILE}"
JSONL_OUT="${JSONL_OUT:-$OUT_DIR/pijs_workload_${BENCH_CARGO_PROFILE}.jsonl}"

mkdir -p "$OUT_DIR"
: > "$JSONL_OUT"

IFS=',' read -r -a TOOL_CALLS_SET <<< "$TOOL_CALLS_CSV"
IFS=',' read -r -a ALLOCATOR_SET <<< "$BENCH_ALLOCATORS_CSV"
for ALLOCATOR_REQUEST in "${ALLOCATOR_SET[@]}"; do
  ALLOCATOR_REQUEST="${ALLOCATOR_REQUEST//[[:space:]]/}"
  ALLOCATOR_REQUEST="$(printf '%s' "$ALLOCATOR_REQUEST" | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$ALLOCATOR_REQUEST" ]]; then
    continue
  fi

  if [[ "$ALLOCATOR_REQUEST" != "system" && "$ALLOCATOR_REQUEST" != "jemalloc" && "$ALLOCATOR_REQUEST" != "auto" ]]; then
    echo "warning: unknown allocator request '$ALLOCATOR_REQUEST'; using 'auto'" >&2
    ALLOCATOR_REQUEST="auto"
  fi

  EFFECTIVE_ALLOCATOR="system"
  FALLBACK_REASON=""

  if [[ "$ALLOCATOR_REQUEST" == "system" ]]; then
    cargo build --profile "$BENCH_CARGO_PROFILE" --bin pijs_workload
    EFFECTIVE_ALLOCATOR="system"
  elif [[ "$ALLOCATOR_REQUEST" == "jemalloc" ]]; then
    if cargo build --profile "$BENCH_CARGO_PROFILE" --features jemalloc --bin pijs_workload; then
      EFFECTIVE_ALLOCATOR="jemalloc"
    elif [[ "$BENCH_ALLOCATOR_FALLBACK" == "system" ]]; then
      echo "warning: jemalloc build failed; falling back to system allocator build" >&2
      cargo build --profile "$BENCH_CARGO_PROFILE" --bin pijs_workload
      EFFECTIVE_ALLOCATOR="system"
      FALLBACK_REASON="jemalloc_build_failed"
    else
      echo "jemalloc build failed and fallback is disabled (BENCH_ALLOCATOR_FALLBACK=$BENCH_ALLOCATOR_FALLBACK)" >&2
      exit 1
    fi
  else
    # auto: prefer jemalloc build and fall back to system.
    if cargo build --profile "$BENCH_CARGO_PROFILE" --features jemalloc --bin pijs_workload; then
      EFFECTIVE_ALLOCATOR="jemalloc"
    else
      cargo build --profile "$BENCH_CARGO_PROFILE" --bin pijs_workload
      EFFECTIVE_ALLOCATOR="system"
      FALLBACK_REASON="auto_jemalloc_build_failed"
    fi
  fi

  for TOOL_CALLS in "${TOOL_CALLS_SET[@]}"; do
    TOOL_CALLS="${TOOL_CALLS//[[:space:]]/}"
    if [[ -z "$TOOL_CALLS" ]]; then
      continue
    fi

    HYPERFINE_OUT="$OUT_DIR/hyperfine_pijs_workload_${ITERATIONS}x${TOOL_CALLS}_${BENCH_CARGO_PROFILE}_${ALLOCATOR_REQUEST}_effective-${EFFECTIVE_ALLOCATOR}.json"
    CMD="PI_BENCH_BUILD_PROFILE=${BENCH_CARGO_PROFILE} PI_BENCH_ALLOCATOR=${ALLOCATOR_REQUEST} $BIN --iterations ${ITERATIONS} --tool-calls ${TOOL_CALLS}"

    hyperfine \
      --warmup "$HYPERFINE_WARMUP" \
      --runs "$HYPERFINE_RUNS" \
      --export-json "$HYPERFINE_OUT" \
      "$CMD"

    PI_BENCH_BUILD_PROFILE="$BENCH_CARGO_PROFILE" \
      PI_BENCH_ALLOCATOR="$ALLOCATOR_REQUEST" \
      "$BIN" --iterations "$ITERATIONS" --tool-calls "$TOOL_CALLS" >> "$JSONL_OUT"
  done

  if [[ -n "$FALLBACK_REASON" ]]; then
    echo "allocator request '$ALLOCATOR_REQUEST' ran as '$EFFECTIVE_ALLOCATOR' ($FALLBACK_REASON)"
  else
    echo "allocator request '$ALLOCATOR_REQUEST' ran as '$EFFECTIVE_ALLOCATOR'"
  fi
done

echo "Wrote artifacts:"
echo "  - profile=$BENCH_CARGO_PROFILE"
echo "  - allocators=$BENCH_ALLOCATORS_CSV"
echo "  - $JSONL_OUT"
echo "  - $OUT_DIR/hyperfine_pijs_workload_${ITERATIONS}x*_${BENCH_CARGO_PROFILE}_*_effective-*.json"
