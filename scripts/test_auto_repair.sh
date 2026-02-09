#!/bin/bash
# E2E auto-repair test runner with human-readable reporting.
#
# Usage:
#   ./scripts/test_auto_repair.sh          # run full corpus
#   ./scripts/test_auto_repair.sh --quick  # run report-structure test only
#
# Outputs:
#   tests/ext_conformance/reports/auto_repair_report.md
#   tests/ext_conformance/reports/auto_repair_summary.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/tests/ext_conformance/reports"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="${REPORT_DIR}/auto_repair_${TIMESTAMP}.log"

cd "$PROJECT_ROOT"

echo "=== Auto-Repair E2E Test ==="
echo "Started: $(date -u)"
echo "Log: ${LOG_FILE}"
echo ""

if [[ "${1:-}" == "--quick" ]]; then
    echo "Running quick validation (report structure only)..."
    TMPDIR="$PROJECT_ROOT/target/tmp" cargo test --test e2e_auto_repair \
        report_structure_is_valid \
        -- --nocapture 2>&1 | tee "${LOG_FILE}"
else
    echo "Running full corpus with auto-repair..."
    TMPDIR="$PROJECT_ROOT/target/tmp" cargo test --test e2e_auto_repair \
        full_corpus_with_auto_repair \
        -- --nocapture --test-threads=1 2>&1 | tee "${LOG_FILE}"
fi

echo ""
echo "=== Done ==="

# Print summary from generated files
if [[ -f "${REPORT_DIR}/auto_repair_summary.json" ]]; then
    echo ""
    echo "--- Summary from auto_repair_summary.json ---"
    python3 -c "
import json, sys
d = json.load(open('${REPORT_DIR}/auto_repair_summary.json'))
print(f\"Total: {d['total']} | Clean: {d['clean_pass']} | Repaired: {d['repaired_pass']} | Failed: {d['failed']} | Skipped: {d['skipped']}\")
if d.get('repairs_by_pattern'):
    print('Repairs by pattern:')
    for pat, cnt in d['repairs_by_pattern'].items():
        print(f'  {pat}: {cnt}')
" 2>/dev/null || true
fi

if [[ -f "${REPORT_DIR}/auto_repair_report.md" ]]; then
    echo ""
    echo "Markdown report: ${REPORT_DIR}/auto_repair_report.md"
fi

echo "JSON summary: ${REPORT_DIR}/auto_repair_summary.json"
echo "Full log: ${LOG_FILE}"
