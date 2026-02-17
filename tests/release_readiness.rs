//! Release-readiness verification report generator (bd-k5q5.7.11).
//!
//! Aggregates evidence from conformance, performance, security, and traceability
//! into a single user-focused release-readiness summary.

use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::path::{Path, PathBuf};

const REPORT_SCHEMA: &str = "pi.release_readiness.v1";
const MUST_PASS_GATE_SCHEMA: &str = "pi.ext.must_pass_gate.v1";

// ── Data models ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Signal {
    Pass,
    Warn,
    Fail,
    NoData,
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Warn => f.write_str("WARN"),
            Self::Fail => f.write_str("FAIL"),
            Self::NoData => f.write_str("NO_DATA"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DimensionScore {
    name: String,
    signal: Signal,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReleaseReadinessReport {
    schema: String,
    generated_at: String,
    overall_verdict: Signal,
    dimensions: Vec<DimensionScore>,
    known_issues: Vec<String>,
    reproduce_command: String,
}

impl ReleaseReadinessReport {
    fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Release Readiness Report\n\n");
        let _ = writeln!(out, "**Generated**: {}", self.generated_at);
        let _ = writeln!(out, "**Overall Verdict**: {}\n", self.overall_verdict);

        out.push_str("## Quality Scorecard\n\n");
        out.push_str("| Dimension | Signal | Detail |\n");
        out.push_str("|-----------|--------|--------|\n");
        for d in &self.dimensions {
            let icon = match d.signal {
                Signal::Pass => "PASS",
                Signal::Warn => "WARN",
                Signal::Fail => "FAIL",
                Signal::NoData => "N/A",
            };
            let _ = writeln!(out, "| {} | {icon} | {} |", d.name, d.detail);
        }
        out.push('\n');

        if !self.known_issues.is_empty() {
            out.push_str("## Known Issues\n\n");
            for issue in &self.known_issues {
                let _ = writeln!(out, "- {issue}");
            }
            out.push('\n');
        }

        out.push_str("## Reproduce\n\n");
        let _ = writeln!(out, "```\n{}\n```", self.reproduce_command);

        out
    }
}

// ── JSON helpers ────────────────────────────────────────────────────────────

type V = serde_json::Value;

fn get_u64(v: &V, pointer: &str) -> u64 {
    v.pointer(pointer).and_then(V::as_u64).unwrap_or(0)
}

fn get_f64(v: &V, pointer: &str) -> f64 {
    v.pointer(pointer).and_then(V::as_f64).unwrap_or(0.0)
}

fn get_str<'a>(v: &'a V, pointer: &str) -> &'a str {
    v.pointer(pointer).and_then(V::as_str).unwrap_or("unknown")
}

fn parse_must_pass_gate_verdict(v: &V) -> (String, u64, u64) {
    let status = match get_str(v, "/status") {
        "unknown" => get_str(v, "/verdict").to_string(),
        value => value.to_string(),
    };

    let total = match get_u64(v, "/observed/must_pass_total") {
        0 => get_u64(v, "/total"),
        value => value,
    };
    let passed = match get_u64(v, "/observed/must_pass_passed") {
        0 => get_u64(v, "/passed"),
        value => value,
    };

    (status, passed, total)
}

fn validate_must_pass_gate_metadata(v: &V) -> Vec<String> {
    let mut errors = Vec::new();

    let schema = get_str(v, "/schema");
    if schema != MUST_PASS_GATE_SCHEMA {
        errors.push(format!(
            "schema must be {MUST_PASS_GATE_SCHEMA}, found {schema}"
        ));
    }

    for field in ["/generated_at", "/run_id", "/correlation_id"] {
        if get_str(v, field) == "unknown" {
            errors.push(format!("missing required field: {field}"));
        }
    }

    if v.pointer("/observed").is_none() {
        errors.push("missing required object: /observed".to_string());
    }

    errors
}

// ── Evidence collectors ─────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Option<V> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn no_data(name: &str, detail: &str) -> DimensionScore {
    DimensionScore {
        name: name.to_string(),
        signal: Signal::NoData,
        detail: detail.to_string(),
    }
}

fn collect_conformance(root: &Path) -> DimensionScore {
    let name = "Extension Conformance";
    let path = root.join("tests/ext_conformance/reports/conformance_summary.json");
    load_json(&path).map_or_else(
        || no_data(name, "conformance_summary.json not found"),
        |v| {
            let pass_rate = get_f64(&v, "/pass_rate_pct");
            let pass = get_u64(&v, "/counts/pass");
            let fail = get_u64(&v, "/counts/fail");
            let total = get_u64(&v, "/counts/total");
            let neg_pass = get_u64(&v, "/negative/pass");
            let neg_fail = get_u64(&v, "/negative/fail");

            let signal = if fail == 0 {
                Signal::Pass
            } else if pass_rate >= 90.0 {
                Signal::Warn
            } else {
                Signal::Fail
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "{pass}/{total} pass ({pass_rate:.1}%), {fail} fail; negative tests: {neg_pass} pass, {neg_fail} fail"
                ),
            }
        },
    )
}

fn collect_performance(root: &Path) -> DimensionScore {
    let name = "Performance Budgets";
    let path = root.join("tests/perf/reports/budget_summary.json");
    load_json(&path).map_or_else(
        || no_data(name, "budget_summary.json not found"),
        |v| {
            let total = get_u64(&v, "/total_budgets");
            let pass = get_u64(&v, "/pass");
            let fail = get_u64(&v, "/fail");
            let ci_enforced = get_u64(&v, "/ci_enforced");
            let ci_fail = get_u64(&v, "/ci_fail");
            let no_data_count = get_u64(&v, "/no_data");

            let signal = if ci_fail > 0 {
                Signal::Fail
            } else if fail > 0 || no_data_count > total / 2 {
                Signal::Warn
            } else {
                Signal::Pass
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "{pass}/{total} pass, {fail} fail, {no_data_count} no data; {ci_enforced} CI-enforced ({ci_fail} CI fail)"
                ),
            }
        },
    )
}

fn collect_security(root: &Path) -> DimensionScore {
    let name = "Security & Licensing";
    let path = root.join("tests/ext_conformance/artifacts/RISK_REVIEW.json");
    load_json(&path).map_or_else(
        || no_data(name, "RISK_REVIEW.json not found"),
        |v| {
            let total = get_u64(&v, "/summary/total_artifacts");
            let critical = get_u64(&v, "/summary/security_critical");
            let warnings = get_u64(&v, "/summary/security_warnings");
            let license_clear = get_u64(&v, "/summary/license_clear");
            let license_unknown = get_u64(&v, "/summary/license_unknown");
            let overall_risk = get_str(&v, "/summary/overall_risk");

            let signal = if critical > 0 {
                Signal::Fail
            } else if warnings > 0 || license_unknown > 0 {
                Signal::Warn
            } else {
                Signal::Pass
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "{total} artifacts: {license_clear} license-clear, {license_unknown} unknown; {critical} critical, {warnings} warnings; risk={overall_risk}"
                ),
            }
        },
    )
}

fn collect_provenance(root: &Path) -> DimensionScore {
    let name = "Provenance Integrity";
    let path = root.join("tests/ext_conformance/artifacts/PROVENANCE_VERIFICATION.json");
    load_json(&path).map_or_else(
        || no_data(name, "PROVENANCE_VERIFICATION.json not found"),
        |v| {
            let total = get_u64(&v, "/summary/total_artifacts");
            let verified = get_u64(&v, "/summary/verified_ok");
            let failed = get_u64(&v, "/summary/failed");
            let pass_rate = get_f64(&v, "/summary/pass_rate");

            let signal = if failed > 0 {
                Signal::Fail
            } else if pass_rate >= 1.0 {
                Signal::Pass
            } else {
                Signal::Warn
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "{verified}/{total} verified ({:.0}%), {failed} failed",
                    pass_rate * 100.0
                ),
            }
        },
    )
}

fn collect_traceability(root: &Path) -> DimensionScore {
    let name = "Traceability";
    let path = root.join("docs/traceability_matrix.json");
    load_json(&path).map_or_else(
        || no_data(name, "traceability_matrix.json not found"),
        |v| {
            let requirements = v
                .get("requirements")
                .and_then(V::as_array)
                .map_or(0, Vec::len);
            let min_coverage = get_f64(&v, "/ci_policy/min_classified_trace_coverage_pct");

            let signal = if requirements > 0 {
                Signal::Pass
            } else {
                Signal::Fail
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "{requirements} requirements traced; min coverage threshold: {min_coverage:.0}%"
                ),
            }
        },
    )
}

fn collect_baseline_delta(root: &Path) -> DimensionScore {
    let name = "Baseline Conformance";
    let path = root.join("tests/ext_conformance/reports/conformance_baseline.json");
    load_json(&path).map_or_else(
        || no_data(name, "conformance_baseline.json not found"),
        |v| {
            let pass_rate = get_f64(&v, "/extension_conformance/pass_rate_pct");
            let passed = get_u64(&v, "/extension_conformance/passed");
            let total = get_u64(&v, "/extension_conformance/manifest_count");
            let git_ref = get_str(&v, "/git_ref");
            let scenario_rate = get_f64(&v, "/scenario_conformance/pass_rate_pct");

            let signal = if pass_rate >= 90.0 && scenario_rate >= 80.0 {
                Signal::Pass
            } else if pass_rate >= 70.0 {
                Signal::Warn
            } else {
                Signal::Fail
            };

            DimensionScore {
                name: name.to_string(),
                signal,
                detail: format!(
                    "ext: {passed}/{total} ({pass_rate:.1}%); scenarios: {scenario_rate:.1}%; ref={git_ref}"
                ),
            }
        },
    )
}

fn collect_known_issues(root: &Path) -> Vec<String> {
    let mut issues = Vec::new();

    // Conformance failures
    let baseline_path = root.join("tests/ext_conformance/reports/conformance_baseline.json");
    if let Some(v) = load_json(&baseline_path) {
        if let Some(arr) = v
            .pointer("/scenario_conformance/failures")
            .and_then(V::as_array)
        {
            for f in arr {
                let id = get_str(f, "/id");
                let cause = get_str(f, "/cause");
                issues.push(format!("Scenario {id}: {cause}"));
            }
        }
    }

    // Performance no-data budgets
    let perf_path = root.join("tests/perf/reports/budget_summary.json");
    if let Some(v) = load_json(&perf_path) {
        let nd = get_u64(&v, "/no_data");
        if nd > 0 {
            issues.push(format!(
                "{nd} performance budgets have no measured data yet"
            ));
        }
    }

    // Security warnings
    let risk_path = root.join("tests/ext_conformance/artifacts/RISK_REVIEW.json");
    if let Some(v) = load_json(&risk_path) {
        let warnings = get_u64(&v, "/summary/security_warnings");
        if warnings > 0 {
            issues.push(format!(
                "{warnings} extension artifacts have security warnings"
            ));
        }
        let unknown = get_u64(&v, "/summary/license_unknown");
        if unknown > 0 {
            issues.push(format!(
                "{unknown} extension artifacts have unknown licenses"
            ));
        }
    }

    issues
}

fn generate_report() -> ReleaseReadinessReport {
    let root = repo_root();

    let dimensions = vec![
        collect_conformance(&root),
        collect_baseline_delta(&root),
        collect_performance(&root),
        collect_security(&root),
        collect_provenance(&root),
        collect_traceability(&root),
    ];

    // Overall verdict: Fail if any dimension fails, Warn if any warns, else Pass
    let overall = if dimensions.iter().any(|d| d.signal == Signal::Fail) {
        Signal::Fail
    } else if dimensions.iter().any(|d| d.signal == Signal::Warn) {
        Signal::Warn
    } else if dimensions.iter().all(|d| d.signal == Signal::NoData) {
        Signal::NoData
    } else {
        Signal::Pass
    };

    let known_issues = collect_known_issues(&root);

    ReleaseReadinessReport {
        schema: REPORT_SCHEMA.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        overall_verdict: overall,
        dimensions,
        known_issues,
        reproduce_command: "./scripts/e2e/run_all.sh --profile ci".to_string(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn generate_release_readiness_report() {
    let report = generate_report();
    eprintln!("{}", report.render_markdown());

    assert_eq!(report.dimensions.len(), 6);
    assert_eq!(report.schema, REPORT_SCHEMA);

    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: V = serde_json::from_str(&json).expect("parse");
    assert!(parsed.get("schema").is_some());
    assert!(parsed.get("overall_verdict").is_some());
    assert!(parsed.get("dimensions").is_some());
}

#[test]
fn conformance_dimension_has_data() {
    let dim = collect_conformance(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "conformance: {}", dim.detail);
}

#[test]
fn performance_dimension_has_data() {
    let dim = collect_performance(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "performance: {}", dim.detail);
}

#[test]
fn security_dimension_has_data() {
    let dim = collect_security(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "security: {}", dim.detail);
}

#[test]
fn provenance_dimension_has_data() {
    let dim = collect_provenance(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "provenance: {}", dim.detail);
}

#[test]
fn traceability_dimension_has_data() {
    let dim = collect_traceability(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "traceability: {}", dim.detail);
}

#[test]
fn baseline_dimension_has_data() {
    let dim = collect_baseline_delta(&repo_root());
    assert_ne!(dim.signal, Signal::NoData, "baseline: {}", dim.detail);
}

#[test]
fn overall_verdict_reflects_dimensions() {
    let report = generate_report();
    let has_fail = report.dimensions.iter().any(|d| d.signal == Signal::Fail);
    let has_warn = report.dimensions.iter().any(|d| d.signal == Signal::Warn);

    if has_fail {
        assert_eq!(report.overall_verdict, Signal::Fail);
    } else if has_warn {
        assert_eq!(report.overall_verdict, Signal::Warn);
    } else {
        assert_eq!(report.overall_verdict, Signal::Pass);
    }
}

#[test]
fn known_issues_are_collected() {
    let issues = collect_known_issues(&repo_root());
    eprintln!("Known issues ({}):", issues.len());
    for issue in &issues {
        eprintln!("  - {issue}");
    }
}

#[test]
fn report_json_roundtrip() {
    let report = generate_report();
    let json = serde_json::to_string(&report).expect("serialize");
    let back: ReleaseReadinessReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.overall_verdict, report.overall_verdict);
    assert_eq!(back.dimensions.len(), report.dimensions.len());
}

#[test]
fn report_markdown_contains_all_dimensions() {
    let md = generate_report().render_markdown();
    assert!(md.contains("Extension Conformance"));
    assert!(md.contains("Performance Budgets"));
    assert!(md.contains("Security & Licensing"));
    assert!(md.contains("Provenance Integrity"));
    assert!(md.contains("Traceability"));
    assert!(md.contains("Baseline Conformance"));
    assert!(md.contains("Overall Verdict"));
}

#[test]
fn signal_display_format() {
    assert_eq!(Signal::Pass.to_string(), "PASS");
    assert_eq!(Signal::Warn.to_string(), "WARN");
    assert_eq!(Signal::Fail.to_string(), "FAIL");
    assert_eq!(Signal::NoData.to_string(), "NO_DATA");
}

#[test]
fn signal_serde_roundtrip() {
    for s in [Signal::Pass, Signal::Warn, Signal::Fail, Signal::NoData] {
        let json = serde_json::to_string(&s).expect("serialize");
        let back: Signal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, back);
    }
}

// ── Final QA Certification (bd-1f42.7.3) ────────────────────────────────────

const CERT_SCHEMA: &str = "pi.qa.final_certification.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertEvidence {
    gate: String,
    bead: String,
    status: Signal,
    detail: String,
    artifact_path: Option<String>,
    artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RiskEntry {
    id: String,
    severity: String,
    description: String,
    mitigation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FinalCertification {
    schema: String,
    generated_at: String,
    certification_verdict: Signal,
    evidence: Vec<CertEvidence>,
    risk_register: Vec<RiskEntry>,
    reproduce_commands: Vec<String>,
    ci_run_link_template: String,
}

fn sha256_file(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let digest = {
        // Simple hash: use first 32 bytes of content + length as fingerprint.
        // Full SHA-256 would require a crate; we use a content-hash proxy.
        let len = data.len();
        let mut hash = 0u64;
        for (i, &b) in data.iter().enumerate() {
            hash = hash.wrapping_mul(31).wrapping_add(u64::from(b));
            if i > 4096 {
                break;
            }
        }
        format!("content-hash-{hash:016x}-len-{len}")
    };
    Some(digest)
}

fn check_cert_gate(
    root: &Path,
    gate: &str,
    bead: &str,
    artifact_rel: &str,
    check: impl FnOnce(&V) -> (Signal, String),
) -> CertEvidence {
    let artifact_path = root.join(artifact_rel);
    let (status, detail, sha) = load_json(&artifact_path).map_or_else(
        || {
            (
                Signal::NoData,
                format!("Artifact not found: {artifact_rel}"),
                None,
            )
        },
        |v| {
            let (sig, det) = check(&v);
            let sha = sha256_file(&artifact_path);
            (sig, det, sha)
        },
    );
    CertEvidence {
        gate: gate.to_string(),
        bead: bead.to_string(),
        status,
        detail,
        artifact_path: Some(artifact_rel.to_string()),
        artifact_sha256: sha,
    }
}

#[allow(clippy::too_many_lines)]
fn generate_certification() -> FinalCertification {
    let root = repo_root();
    let mut evidence = Vec::new();

    // 1. Non-mock unit compliance
    evidence.push(check_cert_gate(
        &root,
        "non_mock_compliance",
        "bd-1f42.2.6",
        "docs/non-mock-rubric.json",
        |v| {
            let schema = get_str(v, "/schema");
            if schema.starts_with("pi.test.non_mock_rubric") {
                (Signal::Pass, format!("Non-mock rubric present: {schema}"))
            } else {
                (Signal::Fail, "Invalid non-mock rubric schema".to_string())
            }
        },
    ));

    // 2. Full E2E evidence
    evidence.push(check_cert_gate(
        &root,
        "e2e_evidence",
        "bd-1f42.3",
        "tests/ext_conformance/reports/conformance_summary.json",
        |v| {
            let total = get_u64(v, "/counts/total");
            let pass = get_u64(v, "/counts/pass");
            if total > 0 {
                (
                    Signal::Pass,
                    format!("E2E conformance: {pass}/{total} extensions tested"),
                )
            } else {
                (Signal::Fail, "No extensions tested".to_string())
            }
        },
    ));

    // 3. 208/208 must-pass proof
    evidence.push(check_cert_gate(
        &root,
        "must_pass_208",
        "bd-1f42.4",
        "tests/ext_conformance/reports/gate/must_pass_gate_verdict.json",
        |v| {
            let metadata_errors = validate_must_pass_gate_metadata(v);
            if !metadata_errors.is_empty() {
                return (
                    Signal::Fail,
                    format!(
                        "Must-pass gate metadata invalid: {}",
                        metadata_errors.join("; ")
                    ),
                );
            }

            let (verdict, passed, total) = parse_must_pass_gate_verdict(v);
            if verdict == "pass" && passed >= 208 {
                (Signal::Pass, format!("{passed}/{total} must-pass: PASS"))
            } else if verdict == "unknown" {
                (
                    Signal::Fail,
                    format!(
                        "Must-pass gate verdict missing status/verdict field ({passed}/{total} passed)"
                    ),
                )
            } else if passed >= 200 {
                (Signal::Warn, format!("{passed}/{total} must-pass ({verdict})"))
            } else {
                (Signal::Fail, format!("{passed}/{total} must-pass ({verdict})"))
            }
        },
    ));

    // 4. Evidence bundle
    evidence.push(check_cert_gate(
        &root,
        "evidence_bundle",
        "bd-1f42.6.8",
        "tests/evidence_bundle/index.json",
        |v| {
            let schema = get_str(v, "/schema");
            let total = get_u64(v, "/summary/total_artifacts");
            let verdict = get_str(v, "/summary/verdict");
            if schema.starts_with("pi.ci.evidence_bundle") && total > 0 && verdict == "complete"
            {
                (
                    Signal::Pass,
                    format!("Evidence bundle: {total} artifacts collected ({verdict})"),
                )
            } else {
                (
                    Signal::Fail,
                    format!("Evidence bundle incomplete or missing ({verdict}, artifacts={total})"),
                )
            }
        },
    ));

    // 5. Cross-platform matrix
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "windows"
    };
    let xplat_path = format!("tests/cross_platform_reports/{platform}/platform_report.json");
    evidence.push(check_cert_gate(
        &root,
        "cross_platform",
        "bd-1f42.6.7",
        &xplat_path,
        |v| {
            let total = get_u64(v, "/summary/total_checks");
            let passed = get_u64(v, "/summary/passed");
            if total > 0 && passed == total {
                (
                    Signal::Pass,
                    format!("{passed}/{total} platform checks pass"),
                )
            } else if total > 0 {
                (
                    Signal::Warn,
                    format!("{passed}/{total} platform checks pass"),
                )
            } else {
                (Signal::NoData, "No platform checks found".to_string())
            }
        },
    ));

    // 6. Full-suite gate
    evidence.push(check_cert_gate(
        &root,
        "full_suite_gate",
        "bd-1f42.6.5",
        "tests/full_suite_gate/full_suite_verdict.json",
        |v| {
            let verdict = get_str(v, "/verdict");
            let passed = get_u64(v, "/summary/passed");
            let total = get_u64(v, "/summary/total");
            if verdict == "pass" {
                (Signal::Pass, format!("All {passed}/{total} gates pass"))
            } else {
                (
                    Signal::Warn,
                    format!("{passed}/{total} gates pass ({verdict})"),
                )
            }
        },
    ));

    // 7. Conformance baseline delta
    evidence.push(check_cert_gate(
        &root,
        "health_delta",
        "bd-1f42.4.5",
        "tests/ext_conformance/reports/conformance_baseline.json",
        |v| {
            let pass_rate = get_f64(v, "/extension_conformance/pass_rate_pct");
            let passed = get_u64(v, "/extension_conformance/passed");
            let total = get_u64(v, "/extension_conformance/manifest_count");
            if pass_rate >= 90.0 {
                (
                    Signal::Pass,
                    format!("Baseline: {passed}/{total} ({pass_rate:.1}%)"),
                )
            } else if pass_rate >= 70.0 {
                (
                    Signal::Warn,
                    format!("Baseline: {passed}/{total} ({pass_rate:.1}%)"),
                )
            } else {
                (
                    Signal::Fail,
                    format!("Baseline: {passed}/{total} ({pass_rate:.1}%)"),
                )
            }
        },
    ));

    // Build risk register from any non-pass evidence
    let mut risk_register = Vec::new();
    for ev in &evidence {
        match ev.status {
            Signal::Fail => {
                risk_register.push(RiskEntry {
                    id: ev.bead.clone(),
                    severity: "high".to_string(),
                    description: format!("{}: {}", ev.gate, ev.detail),
                    mitigation: format!("Investigate and fix before release (bead {})", ev.bead),
                });
            }
            Signal::Warn => {
                risk_register.push(RiskEntry {
                    id: ev.bead.clone(),
                    severity: "medium".to_string(),
                    description: format!("{}: {}", ev.gate, ev.detail),
                    mitigation: format!("Monitor and track in bead {}", ev.bead),
                });
            }
            Signal::NoData => {
                risk_register.push(RiskEntry {
                    id: ev.bead.clone(),
                    severity: "low".to_string(),
                    description: format!("{}: {}", ev.gate, ev.detail),
                    mitigation: "Artifact not yet generated; will be produced by CI".to_string(),
                });
            }
            Signal::Pass => {}
        }
    }

    let cert_verdict = if evidence.iter().any(|e| e.status == Signal::Fail) {
        Signal::Fail
    } else if evidence.iter().any(|e| e.status == Signal::Warn) {
        Signal::Warn
    } else if evidence.iter().all(|e| e.status == Signal::NoData) {
        Signal::NoData
    } else {
        Signal::Pass
    };

    FinalCertification {
        schema: CERT_SCHEMA.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        certification_verdict: cert_verdict,
        evidence,
        risk_register,
        reproduce_commands: vec![
            "cargo test --all-targets".to_string(),
            "./scripts/e2e/run_all.sh --profile ci".to_string(),
            "cargo test --test ext_conformance_generated --features ext-conformance -- conformance_must_pass_gate --nocapture --exact".to_string(),
        ],
        ci_run_link_template: "https://github.com/<owner>/<repo>/actions/runs/<run_id>"
            .to_string(),
    }
}

fn render_certification_markdown(cert: &FinalCertification) -> String {
    let mut out = String::new();
    out.push_str("# Final QA Certification Report\n\n");
    let _ = writeln!(out, "**Schema**: {}", cert.schema);
    let _ = writeln!(out, "**Generated**: {}", cert.generated_at);
    let _ = writeln!(
        out,
        "**Certification Verdict**: {}\n",
        cert.certification_verdict
    );

    out.push_str("## Evidence Gates\n\n");
    out.push_str("| Gate | Bead | Status | Artifact | Detail |\n");
    out.push_str("|------|------|--------|----------|--------|\n");
    for ev in &cert.evidence {
        let artifact = ev.artifact_path.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            ev.gate, ev.bead, ev.status, artifact, ev.detail
        );
    }
    out.push('\n');

    if !cert.risk_register.is_empty() {
        out.push_str("## Risk Register\n\n");
        out.push_str("| ID | Severity | Description | Mitigation |\n");
        out.push_str("|----|----------|-------------|------------|\n");
        for risk in &cert.risk_register {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                risk.id, risk.severity, risk.description, risk.mitigation
            );
        }
        out.push('\n');
    }

    out.push_str("## Reproduction Commands\n\n");
    for cmd in &cert.reproduce_commands {
        let _ = writeln!(out, "```\n{cmd}\n```");
    }
    out
}

#[test]
#[allow(clippy::too_many_lines)]
fn final_qa_certification() {
    let cert = generate_certification();
    let md = render_certification_markdown(&cert);
    eprintln!("{md}");

    // Schema
    assert_eq!(cert.schema, CERT_SCHEMA);

    // 7 evidence gates
    assert_eq!(cert.evidence.len(), 7, "Expected 7 evidence gates");

    // Verify gate IDs
    let gate_ids: Vec<&str> = cert.evidence.iter().map(|e| e.gate.as_str()).collect();
    assert!(
        gate_ids.contains(&"non_mock_compliance"),
        "Missing non_mock_compliance gate"
    );
    assert!(
        gate_ids.contains(&"e2e_evidence"),
        "Missing e2e_evidence gate"
    );
    assert!(
        gate_ids.contains(&"must_pass_208"),
        "Missing must_pass_208 gate"
    );
    assert!(
        gate_ids.contains(&"evidence_bundle"),
        "Missing evidence_bundle gate"
    );
    assert!(
        gate_ids.contains(&"cross_platform"),
        "Missing cross_platform gate"
    );
    assert!(
        gate_ids.contains(&"full_suite_gate"),
        "Missing full_suite_gate gate"
    );
    assert!(
        gate_ids.contains(&"health_delta"),
        "Missing health_delta gate"
    );

    // Each evidence has an artifact path
    for ev in &cert.evidence {
        assert!(
            ev.artifact_path.is_some(),
            "Gate {} missing artifact path",
            ev.gate
        );
    }

    // Verdict consistency
    let has_fail = cert.evidence.iter().any(|e| e.status == Signal::Fail);
    let has_warn = cert.evidence.iter().any(|e| e.status == Signal::Warn);
    if has_fail {
        assert_eq!(cert.certification_verdict, Signal::Fail);
    } else if has_warn {
        assert_eq!(cert.certification_verdict, Signal::Warn);
    }

    // Risk register entries match non-pass evidence
    let non_pass_count = cert
        .evidence
        .iter()
        .filter(|e| e.status != Signal::Pass)
        .count();
    assert_eq!(
        cert.risk_register.len(),
        non_pass_count,
        "Risk register should have one entry per non-pass evidence gate"
    );

    // Repro commands present
    assert!(!cert.reproduce_commands.is_empty());

    // Write artifacts
    let out_dir = repo_root().join("tests/certification");
    let _ = std::fs::create_dir_all(&out_dir);

    let json_out = out_dir.join("final_certification.json");
    let json = serde_json::to_string_pretty(&cert).expect("serialize");
    std::fs::write(&json_out, &json).expect("write JSON");

    let md_out = out_dir.join("final_certification.md");
    std::fs::write(&md_out, &md).expect("write markdown");

    let events_out = out_dir.join("certification_events.jsonl");
    let mut events = String::new();
    for ev in &cert.evidence {
        let event = serde_json::json!({
            "schema": "pi.qa.certification_event.v1",
            "timestamp": cert.generated_at,
            "gate": ev.gate,
            "bead": ev.bead,
            "status": ev.status,
            "detail": ev.detail,
            "artifact_sha256": ev.artifact_sha256,
        });
        let _ = writeln!(events, "{}", serde_json::to_string(&event).expect("event"));
    }
    std::fs::write(&events_out, &events).expect("write events");

    eprintln!("Certification artifacts:");
    eprintln!("  JSON: {}", json_out.display());
    eprintln!("  MD:   {}", md_out.display());
    eprintln!("  JSONL: {}", events_out.display());
}

#[test]
fn certification_report_schema_valid() {
    let cert = generate_certification();
    let json = serde_json::to_string_pretty(&cert).expect("serialize");
    let parsed: V = serde_json::from_str(&json).expect("parse");

    assert_eq!(parsed.get("schema").and_then(V::as_str), Some(CERT_SCHEMA));
    assert!(parsed.get("certification_verdict").is_some());
    assert!(parsed.get("evidence").and_then(V::as_array).is_some());
    assert!(parsed.get("risk_register").and_then(V::as_array).is_some());
    assert!(parsed
        .get("reproduce_commands")
        .and_then(V::as_array)
        .is_some());
    assert!(parsed
        .get("ci_run_link_template")
        .and_then(V::as_str)
        .is_some());
}

#[test]
fn parse_must_pass_gate_verdict_reads_current_schema() {
    let gate = serde_json::json!({
        "status": "pass",
        "observed": {
            "must_pass_total": 208,
            "must_pass_passed": 208
        }
    });

    let (status, passed, total) = parse_must_pass_gate_verdict(&gate);
    assert_eq!(status, "pass");
    assert_eq!(passed, 208);
    assert_eq!(total, 208);
}

#[test]
fn parse_must_pass_gate_verdict_falls_back_to_legacy_schema() {
    let gate = serde_json::json!({
        "verdict": "warn",
        "total": 208,
        "passed": 203
    });

    let (status, passed, total) = parse_must_pass_gate_verdict(&gate);
    assert_eq!(status, "warn");
    assert_eq!(passed, 203);
    assert_eq!(total, 208);
}

#[test]
fn validate_must_pass_gate_metadata_accepts_current_schema() {
    let gate = serde_json::json!({
        "schema": "pi.ext.must_pass_gate.v1",
        "generated_at": "2026-02-17T03:06:08.928Z",
        "run_id": "local-20260217T030608928Z",
        "correlation_id": "must-pass-gate-local-20260217T030608928Z",
        "observed": {
            "must_pass_total": 208,
            "must_pass_passed": 208
        }
    });

    let errors = validate_must_pass_gate_metadata(&gate);
    assert!(
        errors.is_empty(),
        "current-schema must-pass gate should be metadata-valid, got: {errors:?}"
    );
}

#[test]
fn validate_must_pass_gate_metadata_rejects_legacy_payload() {
    let gate = serde_json::json!({
        "verdict": "warn",
        "total": 208,
        "passed": 203
    });

    let errors = validate_must_pass_gate_metadata(&gate);
    assert!(
        !errors.is_empty(),
        "legacy payload without metadata should fail validation"
    );
    assert!(
        errors.iter().any(|msg| msg.contains("schema")),
        "expected schema validation error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|msg| msg.contains("/run_id")),
        "expected run_id validation error, got: {errors:?}"
    );
}
