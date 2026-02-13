//! Unified CI Evidence Bundle — collects all test artifacts into a single
//! structured bundle per CI run (bd-1f42.6.8).
//!
//! Produces:
//! - `tests/evidence_bundle/index.json` — machine-readable index with pointers
//!   to every section.
//! - `tests/evidence_bundle/bundle_report.md` — human-readable summary with
//!   pass/fail verdict for every section.
//! - `tests/evidence_bundle/events.jsonl` — JSONL event log of all collected
//!   artifacts.
//!
//! The bundle unifies:
//! 1. Extension conformance reports (summaries, baselines, gate verdicts)
//! 2. Extension diagnostics (dossiers, health delta, provider compat)
//! 3. E2E test results and transcripts
//! 4. Unit coverage summaries
//! 5. Quarantine audit trails
//! 6. Release gate verdicts
//! 7. Performance budgets
//! 8. Traceability matrices
//!
//! Run:
//!   cargo test --test `ci_evidence_bundle` -- --nocapture

use serde_json::Value;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// A section in the evidence bundle.
#[derive(Debug, Clone, serde::Serialize)]
struct BundleSection {
    id: String,
    label: String,
    category: String,
    status: String, // "present", "missing", "invalid"
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<String>,
    file_count: usize,
    total_bytes: u64,
}

/// The full evidence bundle index.
#[derive(Debug, serde::Serialize)]
struct EvidenceBundle {
    schema: String,
    generated_at: String,
    git_ref: String,
    ci_run_id: String,
    sections: Vec<BundleSection>,
    summary: BundleSummary,
}

/// Summary statistics for the bundle.
#[derive(Debug, serde::Serialize)]
struct BundleSummary {
    total_sections: usize,
    present_sections: usize,
    missing_sections: usize,
    invalid_sections: usize,
    total_artifacts: usize,
    total_bytes: u64,
    verdict: String, // "complete", "partial", "insufficient"
}

/// Artifact source descriptor.
struct ArtifactSource {
    id: &'static str,
    label: &'static str,
    category: &'static str,
    path: &'static str,
    /// Expected schema identifier (if JSON with `schema` field).
    expected_schema: Option<&'static str>,
    /// If true, this is a directory and we count all files inside.
    is_directory: bool,
    /// If true, missing this artifact downgrades verdict.
    required: bool,
}

const ARTIFACT_SOURCES: &[ArtifactSource] = &[
    // ── Extension conformance ──
    ArtifactSource {
        id: "conformance_summary",
        label: "Extension conformance summary",
        category: "conformance",
        path: "tests/ext_conformance/reports/conformance_summary.json",
        expected_schema: Some("pi.ext.conformance_summary"),
        is_directory: false,
        required: true,
    },
    ArtifactSource {
        id: "conformance_baseline",
        label: "Conformance baseline",
        category: "conformance",
        path: "tests/ext_conformance/reports/conformance_baseline.json",
        expected_schema: Some("pi.ext.conformance_baseline"),
        is_directory: false,
        required: true,
    },
    ArtifactSource {
        id: "conformance_events",
        label: "Conformance event log",
        category: "conformance",
        path: "tests/ext_conformance/reports/conformance_events.jsonl",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "conformance_report_md",
        label: "Conformance report (Markdown)",
        category: "conformance",
        path: "tests/ext_conformance/reports/CONFORMANCE_REPORT.md",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "regression_verdict",
        label: "Regression gate verdict",
        category: "conformance",
        path: "tests/ext_conformance/reports/regression_verdict.json",
        expected_schema: Some("pi.conformance.regression_gate"),
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "conformance_trend",
        label: "Conformance trend data",
        category: "conformance",
        path: "tests/ext_conformance/reports/conformance_trend.jsonl",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    // ── Extension diagnostics ──
    ArtifactSource {
        id: "must_pass_gate",
        label: "Must-pass gate verdict (208 extensions)",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/gate",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "failure_dossiers",
        label: "Per-extension failure dossiers",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/dossiers",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "health_delta",
        label: "Health & regression delta report",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/health_delta",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "provider_compat",
        label: "Provider compatibility matrix",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/provider_compat",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "sharded_reports",
        label: "Sharded extension matrix reports",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/sharded",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "journey_reports",
        label: "Extension journey reports",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/journeys",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    ArtifactSource {
        id: "auto_repair_summary",
        label: "Auto-repair summary",
        category: "diagnostics",
        path: "tests/ext_conformance/reports/auto_repair_summary.json",
        expected_schema: Some("pi.ext.auto_repair_summary"),
        is_directory: false,
        required: false,
    },
    // ── E2E results ──
    ArtifactSource {
        id: "e2e_results",
        label: "E2E test results",
        category: "e2e",
        path: "tests/e2e_results",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
    // ── Quarantine ──
    ArtifactSource {
        id: "quarantine_report",
        label: "Quarantine report",
        category: "quarantine",
        path: "tests/quarantine_report.json",
        expected_schema: Some("pi.test.quarantine_report"),
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "quarantine_audit",
        label: "Quarantine audit trail",
        category: "quarantine",
        path: "tests/quarantine_audit.jsonl",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    // ── Performance ──
    ArtifactSource {
        id: "perf_budget_summary",
        label: "Performance budget summary",
        category: "performance",
        path: "tests/perf/reports/budget_summary.json",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "load_time_benchmark",
        label: "Extension load-time benchmark",
        category: "performance",
        path: "tests/ext_conformance/reports/load_time_benchmark.json",
        expected_schema: None,
        is_directory: false,
        required: false,
    },
    // ── Security & provenance ──
    ArtifactSource {
        id: "risk_review",
        label: "Security and licensing risk review",
        category: "security",
        path: "tests/ext_conformance/artifacts/RISK_REVIEW.json",
        expected_schema: None,
        is_directory: false,
        required: true,
    },
    ArtifactSource {
        id: "provenance_verification",
        label: "Extension provenance verification",
        category: "security",
        path: "tests/ext_conformance/artifacts/PROVENANCE_VERIFICATION.json",
        expected_schema: None,
        is_directory: false,
        required: true,
    },
    // ── Traceability ──
    ArtifactSource {
        id: "traceability_matrix",
        label: "Requirement-to-test traceability matrix",
        category: "traceability",
        path: "docs/traceability_matrix.json",
        expected_schema: None,
        is_directory: false,
        required: true,
    },
    // ── Inventory ──
    ArtifactSource {
        id: "extension_inventory",
        label: "Extension inventory",
        category: "inventory",
        path: "tests/ext_conformance/reports/inventory.json",
        expected_schema: Some("pi.ext.inventory"),
        is_directory: false,
        required: false,
    },
    ArtifactSource {
        id: "inclusion_manifest",
        label: "Extension inclusion manifest",
        category: "inventory",
        path: "tests/ext_conformance/reports/inclusion_manifest",
        expected_schema: None,
        is_directory: true,
        required: false,
    },
];

/// Count files and total bytes in a directory recursively.
fn dir_stats(path: &Path) -> (usize, u64) {
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let ft = entry.file_type();
            if ft.as_ref().is_ok_and(std::fs::FileType::is_dir) {
                let (c, b) = dir_stats(&entry.path());
                count += c;
                bytes += b;
            } else if ft.as_ref().is_ok_and(std::fs::FileType::is_file) {
                count += 1;
                bytes += entry.metadata().map_or(0, |m| m.len());
            }
        }
    }
    (count, bytes)
}

/// Collect a section from an artifact source.
fn collect_section(root: &Path, source: &ArtifactSource) -> BundleSection {
    let full_path = root.join(source.path);

    if source.is_directory {
        if full_path.is_dir() {
            let (file_count, total_bytes) = dir_stats(&full_path);
            BundleSection {
                id: source.id.to_string(),
                label: source.label.to_string(),
                category: source.category.to_string(),
                status: if file_count > 0 {
                    "present".to_string()
                } else {
                    "missing".to_string()
                },
                artifact_path: Some(source.path.to_string()),
                schema: None,
                summary: Some(serde_json::json!({
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                })),
                diagnostics: None,
                file_count,
                total_bytes,
            }
        } else {
            BundleSection {
                id: source.id.to_string(),
                label: source.label.to_string(),
                category: source.category.to_string(),
                status: "missing".to_string(),
                artifact_path: Some(source.path.to_string()),
                schema: None,
                summary: None,
                diagnostics: Some("Directory not found".to_string()),
                file_count: 0,
                total_bytes: 0,
            }
        }
    } else if full_path.is_file() {
        let file_size = std::fs::metadata(&full_path).map_or(0, |m| m.len());
        let mut schema_found = None;
        let mut summary = None;
        let mut status = "present".to_string();

        // Try to validate JSON files.
        if std::path::Path::new(source.path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            match load_json(&full_path) {
                Some(val) => {
                    schema_found = val.get("schema").and_then(Value::as_str).map(String::from);

                    // Validate schema prefix if expected.
                    if let Some(expected) = source.expected_schema {
                        if let Some(ref actual) = schema_found {
                            if !actual.starts_with(expected) {
                                status = "invalid".to_string();
                            }
                        }
                    }

                    // Extract lightweight summary for index.
                    summary = extract_summary(&val, source.id);
                }
                None => {
                    status = "invalid".to_string();
                }
            }
        }

        BundleSection {
            id: source.id.to_string(),
            label: source.label.to_string(),
            category: source.category.to_string(),
            status,
            artifact_path: Some(source.path.to_string()),
            schema: schema_found,
            summary,
            diagnostics: None,
            file_count: 1,
            total_bytes: file_size,
        }
    } else {
        BundleSection {
            id: source.id.to_string(),
            label: source.label.to_string(),
            category: source.category.to_string(),
            status: "missing".to_string(),
            artifact_path: Some(source.path.to_string()),
            schema: None,
            summary: None,
            diagnostics: Some("File not found".to_string()),
            file_count: 0,
            total_bytes: 0,
        }
    }
}

/// Extract a lightweight summary from a JSON artifact for the bundle index.
fn extract_summary(val: &Value, section_id: &str) -> Option<Value> {
    match section_id {
        "conformance_summary" => {
            let counts = val.get("counts")?;
            Some(serde_json::json!({
                "total": counts.get("total"),
                "pass": counts.get("pass"),
                "fail": counts.get("fail"),
                "pass_rate_pct": val.get("pass_rate_pct"),
            }))
        }
        "conformance_baseline" => {
            let ec = val.get("extension_conformance")?;
            Some(serde_json::json!({
                "tested": ec.get("tested"),
                "passed": ec.get("passed"),
                "failed": ec.get("failed"),
                "pass_rate_pct": ec.get("pass_rate_pct"),
                "generated_at": val.get("generated_at"),
            }))
        }
        "regression_verdict" => Some(serde_json::json!({
            "status": val.get("status"),
            "effective_pass_rate_pct": val.get("effective_pass_rate_pct"),
        })),
        "quarantine_report" => Some(serde_json::json!({
            "active_count": val.get("active_count"),
            "expired_count": val.get("expired_count"),
        })),
        "extension_inventory" => Some(serde_json::json!({
            "total_extensions": val.get("total_extensions"),
        })),
        _ => None,
    }
}

/// Build the unified evidence bundle.
///
/// Run with:
/// `cargo test --test ci_evidence_bundle -- build_evidence_bundle --nocapture`
#[test]
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
fn build_evidence_bundle() {
    use chrono::{SecondsFormat, Utc};
    use std::fmt::Write as _;

    let root = repo_root();
    let bundle_dir = root.join("tests").join("evidence_bundle");
    let _ = std::fs::create_dir_all(&bundle_dir);

    let git_ref = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());

    let ci_run_id = std::env::var("GITHUB_RUN_ID")
        .or_else(|_| std::env::var("CI_RUN_ID"))
        .unwrap_or_else(|_| format!("local-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));

    eprintln!("\n=== Unified CI Evidence Bundle (bd-1f42.6.8) ===");
    eprintln!("  Git ref:    {git_ref}");
    eprintln!("  CI run:     {ci_run_id}");
    eprintln!("  Bundle dir: {}", bundle_dir.display());
    eprintln!();

    // ── Collect all sections ──
    let mut sections: Vec<BundleSection> = Vec::new();

    for source in ARTIFACT_SOURCES {
        eprint!("  [{:.<40}] ", source.label);
        let section = collect_section(&root, source);
        match section.status.as_str() {
            "present" => eprintln!(
                "PRESENT  ({} file(s), {} bytes)",
                section.file_count, section.total_bytes
            ),
            "invalid" => eprintln!("INVALID  {}", section.diagnostics.as_deref().unwrap_or("")),
            _ => eprintln!("MISSING"),
        }
        sections.push(section);
    }

    // ── Compute summary ──
    let present = sections.iter().filter(|s| s.status == "present").count();
    let missing = sections.iter().filter(|s| s.status == "missing").count();
    let invalid = sections.iter().filter(|s| s.status == "invalid").count();
    let total_artifacts: usize = sections.iter().map(|s| s.file_count).sum();
    let total_bytes: u64 = sections.iter().map(|s| s.total_bytes).sum();

    let required_present = ARTIFACT_SOURCES
        .iter()
        .zip(sections.iter())
        .filter(|(src, sec)| src.required && sec.status == "present")
        .count();
    let required_total = ARTIFACT_SOURCES.iter().filter(|s| s.required).count();

    let verdict = if required_present == required_total && invalid == 0 {
        "complete"
    } else if required_present > 0 {
        "partial"
    } else {
        "insufficient"
    };

    let bundle = EvidenceBundle {
        schema: "pi.ci.evidence_bundle.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        git_ref: git_ref.clone(),
        ci_run_id: ci_run_id.clone(),
        sections: sections.clone(),
        summary: BundleSummary {
            total_sections: sections.len(),
            present_sections: present,
            missing_sections: missing,
            invalid_sections: invalid,
            total_artifacts,
            total_bytes,
            verdict: verdict.to_string(),
        },
    };

    // ── Write index.json ──
    let index_path = bundle_dir.join("index.json");
    let _ = std::fs::write(
        &index_path,
        serde_json::to_string_pretty(&bundle).unwrap_or_default(),
    );

    // ── Write events.jsonl ──
    let events_path = bundle_dir.join("events.jsonl");
    let mut event_lines: Vec<String> = Vec::new();
    for section in &sections {
        let line = serde_json::json!({
            "schema": "pi.ci.evidence_bundle_event.v1",
            "section_id": section.id,
            "category": section.category,
            "status": section.status,
            "file_count": section.file_count,
            "total_bytes": section.total_bytes,
            "artifact_path": section.artifact_path,
            "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        event_lines.push(serde_json::to_string(&line).unwrap_or_default());
    }
    let _ = std::fs::write(&events_path, event_lines.join("\n") + "\n");

    // ── Write bundle_report.md ──
    let mut md = String::new();
    md.push_str("# Unified CI Evidence Bundle\n\n");
    let _ = writeln!(
        md,
        "> Generated: {}",
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let _ = writeln!(md, "> Git ref: {git_ref}");
    let _ = writeln!(md, "> CI run: {ci_run_id}");
    let _ = writeln!(md, "> Verdict: **{}**\n", verdict.to_uppercase());

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    let _ = writeln!(md, "| Total sections | {} |", sections.len());
    let _ = writeln!(md, "| Present | {present} |");
    let _ = writeln!(md, "| Missing | {missing} |");
    let _ = writeln!(md, "| Invalid | {invalid} |");
    let _ = writeln!(md, "| Total artifacts | {total_artifacts} |");
    let _ = writeln!(md, "| Total size | {:.1} KB |", total_bytes as f64 / 1024.0);
    let _ = writeln!(
        md,
        "| Required present | {required_present}/{required_total} |"
    );
    md.push('\n');

    // Group by category.
    let categories: Vec<&str> = {
        let mut cats: Vec<&str> = sections.iter().map(|s| s.category.as_str()).collect();
        cats.dedup();
        cats
    };

    for cat in &categories {
        let cat_sections: Vec<&BundleSection> =
            sections.iter().filter(|s| s.category == *cat).collect();

        let _ = writeln!(md, "## {} ({})\n", capitalize(cat), cat_sections.len());
        md.push_str(
            "| Section | Status | Files | Size | Path |\n|---------|--------|-------|------|------|\n",
        );
        for s in &cat_sections {
            let status_icon = match s.status.as_str() {
                "present" => "PASS",
                "invalid" => "WARN",
                _ => "MISS",
            };
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} B | `{}` |",
                s.label,
                status_icon,
                s.file_count,
                s.total_bytes,
                s.artifact_path.as_deref().unwrap_or("-"),
            );
        }
        md.push('\n');
    }

    // Failures section for quick navigation.
    let failures: Vec<&BundleSection> = sections
        .iter()
        .filter(|s| s.status == "missing" || s.status == "invalid")
        .collect();
    if !failures.is_empty() {
        md.push_str("## Missing / Invalid Sections\n\n");
        for s in &failures {
            let required_marker = if ARTIFACT_SOURCES
                .iter()
                .any(|src| src.id == s.id && src.required)
            {
                " **(REQUIRED)**"
            } else {
                ""
            };
            let _ = writeln!(
                md,
                "- **{}** ({}): {}{}\n  Path: `{}`",
                s.label,
                s.status,
                s.diagnostics.as_deref().unwrap_or(""),
                required_marker,
                s.artifact_path.as_deref().unwrap_or("-"),
            );
        }
        md.push('\n');
    }

    let md_path = bundle_dir.join("bundle_report.md");
    let _ = std::fs::write(&md_path, &md);

    // ── Print summary ──
    eprintln!("\n=== Evidence Bundle Summary ===");
    eprintln!("  Verdict:    {}", verdict.to_uppercase());
    eprintln!("  Sections:   {present}/{} present", sections.len());
    eprintln!("  Missing:    {missing}");
    eprintln!("  Invalid:    {invalid}");
    eprintln!("  Artifacts:  {total_artifacts} files");
    eprintln!("  Size:       {:.1} KB", total_bytes as f64 / 1024.0);
    eprintln!("  Required:   {required_present}/{required_total}");
    eprintln!();
    eprintln!("  Reports:");
    eprintln!("    Index: {}", index_path.display());
    eprintln!("    JSONL: {}", events_path.display());
    eprintln!("    MD:    {}", md_path.display());
    eprintln!();
}

/// Verify the evidence bundle index has the correct structure.
#[test]
fn evidence_bundle_index_schema() {
    let bundle_path = repo_root()
        .join("tests")
        .join("evidence_bundle")
        .join("index.json");

    // Bundle may not exist yet on first run; skip gracefully.
    let Some(val) = load_json(&bundle_path) else {
        eprintln!(
            "  SKIP: Bundle index not found at {}. Run build_evidence_bundle first.",
            bundle_path.display()
        );
        return;
    };

    // Validate schema.
    assert_eq!(
        val.get("schema").and_then(Value::as_str),
        Some("pi.ci.evidence_bundle.v1"),
        "Bundle index must have schema pi.ci.evidence_bundle.v1"
    );

    // Must have sections array.
    let sections = val
        .get("sections")
        .and_then(Value::as_array)
        .expect("Bundle must have sections array");
    assert!(
        !sections.is_empty(),
        "Bundle must have at least one section"
    );

    // Each section must have required fields.
    for section in sections {
        assert!(
            section.get("id").and_then(Value::as_str).is_some(),
            "Section missing id"
        );
        assert!(
            section.get("status").and_then(Value::as_str).is_some(),
            "Section missing status"
        );
        assert!(
            section.get("category").and_then(Value::as_str).is_some(),
            "Section missing category"
        );
    }

    // Must have summary.
    let summary = val.get("summary").expect("Bundle must have summary");
    assert!(
        summary.get("verdict").and_then(Value::as_str).is_some(),
        "Summary must have verdict"
    );
    assert!(
        summary.get("total_sections").is_some(),
        "Summary must have total_sections"
    );
}

/// Verify that every failing section in the bundle points to a precise path.
#[test]
fn evidence_bundle_failures_have_paths() {
    let bundle_path = repo_root()
        .join("tests")
        .join("evidence_bundle")
        .join("index.json");

    let Some(val) = load_json(&bundle_path) else {
        eprintln!("  SKIP: Bundle not found. Run build_evidence_bundle first.");
        return;
    };

    let sections = val
        .get("sections")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .clone();

    for section in &sections {
        let status = section.get("status").and_then(Value::as_str).unwrap_or("");
        if status == "missing" || status == "invalid" {
            let has_path = section
                .get("artifact_path")
                .and_then(Value::as_str)
                .is_some_and(|p| !p.is_empty());
            assert!(
                has_path,
                "Failing section {:?} must have artifact_path",
                section.get("id")
            );
        }
    }
}

/// Capitalize the first letter of a string.
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map_or_else(String::new, |f| f.to_uppercase().to_string() + c.as_str())
}
