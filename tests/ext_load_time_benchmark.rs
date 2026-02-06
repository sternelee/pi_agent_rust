#![cfg(feature = "ext-conformance")]
//! Extension load-time benchmarks (bd-xs79).
//!
//! Measures cold-start load time for every extension in the conformance suite.
//! Each extension is loaded N times (configurable) into a fresh QuickJS runtime,
//! and P50/P95/P99 statistics are computed per extension and per tier.
//!
//! Run:
//!   cargo test --test ext_load_time_benchmark --features ext-conformance -- --nocapture
//!
//! Environment variables:
//!   PI_LOAD_BENCH_ITERATIONS  - iterations per extension (default: 5)
//!   PI_LOAD_BENCH_BUDGET_MS   - P99 budget in ms (default: 200 debug, 150 release)
//!   PI_OFFICIAL_MAX           - limit to first N official extensions

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use pi::extensions::{ExtensionManager, JsExtensionLoadSpec, JsExtensionRuntimeHandle};
use pi::extensions_js::PiJsRuntimeConfig;
use pi::tools::ToolRegistry;
use serde_json::Value;
use std::sync::Arc;

// ─── Configuration ──────────────────────────────────────────────────────────

fn iterations() -> usize {
    std::env::var("PI_LOAD_BENCH_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

fn p99_budget_ms() -> u64 {
    std::env::var("PI_LOAD_BENCH_BUDGET_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 200 } else { 150 })
}

fn max_official() -> Option<usize> {
    std::env::var("PI_OFFICIAL_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
}

// ─── Manifest types (shared with ext_conformance_generated) ─────────────────

#[derive(Debug, Clone)]
struct ManifestEntry {
    id: String,
    entry_path: String,
    conformance_tier: u32,
}

struct Manifest {
    extensions: Vec<ManifestEntry>,
}

impl Manifest {
    fn official(&self) -> Vec<&ManifestEntry> {
        self.extensions
            .iter()
            .filter(|e| {
                !e.id.starts_with("community/")
                    && !e.id.starts_with("npm/")
                    && !e.id.starts_with("third-party/")
                    && !e.id.starts_with("agents-")
            })
            .collect()
    }
}

fn artifacts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ext_conformance/artifacts")
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ext_conformance/VALIDATED_MANIFEST.json")
}

fn reports_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ext_conformance/reports")
}

fn load_manifest() -> &'static Manifest {
    static MANIFEST: OnceLock<Manifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let data = std::fs::read_to_string(manifest_path())
            .expect("Failed to read VALIDATED_MANIFEST.json");
        let json: Value =
            serde_json::from_str(&data).expect("Failed to parse VALIDATED_MANIFEST.json");
        let extensions = json["extensions"]
            .as_array()
            .expect("manifest.extensions should be an array")
            .iter()
            .map(|e| ManifestEntry {
                id: e["id"].as_str().unwrap_or("").to_string(),
                entry_path: e["entry_path"].as_str().unwrap_or("").to_string(),
                conformance_tier: u32::try_from(e["conformance_tier"].as_u64().unwrap_or(0))
                    .unwrap_or(0),
            })
            .collect();
        Manifest { extensions }
    })
}

// ─── Statistics ─────────────────────────────────────────────────────────────

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Debug, Clone, serde::Serialize)]
struct LoadStats {
    iterations: usize,
    min_ms: u64,
    max_ms: u64,
    mean_ms: u64,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
}

impl LoadStats {
    fn from_samples(samples: &[u64]) -> Self {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let sum: u64 = sorted.iter().sum();
        let count = sorted.len().max(1) as u64;
        Self {
            iterations: sorted.len(),
            min_ms: sorted.first().copied().unwrap_or(0),
            max_ms: sorted.last().copied().unwrap_or(0),
            mean_ms: sum / count,
            p50_ms: percentile(&sorted, 50.0),
            p95_ms: percentile(&sorted, 95.0),
            p99_ms: percentile(&sorted, 99.0),
        }
    }
}

// ─── Per-extension result ───────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
struct ExtLoadResult {
    id: String,
    tier: u32,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    cold_start: LoadStats,
    samples_ms: Vec<u64>,
}

// ─── Core benchmark runner ──────────────────────────────────────────────────

/// Load an extension `n` times, each in a fresh runtime, measuring cold-start time.
fn benchmark_extension(entry: &ManifestEntry, n: usize) -> ExtLoadResult {
    let entry_file = artifacts_dir().join(&entry.entry_path);
    if !entry_file.exists() {
        return ExtLoadResult {
            id: entry.id.clone(),
            tier: entry.conformance_tier,
            success: false,
            error: Some(format!("Artifact not found: {}", entry_file.display())),
            cold_start: LoadStats::from_samples(&[]),
            samples_ms: vec![],
        };
    }

    let spec = match JsExtensionLoadSpec::from_entry_path(&entry_file) {
        Ok(s) => s,
        Err(e) => {
            return ExtLoadResult {
                id: entry.id.clone(),
                tier: entry.conformance_tier,
                success: false,
                error: Some(format!("Load spec error: {e}")),
                cold_start: LoadStats::from_samples(&[]),
                samples_ms: vec![],
            };
        }
    };

    let cwd = std::env::temp_dir().join(format!("pi-loadbench-{}", entry.id.replace('/', "_")));
    let _ = std::fs::create_dir_all(&cwd);

    let mut samples = Vec::with_capacity(n);
    let mut last_error = None;

    for _ in 0..n {
        let start = Instant::now();

        let manager = ExtensionManager::new();
        let tools = Arc::new(ToolRegistry::new(&[], &cwd, None));
        let js_config = PiJsRuntimeConfig {
            cwd: cwd.display().to_string(),
            ..Default::default()
        };

        let runtime_result = common::run_async({
            let manager = manager.clone();
            let tools = Arc::clone(&tools);
            async move { JsExtensionRuntimeHandle::start(js_config, tools, manager).await }
        });
        let runtime = match runtime_result {
            Ok(rt) => rt,
            Err(e) => {
                last_error = Some(format!("Runtime start error: {e}"));
                continue;
            }
        };
        manager.set_js_runtime(runtime);

        let load_result = common::run_async({
            let manager = manager.clone();
            let spec = spec.clone();
            async move { manager.load_js_extensions(vec![spec]).await }
        });

        let elapsed_ms = start.elapsed().as_millis() as u64;

        match load_result {
            Ok(()) => samples.push(elapsed_ms),
            Err(e) => {
                last_error = Some(format!("Load error: {e}"));
            }
        }

        // Shut down to avoid thread leaks.
        common::run_async({
            let manager = manager.clone();
            async move {
                let _ = manager.shutdown(Duration::from_millis(250)).await;
            }
        });
    }

    let success = !samples.is_empty();
    ExtLoadResult {
        id: entry.id.clone(),
        tier: entry.conformance_tier,
        success,
        error: if success { None } else { last_error },
        cold_start: LoadStats::from_samples(&samples),
        samples_ms: samples,
    }
}

// ─── Tier aggregation ───────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
struct TierStats {
    tier: u32,
    count: usize,
    aggregate: LoadStats,
    over_budget: Vec<String>,
}

fn aggregate_by_tier(results: &[ExtLoadResult], budget_ms: u64) -> Vec<TierStats> {
    let mut by_tier: BTreeMap<u32, Vec<&ExtLoadResult>> = BTreeMap::new();
    for r in results {
        by_tier.entry(r.tier).or_default().push(r);
    }

    by_tier
        .into_iter()
        .map(|(tier, exts)| {
            let all_samples: Vec<u64> = exts
                .iter()
                .filter(|e| e.success)
                .flat_map(|e| e.samples_ms.iter().copied())
                .collect();
            let over_budget: Vec<String> = exts
                .iter()
                .filter(|e| e.success && e.cold_start.p99_ms > budget_ms)
                .map(|e| format!("{} (P99={}ms)", e.id, e.cold_start.p99_ms))
                .collect();
            TierStats {
                tier,
                count: exts.len(),
                aggregate: LoadStats::from_samples(&all_samples),
                over_budget,
            }
        })
        .collect()
}

// ─── Report generation ──────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize)]
struct BenchmarkReport {
    generated_at: String,
    config: BenchmarkConfig,
    summary: BenchmarkSummary,
    tiers: Vec<TierStats>,
    results: Vec<ExtLoadResult>,
}

#[derive(Debug, serde::Serialize)]
struct BenchmarkConfig {
    iterations: usize,
    budget_ms: u64,
    debug_build: bool,
}

#[derive(Debug, serde::Serialize)]
struct BenchmarkSummary {
    total: usize,
    success: usize,
    failed: usize,
    over_budget: usize,
    global_p50_ms: u64,
    global_p95_ms: u64,
    global_p99_ms: u64,
}

fn generate_markdown(report: &BenchmarkReport) -> String {
    let mut md = String::with_capacity(8192);
    writeln!(md, "# Extension Load-Time Benchmark Report").unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "Generated: {} | Iterations: {} | Budget: {}ms | Build: {}",
        report.generated_at,
        report.config.iterations,
        report.config.budget_ms,
        if report.config.debug_build {
            "debug"
        } else {
            "release"
        }
    )
    .unwrap();
    writeln!(md).unwrap();

    // Summary
    writeln!(md, "## Summary").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "| Metric | Value |").unwrap();
    writeln!(md, "|--------|-------|").unwrap();
    writeln!(md, "| Total extensions | {} |", report.summary.total).unwrap();
    writeln!(md, "| Loaded successfully | {} |", report.summary.success).unwrap();
    writeln!(md, "| Failed to load | {} |", report.summary.failed).unwrap();
    writeln!(
        md,
        "| Over budget (P99 > {}ms) | {} |",
        report.config.budget_ms, report.summary.over_budget
    )
    .unwrap();
    writeln!(md, "| Global P50 | {}ms |", report.summary.global_p50_ms).unwrap();
    writeln!(md, "| Global P95 | {}ms |", report.summary.global_p95_ms).unwrap();
    writeln!(md, "| Global P99 | {}ms |", report.summary.global_p99_ms).unwrap();
    writeln!(md).unwrap();

    // Per-tier
    writeln!(md, "## Per-Tier Breakdown").unwrap();
    writeln!(md).unwrap();
    writeln!(md, "| Tier | Count | P50 | P95 | P99 | Over Budget |").unwrap();
    writeln!(md, "|------|-------|-----|-----|-----|-------------|").unwrap();
    for t in &report.tiers {
        writeln!(
            md,
            "| {} | {} | {}ms | {}ms | {}ms | {} |",
            t.tier,
            t.count,
            t.aggregate.p50_ms,
            t.aggregate.p95_ms,
            t.aggregate.p99_ms,
            t.over_budget.len()
        )
        .unwrap();
    }
    writeln!(md).unwrap();

    // Per-extension table (sorted by P99 descending for easy triage)
    writeln!(md, "## Per-Extension Results (sorted by P99 desc)").unwrap();
    writeln!(md).unwrap();
    writeln!(
        md,
        "| Extension | Tier | P50 | P95 | P99 | Min | Max | Status |"
    )
    .unwrap();
    writeln!(
        md,
        "|-----------|------|-----|-----|-----|-----|-----|--------|"
    )
    .unwrap();

    let mut sorted_results: Vec<&ExtLoadResult> = report.results.iter().collect();
    sorted_results.sort_by(|a, b| b.cold_start.p99_ms.cmp(&a.cold_start.p99_ms));

    for r in sorted_results {
        let status = if !r.success {
            "FAIL"
        } else if r.cold_start.p99_ms > report.config.budget_ms {
            "OVER"
        } else {
            "OK"
        };
        writeln!(
            md,
            "| {} | {} | {}ms | {}ms | {}ms | {}ms | {}ms | {} |",
            r.id,
            r.tier,
            r.cold_start.p50_ms,
            r.cold_start.p95_ms,
            r.cold_start.p99_ms,
            r.cold_start.min_ms,
            r.cold_start.max_ms,
            status
        )
        .unwrap();
    }

    md
}

// ─── Test entry point ───────────────────────────────────────────────────────

#[test]
fn load_time_benchmark() {
    let manifest = load_manifest();
    let n = iterations();
    let budget_ms = p99_budget_ms();
    let max = max_official();

    // Select official extensions (tiers 1-5).
    let mut entries: Vec<&ManifestEntry> = manifest.official();
    if let Some(limit) = max {
        entries.truncate(limit);
    }

    eprintln!(
        "[load-bench] extensions={} iterations={} budget={}ms debug={}",
        entries.len(),
        n,
        budget_ms,
        cfg!(debug_assertions)
    );

    let mut results = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        eprint!("  [{}/{}] {} ... ", i + 1, entries.len(), entry.id);
        let result = benchmark_extension(entry, n);
        if result.success {
            eprintln!(
                "P50={}ms P99={}ms",
                result.cold_start.p50_ms, result.cold_start.p99_ms
            );
        } else {
            eprintln!("FAILED: {}", result.error.as_deref().unwrap_or("unknown"));
        }
        results.push(result);
    }

    // Compute statistics.
    let all_samples: Vec<u64> = results
        .iter()
        .filter(|r| r.success)
        .flat_map(|r| r.samples_ms.iter().copied())
        .collect();
    let global_stats = LoadStats::from_samples(&all_samples);
    let tiers = aggregate_by_tier(&results, budget_ms);

    let success_count = results.iter().filter(|r| r.success).count();
    let failed_count = results.iter().filter(|r| !r.success).count();
    let over_budget_count = results
        .iter()
        .filter(|r| r.success && r.cold_start.p99_ms > budget_ms)
        .count();

    let report = BenchmarkReport {
        generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        config: BenchmarkConfig {
            iterations: n,
            budget_ms,
            debug_build: cfg!(debug_assertions),
        },
        summary: BenchmarkSummary {
            total: results.len(),
            success: success_count,
            failed: failed_count,
            over_budget: over_budget_count,
            global_p50_ms: global_stats.p50_ms,
            global_p95_ms: global_stats.p95_ms,
            global_p99_ms: global_stats.p99_ms,
        },
        tiers,
        results,
    };

    // Write reports.
    let dir = reports_dir();
    let _ = std::fs::create_dir_all(&dir);

    let json_path = dir.join("load_time_benchmark_detailed.json");
    let json_data = serde_json::to_string_pretty(&report).expect("serialize report");
    std::fs::write(&json_path, &json_data).expect("write JSON report");
    eprintln!("\n  JSON: {}", json_path.display());

    let md_path = dir.join("LOAD_TIME_BENCHMARK.md");
    let md_data = generate_markdown(&report);
    std::fs::write(&md_path, &md_data).expect("write markdown report");
    eprintln!("  Markdown: {}", md_path.display());

    // Summary.
    eprintln!("\n[load-bench] SUMMARY:");
    eprintln!(
        "  Total: {} | Pass: {} | Fail: {} | Over budget: {}",
        report.summary.total, report.summary.success, report.summary.failed, over_budget_count
    );
    eprintln!(
        "  Global P50={}ms P95={}ms P99={}ms",
        global_stats.p50_ms, global_stats.p95_ms, global_stats.p99_ms
    );

    // Warn about over-budget extensions (don't hard-fail since debug builds are slower).
    if over_budget_count > 0 {
        eprintln!(
            "\n  WARNING: {} extension(s) exceeded P99 budget of {}ms:",
            over_budget_count, budget_ms
        );
        for r in &report.results {
            if r.success && r.cold_start.p99_ms > budget_ms {
                eprintln!("    - {} (P99={}ms)", r.id, r.cold_start.p99_ms);
            }
        }
    }

    // Hard assertion: all extensions must load successfully.
    assert_eq!(
        failed_count, 0,
        "{failed_count} extension(s) failed to load"
    );
}
