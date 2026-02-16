//! Extension workload harness for deterministic legacy-vs-rust perf baselines.
//!
//! This intentionally avoids `JsExtensionRuntimeHandle::start()` (which spawns an OS
//! thread) so it can run in constrained CI / sandbox environments.
#![forbid(unsafe_code)]
// QuickJS runtime types are intentionally single-threaded (Rc-based); this binary
// uses `block_on` and never requires `Send` futures.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::future_not_send,
    clippy::needless_raw_string_hashes,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::suboptimal_flops
)]

use chrono::{SecondsFormat, Utc};
use clap::Parser;
use futures::executor::block_on;
use pi::error::{Error, Result};
use pi::extensions::JsExtensionLoadSpec;
use pi::extensions_js::{HostcallKind, PiJsRuntime, PiJsRuntimeConfig};
use pi::scheduler::{HostcallOutcome, WallClock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BENCH_REPORT_TOOL: &str = "__bench_report";
const BENCH_SCHEMA: &str = "pi.ext.rust_bench.v1";
const HOTSPOT_MATRIX_SCHEMA: &str = "pi.ext.hostcall_hotspot_matrix.v1";
const TRACE_EVENT_SCHEMA: &str = "pi.ext.hostcall_trace.v1";
const DEFAULT_MATRIX_FILENAME: &str = "ext_hostcall_hotspot_matrix.json";
const DEFAULT_TRACE_FILENAME: &str = "ext_hostcall_bridge_trace.jsonl";
const DEFAULT_DOWNSTREAM_BEADS: &[&str] = &[
    "bd-3ar8v.4.12",
    "bd-3ar8v.4.20",
    "bd-3ar8v.4.21",
    "bd-3ar8v.4.23",
    "bd-3ar8v.4.29",
];
const DEFAULT_PMU_LLC_MISS_BUDGET_PCT: f64 = 18.0;
const DEFAULT_PMU_BRANCH_MISS_BUDGET_PCT: f64 = 6.0;
const DEFAULT_PMU_STALL_TOTAL_BUDGET_PCT: f64 = 65.0;

#[derive(Parser, Debug)]
#[command(name = "ext_workloads")]
#[command(about = "Deterministic extension workload runner for perf baselines")]
struct Args {
    /// Number of cold load+init runs per extension (fresh runtime each run).
    #[arg(long, default_value_t = 3)]
    load_runs: usize,

    /// Iterations for tool-call + event-hook scenarios.
    #[arg(long, default_value_t = 2000)]
    iterations: u32,

    /// Iterations for realistic long-session hostcall profiling.
    #[arg(long, default_value_t = 8000)]
    long_session_iterations: u32,

    /// Number of real-corpus extensions to load for long-session profiling.
    #[arg(long, default_value_t = 8)]
    real_corpus_extensions: usize,

    /// Optional JSONL output path (stdout if omitted).
    #[arg(long)]
    out: Option<PathBuf>,

    /// Optional path for hotspot matrix artifact.
    #[arg(long)]
    matrix_out: Option<PathBuf>,

    /// Optional path for trace JSONL artifact.
    #[arg(long)]
    trace_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct SummaryMs {
    count: usize,
    min_ms: Option<f64>,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    max_ms: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct StageWeights {
    marshal: f64,
    queue: f64,
    schedule: f64,
    policy: f64,
    execute: f64,
    io: f64,
}

impl StageWeights {
    fn sum(self) -> f64 {
        self.marshal + self.queue + self.schedule + self.policy + self.execute + self.io
    }

    fn scaled(self, total_us: f64) -> StageTotals {
        StageTotals {
            marshal: self.marshal * total_us,
            queue: self.queue * total_us,
            schedule: self.schedule * total_us,
            policy: self.policy * total_us,
            execute: self.execute * total_us,
            io: self.io * total_us,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct StageTotals {
    marshal: f64,
    queue: f64,
    schedule: f64,
    policy: f64,
    execute: f64,
    io: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PmuBudgetSpec {
    llc_miss_budget_pct: f64,
    branch_miss_budget_pct: f64,
    stall_total_budget_pct: f64,
}

impl Default for PmuBudgetSpec {
    fn default() -> Self {
        Self {
            llc_miss_budget_pct: DEFAULT_PMU_LLC_MISS_BUDGET_PCT,
            branch_miss_budget_pct: DEFAULT_PMU_BRANCH_MISS_BUDGET_PCT,
            stall_total_budget_pct: DEFAULT_PMU_STALL_TOTAL_BUDGET_PCT,
        }
    }
}

impl PmuBudgetSpec {
    fn from_env() -> Self {
        fn parse_env_f64(key: &str) -> Option<f64> {
            std::env::var(key)
                .ok()
                .and_then(|raw| raw.trim().parse::<f64>().ok())
                .filter(|value| value.is_finite())
        }

        let mut budget = Self::default();
        if let Some(value) = parse_env_f64("PI_EXT_PMU_LLC_MISS_BUDGET_PCT") {
            budget.llc_miss_budget_pct = value.clamp(0.1, 100.0);
        }
        if let Some(value) = parse_env_f64("PI_EXT_PMU_BRANCH_MISS_BUDGET_PCT") {
            budget.branch_miss_budget_pct = value.clamp(0.1, 100.0);
        }
        if let Some(value) = parse_env_f64("PI_EXT_PMU_STALL_TOTAL_BUDGET_PCT") {
            budget.stall_total_budget_pct = value.clamp(0.1, 200.0);
        }
        budget
    }

    fn as_json(self) -> Value {
        json!({
            "llc_miss_budget_pct": self.llc_miss_budget_pct,
            "branch_miss_budget_pct": self.branch_miss_budget_pct,
            "stall_total_budget_pct": self.stall_total_budget_pct,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PmuCountersNormalized {
    frontend_stall_pct: Option<f64>,
    backend_stall_pct: Option<f64>,
    llc_miss_pct: Option<f64>,
    branch_miss_pct: Option<f64>,
    cycles_per_call: Option<f64>,
}

impl StageTotals {
    fn add(self, rhs: Self) -> Self {
        Self {
            marshal: self.marshal + rhs.marshal,
            queue: self.queue + rhs.queue,
            schedule: self.schedule + rhs.schedule,
            policy: self.policy + rhs.policy,
            execute: self.execute + rhs.execute,
            io: self.io + rhs.io,
        }
    }

    fn total_us(self) -> f64 {
        self.marshal + self.queue + self.schedule + self.policy + self.execute + self.io
    }
}

#[derive(Debug, Clone)]
struct ParsedProfileRecord {
    scenario: String,
    extension: String,
    samples: u64,
    total_us: f64,
    per_call_us: f64,
    weights: StageWeights,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let started_at = Utc::now();
    let wall_start = Instant::now();

    let mut out: Box<dyn Write> = match args.out.as_ref() {
        Some(path) => Box::new(fs::File::create(path)?),
        None => Box::new(io::stdout()),
    };

    let cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let js_cwd = cwd.display().to_string();

    let hello_entry = artifact_single_file_entry("hello");
    let pirate_entry = artifact_single_file_entry("pirate");

    let hello_spec = JsExtensionLoadSpec::from_entry_path(&hello_entry)?;
    let pirate_spec = JsExtensionLoadSpec::from_entry_path(&pirate_entry)?;

    let env = json!({
        "pkg": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
        "build_ts": option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or(""),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    });

    let mut records = Vec::new();
    let mut trace_events = Vec::new();
    trace_events.push(trace_event(
        "run.start",
        "ext_workloads",
        &json!({
            "load_runs": args.load_runs,
            "iterations": args.iterations,
            "long_session_iterations": args.long_session_iterations,
            "real_corpus_extensions": args.real_corpus_extensions,
        }),
    ));

    // ext_load_init/load_init_cold (hello + pirate)
    let hello_load = block_on(scenario_load_init_cold(
        &hello_spec,
        &js_cwd,
        args.load_runs,
    ))?;
    let hello_load = attach_env(hello_load, &env);
    trace_events.push(trace_event_for_record("scenario.complete", &hello_load));
    records.push(hello_load);

    let pirate_load = block_on(scenario_load_init_cold(
        &pirate_spec,
        &js_cwd,
        args.load_runs,
    ))?;
    let pirate_load = attach_env(pirate_load, &env);
    trace_events.push(trace_event_for_record("scenario.complete", &pirate_load));
    records.push(pirate_load);

    // ext_tool_call/hello
    let tool_call = block_on(scenario_tool_call(&hello_spec, &js_cwd, args.iterations))?;
    let tool_call = attach_env(tool_call, &env);
    trace_events.push(trace_event_for_record("scenario.complete", &tool_call));
    records.push(tool_call);

    // ext_event_hook/before_agent_start
    let event_hook = block_on(scenario_event_hook(&pirate_spec, &js_cwd, args.iterations))?;
    let event_hook = attach_env(event_hook, &env);
    trace_events.push(trace_event_for_record("scenario.complete", &event_hook));
    records.push(event_hook);

    let real_specs = discover_real_corpus_specs(args.real_corpus_extensions)?;
    if real_specs.is_empty() {
        trace_events.push(trace_event(
            "scenario.skip",
            "ext_hostcall_bridge/long_session_real_corpus",
            &json!({
                "reason": "no_safe_official_single_file_extensions_found",
                "requested_extensions": args.real_corpus_extensions,
            }),
        ));
    } else {
        let long_session = block_on(scenario_long_session_real_corpus(
            &real_specs,
            &js_cwd,
            args.long_session_iterations,
        ))?;
        let long_session = attach_env(long_session, &env);
        trace_events.push(trace_event_for_record("scenario.complete", &long_session));
        records.push(long_session);
    }

    for record in &records {
        writeln!(out, "{}", to_json_line(record)?)?;
    }

    let trace_path = args
        .trace_out
        .clone()
        .unwrap_or_else(|| default_perf_artifact_path(DEFAULT_TRACE_FILENAME));
    write_jsonl(&trace_path, &trace_events)?;

    let finished_at = Utc::now();
    let run_metadata = json!({
        "schema": "pi.ext.run_metadata.v1",
        "run_id": format!("ext-hostcall-{}", started_at.timestamp_millis()),
        "started_at": started_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "finished_at": finished_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "elapsed_ms": wall_start.elapsed().as_secs_f64() * 1000.0,
        "cwd": cwd.display().to_string(),
        "commandline": std::env::args().collect::<Vec<_>>(),
        "git_sha": option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
        "build_ts": option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or(""),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    });
    let trace_meta = json!({
        "schema": TRACE_EVENT_SCHEMA,
        "path": trace_path.display().to_string(),
        "event_count": trace_events.len(),
    });
    let pmu_meta = collect_pmu_metadata();
    let flame_meta = collect_flame_metadata();

    let hotspot_matrix =
        build_hotspot_matrix(&records, &run_metadata, &trace_meta, &pmu_meta, &flame_meta);
    validate_hotspot_matrix_schema(&hotspot_matrix)?;

    let matrix_path = args
        .matrix_out
        .unwrap_or_else(|| default_perf_artifact_path(DEFAULT_MATRIX_FILENAME));
    fs::write(&matrix_path, to_json_pretty(&hotspot_matrix)?)?;
    eprintln!(
        "[ext_workloads] wrote hotspot matrix: {}",
        matrix_path.display()
    );
    eprintln!("[ext_workloads] wrote trace log: {}", trace_path.display());

    Ok(())
}

fn attach_env(mut record: Value, env: &Value) -> Value {
    if let Value::Object(ref mut map) = record {
        map.insert("env".to_string(), env.clone());
    }
    record
}

fn artifact_single_file_entry(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/ext_conformance/artifacts")
        .join(name)
        .join(format!("{name}.ts"))
}

fn default_perf_artifact_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/perf")
        .join(filename)
}

fn to_json_line(value: &Value) -> Result<String> {
    serde_json::to_string(value).map_err(|err| Error::Json(Box::new(err)))
}

fn to_json_pretty(value: &Value) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|err| Error::Json(Box::new(err)))
}

fn trace_event(event_type: &str, scenario: &str, details: &Value) -> Value {
    json!({
        "schema": TRACE_EVENT_SCHEMA,
        "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "event_type": event_type,
        "scenario": scenario,
        "details": details,
    })
}

fn trace_event_for_record(event_type: &str, record: &Value) -> Value {
    trace_event(
        event_type,
        record
            .get("scenario")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        &json!({
            "extension": record.get("extension").cloned().unwrap_or(Value::Null),
            "iterations": record.get("iterations").cloned().unwrap_or(Value::Null),
            "runs": record.get("runs").cloned().unwrap_or(Value::Null),
            "elapsed_ms": record.get("elapsed_ms").cloned().unwrap_or(Value::Null),
            "per_call_us": record.get("per_call_us").cloned().unwrap_or(Value::Null),
            "calls_per_sec": record.get("calls_per_sec").cloned().unwrap_or(Value::Null),
            "unexpected_hostcalls": record.get("unexpected_hostcalls").cloned().unwrap_or_else(|| json!({})),
        }),
    )
}

fn write_jsonl(path: &Path, records: &[Value]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = fs::File::create(path)?;
    for record in records {
        writeln!(out, "{}", to_json_line(record)?)?;
    }
    Ok(())
}

fn normalize_pct(value: Option<f64>) -> Option<f64> {
    value.map(|raw| {
        if raw <= 1.0 {
            (raw * 100.0).clamp(0.0, 100.0)
        } else {
            raw.clamp(0.0, 100.0)
        }
    })
}

fn value_as_f64(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_u64).map(|v| v as f64))
        .or_else(|| value.and_then(Value::as_i64).map(|v| v as f64))
}

fn object_counter_value(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| value_as_f64(object.get(*key)))
}

fn parse_pmu_counters(raw: &Value) -> Option<PmuCountersNormalized> {
    let root = raw.as_object()?;
    let source_object = root
        .get("counters")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let counters = PmuCountersNormalized {
        frontend_stall_pct: normalize_pct(object_counter_value(
            source_object,
            &[
                "frontend_stall_pct",
                "frontend_stall_ratio",
                "frontend_bound_pct",
                "frontend_bound",
            ],
        )),
        backend_stall_pct: normalize_pct(object_counter_value(
            source_object,
            &[
                "backend_stall_pct",
                "backend_stall_ratio",
                "backend_bound_pct",
                "backend_bound",
            ],
        )),
        llc_miss_pct: normalize_pct(object_counter_value(
            source_object,
            &[
                "llc_miss_pct",
                "llc_miss_rate_pct",
                "llc_miss_ratio",
                "llc_miss_rate",
            ],
        )),
        branch_miss_pct: normalize_pct(object_counter_value(
            source_object,
            &[
                "branch_miss_pct",
                "branch_miss_rate_pct",
                "branch_miss_ratio",
                "branch_miss_rate",
            ],
        )),
        cycles_per_call: object_counter_value(
            source_object,
            &["cycles_per_call", "cycles_per_hostcall", "cycles_per_op"],
        )
        .map(|value| value.max(0.0)),
    };

    if counters.frontend_stall_pct.is_none()
        && counters.backend_stall_pct.is_none()
        && counters.llc_miss_pct.is_none()
        && counters.branch_miss_pct.is_none()
        && counters.cycles_per_call.is_none()
    {
        None
    } else {
        Some(counters)
    }
}

fn pmu_pressure_score(counters: &PmuCountersNormalized, budget: PmuBudgetSpec) -> f64 {
    let frontend = counters.frontend_stall_pct.unwrap_or(0.0);
    let backend = counters.backend_stall_pct.unwrap_or(0.0);
    let stall_total = frontend + backend;
    let llc = counters.llc_miss_pct.unwrap_or(0.0);
    let branch = counters.branch_miss_pct.unwrap_or(0.0);

    let stall_pressure = (stall_total / budget.stall_total_budget_pct.max(0.1)).clamp(0.0, 2.0);
    let llc_pressure = (llc / budget.llc_miss_budget_pct.max(0.1)).clamp(0.0, 2.0);
    let branch_pressure = (branch / budget.branch_miss_budget_pct.max(0.1)).clamp(0.0, 2.0);
    (stall_pressure * 0.5) + (llc_pressure * 0.35) + (branch_pressure * 0.15)
}

fn evaluate_pmu_budget(counters: &PmuCountersNormalized, budget: PmuBudgetSpec) -> Value {
    let frontend = counters.frontend_stall_pct.unwrap_or(0.0);
    let backend = counters.backend_stall_pct.unwrap_or(0.0);
    let stall_total = frontend + backend;
    let llc = counters.llc_miss_pct.unwrap_or(0.0);
    let branch = counters.branch_miss_pct.unwrap_or(0.0);

    let llc_ok = llc <= budget.llc_miss_budget_pct;
    let branch_ok = branch <= budget.branch_miss_budget_pct;
    let stall_ok = stall_total <= budget.stall_total_budget_pct;
    let status = if llc_ok && branch_ok && stall_ok {
        "pass"
    } else {
        "fail"
    };

    json!({
        "status": status,
        "checks": {
            "llc_miss_pct": { "value": llc, "budget": budget.llc_miss_budget_pct, "ok": llc_ok },
            "branch_miss_pct": { "value": branch, "budget": budget.branch_miss_budget_pct, "ok": branch_ok },
            "stall_total_pct": { "value": stall_total, "budget": budget.stall_total_budget_pct, "ok": stall_ok },
        },
        "pmu_pressure_score": pmu_pressure_score(counters, budget),
    })
}

fn annotate_pmu_payload(
    raw: Value,
    source: &str,
    path: Option<&str>,
    budget: PmuBudgetSpec,
) -> Value {
    let normalized = parse_pmu_counters(&raw);
    let budget_eval = normalized.as_ref().map_or_else(
        || {
            json!({
                "status": "not_evaluated",
                "reason": "recognized PMU counter fields were not found",
            })
        },
        |counters| evaluate_pmu_budget(counters, budget),
    );

    let mut base = json!({
        "status": "collected",
        "source": source,
        "counters": raw,
        "budget": budget.as_json(),
        "budget_evaluation": budget_eval,
    });
    if let Some(path) = path {
        base["path"] = Value::String(path.to_string());
    }
    if let Some(counters) = normalized {
        base["normalized_counters"] =
            serde_json::to_value(counters).unwrap_or_else(|_| Value::Null);
    } else {
        base["normalized_counters"] = Value::Null;
    }
    base
}

fn collect_pmu_metadata() -> Value {
    let budget = PmuBudgetSpec::from_env();

    if let Ok(raw) = std::env::var("PI_EXT_PMU_COUNTERS_JSON") {
        return serde_json::from_str::<Value>(&raw).map_or_else(
            |_| {
                json!({
                    "status": "invalid",
                    "source": "env:PI_EXT_PMU_COUNTERS_JSON",
                    "reason": "failed_to_parse_json",
                    "budget": budget.as_json(),
                })
            },
            |parsed| annotate_pmu_payload(parsed, "env:PI_EXT_PMU_COUNTERS_JSON", None, budget),
        );
    }

    if let Ok(path) = std::env::var("PI_EXT_PMU_COUNTERS_PATH") {
        return fs::read_to_string(&path).map_or_else(
            |_| {
                json!({
                    "status": "missing",
                    "source": "env:PI_EXT_PMU_COUNTERS_PATH",
                    "path": path,
                    "budget": budget.as_json(),
                })
            },
            |raw| {
                serde_json::from_str::<Value>(&raw).map_or_else(
                    |_| {
                        json!({
                            "status": "invalid",
                            "source": "env:PI_EXT_PMU_COUNTERS_PATH",
                            "path": path,
                            "reason": "failed_to_parse_json",
                            "budget": budget.as_json(),
                        })
                    },
                    |parsed| {
                        annotate_pmu_payload(
                            parsed,
                            "env:PI_EXT_PMU_COUNTERS_PATH",
                            Some(&path),
                            budget,
                        )
                    },
                )
            },
        );
    }

    json!({
        "status": "not_collected",
        "reason": "set PI_EXT_PMU_COUNTERS_JSON or PI_EXT_PMU_COUNTERS_PATH to attach PMU counters",
        "budget": budget.as_json(),
    })
}

fn collect_flame_metadata() -> Value {
    if let Ok(path) = std::env::var("PI_EXT_FLAMEGRAPH_PATH") {
        let exists = Path::new(&path).exists();
        return json!({
            "status": if exists { "collected" } else { "missing" },
            "path": path,
            "exists": exists,
        });
    }

    json!({
        "status": "not_collected",
        "reason": "set PI_EXT_FLAMEGRAPH_PATH to attach flamegraph artifact",
    })
}

fn percentile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 {
        return 0;
    }
    // Ceil(rank) then convert to 0-index.
    let rank = len
        .saturating_mul(numerator)
        .saturating_add(denominator - 1)
        / denominator;
    rank.saturating_sub(1).min(len - 1)
}

fn percentile(sorted_ms: &[f64], pct: usize) -> Option<f64> {
    if sorted_ms.is_empty() {
        return None;
    }
    Some(sorted_ms[percentile_index(sorted_ms.len(), pct, 100)])
}

fn summarize_ms(durations: &[Duration]) -> SummaryMs {
    if durations.is_empty() {
        return SummaryMs {
            count: 0,
            min_ms: None,
            p50_ms: None,
            p95_ms: None,
            p99_ms: None,
            max_ms: None,
        };
    }

    let mut ms = durations
        .iter()
        .map(|d| d.as_secs_f64() * 1000.0)
        .collect::<Vec<_>>();
    ms.sort_by(f64::total_cmp);

    SummaryMs {
        count: ms.len(),
        min_ms: Some(ms[0]),
        p50_ms: percentile(&ms, 50),
        p95_ms: percentile(&ms, 95),
        p99_ms: percentile(&ms, 99),
        max_ms: Some(ms[ms.len() - 1]),
    }
}

async fn new_runtime(js_cwd: &str) -> Result<PiJsRuntime> {
    let config = PiJsRuntimeConfig {
        cwd: js_cwd.to_string(),
        ..Default::default()
    };
    PiJsRuntime::with_clock_and_config(WallClock, config).await
}

fn js_literal(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|err| Error::Json(Box::new(err)))
}

struct BenchPumpOutcome {
    report: Value,
    unexpected_hostcalls: BTreeMap<String, u64>,
    elapsed: Duration,
}

async fn run_bench_js(
    runtime: &PiJsRuntime,
    js: &str,
    budget: Duration,
) -> Result<BenchPumpOutcome> {
    let started_at = Instant::now();
    runtime.eval(js).await?;

    let mut report: Option<Value> = None;
    let mut unexpected_hostcalls: BTreeMap<String, u64> = BTreeMap::new();

    while started_at.elapsed() < budget {
        let mut requests = runtime.drain_hostcall_requests();
        while let Some(req) = requests.pop_front() {
            let (kind_key, outcome) = match &req.kind {
                HostcallKind::Tool { name } => {
                    if name == BENCH_REPORT_TOOL {
                        report = Some(req.payload.clone());
                        (
                            "tool.__bench_report".to_string(),
                            HostcallOutcome::Success(json!({})),
                        )
                    } else {
                        (
                            format!("tool.{name}"),
                            HostcallOutcome::Error {
                                code: "UNSUPPORTED_TOOL".to_string(),
                                message: format!(
                                    "benchmark harness does not implement tool {name}"
                                ),
                            },
                        )
                    }
                }
                HostcallKind::Ui { op } => (
                    format!("ui.{op}"),
                    HostcallOutcome::Success(json!({ "ok": true })),
                ),
                HostcallKind::Events { op } => (
                    format!("events.{op}"),
                    HostcallOutcome::Success(json!({ "ok": true })),
                ),
                HostcallKind::Session { op } => (
                    format!("session.{op}"),
                    HostcallOutcome::Success(json!({ "ok": true })),
                ),
                HostcallKind::Exec { cmd } => (
                    format!("exec.{cmd}"),
                    HostcallOutcome::Error {
                        code: "EXEC_DISABLED".to_string(),
                        message: "benchmark harness forbids pi.exec".to_string(),
                    },
                ),
                HostcallKind::Http => (
                    "http".to_string(),
                    HostcallOutcome::Error {
                        code: "HTTP_DISABLED".to_string(),
                        message: "benchmark harness forbids pi.http".to_string(),
                    },
                ),
                HostcallKind::Log => (
                    "log".to_string(),
                    HostcallOutcome::Success(json!({ "logged": true })),
                ),
            };

            if kind_key != "tool.__bench_report" {
                *unexpected_hostcalls.entry(kind_key).or_insert(0) += 1;
            }

            runtime.complete_hostcall(req.call_id, outcome);
            // Deliver the completion (one macrotask) and any microtasks it triggers.
            let _ = runtime.tick().await?;
        }

        // Drain any promise microtasks (even if no macrotasks ran).
        let _ = runtime.drain_microtasks().await?;

        if let Some(report) = report.take() {
            let elapsed = started_at.elapsed();
            return Ok(BenchPumpOutcome {
                report,
                unexpected_hostcalls,
                elapsed,
            });
        }

        if runtime.has_pending() {
            let _ = runtime.tick().await?;
        }
    }

    Err(Error::extension(format!(
        "benchmark timed out after {}ms",
        budget.as_millis()
    )))
}

fn report_ok_or_err(report: &Value) -> Result<()> {
    let ok = report.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if ok {
        return Ok(());
    }
    let err = report
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("unknown js error");
    Err(Error::extension(format!("js bench failed: {err}")))
}

async fn load_extension(runtime: &PiJsRuntime, spec: &JsExtensionLoadSpec) -> Result<()> {
    let ext_id = js_literal(&spec.extension_id)?;
    let entry = js_literal(&spec.entry_path.display().to_string().replace('\\', "/"))?;
    let meta = js_literal(&json!({
        "name": spec.name,
        "version": spec.version,
        "apiVersion": spec.api_version,
    }))?;

    let js = format!(
        r"
(async () => {{
  try {{
    await __pi_load_extension({ext_id}, {entry}, {meta});
    await pi.tool({bench_tool}, {{ ok: true }});
  }} catch (e) {{
    const msg = (e && e.message) ? String(e.message) : String(e);
    await pi.tool({bench_tool}, {{ ok: false, error: msg }});
  }}
}})();
",
        bench_tool = js_literal(&BENCH_REPORT_TOOL)?,
    );

    let outcome = run_bench_js(runtime, &js, Duration::from_secs(10)).await?;
    report_ok_or_err(&outcome.report)?;
    if !outcome.unexpected_hostcalls.is_empty() {
        return Err(Error::extension(format!(
            "unexpected hostcalls during extension load: {:?}",
            outcome.unexpected_hostcalls
        )));
    }
    Ok(())
}

fn discover_real_corpus_specs(limit: usize) -> Result<Vec<JsExtensionLoadSpec>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = root.join("tests/ext_conformance/VALIDATED_MANIFEST.json");
    let raw = fs::read_to_string(&manifest_path)?;
    let manifest: Value = serde_json::from_str(&raw).map_err(|err| Error::Json(Box::new(err)))?;
    let Some(entries) = manifest.get("extensions").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    let artifact_root = root.join("tests/ext_conformance/artifacts");
    let mut specs = Vec::new();
    for entry in entries {
        if specs.len() >= limit {
            break;
        }
        if entry.get("source_tier").and_then(Value::as_str) != Some("official-pi-mono") {
            continue;
        }
        let caps = entry.get("capabilities").cloned().unwrap_or(Value::Null);
        if caps.get("uses_exec").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        if caps.get("is_multi_file").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(entry_path) = entry.get("entry_path").and_then(Value::as_str) else {
            continue;
        };
        let full_path = artifact_root.join(entry_path);
        if !full_path.exists() {
            continue;
        }
        if let Ok(spec) = JsExtensionLoadSpec::from_entry_path(&full_path) {
            specs.push(spec);
        }
    }
    Ok(specs)
}

async fn scenario_load_init_cold(
    spec: &JsExtensionLoadSpec,
    js_cwd: &str,
    runs: usize,
) -> Result<Value> {
    let mut timings = Vec::new();
    for _ in 0..runs {
        let start = Instant::now();
        let runtime = new_runtime(js_cwd).await?;
        load_extension(&runtime, spec).await?;
        timings.push(start.elapsed());
    }

    Ok(json!({
        "schema": BENCH_SCHEMA,
        "runtime": "pi_agent_rust",
        "scenario": "ext_load_init/load_init_cold",
        "extension": spec.extension_id,
        "runs": runs,
        "summary": summarize_ms(&timings),
    }))
}

async fn scenario_tool_call(
    spec: &JsExtensionLoadSpec,
    js_cwd: &str,
    iterations: u32,
) -> Result<Value> {
    let runtime = new_runtime(js_cwd).await?;
    load_extension(&runtime, spec).await?;

    let tool_name = js_literal(&"hello")?;
    let call_id = js_literal(&"bench-call-1")?;
    let input = js_literal(&json!({"name": "World"}))?;
    let ctx = js_literal(&json!({"hasUI": false, "cwd": js_cwd}))?;
    let iterations_js = js_literal(&iterations)?;

    let js = format!(
        r"
(async () => {{
  try {{
    const N = {iterations};
    for (let i = 0; i < N; i++) {{
      await __pi_execute_tool({tool_name}, {call_id}, {input}, {ctx});
    }}
    await pi.tool({bench_tool}, {{ ok: true }});
  }} catch (e) {{
    const msg = (e && e.message) ? String(e.message) : String(e);
    await pi.tool({bench_tool}, {{ ok: false, error: msg }});
  }}
}})();
",
        iterations = iterations_js,
        bench_tool = js_literal(&BENCH_REPORT_TOOL)?,
    );

    let outcome = run_bench_js(&runtime, &js, Duration::from_secs(30)).await?;
    report_ok_or_err(&outcome.report)?;

    let elapsed = outcome.elapsed;
    let elapsed_us = elapsed.as_secs_f64() * 1_000_000.0;
    let iters_f = f64::from(iterations.max(1));
    let per_call_us = elapsed_us / iters_f;
    let calls_per_sec = iters_f / elapsed.as_secs_f64().max(1e-12);

    Ok(json!({
        "schema": BENCH_SCHEMA,
        "runtime": "pi_agent_rust",
        "scenario": "ext_tool_call/hello",
        "extension": spec.extension_id,
        "iterations": iterations,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "per_call_us": per_call_us,
        "calls_per_sec": calls_per_sec,
        "unexpected_hostcalls": outcome.unexpected_hostcalls,
    }))
}

async fn scenario_event_hook(
    spec: &JsExtensionLoadSpec,
    js_cwd: &str,
    iterations: u32,
) -> Result<Value> {
    let runtime = new_runtime(js_cwd).await?;
    load_extension(&runtime, spec).await?;

    let event_name = js_literal(&"before_agent_start")?;
    let event_payload = js_literal(&json!({"systemPrompt": "You are Pi."}))?;
    let ctx = js_literal(&json!({"hasUI": false, "cwd": js_cwd}))?;
    let iterations_js = js_literal(&iterations)?;

    let js = format!(
        r"
(async () => {{
  try {{
    const N = {iterations};
    for (let i = 0; i < N; i++) {{
      await __pi_dispatch_extension_event({event_name}, {event_payload}, {ctx});
    }}
    await pi.tool({bench_tool}, {{ ok: true }});
  }} catch (e) {{
    const msg = (e && e.message) ? String(e.message) : String(e);
    await pi.tool({bench_tool}, {{ ok: false, error: msg }});
  }}
}})();
",
        iterations = iterations_js,
        bench_tool = js_literal(&BENCH_REPORT_TOOL)?,
    );

    let outcome = run_bench_js(&runtime, &js, Duration::from_secs(30)).await?;
    report_ok_or_err(&outcome.report)?;

    let elapsed = outcome.elapsed;
    let elapsed_us = elapsed.as_secs_f64() * 1_000_000.0;
    let iters_f = f64::from(iterations.max(1));
    let per_call_us = elapsed_us / iters_f;
    let calls_per_sec = iters_f / elapsed.as_secs_f64().max(1e-12);

    Ok(json!({
        "schema": BENCH_SCHEMA,
        "runtime": "pi_agent_rust",
        "scenario": "ext_event_hook/before_agent_start",
        "extension": spec.extension_id,
        "iterations": iterations,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "per_call_us": per_call_us,
        "calls_per_sec": calls_per_sec,
        "unexpected_hostcalls": outcome.unexpected_hostcalls,
    }))
}

async fn scenario_long_session_real_corpus(
    specs: &[JsExtensionLoadSpec],
    js_cwd: &str,
    iterations: u32,
) -> Result<Value> {
    let runtime = new_runtime(js_cwd).await?;
    let mut loaded_extension_ids = Vec::new();
    for spec in specs {
        load_extension(&runtime, spec).await?;
        loaded_extension_ids.push(spec.extension_id.clone());
    }

    let event_name = js_literal(&"before_agent_start")?;
    let event_payload = js_literal(&json!({
        "systemPrompt": "You are Pi.",
        "mode": "long-session",
    }))?;
    let ctx = js_literal(&json!({"hasUI": false, "cwd": js_cwd}))?;
    let iterations_js = js_literal(&iterations)?;

    let js = format!(
        r#"
(async () => {{
  try {{
    const N = {iterations};
    for (let i = 0; i < N; i++) {{
      await __pi_dispatch_extension_event({event_name}, {event_payload}, {ctx});
    }}
    await pi.tool({bench_tool}, {{
      ok: true,
      loaded_extensions: {loaded_count},
      workload: "long_session_real_corpus"
    }});
  }} catch (e) {{
    const msg = (e && e.message) ? String(e.message) : String(e);
    await pi.tool({bench_tool}, {{ ok: false, error: msg }});
  }}
}})();
"#,
        iterations = iterations_js,
        bench_tool = js_literal(&BENCH_REPORT_TOOL)?,
        loaded_count = loaded_extension_ids.len(),
    );

    let budget_secs = u64::from(iterations).saturating_div(200).clamp(30, 600);
    let outcome = run_bench_js(&runtime, &js, Duration::from_secs(budget_secs)).await?;
    report_ok_or_err(&outcome.report)?;

    let elapsed = outcome.elapsed;
    let elapsed_us = elapsed.as_secs_f64() * 1_000_000.0;
    let iters_f = f64::from(iterations.max(1));
    let per_call_us = elapsed_us / iters_f;
    let calls_per_sec = iters_f / elapsed.as_secs_f64().max(1e-12);

    Ok(json!({
        "schema": BENCH_SCHEMA,
        "runtime": "pi_agent_rust",
        "scenario": "ext_hostcall_bridge/long_session_real_corpus",
        "extension": format!("real_corpus_{}ext", loaded_extension_ids.len()),
        "iterations": iterations,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "per_call_us": per_call_us,
        "calls_per_sec": calls_per_sec,
        "extensions_loaded": loaded_extension_ids,
        "unexpected_hostcalls": outcome.unexpected_hostcalls,
        "profile_class": "long_session",
    }))
}

fn stage_weights_for_scenario(scenario: &str) -> StageWeights {
    if scenario.contains("load_init") {
        StageWeights {
            marshal: 0.33,
            queue: 0.12,
            schedule: 0.15,
            policy: 0.12,
            execute: 0.20,
            io: 0.08,
        }
    } else if scenario.contains("tool_call") {
        StageWeights {
            marshal: 0.08,
            queue: 0.14,
            schedule: 0.10,
            policy: 0.20,
            execute: 0.34,
            io: 0.14,
        }
    } else if scenario.contains("event_hook") {
        StageWeights {
            marshal: 0.09,
            queue: 0.16,
            schedule: 0.17,
            policy: 0.18,
            execute: 0.28,
            io: 0.12,
        }
    } else if scenario.contains("long_session") {
        StageWeights {
            marshal: 0.06,
            queue: 0.22,
            schedule: 0.16,
            policy: 0.18,
            execute: 0.26,
            io: 0.12,
        }
    } else {
        StageWeights {
            marshal: 0.16,
            queue: 0.16,
            schedule: 0.16,
            policy: 0.16,
            execute: 0.20,
            io: 0.16,
        }
    }
}

fn json_number_as_f64(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_u64).map(|v| v as f64))
        .or_else(|| value.and_then(Value::as_i64).map(|v| v as f64))
}

fn json_number_as_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).or_else(|| {
        value
            .and_then(Value::as_i64)
            .and_then(|v| u64::try_from(v).ok())
    })
}

fn parse_profile_record(record: &Value) -> Option<ParsedProfileRecord> {
    if record.get("schema").and_then(Value::as_str) != Some(BENCH_SCHEMA) {
        return None;
    }
    let scenario = record
        .get("scenario")
        .and_then(Value::as_str)
        .map(ToString::to_string)?;
    let extension = record
        .get("extension")
        .and_then(Value::as_str)
        .map_or_else(|| "unknown".to_string(), ToString::to_string);
    let samples = json_number_as_u64(record.get("iterations"))
        .or_else(|| json_number_as_u64(record.get("runs")))
        .or_else(|| json_number_as_u64(record.get("summary").and_then(|v| v.get("count"))))
        .unwrap_or(0);
    let per_call_us = json_number_as_f64(record.get("per_call_us")).or_else(|| {
        json_number_as_f64(record.get("summary").and_then(|v| v.get("p95_ms")))
            .map(|ms| ms * 1000.0)
    });

    let total_us = match (per_call_us, samples) {
        (Some(per_call), s) if s > 0 => per_call * s as f64,
        _ => json_number_as_f64(record.get("elapsed_ms")).map_or(0.0, |ms| ms * 1000.0),
    };
    if total_us <= 0.0 {
        return None;
    }

    let weights = stage_weights_for_scenario(&scenario);
    let normalized_total = weights.sum();
    if (normalized_total - 1.0).abs() > 1e-9 {
        return None;
    }

    Some(ParsedProfileRecord {
        scenario,
        extension,
        samples,
        total_us,
        per_call_us: per_call_us.unwrap_or_else(|| total_us / (samples.max(1) as f64)),
        weights,
    })
}

fn stage_optimization_potential(stage: &str) -> f64 {
    match stage {
        "queue" => 0.34,
        "schedule" => 0.24,
        "policy" => 0.22,
        "execute" => 0.29,
        "marshal" => 0.16,
        "io" => 0.18,
        _ => 0.10,
    }
}

fn stage_recommendation(stage: &str) -> &'static str {
    match stage {
        "queue" => "Batch hostcall dequeues and reduce lock contention in queue drains",
        "schedule" => {
            "Reduce scheduler turn count and amortize microtask drains per hostcall burst"
        }
        "policy" => "Cache policy/risk decisions on stable param-shape hashes",
        "execute" => "Specialize hot hostcall opcodes and fast-path common tool/session calls",
        "marshal" => "Reduce JSON canonicalization and hash cost on repeated shapes",
        "io" => "Coalesce transport I/O and introduce bounded async pipelining",
        _ => "Profile and optimize dominant path",
    }
}

fn stage_user_impact(stage_total_us: f64, total_samples: u64, potential: f64) -> Value {
    let samples = total_samples.max(1) as f64;
    let per_call_saving_us = (stage_total_us * potential) / samples;
    let interactive_resume_p95_ms = per_call_saving_us / 1000.0;
    let turn_latency_p95_ms = interactive_resume_p95_ms * 1.2;
    json!({
        "interactive_resume_p95_ms": interactive_resume_p95_ms,
        "turn_latency_p95_ms": turn_latency_p95_ms,
        "note": "Projected savings from stage-specific optimization potential on observed traces",
    })
}

fn pmu_budget_from_meta(pmu_meta: &Value) -> PmuBudgetSpec {
    let mut budget = PmuBudgetSpec::default();
    let Some(object) = pmu_meta.get("budget").and_then(Value::as_object) else {
        return budget;
    };
    if let Some(value) = value_as_f64(object.get("llc_miss_budget_pct")) {
        budget.llc_miss_budget_pct = value.clamp(0.1, 100.0);
    }
    if let Some(value) = value_as_f64(object.get("branch_miss_budget_pct")) {
        budget.branch_miss_budget_pct = value.clamp(0.1, 100.0);
    }
    if let Some(value) = value_as_f64(object.get("stall_total_budget_pct")) {
        budget.stall_total_budget_pct = value.clamp(0.1, 200.0);
    }
    budget
}

fn pmu_stage_multiplier(stage: &str, pmu_meta: &Value) -> f64 {
    let budget = pmu_budget_from_meta(pmu_meta);
    let counters = pmu_meta
        .get("normalized_counters")
        .and_then(parse_pmu_counters)
        .or_else(|| parse_pmu_counters(pmu_meta));

    let Some(counters) = counters else {
        return 1.0;
    };

    let pressure = pmu_pressure_score(&counters, budget);
    let stage_sensitivity = match stage {
        "queue" => 1.0,
        "schedule" => 0.95,
        "execute" => 0.8,
        "policy" => 0.65,
        "io" => 0.55,
        "marshal" => 0.35,
        _ => 0.5,
    };
    let adjustment = (pressure - 1.0) * 0.35 * stage_sensitivity;
    (1.0 + adjustment).clamp(0.7, 1.8)
}

fn build_hotspot_matrix(
    records: &[Value],
    run_metadata: &Value,
    trace_meta: &Value,
    pmu_meta: &Value,
    flame_meta: &Value,
) -> Value {
    let parsed = records
        .iter()
        .filter_map(parse_profile_record)
        .collect::<Vec<_>>();
    let mut totals = StageTotals::default();
    let mut total_samples = 0_u64;
    let mut scenario_breakdown = Vec::new();

    for entry in &parsed {
        let weighted = entry.weights.scaled(entry.total_us);
        totals = totals.add(weighted);
        total_samples = total_samples.saturating_add(entry.samples);
        scenario_breakdown.push(json!({
            "scenario": entry.scenario,
            "extension": entry.extension,
            "samples": entry.samples,
            "per_call_us": entry.per_call_us,
            "total_us": entry.total_us,
            "weights": {
                "marshal": entry.weights.marshal,
                "queue": entry.weights.queue,
                "schedule": entry.weights.schedule,
                "policy": entry.weights.policy,
                "execute": entry.weights.execute,
                "io": entry.weights.io,
            }
        }));
    }

    let grand_total = totals.total_us().max(1.0);
    let confidence = ((total_samples as f64).ln_1p() / 8.0).clamp(0.35, 0.99);
    let pmu_budget = pmu_budget_from_meta(pmu_meta);
    let pmu_counters = pmu_meta
        .get("normalized_counters")
        .and_then(parse_pmu_counters)
        .or_else(|| parse_pmu_counters(pmu_meta));
    let pmu_budget_eval = pmu_counters.as_ref().map_or_else(
        || {
            json!({
                "status": "not_evaluated",
                "reason": "PMU counters unavailable",
            })
        },
        |counters| evaluate_pmu_budget(counters, pmu_budget),
    );
    let stage_values = [
        ("marshal", totals.marshal),
        ("queue", totals.queue),
        ("schedule", totals.schedule),
        ("policy", totals.policy),
        ("execute", totals.execute),
        ("io", totals.io),
    ];

    let mut hotspot_entries = stage_values
        .iter()
        .map(|(stage, stage_total_us)| {
            let share_pct = (*stage_total_us / grand_total) * 100.0;
            let potential = stage_optimization_potential(stage);
            let pmu_multiplier = pmu_stage_multiplier(stage, pmu_meta);
            let ev_score = share_pct * potential * confidence * pmu_multiplier;
            json!({
                "stage": stage,
                "total_us": stage_total_us,
                "share_pct": share_pct,
                "avg_us_per_sample": stage_total_us / (total_samples.max(1) as f64),
                "optimization_potential_pct": potential * 100.0,
                "confidence": confidence,
                "pmu_multiplier": pmu_multiplier,
                "ev_score": ev_score,
                "projected_user_impact": stage_user_impact(*stage_total_us, total_samples, potential),
                "pmu_budget_evaluation": pmu_budget_eval.clone(),
                "recommended_action": stage_recommendation(stage),
                "downstream_beads": DEFAULT_DOWNSTREAM_BEADS,
            })
        })
        .collect::<Vec<_>>();

    hotspot_entries.sort_by(|a, b| {
        let lhs = json_number_as_f64(a.get("ev_score")).unwrap_or(0.0);
        let rhs = json_number_as_f64(b.get("ev_score")).unwrap_or(0.0);
        rhs.total_cmp(&lhs)
    });

    json!({
        "schema": HOTSPOT_MATRIX_SCHEMA,
        "generated_at": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "source_schema": BENCH_SCHEMA,
        "records_analyzed": records.len(),
        "scenario_records": scenario_breakdown.len(),
        "sample_count": total_samples,
        "run_metadata": run_metadata,
        "artifacts": {
            "trace_log": trace_meta,
            "pmu_counters": pmu_meta,
            "pmu_budget": pmu_budget.as_json(),
            "pmu_budget_evaluation": pmu_budget_eval,
            "flame_data": flame_meta,
        },
        "stage_totals_us": {
            "marshal": totals.marshal,
            "queue": totals.queue,
            "schedule": totals.schedule,
            "policy": totals.policy,
            "execute": totals.execute,
            "io": totals.io,
            "total": grand_total,
        },
        "hotspot_matrix": hotspot_entries,
        "scenario_breakdown": scenario_breakdown,
        "downstream_consumers": DEFAULT_DOWNSTREAM_BEADS,
        "methodology": {
            "stage_decomposition": ["marshal", "queue", "schedule", "policy", "execute", "io"],
            "ev_formula": "share_pct * optimization_potential * confidence * pmu_multiplier",
            "confidence_formula": "clamp(log(sample_count+1)/8, 0.35, 0.99)",
            "notes": "Queue/schedule attribution is inferred from scenario-specific stage weights; PMU counters shape ev_score via stage multipliers when available."
        },
    })
}

fn validate_hotspot_matrix_schema(matrix: &Value) -> Result<()> {
    let required_top = [
        "schema",
        "generated_at",
        "records_analyzed",
        "run_metadata",
        "artifacts",
        "stage_totals_us",
        "hotspot_matrix",
        "downstream_consumers",
    ];
    for field in required_top {
        if matrix.get(field).is_none() {
            return Err(Error::extension(format!(
                "hotspot matrix missing required field: {field}"
            )));
        }
    }

    if matrix.get("schema").and_then(Value::as_str) != Some(HOTSPOT_MATRIX_SCHEMA) {
        return Err(Error::extension(format!(
            "unexpected hotspot matrix schema: {:?}",
            matrix.get("schema")
        )));
    }

    let Some(hotspots) = matrix.get("hotspot_matrix").and_then(Value::as_array) else {
        return Err(Error::extension(
            "hotspot_matrix must be an array".to_string(),
        ));
    };
    for (idx, entry) in hotspots.iter().enumerate() {
        for field in [
            "stage",
            "ev_score",
            "confidence",
            "pmu_multiplier",
            "pmu_budget_evaluation",
            "projected_user_impact",
            "recommended_action",
            "downstream_beads",
        ] {
            if entry.get(field).is_none() {
                return Err(Error::extension(format!(
                    "hotspot entry {idx} missing field {field}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pmu_counters_normalizes_ratio_inputs() {
        let raw = json!({
            "counters": {
                "frontend_stall_ratio": 0.22,
                "backend_stall_ratio": 0.31,
                "llc_miss_rate": 0.18,
                "branch_miss_rate_pct": 4.5,
                "cycles_per_call": 12345.0
            }
        });
        let parsed = parse_pmu_counters(&raw).expect("pmu counters should parse");
        assert_eq!(parsed.frontend_stall_pct, Some(22.0));
        assert_eq!(parsed.backend_stall_pct, Some(31.0));
        assert_eq!(parsed.llc_miss_pct, Some(18.0));
        assert_eq!(parsed.branch_miss_pct, Some(4.5));
        assert_eq!(parsed.cycles_per_call, Some(12_345.0));
    }

    #[test]
    fn pmu_budget_evaluation_fails_when_thresholds_exceeded() {
        let counters = PmuCountersNormalized {
            frontend_stall_pct: Some(40.0),
            backend_stall_pct: Some(35.0),
            llc_miss_pct: Some(25.0),
            branch_miss_pct: Some(8.0),
            cycles_per_call: Some(20_000.0),
        };
        let budget_eval = evaluate_pmu_budget(&counters, PmuBudgetSpec::default());
        assert_eq!(
            budget_eval.get("status").and_then(Value::as_str),
            Some("fail")
        );
        assert_eq!(
            budget_eval
                .get("checks")
                .and_then(|v| v.get("llc_miss_pct"))
                .and_then(|v| v.get("ok"))
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn stage_weights_are_normalized() {
        for scenario in [
            "ext_load_init/load_init_cold",
            "ext_tool_call/hello",
            "ext_event_hook/before_agent_start",
            "ext_hostcall_bridge/long_session_real_corpus",
            "unknown",
        ] {
            let sum = stage_weights_for_scenario(scenario).sum();
            assert!(
                (sum - 1.0).abs() < 1e-9,
                "weights must sum to 1.0 for {scenario}, got {sum}"
            );
        }
    }

    #[test]
    fn parse_profile_record_from_per_call_fields() {
        let record = json!({
            "schema": BENCH_SCHEMA,
            "scenario": "ext_tool_call/hello",
            "extension": "hello",
            "iterations": 200,
            "per_call_us": 140.0,
        });
        let parsed = parse_profile_record(&record).expect("parse profile record");
        assert_eq!(parsed.samples, 200);
        assert!((parsed.total_us - 28_000.0).abs() < f64::EPSILON);
        assert!((parsed.per_call_us - 140.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_profile_record_from_summary_fields() {
        let record = json!({
            "schema": BENCH_SCHEMA,
            "scenario": "ext_load_init/load_init_cold",
            "extension": "pirate",
            "runs": 4,
            "summary": {
                "count": 4,
                "p95_ms": 3.5
            }
        });
        let parsed = parse_profile_record(&record).expect("parse profile summary");
        assert_eq!(parsed.samples, 4);
        assert!((parsed.per_call_us - 3500.0).abs() < 0.001);
        assert!((parsed.total_us - 14_000.0).abs() < 0.001);
    }

    #[test]
    fn hotspot_matrix_includes_ev_confidence_and_user_impact() {
        let records = vec![
            json!({
                "schema": BENCH_SCHEMA,
                "scenario": "ext_tool_call/hello",
                "extension": "hello",
                "iterations": 1000,
                "per_call_us": 120.0,
            }),
            json!({
                "schema": BENCH_SCHEMA,
                "scenario": "ext_hostcall_bridge/long_session_real_corpus",
                "extension": "real_corpus_4ext",
                "iterations": 5000,
                "per_call_us": 180.0,
            }),
        ];
        let matrix = build_hotspot_matrix(
            &records,
            &json!({ "run_id": "test-run" }),
            &json!({ "schema": TRACE_EVENT_SCHEMA }),
            &json!({
                "status": "collected",
                "normalized_counters": {
                    "frontend_stall_pct": 38.0,
                    "backend_stall_pct": 34.0,
                    "llc_miss_pct": 21.0,
                    "branch_miss_pct": 7.0,
                    "cycles_per_call": 18000.0
                },
                "budget": {
                    "llc_miss_budget_pct": 18.0,
                    "branch_miss_budget_pct": 6.0,
                    "stall_total_budget_pct": 65.0
                }
            }),
            &json!({ "status": "not_collected" }),
        );
        validate_hotspot_matrix_schema(&matrix).expect("schema should validate");
        let hotspots = matrix["hotspot_matrix"]
            .as_array()
            .expect("hotspot_matrix array");
        assert!(!hotspots.is_empty(), "hotspot matrix should not be empty");
        let top = &hotspots[0];
        assert!(top.get("ev_score").is_some(), "missing ev_score");
        assert!(top.get("confidence").is_some(), "missing confidence");
        assert!(
            top.get("pmu_multiplier")
                .and_then(Value::as_f64)
                .is_some_and(|mult| mult > 1.0),
            "expected PMU multiplier to increase under high pressure"
        );
        assert!(
            top.get("projected_user_impact").is_some(),
            "missing projected_user_impact"
        );
    }
}
