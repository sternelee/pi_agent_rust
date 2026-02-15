//! `PiJS` workload harness for deterministic perf baselines.
#![forbid(unsafe_code)]

use clap::Parser;
use futures::executor::block_on;
use pi::error::{Error, Result};
use pi::extensions_js::PiJsRuntime;
use pi::perf_build;
use pi::scheduler::HostcallOutcome;
use serde_json::json;
use std::time::Instant;

const BENCH_BEGIN_FN: &str = "__bench_begin_roundtrip";
const BENCH_ASSERT_FN: &str = "__bench_assert_roundtrip";

const BENCH_TOOL_SETUP: &str = r#"
__pi_begin_extension("ext.bench", { name: "Bench" });
pi.registerTool({
  name: "bench_tool",
  description: "Benchmark tool",
  parameters: { type: "object", properties: { value: { type: "number" } } },
  execute: async (_callId, input) => {
    return { ok: true, value: input.value };
  },
});
globalThis.__bench_done = false;
globalThis.__bench_begin_roundtrip = () => {
  globalThis.__bench_done = false;
  return pi.tool("bench_tool", { value: 1 }).then(() => { globalThis.__bench_done = true; });
};
globalThis.__bench_assert_roundtrip = () => {
  if (!globalThis.__bench_done) {
    throw new Error("bench tool call did not resolve");
  }
};
__pi_end_extension();
"#;

#[derive(Parser, Debug)]
#[command(name = "pijs_workload")]
#[command(about = "Deterministic PiJS workload runner for perf baselines")]
struct Args {
    /// Outer loop iterations.
    #[arg(long, default_value_t = 200)]
    iterations: usize,
    /// Tool calls per iteration.
    #[arg(long, default_value_t = 1)]
    tool_calls: usize,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let runtime = block_on(PiJsRuntime::new())?;
    block_on(runtime.eval(BENCH_TOOL_SETUP))?;
    let build_profile = perf_build::detect_build_profile();
    let allocator = perf_build::resolve_bench_allocator();
    let binary_path = std::env::current_exe()
        .ok()
        .map_or_else(|| "unknown".to_string(), |path| path.display().to_string());

    let start = Instant::now();
    for _ in 0..args.iterations {
        for _ in 0..args.tool_calls {
            run_tool_roundtrip(&runtime)?;
        }
    }
    let elapsed = start.elapsed();

    let total_calls = args.iterations.saturating_mul(args.tool_calls);
    let elapsed_millis = elapsed.as_millis();
    let elapsed_micros = elapsed.as_micros();
    let total_calls_u128 = total_calls as u128;

    let per_call_us = elapsed_micros.checked_div(total_calls_u128).unwrap_or(0);
    let calls_per_sec = total_calls_u128
        .saturating_mul(1_000_000)
        .checked_div(elapsed_micros)
        .unwrap_or(0);

    println!(
        "{}",
        json!({
            "schema": "pi.perf.workload.v1",
            "tool": "pijs_workload",
            "scenario": "tool_call_roundtrip",
            "iterations": args.iterations,
            "tool_calls_per_iteration": args.tool_calls,
            "total_calls": total_calls,
            "elapsed_ms": elapsed_millis,
            "per_call_us": per_call_us,
            "calls_per_sec": calls_per_sec,
            "build_profile": build_profile,
            "allocator_requested": allocator.requested,
            "allocator_request_source": allocator.requested_source,
            "allocator_effective": allocator.effective.as_str(),
            "allocator_fallback_reason": allocator.fallback_reason,
            "binary_path": binary_path,
        })
    );

    Ok(())
}

fn run_tool_roundtrip(runtime: &PiJsRuntime) -> Result<()> {
    block_on(async {
        runtime.call_global_void(BENCH_BEGIN_FN).await?;
        let mut requests = runtime.drain_hostcall_requests();
        let request = requests
            .pop_front()
            .ok_or_else(|| Error::extension("bench workload: missing hostcall request"))?;
        if !requests.is_empty() {
            return Err(Error::extension(
                "bench workload: unexpected extra hostcall requests",
            ));
        }

        runtime.complete_hostcall(
            request.call_id,
            HostcallOutcome::Success(json!({"ok": true})),
        );
        runtime.tick().await?;
        runtime.call_global_void(BENCH_ASSERT_FN).await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use pi::perf_build::profile_from_target_path;
    use std::path::Path;

    #[test]
    fn profile_from_target_path_detects_perf() {
        let path = Path::new("/tmp/repo/target/perf/pijs_workload");
        assert_eq!(profile_from_target_path(path).as_deref(), Some("perf"));
    }

    #[test]
    fn profile_from_target_path_detects_release_deps_binary() {
        let path = Path::new("/tmp/repo/target/release/deps/pijs_workload-abc123");
        assert_eq!(profile_from_target_path(path).as_deref(), Some("release"));
    }

    #[test]
    fn profile_from_target_path_detects_target_triple_perf() {
        let path = Path::new("/tmp/repo/target/x86_64-unknown-linux-gnu/perf/pijs_workload");
        assert_eq!(profile_from_target_path(path).as_deref(), Some("perf"));
    }

    #[test]
    fn profile_from_target_path_detects_target_triple_perf_deps() {
        let path =
            Path::new("/tmp/repo/target/x86_64-unknown-linux-gnu/perf/deps/pijs_workload-abc123");
        assert_eq!(profile_from_target_path(path).as_deref(), Some("perf"));
    }

    #[test]
    fn profile_from_target_path_returns_none_outside_target() {
        let path = Path::new("/tmp/repo/bin/pijs_workload");
        assert_eq!(profile_from_target_path(path), None);
    }
}
