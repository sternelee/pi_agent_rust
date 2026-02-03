//! Conformance and determinism tests for the `PiJS` event loop scheduler.
//!
//! This suite is fixture-driven to make ordering rules explicit and extensible.
#![forbid(unsafe_code)]

use pi::extensions_js::{ClockHandle, MacrotaskKind, ManualClock, PiEventLoop};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct Fixture {
    version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    start_ms: u64,
    ops: Vec<Op>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Op {
    SetTimeout {
        delay_ms: u64,
        save_as: String,
    },
    ClearTimeout {
        timer: String,
    },
    EnqueueHostcallCompletion {
        call_id: String,
    },
    EnqueueInboundEvent {
        event_id: String,
    },
    SetClock {
        ms: u64,
    },
    AdvanceClock {
        ms: u64,
    },
    Tick {
        #[serde(default)]
        microtasks: usize,
        expect: Option<ExpectedTask>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExpectedTask {
    HostcallComplete { call_id: String },
    InboundEvent { event_id: String },
    TimerFired { timer: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedTask {
    HostcallComplete { call_id: String },
    InboundEvent { event_id: String },
    TimerFired { timer_id: u64 },
}

#[test]
fn event_loop_fixture_conformance() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_path = repo_root.join("tests/fixtures/event_loop_conformance.json");
    let contents = fs::read_to_string(&fixture_path).expect("read event loop fixture JSON");
    let fixture: Fixture = serde_json::from_str(&contents).expect("parse event loop fixture JSON");
    assert_eq!(fixture.version, "1.0");

    for case in &fixture.cases {
        run_case(case);
    }
}

fn run_case(case: &Case) {
    let clock = Arc::new(ManualClock::new(case.start_ms));
    let mut loop_state = PiEventLoop::new(ClockHandle::new(clock.clone()));
    let mut timers: HashMap<&str, u64> = HashMap::new();

    for (idx, op) in case.ops.iter().enumerate() {
        match op {
            Op::SetTimeout { delay_ms, save_as } => {
                let id = loop_state.set_timeout(*delay_ms);
                timers.insert(save_as.as_str(), id);
            }
            Op::ClearTimeout { timer } => {
                let id = *timers
                    .get(timer.as_str())
                    .unwrap_or_else(|| panic!("{}: step {idx}: unknown timer {timer}", case.name));
                loop_state.clear_timeout(id);
            }
            Op::EnqueueHostcallCompletion { call_id } => {
                loop_state.enqueue_hostcall_completion(call_id.clone());
            }
            Op::EnqueueInboundEvent { event_id } => {
                loop_state.enqueue_inbound_event(event_id.clone());
            }
            Op::SetClock { ms } => {
                clock.set(*ms);
            }
            Op::AdvanceClock { ms } => {
                clock.advance(*ms);
            }
            Op::Tick { microtasks, expect } => {
                let mut observed = None;
                let mut remaining_drains = *microtasks;

                let result = loop_state.tick(
                    |task| {
                        observed = Some(observe_task(task.kind));
                    },
                    || {
                        if remaining_drains == 0 {
                            return false;
                        }
                        remaining_drains -= 1;
                        true
                    },
                );

                let expected_observed = expect.as_ref().map(|task| match task {
                    ExpectedTask::HostcallComplete { call_id } => ObservedTask::HostcallComplete {
                        call_id: call_id.clone(),
                    },
                    ExpectedTask::InboundEvent { event_id } => ObservedTask::InboundEvent {
                        event_id: event_id.clone(),
                    },
                    ExpectedTask::TimerFired { timer } => {
                        let timer_id = *timers.get(timer.as_str()).unwrap_or_else(|| {
                            panic!("{}: step {idx}: unknown timer {timer}", case.name)
                        });
                        ObservedTask::TimerFired { timer_id }
                    }
                });

                assert_eq!(
                    observed, expected_observed,
                    "{}: step {idx}: unexpected macrotask",
                    case.name
                );

                if expected_observed.is_some() {
                    assert!(
                        result.ran_macrotask,
                        "{}: step {idx}: expected ran_macrotask",
                        case.name
                    );
                    assert_eq!(
                        result.microtasks_drained, *microtasks,
                        "{}: step {idx}: microtask drain count mismatch",
                        case.name
                    );
                } else {
                    assert!(
                        !result.ran_macrotask,
                        "{}: step {idx}: expected idle tick",
                        case.name
                    );
                    assert_eq!(
                        result.microtasks_drained, 0,
                        "{}: step {idx}: idle tick should not drain microtasks",
                        case.name
                    );
                }
            }
        }
    }
}

fn observe_task(kind: MacrotaskKind) -> ObservedTask {
    match kind {
        MacrotaskKind::HostcallComplete { call_id } => ObservedTask::HostcallComplete { call_id },
        MacrotaskKind::InboundEvent { event_id } => ObservedTask::InboundEvent { event_id },
        MacrotaskKind::TimerFired { timer_id } => ObservedTask::TimerFired { timer_id },
    }
}

#[derive(Debug, Clone)]
enum GeneratedOp {
    SetTimeout { delay_ms: u64 },
    ClearTimeout { timer_index: usize },
    EnqueueHostcallCompletion,
    EnqueueInboundEvent,
    AdvanceClock { ms: u64 },
    Tick { microtasks: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceEntry {
    observed: Option<ObservedTask>,
    microtasks_drained: usize,
}

#[test]
fn event_loop_deterministic_for_same_seed() {
    for seed in 0_u64..10 {
        let ops = generate_ops(seed, 200);
        let left = run_ops(0, &ops);
        let right = run_ops(0, &ops);
        assert_eq!(left, right, "determinism failed for seed {seed}");
    }
}

fn run_ops(start_ms: u64, ops: &[GeneratedOp]) -> Vec<TraceEntry> {
    let clock = Arc::new(ManualClock::new(start_ms));
    let mut loop_state = PiEventLoop::new(ClockHandle::new(clock.clone()));
    let mut timers = Vec::new();
    let mut hostcall_seq = 0_u64;
    let mut event_seq = 0_u64;
    let mut trace = Vec::new();

    for op in ops {
        match *op {
            GeneratedOp::SetTimeout { delay_ms } => {
                let timer_id = loop_state.set_timeout(delay_ms);
                timers.push(timer_id);
            }
            GeneratedOp::ClearTimeout { timer_index } => {
                if let Some(timer_id) = timers.get(timer_index).copied() {
                    loop_state.clear_timeout(timer_id);
                }
            }
            GeneratedOp::EnqueueHostcallCompletion => {
                hostcall_seq += 1;
                loop_state.enqueue_hostcall_completion(format!("call-{hostcall_seq}"));
            }
            GeneratedOp::EnqueueInboundEvent => {
                event_seq += 1;
                loop_state.enqueue_inbound_event(format!("evt-{event_seq}"));
            }
            GeneratedOp::AdvanceClock { ms } => {
                clock.advance(ms);
            }
            GeneratedOp::Tick { microtasks } => {
                let mut observed = None;
                let mut remaining_drains = microtasks;
                let result = loop_state.tick(
                    |task| observed = Some(observe_task(task.kind)),
                    || {
                        if remaining_drains == 0 {
                            return false;
                        }
                        remaining_drains -= 1;
                        true
                    },
                );
                trace.push(TraceEntry {
                    observed,
                    microtasks_drained: result.microtasks_drained,
                });
            }
        }
    }

    trace
}

fn generate_ops(seed: u64, len: usize) -> Vec<GeneratedOp> {
    let mut rng = SplitMix64::new(seed);
    let mut ops = Vec::with_capacity(len);
    let mut timer_count = 0_usize;

    for _ in 0..len {
        let choice = rng.next_u64() % 7;
        let op = match choice {
            0 => {
                timer_count += 1;
                GeneratedOp::SetTimeout {
                    delay_ms: rng.next_u64() % 50,
                }
            }
            1 => GeneratedOp::ClearTimeout {
                timer_index: if timer_count == 0 {
                    0
                } else {
                    usize::try_from(rng.next_u64() % u64::try_from(timer_count).unwrap_or(1))
                        .unwrap_or(0)
                },
            },
            2 => GeneratedOp::EnqueueHostcallCompletion,
            3 => GeneratedOp::EnqueueInboundEvent,
            4 => GeneratedOp::AdvanceClock {
                ms: rng.next_u64() % 50,
            },
            _ => GeneratedOp::Tick {
                microtasks: usize::try_from(rng.next_u64() % 4).unwrap_or(0),
            },
        };
        ops.push(op);
    }

    ops
}

/// Tiny deterministic RNG for tests (no external deps).
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}
