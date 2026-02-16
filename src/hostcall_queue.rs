//! Hostcall queue primitives with explicit reclamation telemetry.
//!
//! The fast lane uses a bounded lock-free ring (`ArrayQueue`). When pressure
//! exceeds ring capacity, requests spill into a bounded overflow deque to
//! preserve FIFO ordering across the two lanes.

use crossbeam_queue::ArrayQueue;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const HOSTCALL_FAST_RING_CAPACITY: usize = 256;
pub const HOSTCALL_OVERFLOW_CAPACITY: usize = 2_048;
const SAFE_FALLBACK_BACKLOG_MULTIPLIER: usize = 8;
const SAFE_FALLBACK_BACKLOG_MIN: usize = 32;
const S3_FIFO_GHOST_CAPACITY_MULTIPLIER: usize = 2;
const S3_FIFO_GHOST_CAPACITY_MIN: usize = 16;
const S3_FIFO_MIN_SIGNAL_SAMPLES: u64 = 32;
const S3_FIFO_MAX_SIGNALLESS_STREAK: u64 = 64;
const S3_FIFO_UNSTABLE_REJECTION_STREAK: u64 = 16;

/// BRAVO-style lock bias mode for metadata contention handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BravoBiasMode {
    /// Neutral mode. No explicit read bias is applied.
    Balanced,
    /// Prefer reader throughput under stable read-heavy contention.
    ReadBiased,
    /// Temporary writer-favoring recovery mode after starvation risk.
    WriterRecovery,
}

/// Deterministic contention signature computed from a fixed observation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentionSignature {
    /// Window does not include enough operations for a stable decision.
    InsufficientSamples,
    /// Read-dominant contention with healthy writer behavior.
    ReadDominant,
    /// Mixed read/write contention without starvation indicators.
    MixedContention,
    /// Writer wait/timeout profile indicates starvation risk.
    WriterStarvationRisk,
    /// Write-dominant contention (or low reader pressure).
    WriteDominant,
}

/// Observation bucket consumed by the BRAVO policy state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContentionSample {
    pub read_acquires: u64,
    pub write_acquires: u64,
    pub read_wait_p95_us: u64,
    pub write_wait_p95_us: u64,
    pub write_timeouts: u64,
}

impl ContentionSample {
    #[must_use]
    pub const fn total_acquires(self) -> u64 {
        self.read_acquires.saturating_add(self.write_acquires)
    }

    #[must_use]
    pub fn read_ratio_permille(self) -> u32 {
        let total = self.total_acquires();
        if total == 0 {
            return 0;
        }
        let numerator = self.read_acquires.saturating_mul(1_000);
        let ratio = numerator / total;
        u32::try_from(ratio).unwrap_or(1_000)
    }
}

/// Tuning knobs for deterministic BRAVO contention policy behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BravoContentionConfig {
    pub min_total_acquires: u64,
    pub read_dominant_ratio_permille: u32,
    pub mixed_ratio_floor_permille: u32,
    pub mixed_ratio_ceiling_permille: u32,
    pub writer_starvation_wait_us: u64,
    pub writer_starvation_timeouts: u64,
    pub max_consecutive_read_bias_windows: u32,
    pub writer_recovery_windows: u32,
}

impl Default for BravoContentionConfig {
    fn default() -> Self {
        Self {
            min_total_acquires: 32,
            read_dominant_ratio_permille: 800,
            mixed_ratio_floor_permille: 450,
            mixed_ratio_ceiling_permille: 799,
            writer_starvation_wait_us: 8_000,
            writer_starvation_timeouts: 2,
            max_consecutive_read_bias_windows: 5,
            writer_recovery_windows: 2,
        }
    }
}

/// One policy transition decision generated from an observation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BravoPolicyDecision {
    pub previous_mode: BravoBiasMode,
    pub next_mode: BravoBiasMode,
    pub signature: ContentionSignature,
    pub switched: bool,
    pub rollback_triggered: bool,
}

/// Snapshot of contention policy internals for diagnostics and regression tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BravoPolicyTelemetry {
    pub mode: BravoBiasMode,
    pub transitions: u64,
    pub rollbacks: u64,
    pub windows_observed: u64,
    pub consecutive_read_bias_windows: u32,
    pub writer_recovery_remaining: u32,
    pub last_signature: ContentionSignature,
}

/// Deterministic BRAVO-style contention policy state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BravoContentionState {
    config: BravoContentionConfig,
    mode: BravoBiasMode,
    transitions: u64,
    rollbacks: u64,
    windows_observed: u64,
    consecutive_read_bias_windows: u32,
    writer_recovery_remaining: u32,
    last_signature: ContentionSignature,
}

impl BravoContentionState {
    #[must_use]
    pub const fn new(config: BravoContentionConfig) -> Self {
        Self {
            config,
            mode: BravoBiasMode::Balanced,
            transitions: 0,
            rollbacks: 0,
            windows_observed: 0,
            consecutive_read_bias_windows: 0,
            writer_recovery_remaining: 0,
            last_signature: ContentionSignature::InsufficientSamples,
        }
    }

    #[must_use]
    pub const fn mode(self) -> BravoBiasMode {
        self.mode
    }

    #[must_use]
    pub const fn snapshot(self) -> BravoPolicyTelemetry {
        BravoPolicyTelemetry {
            mode: self.mode,
            transitions: self.transitions,
            rollbacks: self.rollbacks,
            windows_observed: self.windows_observed,
            consecutive_read_bias_windows: self.consecutive_read_bias_windows,
            writer_recovery_remaining: self.writer_recovery_remaining,
            last_signature: self.last_signature,
        }
    }

    pub fn observe(&mut self, sample: ContentionSample) -> BravoPolicyDecision {
        let previous_mode = self.mode;
        let signature = Self::classify(sample, self.config);
        self.windows_observed = self.windows_observed.saturating_add(1);

        let mut rollback_triggered = false;
        match self.mode {
            BravoBiasMode::Balanced => match signature {
                ContentionSignature::WriterStarvationRisk => {
                    self.mode = BravoBiasMode::WriterRecovery;
                    self.writer_recovery_remaining = self.config.writer_recovery_windows.max(1);
                    self.consecutive_read_bias_windows = 0;
                    self.rollbacks = self.rollbacks.saturating_add(1);
                    rollback_triggered = true;
                }
                ContentionSignature::ReadDominant | ContentionSignature::MixedContention => {
                    self.mode = BravoBiasMode::ReadBiased;
                    self.consecutive_read_bias_windows = 1;
                }
                ContentionSignature::InsufficientSamples | ContentionSignature::WriteDominant => {
                    self.consecutive_read_bias_windows = 0;
                }
            },
            BravoBiasMode::ReadBiased => {
                self.consecutive_read_bias_windows =
                    self.consecutive_read_bias_windows.saturating_add(1);

                let starvation = signature == ContentionSignature::WriterStarvationRisk;
                let fairness_budget_exhausted = self.consecutive_read_bias_windows
                    >= self.config.max_consecutive_read_bias_windows.max(1);

                if starvation || fairness_budget_exhausted {
                    self.mode = BravoBiasMode::WriterRecovery;
                    self.writer_recovery_remaining = self.config.writer_recovery_windows.max(1);
                    self.consecutive_read_bias_windows = 0;
                    rollback_triggered = starvation;
                    if starvation {
                        self.rollbacks = self.rollbacks.saturating_add(1);
                    }
                } else if matches!(
                    signature,
                    ContentionSignature::InsufficientSamples | ContentionSignature::WriteDominant
                ) {
                    self.mode = BravoBiasMode::Balanced;
                    self.consecutive_read_bias_windows = 0;
                }
            }
            BravoBiasMode::WriterRecovery => {
                self.consecutive_read_bias_windows = 0;
                if signature == ContentionSignature::WriterStarvationRisk {
                    self.writer_recovery_remaining = self.config.writer_recovery_windows.max(1);
                } else if self.writer_recovery_remaining > 0 {
                    self.writer_recovery_remaining -= 1;
                }
                if self.writer_recovery_remaining == 0 {
                    self.mode = BravoBiasMode::Balanced;
                }
            }
        }

        if self.mode != previous_mode {
            self.transitions = self.transitions.saturating_add(1);
        }
        self.last_signature = signature;

        BravoPolicyDecision {
            previous_mode,
            next_mode: self.mode,
            signature,
            switched: self.mode != previous_mode,
            rollback_triggered,
        }
    }

    #[must_use]
    pub fn classify(
        sample: ContentionSample,
        config: BravoContentionConfig,
    ) -> ContentionSignature {
        if sample.total_acquires() < config.min_total_acquires {
            return ContentionSignature::InsufficientSamples;
        }

        if sample.write_wait_p95_us >= config.writer_starvation_wait_us
            || sample.write_timeouts >= config.writer_starvation_timeouts
        {
            return ContentionSignature::WriterStarvationRisk;
        }

        let read_ratio = sample.read_ratio_permille();
        let read_dominant_floor = config.read_dominant_ratio_permille.min(1_000);
        if read_ratio >= read_dominant_floor {
            return ContentionSignature::ReadDominant;
        }

        let mixed_floor = config.mixed_ratio_floor_permille.min(1_000);
        let mixed_ceiling = config
            .mixed_ratio_ceiling_permille
            .clamp(mixed_floor, 1_000);
        if read_ratio >= mixed_floor && read_ratio <= mixed_ceiling {
            return ContentionSignature::MixedContention;
        }

        ContentionSignature::WriteDominant
    }
}

impl Default for BravoContentionState {
    fn default() -> Self {
        Self::new(BravoContentionConfig::default())
    }
}

/// Optional per-request tenant key used for fairness/admission accounting.
///
/// Implement this for queue payloads that can expose extension-level identity.
/// Primitive test payloads may use the default `None` implementation.
pub trait QueueTenant {
    #[must_use]
    fn tenant_key(&self) -> Option<&str> {
        None
    }
}

macro_rules! impl_queue_tenant_none {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl QueueTenant for $ty {}
        )+
    };
}

impl_queue_tenant_none!(
    (),
    bool,
    char,
    u8,
    u16,
    u32,
    u64,
    usize,
    i8,
    i16,
    i32,
    i64,
    isize,
    String,
);

/// Runtime mode for S3-FIFO-inspired queue admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoMode {
    Active,
    ConservativeFifo,
}

/// Explicit fallback reason when S3-FIFO admission is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoFallbackReason {
    InsufficientSignalQuality,
    UnstableAdmissionFeedback,
}

/// Deterministic admission configuration for S3-FIFO-inspired behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoConfig {
    pub tenant_budget: usize,
    pub ghost_capacity: usize,
    pub min_signal_samples: u64,
    pub max_signalless_streak: u64,
    pub unstable_rejection_streak: u64,
}

impl S3FifoConfig {
    #[must_use]
    pub fn from_capacities(fast_capacity: usize, overflow_capacity: usize) -> Self {
        let tenant_budget = (overflow_capacity / 2).max(1);
        let ghost_capacity = fast_capacity
            .saturating_add(overflow_capacity)
            .saturating_mul(S3_FIFO_GHOST_CAPACITY_MULTIPLIER)
            .max(S3_FIFO_GHOST_CAPACITY_MIN);
        Self {
            tenant_budget,
            ghost_capacity,
            min_signal_samples: S3_FIFO_MIN_SIGNAL_SAMPLES,
            max_signalless_streak: S3_FIFO_MAX_SIGNALLESS_STREAK,
            unstable_rejection_streak: S3_FIFO_UNSTABLE_REJECTION_STREAK,
        }
    }
}

/// Lightweight diagnostics snapshot for S3-FIFO admission internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoTelemetry {
    pub mode: S3FifoMode,
    pub fallback_reason: Option<S3FifoFallbackReason>,
    pub ghost_depth: usize,
    pub ghost_hits_total: u64,
    pub fairness_rejected_total: u64,
    pub signal_samples: u64,
    pub signalless_streak: u64,
    pub fallback_transitions: u64,
    pub tenant_budget: usize,
    pub active_tenants: usize,
}

#[derive(Debug, Clone)]
struct S3FifoState {
    config: S3FifoConfig,
    mode: S3FifoMode,
    fallback_reason: Option<S3FifoFallbackReason>,
    ghost: VecDeque<String>,
    tenant_backlog: BTreeMap<String, usize>,
    ghost_hits_total: u64,
    fairness_rejected_total: u64,
    signal_samples: u64,
    signalless_streak: u64,
    unstable_rejection_streak: u64,
    fallback_transitions: u64,
}

impl S3FifoState {
    #[must_use]
    const fn new(config: S3FifoConfig) -> Self {
        Self {
            config,
            mode: S3FifoMode::Active,
            fallback_reason: None,
            ghost: VecDeque::new(),
            tenant_backlog: BTreeMap::new(),
            ghost_hits_total: 0,
            fairness_rejected_total: 0,
            signal_samples: 0,
            signalless_streak: 0,
            unstable_rejection_streak: 0,
            fallback_transitions: 0,
        }
    }

    fn observe_signal(&mut self, tenant_key: Option<&str>) {
        if self.mode != S3FifoMode::Active {
            return;
        }
        if tenant_key.is_some() {
            self.signal_samples = self.signal_samples.saturating_add(1);
            self.signalless_streak = 0;
        } else {
            self.signalless_streak = self.signalless_streak.saturating_add(1);
            if self.signalless_streak >= self.config.max_signalless_streak
                && self.signal_samples < self.config.min_signal_samples
            {
                self.transition_to_fallback(S3FifoFallbackReason::InsufficientSignalQuality);
            }
        }
    }

    fn allow_main_admission(&mut self, tenant_key: Option<&str>) -> bool {
        if self.mode != S3FifoMode::Active {
            return true;
        }
        let Some(tenant_key) = tenant_key else {
            return true;
        };
        let backlog = self.tenant_backlog.get(tenant_key).copied().unwrap_or(0);
        if backlog < self.config.tenant_budget {
            return true;
        }
        if self.consume_ghost_hit(tenant_key) {
            self.unstable_rejection_streak = 0;
            return true;
        }

        self.fairness_rejected_total = self.fairness_rejected_total.saturating_add(1);
        self.unstable_rejection_streak = self.unstable_rejection_streak.saturating_add(1);
        self.record_ghost(tenant_key);
        if self.unstable_rejection_streak >= self.config.unstable_rejection_streak {
            self.transition_to_fallback(S3FifoFallbackReason::UnstableAdmissionFeedback);
        }
        false
    }

    fn on_main_enqueued(&mut self, tenant_key: Option<&str>) {
        if self.mode != S3FifoMode::Active {
            return;
        }
        if let Some(tenant_key) = tenant_key {
            let entry = self
                .tenant_backlog
                .entry(tenant_key.to_string())
                .or_insert(0);
            *entry = entry.saturating_add(1);
        }
        self.unstable_rejection_streak = 0;
    }

    fn on_main_dequeued(&mut self, tenant_key: Option<&str>) {
        if self.mode != S3FifoMode::Active {
            return;
        }
        if let Some(tenant_key) = tenant_key {
            if let Some(backlog) = self.tenant_backlog.get_mut(tenant_key) {
                *backlog = backlog.saturating_sub(1);
                if *backlog == 0 {
                    self.tenant_backlog.remove(tenant_key);
                }
            }
            self.record_ghost(tenant_key);
        }
    }

    fn on_main_overflow_reject(&mut self, tenant_key: Option<&str>) {
        if self.mode != S3FifoMode::Active {
            return;
        }
        if let Some(tenant_key) = tenant_key {
            self.record_ghost(tenant_key);
        }
        self.unstable_rejection_streak = self.unstable_rejection_streak.saturating_add(1);
        if self.unstable_rejection_streak >= self.config.unstable_rejection_streak {
            self.transition_to_fallback(S3FifoFallbackReason::UnstableAdmissionFeedback);
        }
    }

    fn transition_to_fallback(&mut self, reason: S3FifoFallbackReason) {
        if self.mode == S3FifoMode::ConservativeFifo {
            return;
        }
        self.mode = S3FifoMode::ConservativeFifo;
        self.fallback_reason = Some(reason);
        self.fallback_transitions = self.fallback_transitions.saturating_add(1);
        self.ghost.clear();
        self.tenant_backlog.clear();
    }

    fn consume_ghost_hit(&mut self, tenant_key: &str) -> bool {
        let position = self.ghost.iter().position(|entry| entry == tenant_key);
        let Some(position) = position else {
            return false;
        };
        self.ghost.remove(position);
        self.ghost_hits_total = self.ghost_hits_total.saturating_add(1);
        true
    }

    fn record_ghost(&mut self, tenant_key: &str) {
        if tenant_key.is_empty() {
            return;
        }
        if let Some(position) = self.ghost.iter().position(|entry| entry == tenant_key) {
            self.ghost.remove(position);
        }
        self.ghost.push_back(tenant_key.to_string());
        while self.ghost.len() > self.config.ghost_capacity {
            let _ = self.ghost.pop_front();
        }
    }

    #[must_use]
    fn snapshot(&self) -> S3FifoTelemetry {
        S3FifoTelemetry {
            mode: self.mode,
            fallback_reason: self.fallback_reason,
            ghost_depth: self.ghost.len(),
            ghost_hits_total: self.ghost_hits_total,
            fairness_rejected_total: self.fairness_rejected_total,
            signal_samples: self.signal_samples,
            signalless_streak: self.signalless_streak,
            fallback_transitions: self.fallback_transitions,
            tenant_budget: self.config.tenant_budget,
            active_tenants: self.tenant_backlog.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostcallQueueMode {
    /// Use epoch-based retirement bookkeeping.
    Ebr,
    /// Disable EBR retirement and drop popped nodes immediately.
    SafeFallback,
}

impl HostcallQueueMode {
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var("PI_HOSTCALL_QUEUE_RECLAIMER")
            .ok()
            .as_deref()
            .and_then(Self::parse)
            .unwrap_or(Self::Ebr)
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ebr" | "epoch" | "epoch-based" => Some(Self::Ebr),
            "fallback" | "safe-fallback" | "off" | "disabled" | "legacy" => {
                Some(Self::SafeFallback)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostcallQueueEnqueueResult {
    FastPath { depth: usize },
    OverflowPath { depth: usize, overflow_depth: usize },
    Rejected { depth: usize, overflow_depth: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostcallQueueTelemetry {
    pub fast_depth: usize,
    pub overflow_depth: usize,
    pub total_depth: usize,
    pub max_depth_seen: usize,
    pub overflow_enqueued_total: u64,
    pub overflow_rejected_total: u64,
    pub fast_capacity: usize,
    pub overflow_capacity: usize,
    pub reclamation_mode: HostcallQueueMode,
    pub retired_backlog: usize,
    pub reclaimed_total: u64,
    pub current_epoch: u64,
    pub epoch_lag: u64,
    pub max_epoch_lag: u64,
    pub reclamation_latency_max_epochs: u64,
    pub fallback_transitions: u64,
    pub active_epoch_pins: usize,
    pub bravo_mode: BravoBiasMode,
    pub bravo_transitions: u64,
    pub bravo_rollbacks: u64,
    pub bravo_consecutive_read_bias_windows: u32,
    pub bravo_writer_recovery_remaining: u32,
    pub bravo_last_signature: ContentionSignature,
    pub s3fifo_mode: S3FifoMode,
    pub s3fifo_fallback_reason: Option<S3FifoFallbackReason>,
    pub s3fifo_ghost_depth: usize,
    pub s3fifo_ghost_hits_total: u64,
    pub s3fifo_fairness_rejected_total: u64,
    pub s3fifo_signal_samples: u64,
    pub s3fifo_signalless_streak: u64,
    pub s3fifo_fallback_transitions: u64,
    pub s3fifo_tenant_budget: usize,
    pub s3fifo_active_tenants: usize,
}

#[derive(Debug)]
struct RetiredNode<T> {
    value: T,
    retired_epoch: u64,
}

#[derive(Debug)]
pub struct HostcallEpochPin {
    active_epoch_pins: Arc<AtomicUsize>,
}

impl Drop for HostcallEpochPin {
    fn drop(&mut self) {
        let previous = self.active_epoch_pins.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "epoch pin underflow");
    }
}

#[derive(Debug)]
pub struct HostcallRequestQueue<T: Clone + QueueTenant> {
    fast: ArrayQueue<T>,
    fast_capacity: usize,
    overflow: VecDeque<T>,
    overflow_enqueued_total: u64,
    overflow_rejected_total: u64,
    max_depth_seen: usize,
    overflow_capacity: usize,
    reclamation_mode: HostcallQueueMode,
    active_epoch_pins: Arc<AtomicUsize>,
    current_epoch: u64,
    retired: VecDeque<RetiredNode<T>>,
    reclaimed_total: u64,
    max_epoch_lag: u64,
    reclamation_latency_max_epochs: u64,
    fallback_transitions: u64,
    safe_fallback_backlog_threshold: usize,
    contention_policy: BravoContentionState,
    s3fifo: S3FifoState,
}

impl<T: Clone + QueueTenant> HostcallRequestQueue<T> {
    #[must_use]
    pub fn with_capacities(fast_capacity: usize, overflow_capacity: usize) -> Self {
        Self::with_mode(
            fast_capacity,
            overflow_capacity,
            HostcallQueueMode::from_env(),
        )
    }

    #[must_use]
    pub fn with_mode(
        fast_capacity: usize,
        overflow_capacity: usize,
        reclamation_mode: HostcallQueueMode,
    ) -> Self {
        let fast_capacity = fast_capacity.max(1);
        let overflow_capacity = overflow_capacity.max(1);
        let safe_fallback_backlog_threshold = fast_capacity
            .saturating_add(overflow_capacity)
            .saturating_mul(SAFE_FALLBACK_BACKLOG_MULTIPLIER)
            .max(SAFE_FALLBACK_BACKLOG_MIN);
        let s3fifo = S3FifoState::new(S3FifoConfig::from_capacities(
            fast_capacity,
            overflow_capacity,
        ));
        Self {
            fast: ArrayQueue::new(fast_capacity),
            fast_capacity,
            overflow: VecDeque::new(),
            overflow_enqueued_total: 0,
            overflow_rejected_total: 0,
            max_depth_seen: 0,
            overflow_capacity,
            reclamation_mode,
            active_epoch_pins: Arc::new(AtomicUsize::new(0)),
            current_epoch: 0,
            retired: VecDeque::new(),
            reclaimed_total: 0,
            max_epoch_lag: 0,
            reclamation_latency_max_epochs: 0,
            fallback_transitions: 0,
            safe_fallback_backlog_threshold,
            contention_policy: BravoContentionState::default(),
            s3fifo,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.fast.len() + self.overflow.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fast.is_empty() && self.overflow.is_empty()
    }

    #[must_use]
    pub const fn reclamation_mode(&self) -> HostcallQueueMode {
        self.reclamation_mode
    }

    pub fn pin_epoch(&self) -> HostcallEpochPin {
        self.active_epoch_pins.fetch_add(1, Ordering::SeqCst);
        HostcallEpochPin {
            active_epoch_pins: Arc::clone(&self.active_epoch_pins),
        }
    }

    pub fn clear(&mut self) {
        while self.fast.pop().is_some() {}
        self.overflow.clear();
        self.overflow_enqueued_total = 0;
        self.overflow_rejected_total = 0;
        self.max_depth_seen = 0;
        self.current_epoch = 0;
        self.retired.clear();
        self.reclaimed_total = 0;
        self.max_epoch_lag = 0;
        self.reclamation_latency_max_epochs = 0;
        self.fallback_transitions = 0;
        self.contention_policy = BravoContentionState::default();
        self.s3fifo = S3FifoState::new(S3FifoConfig::from_capacities(
            self.fast_capacity,
            self.overflow_capacity,
        ));
    }

    pub fn push_back(&mut self, request: T) -> HostcallQueueEnqueueResult {
        let tenant_key = request.tenant_key().map(std::borrow::ToOwned::to_owned);
        self.s3fifo.observe_signal(tenant_key.as_deref());
        let mut request = request;

        // Preserve FIFO across lanes by pinning to overflow once spill begins.
        if self.overflow.is_empty() {
            match self.fast.push(request) {
                Ok(()) => {
                    self.bump_epoch();
                    self.try_reclaim();
                    let depth = self.len();
                    self.max_depth_seen = self.max_depth_seen.max(depth);
                    tracing::debug!(
                        target: "pi.extensions.hostcall_queue",
                        event = "hostcall_queue.enqueue",
                        reason = "small_tier",
                        depth,
                        overflow_depth = self.overflow.len(),
                        "hostcall admitted to fast tier"
                    );
                    return HostcallQueueEnqueueResult::FastPath { depth };
                }
                Err(returned) => request = returned,
            }
        }

        if !self.s3fifo.allow_main_admission(tenant_key.as_deref()) {
            self.overflow_rejected_total = self.overflow_rejected_total.saturating_add(1);
            tracing::debug!(
                target: "pi.extensions.hostcall_queue",
                event = "hostcall_queue.reject",
                reason = "fairness_budget",
                depth = self.len(),
                overflow_depth = self.overflow.len(),
                s3fifo_mode = ?self.s3fifo.snapshot().mode,
                "hostcall rejected by S3-FIFO fairness budget"
            );
            return HostcallQueueEnqueueResult::Rejected {
                depth: self.len(),
                overflow_depth: self.overflow.len(),
            };
        }

        if self.overflow.len() < self.overflow_capacity {
            self.overflow.push_back(request);
            self.overflow_enqueued_total = self.overflow_enqueued_total.saturating_add(1);
            self.s3fifo.on_main_enqueued(tenant_key.as_deref());
            self.bump_epoch();
            self.try_reclaim();
            let depth = self.len();
            let overflow_depth = self.overflow.len();
            self.max_depth_seen = self.max_depth_seen.max(depth);
            tracing::debug!(
                target: "pi.extensions.hostcall_queue",
                event = "hostcall_queue.enqueue",
                reason = "main_tier",
                depth,
                overflow_depth,
                "hostcall admitted to overflow/main tier"
            );
            return HostcallQueueEnqueueResult::OverflowPath {
                depth,
                overflow_depth,
            };
        }

        self.overflow_rejected_total = self.overflow_rejected_total.saturating_add(1);
        self.s3fifo.on_main_overflow_reject(tenant_key.as_deref());
        tracing::debug!(
            target: "pi.extensions.hostcall_queue",
            event = "hostcall_queue.reject",
            reason = "overflow_capacity",
            depth = self.len(),
            overflow_depth = self.overflow.len(),
            "hostcall rejected because overflow queue reached capacity"
        );
        HostcallQueueEnqueueResult::Rejected {
            depth: self.len(),
            overflow_depth: self.overflow.len(),
        }
    }

    fn pop_front(&mut self) -> Option<T> {
        let value = if let Some(value) = self.fast.pop() {
            value
        } else {
            let value = self.overflow.pop_front()?;
            let tenant_key = value.tenant_key().map(std::borrow::ToOwned::to_owned);
            self.s3fifo.on_main_dequeued(tenant_key.as_deref());
            value
        };
        self.bump_epoch();
        if self.reclamation_mode == HostcallQueueMode::Ebr {
            self.retire_for_reclamation(value.clone());
        }
        self.try_reclaim();
        Some(value)
    }

    pub fn drain_all(&mut self) -> VecDeque<T> {
        let mut drained = VecDeque::with_capacity(self.len());
        while let Some(request) = self.pop_front() {
            drained.push_back(request);
        }
        drained
    }

    /// Explicit reclamation point used by tests and slow-path maintenance.
    pub fn force_reclaim(&mut self) {
        self.bump_epoch();
        self.try_reclaim();
    }

    /// Immediately disable EBR and switch to the safe fallback mode.
    pub fn force_safe_fallback(&mut self) {
        self.transition_to_safe_fallback();
    }

    /// Feed one deterministic contention observation window into the BRAVO
    /// policy controller.
    pub fn observe_contention_window(&mut self, sample: ContentionSample) -> BravoPolicyDecision {
        self.contention_policy.observe(sample)
    }

    #[must_use]
    pub const fn contention_policy_snapshot(&self) -> BravoPolicyTelemetry {
        self.contention_policy.snapshot()
    }

    #[must_use]
    pub fn snapshot(&self) -> HostcallQueueTelemetry {
        let epoch_lag = self.retired.front().map_or(0, |node| {
            self.current_epoch.saturating_sub(node.retired_epoch)
        });
        let contention = self.contention_policy.snapshot();
        let s3fifo = self.s3fifo.snapshot();

        HostcallQueueTelemetry {
            fast_depth: self.fast.len(),
            overflow_depth: self.overflow.len(),
            total_depth: self.len(),
            max_depth_seen: self.max_depth_seen,
            overflow_enqueued_total: self.overflow_enqueued_total,
            overflow_rejected_total: self.overflow_rejected_total,
            fast_capacity: self.fast_capacity,
            overflow_capacity: self.overflow_capacity,
            reclamation_mode: self.reclamation_mode,
            retired_backlog: self.retired.len(),
            reclaimed_total: self.reclaimed_total,
            current_epoch: self.current_epoch,
            epoch_lag,
            max_epoch_lag: self.max_epoch_lag,
            reclamation_latency_max_epochs: self.reclamation_latency_max_epochs,
            fallback_transitions: self.fallback_transitions,
            active_epoch_pins: self.active_epoch_pins.load(Ordering::SeqCst),
            bravo_mode: contention.mode,
            bravo_transitions: contention.transitions,
            bravo_rollbacks: contention.rollbacks,
            bravo_consecutive_read_bias_windows: contention.consecutive_read_bias_windows,
            bravo_writer_recovery_remaining: contention.writer_recovery_remaining,
            bravo_last_signature: contention.last_signature,
            s3fifo_mode: s3fifo.mode,
            s3fifo_fallback_reason: s3fifo.fallback_reason,
            s3fifo_ghost_depth: s3fifo.ghost_depth,
            s3fifo_ghost_hits_total: s3fifo.ghost_hits_total,
            s3fifo_fairness_rejected_total: s3fifo.fairness_rejected_total,
            s3fifo_signal_samples: s3fifo.signal_samples,
            s3fifo_signalless_streak: s3fifo.signalless_streak,
            s3fifo_fallback_transitions: s3fifo.fallback_transitions,
            s3fifo_tenant_budget: s3fifo.tenant_budget,
            s3fifo_active_tenants: s3fifo.active_tenants,
        }
    }

    const fn bump_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1);
    }

    fn retire_for_reclamation(&mut self, value: T) {
        self.retired.push_back(RetiredNode {
            value,
            retired_epoch: self.current_epoch,
        });
    }

    fn transition_to_safe_fallback(&mut self) {
        if self.reclamation_mode == HostcallQueueMode::SafeFallback {
            return;
        }
        self.reclamation_mode = HostcallQueueMode::SafeFallback;
        self.fallback_transitions = self.fallback_transitions.saturating_add(1);
        self.retired.clear();
    }

    fn try_reclaim(&mut self) {
        if self.reclamation_mode != HostcallQueueMode::Ebr {
            return;
        }

        let active = self.active_epoch_pins.load(Ordering::SeqCst);
        if active > 0 {
            if let Some(front) = self.retired.front() {
                let lag = self.current_epoch.saturating_sub(front.retired_epoch);
                self.max_epoch_lag = self.max_epoch_lag.max(lag);
            }
            if self.retired.len() > self.safe_fallback_backlog_threshold {
                self.transition_to_safe_fallback();
            }
            return;
        }

        while self
            .retired
            .front()
            .is_some_and(|front| front.retired_epoch < self.current_epoch)
        {
            if let Some(node) = self.retired.pop_front() {
                let latency = self.current_epoch.saturating_sub(node.retired_epoch);
                self.reclamation_latency_max_epochs =
                    self.reclamation_latency_max_epochs.max(latency);
                self.reclaimed_total = self.reclaimed_total.saturating_add(1);
                drop(node.value);
            }
        }
    }
}

impl<T: Clone + QueueTenant> Default for HostcallRequestQueue<T> {
    fn default() -> Self {
        Self::with_capacities(HOSTCALL_FAST_RING_CAPACITY, HOSTCALL_OVERFLOW_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_config() -> BravoContentionConfig {
        BravoContentionConfig {
            min_total_acquires: 10,
            read_dominant_ratio_permille: 750,
            mixed_ratio_floor_permille: 400,
            mixed_ratio_ceiling_permille: 749,
            writer_starvation_wait_us: 4_000,
            writer_starvation_timeouts: 2,
            max_consecutive_read_bias_windows: 3,
            writer_recovery_windows: 2,
        }
    }

    fn sample(
        reads: u64,
        writes: u64,
        read_wait_p95_us: u64,
        write_wait_p95_us: u64,
        write_timeouts: u64,
    ) -> ContentionSample {
        ContentionSample {
            read_acquires: reads,
            write_acquires: writes,
            read_wait_p95_us,
            write_wait_p95_us,
            write_timeouts,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TenantRequest {
        tenant: Option<&'static str>,
        value: u8,
    }

    impl QueueTenant for TenantRequest {
        fn tenant_key(&self) -> Option<&str> {
            self.tenant
        }
    }

    #[test]
    fn hostcall_queue_mode_parsing_supports_ebr_and_fallback() {
        assert_eq!(
            HostcallQueueMode::parse("ebr"),
            Some(HostcallQueueMode::Ebr)
        );
        assert_eq!(
            HostcallQueueMode::parse("safe-fallback"),
            Some(HostcallQueueMode::SafeFallback)
        );
        assert_eq!(HostcallQueueMode::parse("nope"), None);
    }

    #[test]
    fn contention_classifier_flags_writer_starvation_deterministically() {
        let config = deterministic_config();
        let starvation = sample(90, 10, 100, 10_000, 3);
        let signature = BravoContentionState::classify(starvation, config);
        assert_eq!(signature, ContentionSignature::WriterStarvationRisk);

        let read_dominant = sample(90, 10, 100, 300, 0);
        let signature = BravoContentionState::classify(read_dominant, config);
        assert_eq!(signature, ContentionSignature::ReadDominant);
    }

    #[test]
    fn bravo_policy_rolls_back_on_starvation_and_recovers() {
        let mut policy = BravoContentionState::new(deterministic_config());

        let first = policy.observe(sample(80, 20, 120, 500, 0));
        assert_eq!(first.previous_mode, BravoBiasMode::Balanced);
        assert_eq!(first.next_mode, BravoBiasMode::ReadBiased);
        assert_eq!(first.signature, ContentionSignature::ReadDominant);
        assert!(first.switched);

        let second = policy.observe(sample(85, 15, 100, 8_500, 3));
        assert_eq!(second.previous_mode, BravoBiasMode::ReadBiased);
        assert_eq!(second.next_mode, BravoBiasMode::WriterRecovery);
        assert_eq!(second.signature, ContentionSignature::WriterStarvationRisk);
        assert!(second.rollback_triggered);

        let third = policy.observe(sample(30, 70, 200, 500, 0));
        assert_eq!(third.next_mode, BravoBiasMode::WriterRecovery);
        assert!(!third.switched);

        let fourth = policy.observe(sample(35, 65, 200, 450, 0));
        assert_eq!(fourth.next_mode, BravoBiasMode::Balanced);
        assert!(fourth.switched);

        let telemetry = policy.snapshot();
        assert_eq!(telemetry.mode, BravoBiasMode::Balanced);
        assert!(telemetry.rollbacks >= 1);
        assert!(telemetry.transitions >= 3);
    }

    #[test]
    fn bravo_policy_enforces_writer_fairness_budget() {
        let mut config = deterministic_config();
        config.max_consecutive_read_bias_windows = 2;
        config.writer_recovery_windows = 1;
        let mut policy = BravoContentionState::new(config);

        let _ = policy.observe(sample(80, 20, 100, 250, 0));
        let second = policy.observe(sample(85, 15, 100, 260, 0));
        assert_eq!(second.next_mode, BravoBiasMode::WriterRecovery);
        assert_eq!(second.signature, ContentionSignature::ReadDominant);
        assert!(!second.rollback_triggered);

        let recovery = policy.observe(sample(40, 60, 150, 400, 0));
        assert_eq!(recovery.next_mode, BravoBiasMode::Balanced);

        let telemetry = policy.snapshot();
        assert_eq!(telemetry.mode, BravoBiasMode::Balanced);
        assert_eq!(telemetry.writer_recovery_remaining, 0);
    }

    #[test]
    fn queue_snapshot_exposes_bravo_policy_telemetry() {
        let mut queue: HostcallRequestQueue<u8> =
            HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::SafeFallback);

        let decision = queue.observe_contention_window(sample(70, 30, 120, 350, 0));
        assert_eq!(decision.next_mode, BravoBiasMode::ReadBiased);

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.bravo_mode, BravoBiasMode::ReadBiased);
        assert_eq!(
            snapshot.bravo_last_signature,
            ContentionSignature::MixedContention
        );
        assert!(snapshot.bravo_transitions >= 1);
    }

    #[test]
    fn queue_spills_to_overflow_with_stable_order() {
        let mut queue = HostcallRequestQueue::with_mode(2, 4, HostcallQueueMode::SafeFallback);
        assert!(matches!(
            queue.push_back(0_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(1_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(2_u8),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.fast_depth, 2);
        assert_eq!(snapshot.overflow_depth, 1);
        assert_eq!(snapshot.total_depth, 3);
        assert_eq!(snapshot.overflow_enqueued_total, 1);

        let drained = queue.drain_all();
        assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn queue_rejects_when_overflow_capacity_reached() {
        let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::SafeFallback);
        assert!(matches!(
            queue.push_back(0_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(1_u8),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));
        assert!(matches!(
            queue.push_back(2_u8),
            HostcallQueueEnqueueResult::Rejected { .. }
        ));

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.total_depth, 2);
        assert_eq!(snapshot.overflow_depth, 1);
        assert_eq!(snapshot.overflow_rejected_total, 1);
    }

    #[test]
    fn s3fifo_fairness_budget_rejects_noisy_tenant_before_overflow_full() {
        let mut queue = HostcallRequestQueue::with_mode(1, 3, HostcallQueueMode::SafeFallback);

        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.noisy"),
                value: 0
            }),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.noisy"),
                value: 1
            }),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.noisy"),
                value: 2
            }),
            HostcallQueueEnqueueResult::Rejected { .. }
        ));

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.s3fifo_mode, S3FifoMode::Active);
        assert_eq!(snapshot.s3fifo_tenant_budget, 1);
        assert_eq!(snapshot.s3fifo_fairness_rejected_total, 1);
        assert_eq!(snapshot.overflow_rejected_total, 1);
    }

    #[test]
    fn s3fifo_ghost_hits_allow_reentry_after_prior_rejection() {
        let mut queue = HostcallRequestQueue::with_mode(1, 4, HostcallQueueMode::SafeFallback);

        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 0
            }),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 1
            }),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 2
            }),
            HostcallQueueEnqueueResult::Rejected { .. }
        ));

        let drained = queue.drain_all();
        assert_eq!(
            drained
                .into_iter()
                .map(|entry| entry.value)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 3
            }),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 4
            }),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));
        assert!(matches!(
            queue.push_back(TenantRequest {
                tenant: Some("ext.ghost"),
                value: 5
            }),
            HostcallQueueEnqueueResult::OverflowPath { .. }
        ));

        let snapshot = queue.snapshot();
        assert!(snapshot.s3fifo_ghost_hits_total >= 1);
        assert_eq!(snapshot.s3fifo_fairness_rejected_total, 1);
    }

    #[test]
    fn s3fifo_falls_back_to_conservative_fifo_when_signal_is_insufficient() {
        let mut queue = HostcallRequestQueue::with_mode(1, 2, HostcallQueueMode::SafeFallback);

        for value in 0..96_u8 {
            let _ = queue.push_back(value);
            let _ = queue.drain_all();
        }

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.s3fifo_mode, S3FifoMode::ConservativeFifo);
        assert_eq!(
            snapshot.s3fifo_fallback_reason,
            Some(S3FifoFallbackReason::InsufficientSignalQuality)
        );
        assert!(snapshot.s3fifo_fallback_transitions >= 1);
    }

    #[test]
    fn ebr_reclamation_tracks_lag_and_latency() {
        let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::Ebr);
        let pin = queue.pin_epoch();
        assert!(matches!(
            queue.push_back(1_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        assert!(matches!(
            queue.push_back(2_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        let drained = queue.drain_all();
        assert_eq!(drained.len(), 2);

        queue.force_reclaim();
        let blocked = queue.snapshot();
        assert_eq!(blocked.reclamation_mode, HostcallQueueMode::Ebr);
        assert_eq!(blocked.retired_backlog, 2);
        assert_eq!(blocked.reclaimed_total, 0);
        assert!(blocked.epoch_lag >= 1);

        drop(pin);
        queue.force_reclaim();
        let reclaimed = queue.snapshot();
        assert_eq!(reclaimed.retired_backlog, 0);
        assert!(reclaimed.reclaimed_total >= 2);
        assert!(reclaimed.reclamation_latency_max_epochs >= 1);
    }

    #[test]
    fn safe_fallback_mode_skips_retirement_tracking() {
        let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::SafeFallback);
        let _pin = queue.pin_epoch();
        assert!(matches!(
            queue.push_back(1_u8),
            HostcallQueueEnqueueResult::FastPath { .. }
        ));
        let _ = queue.drain_all();
        queue.force_reclaim();

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::SafeFallback);
        assert_eq!(snapshot.retired_backlog, 0);
        assert_eq!(snapshot.reclaimed_total, 0);
    }

    #[test]
    fn ebr_auto_falls_back_when_retired_backlog_runs_away() {
        let mut queue = HostcallRequestQueue::with_mode(1, 1, HostcallQueueMode::Ebr);
        let _pin = queue.pin_epoch();

        // Keep a pin active while repeatedly retiring nodes so backlog exceeds
        // the safety threshold and forces fallback.
        for value in 0..64_u8 {
            let result = queue.push_back(value);
            assert!(
                !matches!(result, HostcallQueueEnqueueResult::Rejected { .. }),
                "queue should accept one item per cycle"
            );
            let drained = queue.drain_all();
            assert_eq!(drained.len(), 1);
            queue.force_reclaim();
        }

        let snapshot = queue.snapshot();
        assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::SafeFallback);
        assert!(snapshot.fallback_transitions >= 1);
    }

    #[test]
    fn ebr_stress_cycle_keeps_retired_backlog_bounded() {
        let mut queue = HostcallRequestQueue::with_mode(4, 8, HostcallQueueMode::Ebr);

        for value in 0..10_000_u32 {
            let _ = queue.push_back(value);
            let drained = queue.drain_all();
            assert_eq!(drained.len(), 1);
            if value % 64 == 0 {
                queue.force_reclaim();
            }
        }

        queue.force_reclaim();
        let snapshot = queue.snapshot();
        assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::Ebr);
        assert_eq!(snapshot.retired_backlog, 0);
        assert!(snapshot.reclaimed_total >= 10_000);
    }

    #[test]
    fn loom_epoch_pin_blocks_reclamation_until_release() {
        use loom::sync::atomic::{AtomicBool, Ordering as LoomOrdering};
        use loom::sync::{Arc, Mutex};
        use loom::thread;

        loom::model(|| {
            let queue = Arc::new(Mutex::new(HostcallRequestQueue::with_mode(
                1,
                2,
                HostcallQueueMode::Ebr,
            )));
            let pin_ready = Arc::new(AtomicBool::new(false));
            let release_pin = Arc::new(AtomicBool::new(false));

            let queue_for_pin = Arc::clone(&queue);
            let pin_ready_for_thread = Arc::clone(&pin_ready);
            let release_pin_for_thread = Arc::clone(&release_pin);
            let pin_thread = thread::spawn(move || {
                let pin = queue_for_pin.lock().expect("lock queue").pin_epoch();
                pin_ready_for_thread.store(true, LoomOrdering::SeqCst);
                while !release_pin_for_thread.load(LoomOrdering::SeqCst) {
                    thread::yield_now();
                }
                drop(pin);
            });

            let queue_for_worker = Arc::clone(&queue);
            let pin_ready_for_worker = Arc::clone(&pin_ready);
            let worker = thread::spawn(move || {
                while !pin_ready_for_worker.load(LoomOrdering::SeqCst) {
                    thread::yield_now();
                }

                let mut queue = queue_for_worker.lock().expect("lock queue");
                let _ = queue.push_back(1_u8);
                let _ = queue.push_back(2_u8);
                let drained = queue.drain_all();
                assert_eq!(drained.len(), 2);
                queue.force_reclaim();
                let snapshot = queue.snapshot();
                assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::Ebr);
                assert!(snapshot.retired_backlog >= 2);
                assert_eq!(snapshot.reclaimed_total, 0);
                drop(queue);
            });

            worker.join().expect("worker join");
            release_pin.store(true, LoomOrdering::SeqCst);
            pin_thread.join().expect("pin thread join");

            let mut queue = queue.lock().expect("lock queue");
            queue.force_reclaim();
            let snapshot = queue.snapshot();
            assert_eq!(snapshot.retired_backlog, 0);
            assert!(snapshot.reclaimed_total >= 2);
            drop(queue);
        });
    }

    #[test]
    fn loom_concurrent_enqueue_dequeue_keeps_values_unique() {
        use loom::sync::{Arc, Mutex};
        use loom::thread;

        loom::model(|| {
            let queue = Arc::new(Mutex::new(HostcallRequestQueue::with_mode(
                2,
                2,
                HostcallQueueMode::SafeFallback,
            )));

            let queue_a = Arc::clone(&queue);
            let producer_a = thread::spawn(move || {
                let mut queue = queue_a.lock().expect("lock queue");
                let _ = queue.push_back(10_u8);
            });

            let queue_b = Arc::clone(&queue);
            let producer_b = thread::spawn(move || {
                let mut queue = queue_b.lock().expect("lock queue");
                let _ = queue.push_back(11_u8);
            });

            producer_a.join().expect("producer_a join");
            producer_b.join().expect("producer_b join");

            let mut queue = queue.lock().expect("lock queue");
            let drained = queue.drain_all();
            drop(queue);
            let mut values = drained.into_iter().collect::<Vec<_>>();
            values.sort_unstable();
            assert_eq!(values, vec![10, 11]);
        });
    }
}
