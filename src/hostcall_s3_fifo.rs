//! Deterministic S3-FIFO-inspired admission policy for hostcall queues.
//!
//! This module models a tri-queue policy core that can be wired into the
//! hostcall queue runtime:
//! - `small`: probationary live entries
//! - `main`: protected live entries
//! - `ghost`: recently evicted identifiers for cheap reuse signals
//!
//! It is intentionally runtime-agnostic and side-effect free beyond state
//! mutations, so integration code can compose it with existing queue and
//! telemetry paths.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Fallback trigger reason when S3-FIFO policy is disabled at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoFallbackReason {
    SignalQualityInsufficient,
    FairnessInstability,
}

/// Where a key ends up after one policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoTier {
    Small,
    Main,
    Ghost,
    Fallback,
}

/// Deterministic decision kind from one `access` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3FifoDecisionKind {
    AdmitSmall,
    PromoteSmallToMain,
    HitMain,
    AdmitFromGhost,
    RejectFairnessBudget,
    FallbackBypass,
}

/// Decision payload produced by [`S3FifoPolicy::access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoDecision {
    pub kind: S3FifoDecisionKind,
    pub tier: S3FifoTier,
    pub ghost_hit: bool,
    pub fallback_reason: Option<S3FifoFallbackReason>,
    pub live_depth: usize,
    pub small_depth: usize,
    pub main_depth: usize,
    pub ghost_depth: usize,
}

/// Configuration for deterministic S3-FIFO policy behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S3FifoConfig {
    pub live_capacity: usize,
    pub small_capacity: usize,
    pub ghost_capacity: usize,
    pub max_entries_per_owner: usize,
    pub fallback_window: usize,
    pub min_ghost_hits_in_window: usize,
    pub max_budget_rejections_in_window: usize,
}

impl Default for S3FifoConfig {
    fn default() -> Self {
        Self {
            live_capacity: 256,
            small_capacity: 64,
            ghost_capacity: 512,
            max_entries_per_owner: 64,
            fallback_window: 32,
            min_ghost_hits_in_window: 2,
            max_budget_rejections_in_window: 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveTier {
    Small,
    Main,
}

#[derive(Debug, Clone, Copy)]
struct DecisionSignal {
    ghost_hit: bool,
    budget_rejected: bool,
}

/// Snapshot for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3FifoTelemetry {
    pub fallback_reason: Option<S3FifoFallbackReason>,
    pub small_depth: usize,
    pub main_depth: usize,
    pub ghost_depth: usize,
    pub live_depth: usize,
    pub ghost_hits_total: u64,
    pub admissions_total: u64,
    pub promotions_total: u64,
    pub budget_rejections_total: u64,
    pub owner_live_counts: BTreeMap<String, usize>,
}

/// Deterministic S3-FIFO-inspired tri-queue admission controller.
#[derive(Debug, Clone)]
pub struct S3FifoPolicy<K: Ord + Clone> {
    cfg: S3FifoConfig,
    small: VecDeque<K>,
    main: VecDeque<K>,
    ghost: VecDeque<K>,
    ghost_set: BTreeSet<K>,
    live_tiers: BTreeMap<K, LiveTier>,
    live_owners: BTreeMap<K, String>,
    owner_live_counts: BTreeMap<String, usize>,
    recent_signals: VecDeque<DecisionSignal>,
    fallback_reason: Option<S3FifoFallbackReason>,
    ghost_hits_total: u64,
    admissions_total: u64,
    promotions_total: u64,
    budget_rejections_total: u64,
}

impl<K: Ord + Clone> S3FifoPolicy<K> {
    #[must_use]
    pub fn new(config: S3FifoConfig) -> Self {
        let live_capacity = config.live_capacity.max(2);
        let small_cap_floor = live_capacity.saturating_sub(1).max(1);
        let small_capacity = config.small_capacity.max(1).min(small_cap_floor);
        let ghost_capacity = config.ghost_capacity.max(1);
        let max_entries_per_owner = config.max_entries_per_owner.max(1);
        let fallback_window = config.fallback_window.max(1);

        Self {
            cfg: S3FifoConfig {
                live_capacity,
                small_capacity,
                ghost_capacity,
                max_entries_per_owner,
                fallback_window,
                min_ghost_hits_in_window: config.min_ghost_hits_in_window.min(fallback_window),
                max_budget_rejections_in_window: config
                    .max_budget_rejections_in_window
                    .min(fallback_window),
            },
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost: VecDeque::new(),
            ghost_set: BTreeSet::new(),
            live_tiers: BTreeMap::new(),
            live_owners: BTreeMap::new(),
            owner_live_counts: BTreeMap::new(),
            recent_signals: VecDeque::new(),
            fallback_reason: None,
            ghost_hits_total: 0,
            admissions_total: 0,
            promotions_total: 0,
            budget_rejections_total: 0,
        }
    }

    #[must_use]
    pub const fn config(&self) -> S3FifoConfig {
        self.cfg
    }

    #[must_use]
    pub fn telemetry(&self) -> S3FifoTelemetry {
        S3FifoTelemetry {
            fallback_reason: self.fallback_reason,
            small_depth: self.small.len(),
            main_depth: self.main.len(),
            ghost_depth: self.ghost.len(),
            live_depth: self.live_depth(),
            ghost_hits_total: self.ghost_hits_total,
            admissions_total: self.admissions_total,
            promotions_total: self.promotions_total,
            budget_rejections_total: self.budget_rejections_total,
            owner_live_counts: self.owner_live_counts.clone(),
        }
    }

    #[must_use]
    pub fn live_depth(&self) -> usize {
        self.small.len().saturating_add(self.main.len())
    }

    pub fn clear_fallback(&mut self) {
        self.fallback_reason = None;
        self.recent_signals.clear();
    }

    pub fn access(&mut self, owner: &str, key: K) -> S3FifoDecision {
        if let Some(reason) = self.fallback_reason {
            return self.decision(
                S3FifoDecisionKind::FallbackBypass,
                S3FifoTier::Fallback,
                false,
                Some(reason),
            );
        }

        let mut ghost_hit = false;
        let kind = if matches!(self.live_tiers.get(&key), Some(LiveTier::Main)) {
            self.touch_main(&key);
            S3FifoDecisionKind::HitMain
        } else if matches!(self.live_tiers.get(&key), Some(LiveTier::Small)) {
            self.promote_small_to_main(&key);
            self.promotions_total = self.promotions_total.saturating_add(1);
            S3FifoDecisionKind::PromoteSmallToMain
        } else if self.ghost_set.contains(&key) {
            ghost_hit = true;
            self.ghost_hits_total = self.ghost_hits_total.saturating_add(1);
            if self.owner_at_budget(owner) {
                self.budget_rejections_total = self.budget_rejections_total.saturating_add(1);
                S3FifoDecisionKind::RejectFairnessBudget
            } else {
                self.admit_from_ghost(owner, key);
                self.admissions_total = self.admissions_total.saturating_add(1);
                S3FifoDecisionKind::AdmitFromGhost
            }
        } else if self.owner_at_budget(owner) {
            self.budget_rejections_total = self.budget_rejections_total.saturating_add(1);
            S3FifoDecisionKind::RejectFairnessBudget
        } else {
            self.admit_small(owner, key);
            self.admissions_total = self.admissions_total.saturating_add(1);
            S3FifoDecisionKind::AdmitSmall
        };

        let signal = DecisionSignal {
            ghost_hit,
            budget_rejected: kind == S3FifoDecisionKind::RejectFairnessBudget,
        };
        self.record_signal(signal);
        self.evaluate_fallback();

        let tier = Self::resolve_tier(kind, ghost_hit);
        self.decision(kind, tier, ghost_hit, self.fallback_reason)
    }

    const fn resolve_tier(kind: S3FifoDecisionKind, ghost_hit: bool) -> S3FifoTier {
        match kind {
            S3FifoDecisionKind::HitMain
            | S3FifoDecisionKind::PromoteSmallToMain
            | S3FifoDecisionKind::AdmitFromGhost => S3FifoTier::Main,
            S3FifoDecisionKind::AdmitSmall => S3FifoTier::Small,
            S3FifoDecisionKind::RejectFairnessBudget => {
                if ghost_hit {
                    S3FifoTier::Ghost
                } else {
                    S3FifoTier::Small
                }
            }
            S3FifoDecisionKind::FallbackBypass => S3FifoTier::Fallback,
        }
    }

    fn decision(
        &self,
        kind: S3FifoDecisionKind,
        tier: S3FifoTier,
        ghost_hit: bool,
        fallback_reason: Option<S3FifoFallbackReason>,
    ) -> S3FifoDecision {
        S3FifoDecision {
            kind,
            tier,
            ghost_hit,
            fallback_reason,
            live_depth: self.live_depth(),
            small_depth: self.small.len(),
            main_depth: self.main.len(),
            ghost_depth: self.ghost.len(),
        }
    }

    fn owner_at_budget(&self, owner: &str) -> bool {
        self.owner_live_counts.get(owner).copied().unwrap_or(0) >= self.cfg.max_entries_per_owner
    }

    const fn main_capacity(&self) -> usize {
        self.cfg
            .live_capacity
            .saturating_sub(self.cfg.small_capacity)
    }

    fn admit_small(&mut self, owner: &str, key: K) {
        self.purge_key(&key);
        self.small.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Small);
        self.live_owners.insert(key, owner.to_string());
        self.increment_owner(owner);
        self.enforce_small_capacity();
        self.enforce_live_capacity();
    }

    fn admit_from_ghost(&mut self, owner: &str, key: K) {
        self.remove_ghost(&key);
        self.main.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Main);
        self.live_owners.insert(key, owner.to_string());
        self.increment_owner(owner);
        self.enforce_main_capacity();
        self.enforce_live_capacity();
    }

    fn promote_small_to_main(&mut self, key: &K) {
        remove_from_queue(&mut self.small, key);
        self.main.push_back(key.clone());
        self.live_tiers.insert(key.clone(), LiveTier::Main);
        self.enforce_main_capacity();
        self.enforce_live_capacity();
    }

    fn touch_main(&mut self, key: &K) {
        remove_from_queue(&mut self.main, key);
        self.main.push_back(key.clone());
    }

    fn enforce_small_capacity(&mut self) {
        while self.small.len() > self.cfg.small_capacity {
            self.evict_small_front_to_ghost();
        }
    }

    fn enforce_main_capacity(&mut self) {
        while self.main.len() > self.main_capacity() {
            self.evict_main_front_to_ghost();
        }
    }

    fn enforce_live_capacity(&mut self) {
        while self.live_depth() > self.cfg.live_capacity {
            if self.main.is_empty() {
                self.evict_small_front_to_ghost();
            } else {
                self.evict_main_front_to_ghost();
            }
        }
    }

    fn evict_small_front_to_ghost(&mut self) {
        if let Some(key) = self.small.pop_front() {
            self.live_tiers.remove(&key);
            self.remove_owner_for_key(&key);
            self.push_ghost(key);
        }
    }

    fn evict_main_front_to_ghost(&mut self) {
        if let Some(key) = self.main.pop_front() {
            self.live_tiers.remove(&key);
            self.remove_owner_for_key(&key);
            self.push_ghost(key);
        }
    }

    fn purge_key(&mut self, key: &K) {
        self.remove_live_key(key);
        self.remove_ghost(key);
    }

    fn remove_live_key(&mut self, key: &K) {
        if let Some(tier) = self.live_tiers.remove(key) {
            match tier {
                LiveTier::Small => remove_from_queue(&mut self.small, key),
                LiveTier::Main => remove_from_queue(&mut self.main, key),
            }
            self.remove_owner_for_key(key);
        }
    }

    fn remove_owner_for_key(&mut self, key: &K) {
        if let Some(owner) = self.live_owners.remove(key) {
            self.decrement_owner(&owner);
        }
    }

    fn push_ghost(&mut self, key: K) {
        if self.ghost_set.remove(&key) {
            remove_from_queue(&mut self.ghost, &key);
        }
        self.ghost.push_back(key.clone());
        self.ghost_set.insert(key);

        while self.ghost.len() > self.cfg.ghost_capacity {
            if let Some(evicted) = self.ghost.pop_front() {
                self.ghost_set.remove(&evicted);
            }
        }
    }

    fn remove_ghost(&mut self, key: &K) {
        if self.ghost_set.remove(key) {
            remove_from_queue(&mut self.ghost, key);
        }
    }

    fn increment_owner(&mut self, owner: &str) {
        let entry = self.owner_live_counts.entry(owner.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    fn decrement_owner(&mut self, owner: &str) {
        let Some(count) = self.owner_live_counts.get_mut(owner) else {
            return;
        };
        if *count > 1 {
            *count -= 1;
        } else {
            self.owner_live_counts.remove(owner);
        }
    }

    fn record_signal(&mut self, signal: DecisionSignal) {
        self.recent_signals.push_back(signal);
        while self.recent_signals.len() > self.cfg.fallback_window {
            self.recent_signals.pop_front();
        }
    }

    fn evaluate_fallback(&mut self) {
        if self.fallback_reason.is_some() || self.recent_signals.len() < self.cfg.fallback_window {
            return;
        }

        let mut ghost_hits = 0usize;
        let mut budget_rejections = 0usize;
        for signal in &self.recent_signals {
            if signal.ghost_hit {
                ghost_hits = ghost_hits.saturating_add(1);
            }
            if signal.budget_rejected {
                budget_rejections = budget_rejections.saturating_add(1);
            }
        }

        if ghost_hits < self.cfg.min_ghost_hits_in_window {
            self.fallback_reason = Some(S3FifoFallbackReason::SignalQualityInsufficient);
        } else if budget_rejections > self.cfg.max_budget_rejections_in_window {
            self.fallback_reason = Some(S3FifoFallbackReason::FairnessInstability);
        }
    }
}

fn remove_from_queue<K: Ord>(queue: &mut VecDeque<K>, key: &K) {
    if let Some(index) = queue.iter().position(|existing| existing == key) {
        queue.remove(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> S3FifoConfig {
        S3FifoConfig {
            live_capacity: 4,
            small_capacity: 2,
            ghost_capacity: 4,
            max_entries_per_owner: 2,
            fallback_window: 4,
            min_ghost_hits_in_window: 1,
            max_budget_rejections_in_window: 2,
        }
    }

    fn assert_no_duplicates(policy: &S3FifoPolicy<String>) {
        let small: BTreeSet<_> = policy.small.iter().cloned().collect();
        let main: BTreeSet<_> = policy.main.iter().cloned().collect();
        let ghost: BTreeSet<_> = policy.ghost.iter().cloned().collect();

        assert!(small.is_disjoint(&main));
        assert!(small.is_disjoint(&ghost));
        assert!(main.is_disjoint(&ghost));
        assert_eq!(small.len() + main.len(), policy.live_tiers.len());
    }

    #[test]
    fn small_hit_promotes_to_main() {
        let mut policy = S3FifoPolicy::new(config());
        let first = policy.access("ext-a", "k1".to_string());
        assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);

        let second = policy.access("ext-a", "k1".to_string());
        assert_eq!(second.kind, S3FifoDecisionKind::PromoteSmallToMain);
        assert_eq!(second.tier, S3FifoTier::Main);
        assert_eq!(second.main_depth, 1);
        assert_eq!(second.small_depth, 0);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn ghost_hit_reenters_live_set() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            small_capacity: 1,
            ..config()
        });

        policy.access("ext-a", "k1".to_string());
        policy.access("ext-a", "k2".to_string());
        let decision = policy.access("ext-a", "k1".to_string());

        assert_eq!(decision.kind, S3FifoDecisionKind::AdmitFromGhost);
        assert!(decision.ghost_hit);
        assert_eq!(decision.tier, S3FifoTier::Main);
        assert_eq!(policy.telemetry().ghost_hits_total, 1);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn fairness_budget_rejects_owner_overflow() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            ..config()
        });

        let admitted = policy.access("ext-a", "k1".to_string());
        let rejected = policy.access("ext-a", "k2".to_string());

        assert_eq!(admitted.kind, S3FifoDecisionKind::AdmitSmall);
        assert_eq!(rejected.kind, S3FifoDecisionKind::RejectFairnessBudget);
        assert_eq!(policy.live_depth(), 1);
        assert_eq!(policy.telemetry().budget_rejections_total, 1);
        assert_no_duplicates(&policy);
    }

    #[test]
    fn fallback_triggers_on_low_signal_quality() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            min_ghost_hits_in_window: 2,
            fallback_window: 4,
            ..config()
        });

        for idx in 0..4 {
            let key = format!("cold-{idx}");
            let _ = policy.access("ext-a", key);
        }

        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::SignalQualityInsufficient)
        );

        let bypass = policy.access("ext-a", "late-key".to_string());
        assert_eq!(bypass.kind, S3FifoDecisionKind::FallbackBypass);
        assert_eq!(bypass.tier, S3FifoTier::Fallback);
    }

    #[test]
    fn fallback_triggers_on_rejection_spike() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            max_entries_per_owner: 1,
            fallback_window: 3,
            min_ghost_hits_in_window: 0,
            max_budget_rejections_in_window: 1,
            ..config()
        });

        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());

        assert_eq!(
            policy.telemetry().fallback_reason,
            Some(S3FifoFallbackReason::FairnessInstability)
        );
    }

    #[test]
    fn clear_fallback_resets_policy_gate() {
        let mut policy = S3FifoPolicy::new(S3FifoConfig {
            min_ghost_hits_in_window: 3,
            fallback_window: 3,
            ..config()
        });

        let _ = policy.access("ext-a", "k1".to_string());
        let _ = policy.access("ext-a", "k2".to_string());
        let _ = policy.access("ext-a", "k3".to_string());
        assert!(policy.telemetry().fallback_reason.is_some());

        policy.clear_fallback();
        assert!(policy.telemetry().fallback_reason.is_none());

        let decision = policy.access("ext-a", "k4".to_string());
        assert_ne!(decision.kind, S3FifoDecisionKind::FallbackBypass);
    }
}
