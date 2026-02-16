use pi::hostcall_queue::{HostcallQueueEnqueueResult, HostcallQueueMode, HostcallRequestQueue};

#[test]
fn ebr_mode_reports_retired_backlog_until_epoch_pins_release() {
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
    assert!(matches!(
        queue.push_back(3_u8),
        HostcallQueueEnqueueResult::OverflowPath { .. }
    ));

    let drained = queue.drain_all();
    assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);

    queue.force_reclaim();
    let pinned = queue.snapshot();
    assert_eq!(pinned.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(pinned.active_epoch_pins, 1);
    assert!(pinned.retired_backlog >= 3);
    assert_eq!(pinned.reclaimed_total, 0);

    drop(pin);
    queue.force_reclaim();
    let reclaimed = queue.snapshot();
    assert_eq!(reclaimed.active_epoch_pins, 0);
    assert_eq!(reclaimed.retired_backlog, 0);
    assert!(reclaimed.reclaimed_total >= 3);
    assert!(reclaimed.reclamation_latency_max_epochs >= 1);
}

#[test]
fn safe_fallback_mode_remains_operational_and_fifo() {
    let mut queue = HostcallRequestQueue::with_mode(2, 2, HostcallQueueMode::Ebr);
    assert!(matches!(
        queue.push_back(10_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));
    assert!(matches!(
        queue.push_back(11_u8),
        HostcallQueueEnqueueResult::FastPath { .. }
    ));

    queue.force_safe_fallback();
    let snapshot = queue.snapshot();
    assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::SafeFallback);
    assert_eq!(snapshot.fallback_transitions, 1);

    let drained = queue.drain_all();
    assert_eq!(drained.into_iter().collect::<Vec<_>>(), vec![10, 11]);
}

#[test]
fn ebr_stress_run_reclaims_without_backlog_growth() {
    let mut queue = HostcallRequestQueue::with_mode(8, 32, HostcallQueueMode::Ebr);

    for value in 0..20_000_u32 {
        let _ = queue.push_back(value);
        let drained = queue.drain_all();
        assert_eq!(drained.len(), 1);
        if value % 128 == 0 {
            queue.force_reclaim();
        }
    }

    queue.force_reclaim();
    let snapshot = queue.snapshot();
    assert_eq!(snapshot.reclamation_mode, HostcallQueueMode::Ebr);
    assert_eq!(snapshot.retired_backlog, 0);
    assert!(snapshot.reclaimed_total >= 20_000);
}
