#[path = "../src/hostcall_s3_fifo.rs"]
mod hostcall_s3_fifo;

use hostcall_s3_fifo::{S3FifoConfig, S3FifoDecisionKind, S3FifoPolicy};

#[test]
fn smoke_policy_admits_then_promotes() {
    let mut policy = S3FifoPolicy::new(S3FifoConfig::default());
    let _cfg = policy.config();
    let first = policy.access("ext-smoke", "key-smoke".to_string());
    let second = policy.access("ext-smoke", "key-smoke".to_string());

    assert_eq!(first.kind, S3FifoDecisionKind::AdmitSmall);
    assert_eq!(second.kind, S3FifoDecisionKind::PromoteSmallToMain);
}
