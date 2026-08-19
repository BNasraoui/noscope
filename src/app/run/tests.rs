use chrono::{Duration as ChronoDuration, Utc};
use provenance_macros::verifies;
use std::time::Duration;

#[test]
#[verifies("rule_restart_before_expiry", examples)]
fn restart_is_due_when_expiry_is_nearer_than_the_margin() {
    let now = Utc::now();
    let expiry = now + ChronoDuration::seconds(30);

    assert!(
        super::restart_due(now, expiry, Duration::from_secs(60)),
        "expiry 30s away with a 60s margin is due"
    );
    assert!(
        !super::restart_due(now, expiry, Duration::from_secs(10)),
        "expiry 30s away with a 10s margin is not due"
    );
}

#[test]
fn restart_due_at_exactly_the_margin() {
    let now = Utc::now();
    let expiry = now + ChronoDuration::seconds(60);
    assert!(super::restart_due(now, expiry, Duration::from_secs(60)));
}
