//! A sample `robot.agent.health` record (contract 2.5).

use robodr_ocsf::*;

pub fn sample() -> AgentHealth {
    AgentHealth {
        state: HealthLabel::Degraded,
        reasons: vec!["profile not enforced (observe-only)".into()],
        interval_ms: 60_000,
        uptime_ms: 3_600_000,
        seq: 60,
        versions: vec![
            ComponentVersion {
                component: "robodr-agentd".into(),
                version: "0.1.0-alpha.1".into(),
            },
            ComponentVersion {
                component: "robodr.findings".into(),
                version: CONTRACT_VERSION.into(),
            },
        ],
        inputs: vec![InputFreshness {
            name: "capture:eth0".into(),
            last_rx_age_ms: Some(120),
            received: 81_234,
            dropped: 0,
            malformed: 2,
            ended: false,
        }],
        counters: HealthCounters {
            findings_spooled: 17,
            ..HealthCounters::default()
        },
        blackbox: BlackBoxHealth {
            degraded: false,
            anchored: true,
            anchor_failures: 0,
        },
        reachability: vec![
            Reachability {
                component: "executor".into(),
                state: ReachState::Reachable,
                last_ok_age_ms: Some(500),
            },
            Reachability {
                component: "gateway".into(),
                state: ReachState::NotConfigured,
                last_ok_age_ms: None,
            },
        ],
        credentials: vec![CredentialExpiry {
            name: "control_plane.server_cert".into(),
            expires_ms: 1_800_000_000_000,
            days_to_expiry: 115,
        }],
        clock: ClockHealth {
            synchronized: Some(true),
            max_error_ms: Some(12),
            source: Some(robodr_ocsf::ClockSource::Adjtimex),
            adjtimex_errno: None,
            timesync_age_ms: None,
            wall_jumps: 0,
        },
        disks: vec![DiskHealth {
            name: "blackbox".into(),
            free_bytes: 10_000_000_000,
            total_bytes: 32_000_000_000,
        }],
    }
}
