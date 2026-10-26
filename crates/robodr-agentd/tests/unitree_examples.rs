//! The shipped Unitree example configurations: one profile per Unitree model
//! the decoders support (`config/profile.unitree-<model>.example.json`), the
//! passive sensor-box daemon (`config/agentd.unitree-sensor-box.example.json`,
//! Go1 legacy UDP) and the EDU dev-computer daemon
//! (`config/agentd.unitree-edu.example.json`, G1 with the joint firewall).
//! Every one is loaded and validated the way a commissioned robot would
//! (`robodr_agentd::load`, i.e. `--check-config`), and the model-awareness
//! checks of `robot.robot_model` refuse inconsistent combinations.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use robodr_cdr::unitree::{Generation, IdlFamily, Morphology};
use robodr_cdr::UnitreeModel;
use robodr_events::profile::Profile;

const P: &str = "0123456789abcdef01234567";

fn config_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

fn example(name: &str) -> String {
    std::fs::read_to_string(config_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The file name stem of a model's profile example (`None` for the models
/// whose frame layout the decoders do not have: A1, Aliengo, B1).
fn slug(m: UnitreeModel) -> Option<&'static str> {
    Some(match m {
        UnitreeModel::Go2 => "go2",
        UnitreeModel::Go2W => "go2w",
        UnitreeModel::B2 => "b2",
        UnitreeModel::B2W => "b2w",
        UnitreeModel::A2 => "a2",
        UnitreeModel::As2 => "as2",
        UnitreeModel::H1 => "h1",
        UnitreeModel::H1_2 => "h1-2",
        UnitreeModel::H2 => "h2",
        UnitreeModel::G1 => "g1",
        UnitreeModel::R1 => "r1",
        UnitreeModel::Go1 => "go1",
        UnitreeModel::A1 | UnitreeModel::Aliengo | UnitreeModel::B1 => return None,
    })
}

fn profile_example(m: UnitreeModel) -> Profile {
    let name = format!("profile.unitree-{}.example.json", slug(m).unwrap());
    robodr_agent::strict_from_str::<Profile>(&example(&name))
        .unwrap_or_else(|e| panic!("{name}: not a strict profile: {e}"))
}

#[test]
fn every_supported_model_has_a_valid_profile_example() {
    let mut seen = 0;
    for m in UnitreeModel::ALL {
        let info = m.info();
        let Some(s) = slug(m) else {
            // No decodable frame layout: no example on purpose.
            assert!(info.idl.is_none(), "{m:?}");
            assert!(!config_dir()
                .join(format!(
                    "profile.unitree-{}.example.json",
                    info.name.to_lowercase()
                ))
                .exists());
            continue;
        };
        seen += 1;
        let p = profile_example(m);
        p.validate()
            .unwrap_or_else(|e| panic!("{s}: profile does not validate: {e:?}"));
        assert!(!p.locked, "{s}: an example is a draft");
        assert!(
            p.model.contains("EXAMPLE-replace-with-OEM-data"),
            "{s}: illustrative values must be marked: {}",
            p.model
        );
        assert_eq!(p.participants.iter().collect::<Vec<_>>(), vec![P], "{s}");
        // Low-level joint channels bound torque, gain and step (otherwise a
        // command using them is only reported unverifiable).
        let lowcmd = match info.generation {
            Generation::Sdk2Dds => "/lowcmd",
            Generation::LegacyUdp => robodr_cdr::unitree_legacy::channels::LOW_CMD,
        };
        let has_low = info.idl.is_some();
        assert_eq!(p.motion_envelopes.contains_key(lowcmd), has_low, "{s}");
        for (ch, env) in &p.motion_envelopes {
            if env.max_joint_speed.is_some() {
                assert!(
                    env.max_joint_torque.is_some()
                        && env.max_joint_kp.is_some()
                        && env.max_joint_position_step.is_some(),
                    "{s} {ch}: joint channel without torque / kp / step bound"
                );
            }
        }
        // Every motion API service of the model has a request envelope.
        for svc in info.api_services {
            let ch = format!("/api/{svc}/request");
            assert!(p.motion_envelopes.contains_key(&ch), "{s}: {ch}");
        }
        // The model's topics are writable.
        for t in info
            .lowcmd_topic
            .iter()
            .chain(info.lowstate_topic.iter())
            .chain(info.sport_state_topics)
            .chain(info.other_topics)
        {
            let name = robodr_events::graph::demangle(t).name;
            assert!(p.writer_topics.contains(&name), "{s}: {name}");
        }
        if info.generation == Generation::LegacyUdp {
            for ch in [
                robodr_cdr::unitree_legacy::channels::HIGH_CMD,
                robodr_cdr::unitree_legacy::channels::LOW_CMD,
            ] {
                assert!(p.motion_envelopes.contains_key(ch), "{s}: {ch}");
            }
        }
    }
    assert_eq!(
        seen, 12,
        "Go2, Go2-W, B2, B2-W, A2, AS2, H1, H1-2, H2, G1, R1, Go1"
    );
}

/// The firewall examples' joint envelope fits the profile examples of the
/// same model (the profile's `max_joint_speed` tightens `dq_max`; its
/// torque / kp / step bound the same frames).
#[test]
fn firewall_examples_match_their_profiles() {
    for (m, fw) in [
        (UnitreeModel::G1, "firewall.unitree-g1.example.json"),
        (UnitreeModel::Go2, "firewall.unitree-go2.example.json"),
    ] {
        let p = profile_example(m);
        let fc = robodr_firewall::FirewallConfig::from_json(&example(fw)).unwrap();
        let spec = &fc.joint_channels["/lowcmd"];
        assert_eq!(Some(spec.motors.len()), m.info().motor_slots, "{fw}");
        let env = &p.motion_envelopes["/lowcmd"];
        let on = spec.motors.iter().filter(|x| x.enabled);
        for x in on {
            assert!(
                x.dq_max.unwrap() <= env.max_joint_speed.unwrap(),
                "{fw} {x:?}"
            );
            assert!(
                x.tau_max.unwrap() <= env.max_joint_torque.unwrap(),
                "{fw} {x:?}"
            );
            assert!(x.kp_max.unwrap() <= env.max_joint_kp.unwrap(), "{fw} {x:?}");
            assert!(
                x.max_dq_step.unwrap() <= env.max_joint_position_step.unwrap(),
                "{fw} {x:?}"
            );
        }
        // The file's joint channel compiles against the profile (as the
        // daemon does: twist channels come from the profile and the agent
        // settings, so only the joint channels' envelopes are given here).
        let mut jp = p.clone();
        jp.motion_envelopes.retain(|k, _| k == "/lowcmd");
        fc.compile(&jp).unwrap_or_else(|e| panic!("{fw}: {e}"));
    }
}

/// A temp install root for one daemon example.
struct Root {
    dir: PathBuf,
}

impl Root {
    fn new(tag: &str, model: UnitreeModel, platform: &str, unit: &str, policy: &str) -> Self {
        let dir = tmpdir(tag);
        for d in ["run", "var", "etc", "credentials"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let mut p = profile_example(model);
        p.locked = true;
        let mut md = metadata(1);
        md.platform = platform.into();
        md.unit_id = Some(unit.into());
        p.metadata = Some(md);
        write_profile(&dir.join("etc/profile.json"), &p);
        std::fs::write(
            dir.join("etc/profile-trust.json"),
            robodr_commission::trust::trust_keys_text(&[profile_key().verifying_key()]),
        )
        .unwrap();
        std::fs::write(dir.join("etc/response-policy.json"), example(policy)).unwrap();
        let key = dir.join("credentials/blackbox.key");
        std::fs::write(&key, robodr_blackbox::crypto::to_hex(&KEY)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        Root { dir }
    }

    fn relocate(&self, text: &str) -> String {
        let root = self.dir.to_str().unwrap();
        text.replace(
            "/run/credentials/robodr-agentd.service/",
            &format!("{root}/credentials/"),
        )
        .replace("/etc/robodr/", &format!("{root}/etc/"))
        .replace("/var/lib/robodr/", &format!("{root}/var/"))
        .replace("/run/robodr-agentd/", &format!("{root}/run/"))
    }

    fn load(&self, cfg: &serde_json::Value) -> Result<robodr_agentd::Resolved, String> {
        let path = self.dir.join("agentd.json");
        std::fs::write(&path, serde_json::to_vec_pretty(cfg).unwrap()).unwrap();
        robodr_agentd::load(&path)
    }

    fn example(&self, name: &str) -> serde_json::Value {
        serde_json::from_str(&self.relocate(&example(name))).unwrap()
    }
}

#[test]
fn edu_example_loads_with_the_g1_joint_firewall() {
    let r = Root::new(
        "unitree-edu",
        UnitreeModel::G1,
        "unitree-g1",
        "unitree-g1-001",
        "response-policy.unitree-g1.example.json",
    );
    std::fs::write(
        r.dir.join("etc/firewall.json"),
        example("firewall.unitree-g1.example.json"),
    )
    .unwrap();
    let cfg = r.example("agentd.unitree-edu.example.json");
    let res = r.load(&cfg).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(res.robot_model, Some(UnitreeModel::G1));
    assert_eq!(
        res.sensor.pipeline.motion.robot_model,
        Some(UnitreeModel::G1)
    );
    let fc = res.firewall_joint.as_ref().expect("joint firewall");
    assert!(fc.joint_channels.contains_key("/lowcmd"));
    assert!(!res.sensor.pipeline.legacy.enabled);
    assert!(res.control_plane.is_none());

    // Model awareness: a humanoid with a non-humanoid policy is refused.
    let mut pol: serde_json::Value =
        serde_json::from_str(&example("response-policy.unitree-g1.example.json")).unwrap();
    pol["morphology"] = "quadruped".into();
    std::fs::write(
        r.dir.join("etc/response-policy.json"),
        serde_json::to_vec(&pol).unwrap(),
    )
    .unwrap();
    let e = r.load(&cfg).expect_err("humanoid with a quadruped policy");
    assert!(e.contains("morphology"), "{e}");
    // ... also without a joint firewall (the policy alone).
    let mut no_fw = cfg.clone();
    no_fw.as_object_mut().unwrap().remove("firewall");
    let e = r
        .load(&no_fw)
        .expect_err("humanoid with a quadruped policy");
    assert!(e.contains("humanoid"), "{e}");
    std::fs::write(
        r.dir.join("etc/response-policy.json"),
        example("response-policy.unitree-g1.example.json"),
    )
    .unwrap();

    // A humanoid joint firewall with a damping substitute is refused even
    // though the daemon only records (the file must be gateway-safe).
    let mut fw: serde_json::Value =
        serde_json::from_str(&example("firewall.unitree-g1.example.json")).unwrap();
    fw["platform"]["fail_behaviour"] = "zero_velocity".into();
    std::fs::write(r.dir.join("etc/firewall.json"), fw.to_string()).unwrap();
    let e = r.load(&cfg).expect_err("unsafe humanoid substitute");
    assert!(e.contains("zero_velocity") || e.contains("fall"), "{e}");
    // A firewall morphology that contradicts the policy is refused.
    let mut fw: serde_json::Value =
        serde_json::from_str(&example("firewall.unitree-g1.example.json")).unwrap();
    fw["platform"]["morphology"] = "quadruped".into();
    std::fs::write(r.dir.join("etc/firewall.json"), fw.to_string()).unwrap();
    let e = r.load(&cfg).expect_err("firewall morphology vs policy");
    assert!(e.contains("morphology"), "{e}");
    std::fs::write(
        r.dir.join("etc/firewall.json"),
        example("firewall.unitree-g1.example.json"),
    )
    .unwrap();

    // The wrong low-level layout for the model: H1 sends unitree_go
    // LowCmd_ (20 slots), the G1 firewall file has 35.
    let mut h1 = cfg.clone();
    h1["robot"]["robot_model"] = "H1".into();
    let e = r.load(&h1).expect_err("slot count vs model");
    assert!(e.contains("motor slots"), "{e}");
    // An unknown model name is refused, naming the known ones.
    h1["robot"]["robot_model"] = "G7".into();
    let e = r.load(&h1).expect_err("unknown model");
    assert!(
        e.contains("not a known Unitree model") && e.contains("H1-2"),
        "{e}"
    );
    // Names are matched loosely (case, '-' / '_').
    h1["robot"]["robot_model"] = "g1".into();
    assert!(r.load(&h1).is_ok());
    // A twist bound on a joint channel is a configuration error.
    let mut bad = cfg.clone();
    bad["firewall"]["max_angular"]["/lowcmd"] = 1.0.into();
    let e = r.load(&bad).expect_err("max_angular on a joint channel");
    assert!(e.contains("/lowcmd"), "{e}");
}

#[test]
fn sensor_box_example_loads_with_go1_legacy_udp() {
    let r = Root::new(
        "unitree-box",
        UnitreeModel::Go1,
        "unitree-go1",
        "unitree-go1-001",
        "response-policy.unitree-go2.example.json",
    );
    let cfg = r.example("agentd.unitree-sensor-box.example.json");
    let res = r.load(&cfg).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(res.robot_model, Some(UnitreeModel::Go1));
    let l = &res.sensor.pipeline.legacy;
    assert!(l.enabled);
    assert_eq!(l.ports.len(), 4);
    assert_eq!(l.command_senders.len(), 1);
    let cap = res.sensor.capture.as_ref().expect("passive capture");
    assert_eq!(cap.legacy_udp_ports, l.ports);
    assert!(cap.filter().legacy_udp_ports.contains(&8082));
    assert!(
        res.control_plane.is_none(),
        "a sensor box has no control plane"
    );
    assert!(res.config.event_inputs.is_empty());
    // Strict keys in the new section.
    let mut bad = cfg.clone();
    bad["sensor"]["unitree_legacy"]["command_sender"] = serde_json::json!([]);
    let e = r.load(&bad).expect_err("unknown key");
    assert!(e.contains("sensor.unitree_legacy"), "{e}");
    // Not an address.
    let mut bad = cfg.clone();
    bad["sensor"]["unitree_legacy"]["command_senders"] = serde_json::json!(["pc-1"]);
    assert!(r.load(&bad).is_err());
    // Legacy on a DDS model: only a warning.
    let mut dds = cfg.clone();
    dds["robot"]["robot_model"] = "Go2".into();
    let res = r.load(&dds).unwrap();
    assert!(
        res.warnings.iter().any(|w| w.contains("speaks DDS")),
        "{:?}",
        res.warnings
    );
}

/// Every supported model's profile example with a minimal daemon config
/// (`robot.robot_model` set, a policy of the model's morphology) loads; a
/// non-humanoid policy for a humanoid model never does.
#[test]
fn every_model_profile_loads_in_the_daemon_and_morphology_is_enforced() {
    for m in UnitreeModel::ALL {
        let Some(s) = slug(m) else { continue };
        let info = m.info();
        let humanoid = info.morphology == Morphology::Humanoid;
        let policy = if humanoid {
            "response-policy.unitree-g1.example.json"
        } else {
            "response-policy.unitree-go2.example.json"
        };
        let r = Root::new(
            &format!("unitree-{s}"),
            m,
            &format!("unitree-{s}"),
            "u-1",
            policy,
        );
        let legacy = info.generation == Generation::LegacyUdp;
        let mut sensor = serde_json::json!({
            "profile_path": r.dir.join("etc/profile.json"),
            "listen_spdp": false,
            "capture": {"enabled": true, "interfaces": ["eth0"]},
            "profile_trust": {
                "trusted_keys": r.dir.join("etc/profile-trust.json"),
                "expect_platform": format!("unitree-{s}"),
                "expect_unit_id": "u-1",
            },
        });
        if legacy {
            sensor["unitree_legacy"] =
                serde_json::json!({"enabled": true, "command_senders": ["192.168.123.15"]});
        }
        let cfg = serde_json::json!({
            "robot": {"id": "u-1", "site": "lab", "robot_model": info.name},
            "sensor": sensor,
            "policy_path": r.dir.join("etc/response-policy.json"),
            "blackbox": {"dir": r.dir.join("var/bb"), "key_file": r.dir.join("credentials/blackbox.key")},
            "spool": {"dir": r.dir.join("var/spool")},
        });
        let res = r.load(&cfg).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(res.robot_model, Some(m), "{s}");
        assert!(
            !res.warnings.iter().any(|w| w.contains("robot_model")),
            "{s}: {:?}",
            res.warnings
        );
        if info.idl == Some(IdlFamily::Hg) {
            assert!(humanoid, "{s}");
        }
        // The opposite morphology.
        let mut pol: serde_json::Value = serde_json::from_str(&example(policy)).unwrap();
        pol["morphology"] = if humanoid {
            "quadruped"
        } else {
            "wheeled_mobile"
        }
        .into();
        std::fs::write(
            r.dir.join("etc/response-policy.json"),
            serde_json::to_vec(&pol).unwrap(),
        )
        .unwrap();
        let e = r.load(&cfg).expect_err(s);
        assert!(e.contains("morphology"), "{s}: {e}");
    }
}

/// Rewrite a [`Root`]'s profile (locked and signed metadata as
/// `Root::new` writes it).
fn rewrite_profile(r: &Root, platform: &str, unit: &str, mut p: Profile) {
    p.locked = true;
    let mut md = metadata(1);
    md.platform = platform.into();
    md.unit_id = Some(unit.into());
    p.metadata = Some(md);
    write_profile(&r.dir.join("etc/profile.json"), &p);
}

/// Review M2: without `robot.robot_model` the morphology no longer fails
/// open: a 35-slot (`unitree_hg`) joint channel needs a humanoid policy and
/// firewall platform (every hg model is a humanoid), and a profile with
/// Unitree low-level / API channels but no model is warned about.
#[test]
fn hg_joint_channel_requires_humanoid_without_robot_model() {
    // Every hg model is a humanoid (the premise of the check).
    for m in UnitreeModel::ALL {
        if m.info().idl == Some(IdlFamily::Hg) {
            assert_eq!(m.info().morphology, Morphology::Humanoid, "{m:?}");
        }
    }
    let r = Root::new(
        "unitree-m2",
        UnitreeModel::G1,
        "unitree-g1",
        "unitree-g1-001",
        "response-policy.unitree-g1.example.json",
    );
    std::fs::write(
        r.dir.join("etc/firewall.json"),
        example("firewall.unitree-g1.example.json"),
    )
    .unwrap();
    let mut cfg = r.example("agentd.unitree-edu.example.json");
    cfg["robot"].as_object_mut().unwrap().remove("robot_model");
    // Humanoid everywhere, no model: loads, with a warning to set it.
    let res = r.load(&cfg).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        res.warnings
            .iter()
            .any(|w| w.contains("robot.robot_model") && w.contains("/lowcmd")),
        "{:?}",
        res.warnings
    );
    // Quadruped policy and firewall platform for a 35-slot channel: refused.
    let mut pol: serde_json::Value =
        serde_json::from_str(&example("response-policy.unitree-g1.example.json")).unwrap();
    pol["morphology"] = "quadruped".into();
    std::fs::write(
        r.dir.join("etc/response-policy.json"),
        serde_json::to_vec(&pol).unwrap(),
    )
    .unwrap();
    let mut fw: serde_json::Value =
        serde_json::from_str(&example("firewall.unitree-g1.example.json")).unwrap();
    fw["platform"]["morphology"] = "quadruped".into();
    fw["platform"]["fail_behaviour"] =
        serde_json::json!({"hold_last": {"max_hold_ns": 100_000_000}});
    std::fs::write(r.dir.join("etc/firewall.json"), fw.to_string()).unwrap();
    let e = r.load(&cfg).expect_err("35-slot channel on a quadruped");
    assert!(e.contains("humanoid") && e.contains("35"), "{e}");
}

/// Review M2: the slot count of a joint channel is checked by the profile's
/// recorded type (any name), not only for `/lowcmd`, `/arm_sdk`,
/// `/user_lowcmd`, and with or without a model.
#[test]
fn joint_slot_count_follows_the_recorded_type() {
    let r = Root::new(
        "unitree-m2-type",
        UnitreeModel::Go2,
        "unitree-go2",
        "u-1",
        "response-policy.unitree-go2.example.json",
    );
    // The Go2 firewall file (20 slots) on a channel recorded as hg LowCmd_.
    let mut p = profile_example(UnitreeModel::Go2);
    p.motion_types
        .insert("/lowcmd".into(), "unitree_hg::msg::dds_::LowCmd_".into());
    rewrite_profile(&r, "unitree-go2", "u-1", p);
    std::fs::write(
        r.dir.join("etc/firewall.json"),
        example("firewall.unitree-go2.example.json"),
    )
    .unwrap();
    let mut cfg = r.example("agentd.unitree-edu.example.json");
    cfg["robot"].as_object_mut().unwrap().remove("robot_model");
    cfg["sensor"]["profile_trust"]["expect_platform"] = "unitree-go2".into();
    cfg["sensor"]["profile_trust"]["expect_unit_id"] = "u-1".into();
    cfg["robot"]["id"] = "u-1".into();
    let e = r.load(&cfg).expect_err("20 slots vs hg type");
    assert!(e.contains("motor slots") && e.contains("LowCmd_"), "{e}");
    // The right type loads.
    let mut p = profile_example(UnitreeModel::Go2);
    p.motion_types
        .insert("/lowcmd".into(), "unitree_go::msg::dds_::LowCmd_".into());
    rewrite_profile(&r, "unitree-go2", "u-1", p);
    r.load(&cfg).unwrap_or_else(|e| panic!("{e}"));
}

/// Review M2: a legacy (Go1) channel as a joint-firewall channel is refused:
/// legacy frames carry no writer identity the firewall could authorise, so
/// every frame would be rejected as an unknown source before its joints
/// were checked (the profile envelope still checks them in the sensor).
#[test]
fn legacy_low_cmd_is_refused_as_a_joint_firewall_channel() {
    let r = Root::new(
        "unitree-m2-legacy",
        UnitreeModel::Go1,
        "unitree-go1",
        "unitree-go1-001",
        "response-policy.unitree-go2.example.json",
    );
    let mut fw: serde_json::Value =
        serde_json::from_str(&example("firewall.unitree-go2.example.json")).unwrap();
    let spec = fw["joint_channels"]["/lowcmd"].take();
    fw["joint_channels"] = serde_json::json!({ "/unitree_legacy/low_cmd": spec });
    std::fs::write(r.dir.join("etc/firewall.json"), fw.to_string()).unwrap();
    let mut cfg = r.example("agentd.unitree-sensor-box.example.json");
    cfg["firewall"] = serde_json::json!({"joint_config": r.dir.join("etc/firewall.json")});
    let e = r.load(&cfg).expect_err("legacy joint channel");
    assert!(e.contains("/unitree_legacy/low_cmd"), "{e}");
}

/// Review LOW: the SDK examples of Go2-W, H1, H2 and R1 switch modes
/// through `rt/api/motion_switcher/request`; their profile examples carry it
/// (writable, with a request envelope), as G1's and B2's do.
#[test]
fn motion_switcher_is_in_the_profile_examples() {
    for m in [
        UnitreeModel::Go2W,
        UnitreeModel::H1,
        UnitreeModel::H2,
        UnitreeModel::R1,
        UnitreeModel::G1,
        UnitreeModel::B2,
    ] {
        let p = profile_example(m);
        for t in [
            "/api/motion_switcher/request",
            "/api/motion_switcher/response",
        ] {
            assert!(p.writer_topics.contains(t), "{m:?}: {t}");
        }
        let env = &p.motion_envelopes["/api/motion_switcher/request"];
        assert_eq!(env.max_joint_speed, None, "{m:?}");
        assert!(env.max_linear_speed.is_some(), "{m:?}");
    }
}

/// Review LOW: the sensor-box example does not present a Go1 internal
/// computer (192.168.123.13 / .14 / .15) as the operator PC; its sender is
/// labelled as an example.
#[test]
fn sensor_box_example_command_sender_is_labelled() {
    let v: serde_json::Value =
        serde_json::from_str(&example("agentd.unitree-sensor-box.example.json")).unwrap();
    let senders = v["sensor"]["unitree_legacy"]["command_senders"]
        .as_array()
        .unwrap();
    assert!(!senders.is_empty());
    for s in senders {
        let ip = s["ip"].as_str().expect("table form with a label");
        assert!(
            !["192.168.123.13", "192.168.123.14", "192.168.123.15"].contains(&ip),
            "{ip} is a Go1 internal computer"
        );
        assert!(s["label"].as_str().unwrap().contains("EXAMPLE"), "{s}");
    }
}
