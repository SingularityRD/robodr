//! `bind`, `firewall-draft`, `report-html` and `poc-init` (see the usage
//! text and `robodr_commission::{trust::bound, firewall_draft,
//! report_html, poc}`).

use super::{
    distinct_paths, json, load_signoff_sigs, precheck_outputs, publish_with_manifest, read_text,
    write_file, Args, Failure, Outcome, MAX_SIGNOFF_BYTES,
};
use robodr_commission::firewall_draft::{draft_firewall, DraftOptions};
use robodr_commission::ops::{manifest_path_for, Manifest};
use robodr_commission::profile_file::MAX_PROFILE_BYTES;
use robodr_commission::report_html::{render, RenderInputs};
use robodr_commission::signoff::{
    bound_config_item, draft_digest, sha256_hex, signoff_sig_path, Signoff, BOUND_CONFIG_KIND,
};
use robodr_commission::trust::bound::{
    digest_for_role, summarize, ROLE_EXECUTOR_MOTION, ROLE_JOINT_FIREWALL, ROLE_MOTION_FIREWALL,
    ROLE_RESPONSE_POLICY,
};
use robodr_commission::trust::file_digest;
use robodr_commission::{parse_profile_text, CommissioningReport};
use std::path::Path;

/// Largest file `bind` reads (policy, firewall, executor configuration).
const MAX_BOUND_FILE_BYTES: u64 = 1 << 20;
/// Largest report `report-html` / `firewall-draft` read.
const MAX_REPORT_BYTES: u64 = robodr_commission::ops::MAX_REPORT_BYTES;

/// Check `text` is a valid file of `role` for `draft` (what the unit will
/// load), before its digest is bound.
fn validate_role(
    role: &str,
    path: &str,
    text: &str,
    draft: &robodr_events::profile::Profile,
) -> Result<(), String> {
    let bad = |e: String| format!("{path}: not a valid {role} file: {e}");
    match role {
        ROLE_RESPONSE_POLICY => {
            robodr_responder::ResponsePolicy::from_json(text).map_err(|e| bad(e.to_string()))?;
        }
        ROLE_MOTION_FIREWALL => {
            let fc = robodr_firewall::FirewallConfig::from_json(text)
                .map_err(|e| bad(format!("{e:?}")))?;
            fc.compile(draft).map_err(|e| {
                bad(format!(
                    "{e:?} (it must compile against this draft: every motion channel specified, \
                     every allowed source a profiled participant)"
                ))
            })?;
        }
        ROLE_JOINT_FIREWALL => {
            let fc = robodr_firewall::FirewallConfig::from_json(text)
                .map_err(|e| bad(format!("{e:?}")))?;
            if !fc.channels.is_empty() || fc.joint_channels.is_empty() {
                return Err(bad(
                    "agentd's joint_config defines joint_channels (and platform) only".into(),
                ));
            }
        }
        _ => {
            digest_for_role(role, text).map_err(bad)?;
        }
    }
    Ok(())
}

pub(super) fn cmd_bind(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "in",
            "out",
            "signoff",
            "signoff-out",
            "response-policy",
            "motion-firewall",
            "joint-firewall",
            "executor-config",
        ],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let input = a.required("in")?;
    let out = a.required("out")?;
    let so_default = format!("{out}.signoff.json");
    let so_out = a.one("signoff-out")?.unwrap_or(&so_default).to_string();
    let manifest = manifest_path_for(Path::new(out)).display().to_string();
    let mut files: Vec<(&str, &str)> = Vec::new();
    for (flag, role) in [
        ("response-policy", ROLE_RESPONSE_POLICY),
        ("motion-firewall", ROLE_MOTION_FIREWALL),
        ("joint-firewall", ROLE_JOINT_FIREWALL),
        ("executor-config", ROLE_EXECUTOR_MOTION),
    ] {
        if let Some(p) = a.one(flag)? {
            files.push((role, p));
        }
    }
    if files.is_empty() {
        return Err(
            "nothing to bind: give --response-policy, --motion-firewall, \
             --joint-firewall and/or --executor-config"
                .to_string()
                .into(),
        );
    }
    let mut inputs: Vec<&str> = vec![input];
    inputs.extend(files.iter().map(|(_, p)| *p));
    inputs.extend(a.one("signoff")?);
    distinct_paths(&[out, so_out.as_str(), manifest.as_str()], &inputs)?;
    let force = a.switch("force");
    precheck_outputs(&[out, so_out.as_str(), manifest.as_str()], force)?;

    let text = read_text(input, MAX_PROFILE_BYTES)?;
    let mut p = parse_profile_text(&text).map_err(|e| format!("{input}: {e}"))?;
    if p.locked {
        return Err(format!(
            "{input}: already locked; bind a draft and lock it again (with --parent): a binding \
             is part of the content the operators sign"
        )
        .into());
    }
    let mut items = Vec::new();
    for (role, path) in &files {
        let t = read_text(path, MAX_BOUND_FILE_BYTES)?;
        validate_role(role, path, &t, &p)?;
        let d = digest_for_role(role, &t).map_err(|e| format!("{path}: {e}"))?;
        items.push(bound_config_item(role, &d, &summarize(role, &t)));
        p.bound_config.insert((*role).to_string(), d);
    }
    if let Err(errs) = p.validate() {
        let list: Vec<String> = errs.iter().map(|e| format!("  - {e}")).collect();
        return Err(format!("the bound draft fails validation:\n{}", list.join("\n")).into());
    }
    // The sign-off: the learner's list (if it belongs to the input draft)
    // with every binding item replaced, all unconfirmed again (the content
    // changed); else the conservative list for the bound draft.
    let signoff = match a.one("signoff")? {
        Some(sp) => {
            let st = read_text(sp, MAX_SIGNOFF_BYTES)?;
            let so: Signoff =
                serde_json::from_str(&st).map_err(|e| format!("{sp}: not a sign-off: {e}"))?;
            so.check_shape().map_err(|e| format!("{sp}: {e}"))?;
            let input_draft = parse_profile_text(&text).map_err(|e| format!("{input}: {e}"))?;
            let ok_digest = so.profile_sha256 == sha256_hex(text.as_bytes())
                || so.profile_sha256 == draft_digest(&input_draft);
            if !ok_digest || !so.items_intact() || so.model != p.model {
                return Err(format!(
                    "{sp}: not the intact sign-off list of {input} (other draft, other model or \
                     edited items)"
                )
                .into());
            }
            let mut kept: Vec<_> = so
                .items
                .into_iter()
                .filter(|i| i.kind != BOUND_CONFIG_KIND)
                .collect();
            kept.extend(items);
            for i in &mut kept {
                i.confirmed = false;
            }
            Signoff::new(&p, kept)
        }
        None => Signoff::for_profile(&p),
    };
    let draft_text = json(&p)?;
    let list = json(&signoff)?;
    publish_with_manifest(
        &[(out, draft_text.as_str()), (so_out.as_str(), list.as_str())],
        &manifest,
        force,
        force,
        |m| {
            Manifest::new(
                m,
                &p.model,
                (Path::new(out), draft_text.as_bytes()),
                Some((Path::new(&so_out), &signoff)),
                None,
            )
        },
    )?;
    for (role, d) in &p.bound_config {
        eprintln!("bound {role} {d}");
    }
    eprintln!(
        "wrote bound draft {out}, sign-off list {so_out} ({} item(s), all unconfirmed) and \
         manifest {manifest}. Every bound_config item is a motion item: motion_quorum operators \
         must sign. After lock + sign, the unit honours oem_validated and the firewall envelope \
         only for exactly these files; changing one means bind + lock again.",
        signoff.items.len()
    );
    Ok(())
}

fn morphology(s: &str) -> Result<robodr_firewall::Morphology, String> {
    use robodr_firewall::Morphology as M;
    Ok(match s {
        "wheeled" => M::Wheeled,
        "quadruped" => M::Quadruped,
        "humanoid" => M::Humanoid,
        "arm" => M::Arm,
        "other" => M::Other,
        _ => {
            return Err(format!(
                "--morphology {s:?}: wheeled|quadruped|humanoid|arm|other"
            ))
        }
    })
}

pub(super) fn cmd_firewall_draft(argv: &[String]) -> Outcome {
    let a = Args::parse(
        argv,
        &[
            "in",
            "report",
            "out",
            "max-angular",
            "ceiling-linear",
            "morphology",
        ],
        &["force"],
    )?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let input = a.required("in")?;
    let report_path = a.required("report")?;
    let out = a.required("out")?;
    distinct_paths(&[out], &[input, report_path])?;
    let force = a.switch("force");
    precheck_outputs(&[out], force)?;
    let max_angular = a.f64_opt("max-angular")?.ok_or_else(|| {
        "--max-angular RAD_PER_S is required: the profile learns no yaw rate, the OEM's \
                ceiling is the angular limit"
            .to_string()
    })?;
    let mut platform = robodr_firewall::PlatformConfig::default();
    if let Some(m) = a.one("morphology")? {
        platform.morphology = morphology(m)?;
        if platform.morphology == robodr_firewall::Morphology::Humanoid {
            platform.fail_behaviour = robodr_firewall::FailBehaviour::HoldLast {
                max_hold_ns: 100_000_000,
            };
        }
    }
    let p = parse_profile_text(&read_text(input, MAX_PROFILE_BYTES)?)
        .map_err(|e| format!("{input}: {e}"))?;
    let r: CommissioningReport =
        serde_json::from_str(&read_text(report_path, MAX_REPORT_BYTES)?)
            .map_err(|e| format!("{report_path}: not a commissioning report: {e}"))?;
    let d = draft_firewall(
        &p,
        &r,
        &DraftOptions {
            max_angular,
            ceiling_linear: a.f64_opt("ceiling-linear")?,
            platform,
        },
    )?;
    write_file(out, &json(&d.config)?, force)?;
    for n in &d.notes {
        eprintln!("note: {n}");
    }
    eprintln!(
        "wrote draft Motion Firewall file {out} ({} Twist channel(s)); review it with the OEM, \
         then bind it (`bind --motion-firewall {out}`)",
        d.config.channels.len()
    );
    if d.missing.is_empty() {
        Ok(())
    } else {
        for m in &d.missing {
            eprintln!("INCOMPLETE: {m}");
        }
        eprintln!(
            "the draft is incomplete ({} channel(s)): it does not compile against the profile \
             and bind refuses it until they are specified",
            d.missing.len()
        );
        Err(Failure::Negative)
    }
}

pub(super) fn cmd_report_html(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["report", "out", "signoff", "note"], &["force"])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let report_path = a.required("report")?;
    let out = a.required("out")?;
    let so_path = a.one("signoff")?;
    let mut inputs = vec![report_path];
    inputs.extend(so_path);
    distinct_paths(&[out], &inputs)?;
    let force = a.switch("force");
    precheck_outputs(&[out], force)?;
    let rt = read_text(report_path, MAX_REPORT_BYTES)?;
    let r: CommissioningReport = serde_json::from_str(&rt)
        .map_err(|e| format!("{report_path}: not a commissioning report: {e}"))?;
    let so = match so_path {
        None => None,
        Some(sp) => {
            let st = read_text(sp, MAX_SIGNOFF_BYTES)?;
            let so: Signoff =
                serde_json::from_str(&st).map_err(|e| format!("{sp}: not a sign-off: {e}"))?;
            Some((so, file_digest(st.as_bytes()), sp))
        }
    };
    let sig_ids = match &so {
        None => Vec::new(),
        Some((_, _, sp)) => {
            let sig = signoff_sig_path(Path::new(sp)).display().to_string();
            load_signoff_sigs(&sig)?
                .map(|s| s.signatures.into_iter().map(|x| x.key_id).collect())
                .unwrap_or_default()
        }
    };
    let html = render(
        &r,
        &RenderInputs {
            report_digest: file_digest(rt.as_bytes()),
            signoff: so.as_ref().map(|(s, d, _)| (s, d.clone())),
            signature_key_ids: sig_ids,
            title_note: a.one("note")?.map(str::to_string),
        },
    );
    write_file(out, &html, force)?;
    eprintln!("wrote {out}: open it in a browser (print to PDF for the commissioning record)");
    Ok(())
}

pub(super) fn cmd_poc_init(argv: &[String]) -> Outcome {
    let a = Args::parse(argv, &["dir", "operator"], &[])?;
    if let Some(p) = a.positionals.first() {
        return Err(format!("unexpected argument {p:?}").into());
    }
    let dir = a.required("dir")?;
    let op = a.one("operator")?.unwrap_or("poc-operator");
    let c = robodr_commission::poc::init(Path::new(dir), op)?;
    eprintln!("\n*** {} ***\n", robodr_commission::poc::LAB_ONLY_BANNER);
    eprintln!(
        "wrote a lab-only chain in {dir}: keys (0600) {}, {}, {}; operators {} (one operator \
         {:?}, motion_quorum 1); for the unit: {}, {} + {}. Next steps: {}",
        c.root_key.display(),
        c.profile_key.display(),
        c.operator_key.display(),
        c.operators.display(),
        c.operator_name,
        c.trust_roots.display(),
        c.trust_file.display(),
        c.trust_sig.display(),
        c.readme.display()
    );
    Ok(())
}
