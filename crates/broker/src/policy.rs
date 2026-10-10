//! Authorization decisions over resolved operations.

use percent_encoding::percent_decode_str;
use regex::Regex;
use ztac_core::Decision;

use crate::auth::Principal;
use crate::config::{Access, BrokerConfig, Defenses, FsRule, Mode, ProgramKind, RuleAction};
use crate::glob;
use crate::resolve::{FsTarget, Op};

pub const GIT_SAFE: &[&str] = &[
    "status",
    "diff",
    "log",
    "show",
    "rev-parse",
    "ls-files",
    "add",
];
pub const GIT_APPROVE: &[&str] = &[
    "commit", "push", "checkout", "switch", "reset", "tag", "merge", "rebase", "stash",
];

/// Options that make git write to arbitrary paths, run programs, or change
/// which repository it operates on. Matched as `--opt` or `--opt=value`.
/// Global options such as `-c` and `-C` cannot occur because the first
/// argument must be an allowlisted subcommand.
pub const GIT_DANGEROUS_OPTIONS: &[&str] = &[
    "--output",
    "--exec",
    "--exec-path",
    "--upload-pack",
    "--receive-pack",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--ext-diff",
    "--textconv",
    "--open-files-in-pager",
    "-O",
];

#[derive(Debug, Clone)]
pub struct Outcome {
    pub decision: Decision,
    pub reason: String,
}

fn outcome(decision: Decision, reason: impl Into<String>) -> Outcome {
    Outcome {
        decision,
        reason: reason.into(),
    }
}

pub struct CompiledRule {
    pub rule: FsRule,
    pub regex: Regex,
}

pub struct Policy {
    pub rules: Vec<CompiledRule>,
    pub dlp: Vec<Regex>,
}

impl Policy {
    pub fn new(config: &BrokerConfig) -> anyhow::Result<Self> {
        let rules = config
            .fs_rules
            .iter()
            .map(|r| CompiledRule {
                regex: glob::compile(&r.pattern),
                rule: r.clone(),
            })
            .collect();
        let dlp = config
            .dlp_patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<_, _>>()?;
        Ok(Self { rules, dlp })
    }

    pub fn decide(
        &self,
        config: &BrokerConfig,
        principal: &Principal,
        tool: ztac_core::Tool,
        op: &Op,
    ) -> Outcome {
        if !principal.tools.contains(&tool) {
            return outcome(
                Decision::Deny,
                format!("tool {tool} is not granted to this cell"),
            );
        }
        match config.mode {
            Mode::Permissive => outcome(Decision::Allow, "permissive mode"),
            Mode::Allowlist | Mode::CommandSandbox => self.decide_allowlist(config, op),
            Mode::Ztac => {
                let o = self.decide_ztac(config, op);
                if o.decision == Decision::NeedsApproval && !config.defenses.approvals {
                    return outcome(
                        Decision::Allow,
                        format!("{} (approval tier disabled)", o.reason),
                    );
                }
                o
            }
        }
    }

    fn decide_allowlist(&self, config: &BrokerConfig, op: &Op) -> Outcome {
        match op {
            Op::Ping | Op::FsRead { .. } | Op::FsWrite { .. } => {
                outcome(Decision::Allow, "allowlisted tool")
            }
            Op::Exec { program, args, .. } => {
                if program.kind == ProgramKind::Git {
                    let sub = args.first().map(String::as_str).unwrap_or("");
                    if !GIT_SAFE.contains(&sub) && !GIT_APPROVE.contains(&sub) {
                        return outcome(Decision::Deny, format!("git {sub} is not allowlisted"));
                    }
                }
                outcome(Decision::Allow, "allowlisted program")
            }
            Op::Net { url, .. } => {
                let host = url.host_str().unwrap_or("");
                if config.net.iter().any(|e| e.host.eq_ignore_ascii_case(host)) {
                    outcome(Decision::Allow, "allowlisted host")
                } else {
                    outcome(Decision::Deny, "host is not allowlisted")
                }
            }
        }
    }

    fn decide_ztac(&self, config: &BrokerConfig, op: &Op) -> Outcome {
        let d = &config.defenses;
        match op {
            Op::Ping => outcome(Decision::Allow, "ping"),
            Op::FsRead { target, .. } => self.classify_fs(d, target, false),
            Op::FsWrite { target, .. } => self.classify_fs(d, target, true),
            Op::Exec { program, args, .. } => decide_exec(d, program.kind, args),
            Op::Net {
                url, headers, body, ..
            } => self.decide_net(config, url, headers, body.as_deref()),
        }
    }

    fn classify_fs(&self, d: &Defenses, target: &FsTarget, write: bool) -> Outcome {
        let subject = if d.resolved_classification {
            target.rel.clone()
        } else {
            target.raw.trim_start_matches("./").to_string()
        };
        if d.vcs_guard && write && is_vcs_metadata(&target.rel) {
            return outcome(Decision::Deny, "repository metadata is read-only to cells");
        }
        if d.resolved_classification && !write && target.multiply_linked && !target.cell_originated
        {
            return outcome(
                Decision::NeedsApproval,
                "file has several hard links; its other names are unknown",
            );
        }
        for c in &self.rules {
            let applies = match c.rule.access {
                Access::Any => true,
                Access::Read => !write,
                Access::Write => write,
            };
            if applies && c.regex.is_match(&subject) {
                // Reading back content the cell itself wrote discloses nothing.
                if !write && target.cell_originated && c.rule.action != RuleAction::Allow {
                    return outcome(Decision::Allow, "content was written by this cell");
                }
                return match c.rule.action {
                    RuleAction::Allow => {
                        outcome(Decision::Allow, format!("rule {}", c.rule.pattern))
                    }
                    RuleAction::Approve => outcome(
                        Decision::NeedsApproval,
                        format!("path matches sensitive rule {}", c.rule.pattern),
                    ),
                    RuleAction::Deny => outcome(
                        Decision::Deny,
                        format!("path denied by rule {}", c.rule.pattern),
                    ),
                };
            }
        }
        outcome(Decision::Allow, "workspace path")
    }

    fn decide_net(
        &self,
        config: &BrokerConfig,
        url: &url::Url,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Outcome {
        let d = &config.defenses;
        if !matches!(url.scheme(), "http" | "https") {
            return outcome(
                Decision::Deny,
                format!("scheme {} is not permitted", url.scheme()),
            );
        }
        let Some(endpoint) = endpoint_for(config, url) else {
            return outcome(
                Decision::Deny,
                format!(
                    "endpoint {}:{} is not allowlisted",
                    url.host_str().unwrap_or(""),
                    url.port_or_known_default().unwrap_or(0)
                ),
            );
        };

        let mut scanned: Vec<String> = Vec::new();
        if let Some(b) = body {
            scanned.push(b.to_string());
        }
        if d.dlp_full {
            scanned.push(
                percent_decode_str(url.as_str())
                    .decode_utf8_lossy()
                    .into_owned(),
            );
            for (k, v) in headers {
                scanned.push(format!("{k}: {v}"));
            }
        }
        for text in &scanned {
            if let Some(re) = self.dlp.iter().find(|re| re.is_match(text)) {
                return outcome(
                    Decision::Deny,
                    format!("outbound data matches DLP pattern {}", re.as_str()),
                );
            }
        }

        if endpoint.auto {
            outcome(Decision::Allow, "allowlisted endpoint")
        } else {
            outcome(Decision::NeedsApproval, "endpoint requires approval")
        }
    }
}

/// Finds the allowlist entry for a URL. Under net_strict an entry with a port
/// matches only that port; otherwise the host alone decides.
pub fn endpoint_for<'a>(
    config: &'a BrokerConfig,
    url: &url::Url,
) -> Option<&'a crate::config::NetEndpoint> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str().unwrap_or("");
    let port = url.port_or_known_default();
    let strict = config.defenses.net_strict;
    config.net.iter().find(|e| {
        e.host.eq_ignore_ascii_case(host) && (!strict || e.port.is_none() || e.port == port)
    })
}

fn decide_exec(d: &Defenses, kind: ProgramKind, args: &[String]) -> Outcome {
    match kind {
        ProgramKind::Plain => outcome(Decision::Allow, "plain program"),
        ProgramKind::Interpreter => {
            if d.exec_sandbox {
                outcome(Decision::Allow, "interpreter runs inside the exec sandbox")
            } else {
                outcome(Decision::Deny, "interpreters require the exec sandbox")
            }
        }
        ProgramKind::Git => {
            let Some(sub) = args.first() else {
                return outcome(Decision::Deny, "git requires a subcommand");
            };
            if d.vcs_guard {
                if let Some(bad) = args.iter().find(|a| is_dangerous_git_option(a)) {
                    return outcome(Decision::Deny, format!("git option {bad} is not permitted"));
                }
            }
            if sub == "commit" {
                if let Some(bad) = commit_extra_input(&args[1..]) {
                    return outcome(
                        Decision::Deny,
                        format!("git commit {bad} reads the working tree; stage changes first"),
                    );
                }
            }
            if GIT_SAFE.contains(&sub.as_str()) {
                outcome(Decision::Allow, format!("git {sub} is read-only"))
            } else if GIT_APPROVE.contains(&sub.as_str()) {
                outcome(
                    Decision::NeedsApproval,
                    format!("git {sub} changes repository state"),
                )
            } else {
                outcome(Decision::Deny, format!("git {sub} is not permitted"))
            }
        }
    }
}

/// An approval for `git commit` is bound to HEAD and the index. Forms that
/// also take content from the working tree at commit time (`-a`,
/// `--include`, `--only`, pathspecs) would commit content the binding does
/// not cover, so only a commit of what is already staged is accepted.
/// Returns the first argument outside that form.
pub fn commit_extra_input(args: &[String]) -> Option<String> {
    const FLAGS: &[&str] = &[
        "-q",
        "--quiet",
        "--allow-empty",
        "--amend",
        "--no-edit",
        "-s",
        "--signoff",
    ];
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-m" || a == "--message" {
            i += 2;
            continue;
        }
        if a.starts_with("--message=") || (a.starts_with("-m") && a.len() > 2) || FLAGS.contains(&a)
        {
            i += 1;
            continue;
        }
        return Some(a.to_string());
    }
    None
}

/// git's option parser accepts any unambiguous prefix of a long option
/// (`--upload-pa` for `--upload-pack`), so a long argument is rejected when
/// its name is a prefix of a dangerous option, not only when it is equal.
pub fn is_dangerous_git_option(arg: &str) -> bool {
    if let Some(long) = arg.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or("");
        if name.len() < 2 {
            return false;
        }
        return GIT_DANGEROUS_OPTIONS
            .iter()
            .filter_map(|o| o.strip_prefix("--"))
            .any(|o| o.starts_with(name));
    }
    // Short options, possibly with an attached value (-Oprog).
    GIT_DANGEROUS_OPTIONS
        .iter()
        .filter(|o| o.len() == 2)
        .any(|o| arg.starts_with(*o))
}

/// Any path component spelled `.git` in any case: on a case-insensitive
/// volume `sub/.GIT` is what git finds when it looks for `sub/.git`.
pub fn is_vcs_metadata(rel: &str) -> bool {
    rel.split('/').any(|c| c.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_options() {
        assert!(is_dangerous_git_option("--output=/tmp/x"));
        assert!(is_dangerous_git_option("--output"));
        assert!(is_dangerous_git_option("-Oless"));
        assert!(!is_dangerous_git_option("-C"));
        assert!(is_dangerous_git_option("--upload-pa=evil"));
        assert!(is_dangerous_git_option("--outp=/x"));
        assert!(is_dangerous_git_option("--ex"));
        assert!(!is_dangerous_git_option("--oneline"));
        assert!(!is_dangerous_git_option("--stat"));
        assert!(!is_dangerous_git_option("--porcelain"));
        assert!(!is_dangerous_git_option("--name-only"));
        assert!(!is_dangerous_git_option("--cached"));
        assert!(!is_dangerous_git_option("--short"));
        assert!(!is_dangerous_git_option("-m"));
    }

    #[test]
    fn commit_forms() {
        let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(commit_extra_input(&v(&["-m", "fix: typo"])), None);
        assert_eq!(commit_extra_input(&v(&["--allow-empty", "-mmsg"])), None);
        assert_eq!(
            commit_extra_input(&v(&["-a", "-m", "x"])),
            Some("-a".into())
        );
        assert_eq!(commit_extra_input(&v(&["-am", "x"])), Some("-am".into()));
        assert_eq!(
            commit_extra_input(&v(&["-m", "x", "src/app.py"])),
            Some("src/app.py".into())
        );
        assert_eq!(
            commit_extra_input(&v(&["--include", "-m", "x"])),
            Some("--include".into())
        );
    }

    #[test]
    fn vcs_paths() {
        assert!(is_vcs_metadata(".git/config"));
        assert!(is_vcs_metadata("sub/.git"));
        assert!(is_vcs_metadata("tools/.GIT"));
        assert!(!is_vcs_metadata(".gitignore"));
    }
}
