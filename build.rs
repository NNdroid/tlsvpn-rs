use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn main() {
    println!("cargo:rerun-if-env-changed=TLSVPN_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=TLSVPN_BUILD_TIME");
    println!("cargo:rerun-if-changed=.git/HEAD");

    let commit = std::env::var("TLSVPN_GIT_COMMIT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git(&["rev-parse", "HEAD"]));
    if let Some(value) = commit {
        println!("cargo:rustc-env=TLSVPN_GIT_COMMIT={value}");
    }

    // Keep builds reproducible: this is the VCS commit timestamp unless the
    // build environment explicitly supplies TLSVPN_BUILD_TIME. We do not use
    // wall-clock `now` here.
    let build_time = std::env::var("TLSVPN_BUILD_TIME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git(&["show", "-s", "--format=%cI", "HEAD"]));
    if let Some(value) = build_time {
        println!("cargo:rustc-env=TLSVPN_BUILD_TIME={value}");
    }
}
