use std::fs;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

// A symbolic .git/HEAD does not change when the branch advances. Watch both
// HEAD and its resolved ref (plus packed-refs) so incremental Cargo builds do
// not keep stale git_commit/build_time metadata after a new commit.
fn watch_git_revision() {
    let Some(head_path) = git(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={head_path}");

    if let Ok(head) = fs::read_to_string(&head_path) {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            if let Some(reference_path) = git(&["rev-parse", "--git-path", reference]) {
                println!("cargo:rerun-if-changed={reference_path}");
            }
        }
    }

    if let Some(packed_refs) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        println!("cargo:rerun-if-changed={packed_refs}");
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=TLSVPN_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=TLSVPN_BUILD_TIME");
    watch_git_revision();

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
