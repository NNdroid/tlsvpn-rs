use parking_lot::Mutex;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

const HOOK_TIMEOUT: Duration = Duration::from_secs(30);
const HOOK_OUTPUT_CAP: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookEnv {
    pub mode: String,
    pub dev: String,
    pub config: String,
    pub ipv4: String,
    pub ipv6: String,
    pub gateway_v4: String,
    pub gateway_v6: String,
}

#[derive(Default)]
struct HookState {
    active: bool,
    env: HookEnv,
    up_result: Option<Result<(), String>>,
    down_result: Option<Result<(), String>>,
}

/// Process-level tunnel lifecycle hooks.  The mutex deliberately covers hook
/// execution: four simultaneous client handshakes must observe one completed
/// up result, not start four copies of the script.
pub struct LifecycleHooks {
    up_path: String,
    down_path: String,
    state: Mutex<HookState>,
}

impl LifecycleHooks {
    pub fn new(up_path: String, down_path: String) -> Self {
        Self { up_path, down_path, state: Mutex::new(HookState::default()) }
    }

    pub fn configured(&self) -> bool {
        !self.up_path.is_empty() || !self.down_path.is_empty()
    }

    pub fn activate(&self, env: HookEnv) {
        let mut state = self.state.lock();
        state.active = true;
        state.env = env;
    }

    pub fn up(&self, env: HookEnv) -> Result<(), String> {
        let mut state = self.state.lock();
        if let Some(result) = &state.up_result {
            return result.clone();
        }
        state.active = true;
        state.env = env.clone();
        let result = if self.up_path.is_empty() {
            Ok(())
        } else {
            run_hook("up", &self.up_path, &env)
        };
        state.up_result = Some(result.clone());
        result
    }

    pub fn down(&self) -> Result<(), String> {
        let mut state = self.state.lock();
        if let Some(result) = &state.down_result {
            return result.clone();
        }
        if !state.active || self.down_path.is_empty() {
            state.down_result = Some(Ok(()));
            return Ok(());
        }
        let result = run_hook("down", &self.down_path, &state.env);
        state.down_result = Some(result.clone());
        result
    }
}

fn run_hook(kind: &str, path: &str, env: &HookEnv) -> Result<(), String> {
    let mut cmd = Command::new(path);
    cmd.env_clear();
    cmd.envs(base_hook_environment());
    cmd.envs(hook_environment(kind, env));
    if let Some(dir) = hook_work_dir(&env.config) {
        cmd.current_dir(dir);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("{kind} hook {path} failed: {e}"))?;
    let stdout = child.stdout.take().map(spawn_output_reader);
    let stderr = child.stderr.take().map(spawn_output_reader);
    let deadline = Instant::now() + HOOK_TIMEOUT;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                break (child.wait().ok(), true);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{kind} hook {path} failed while waiting: {e}"));
            }
        }
    };
    let mut output = Vec::new();
    let output_deadline = Instant::now() + Duration::from_secs(2);
    if let Some(receiver) = stdout {
        if let Ok(mut bytes) = receiver.recv_timeout(output_deadline.saturating_duration_since(Instant::now())) {
            output.append(&mut bytes);
        }
    }
    if let Some(receiver) = stderr {
        if let Ok(mut bytes) = receiver.recv_timeout(output_deadline.saturating_duration_since(Instant::now())) {
            if !output.is_empty() && !bytes.is_empty() {
                output.push(b'\n');
            }
            output.append(&mut bytes);
        }
    }
    output.truncate(HOOK_OUTPUT_CAP);
    let detail = String::from_utf8_lossy(&output).trim().to_string();
    if timed_out {
        return Err(with_output(
            format!("{kind} hook {path} timed out after 30s"),
            &detail,
        ));
    }
    match status {
        Some(s) if s.success() => {
            if !detail.is_empty() {
                tracing::info!("{} hook output: {}", kind, detail);
            }
            Ok(())
        }
        Some(s) => Err(with_output(
            format!("{kind} hook {path} failed with {s}"),
            &detail,
        )),
        None => Err(with_output(
            format!("{kind} hook {path} failed without exit status"),
            &detail,
        )),
    }
}

fn spawn_output_reader<R: Read + Send + 'static>(mut reader: R) -> Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::with_capacity(HOOK_OUTPUT_CAP / 2);
        let mut buf = [0u8; 4096];
        while kept.len() < HOOK_OUTPUT_CAP / 2 {
            let remaining = HOOK_OUTPUT_CAP / 2 - kept.len();
            let read_len = remaining.min(buf.len());
            match reader.read(&mut buf[..read_len]) {
                Ok(0) | Err(_) => break,
                Ok(n) => kept.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tx.send(kept);
    });
    rx
}

fn with_output(message: String, output: &str) -> String {
    if output.is_empty() { message } else { format!("{message} (output: {output})") }
}

fn hook_work_dir(config: &str) -> Option<PathBuf> {
    if config.is_empty() {
        return None;
    }
    std::fs::canonicalize(config)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

fn hook_environment(kind: &str, env: &HookEnv) -> Vec<(String, String)> {
    vec![
        ("script_type".into(), kind.into()),
        ("dev".into(), env.dev.clone()),
        ("dev_type".into(), "tap".into()),
        ("config".into(), env.config.clone()),
        ("ifconfig_local".into(), strip_cidr(&env.ipv4).into()),
        ("ifconfig_ipv6_local".into(), strip_cidr(&env.ipv6).into()),
        ("route_vpn_gateway".into(), env.gateway_v4.clone()),
        ("route_ipv6_gateway".into(), env.gateway_v6.clone()),
        ("TLSVPN_SCRIPT_TYPE".into(), kind.into()),
        ("TLSVPN_MODE".into(), env.mode.clone()),
        ("TLSVPN_DEV".into(), env.dev.clone()),
        ("TLSVPN_CONFIG".into(), env.config.clone()),
        ("TLSVPN_IPV4".into(), env.ipv4.clone()),
        ("TLSVPN_IPV6".into(), env.ipv6.clone()),
        ("TLSVPN_GATEWAY_V4".into(), env.gateway_v4.clone()),
        ("TLSVPN_GATEWAY_V6".into(), env.gateway_v6.clone()),
    ]
}

#[cfg(not(windows))]
fn base_hook_environment() -> Vec<(String, String)> {
    vec![
        ("PATH".into(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()),
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
    ]
}

#[cfg(windows)]
fn base_hook_environment() -> Vec<(String, String)> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let mut out = vec![
        ("SystemRoot".into(), root.clone()),
        ("WINDIR".into(), root.clone()),
        ("PATH".into(), format!("{}\\System32;{}", root, root)),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
    ];
    for key in ["TEMP", "TMP"] {
        if let Ok(value) = std::env::var(key) {
            out.push((key.into(), value));
        }
    }
    out
}

fn strip_cidr(value: &str) -> &str {
    value.split_once('/').map_or(value, |(ip, _)| ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_environment_has_openvpn_and_tlsvpn_names() {
        let env = HookEnv {
            mode: "client".into(), dev: "tap7".into(), config: "/etc/tlsvpn/client.json".into(),
            ipv4: "10.5.8.2/24".into(), ipv6: "fd00::2/64".into(),
            gateway_v4: "10.5.8.1".into(), gateway_v6: "fd00::1".into(),
        };
        let vars = hook_environment("up", &env).into_iter().collect::<std::collections::HashMap<_, _>>();
        assert_eq!(vars.get("script_type").map(String::as_str), Some("up"));
        assert_eq!(vars.get("ifconfig_local").map(String::as_str), Some("10.5.8.2"));
        assert_eq!(vars.get("TLSVPN_IPV4").map(String::as_str), Some("10.5.8.2/24"));
        assert!(!base_hook_environment().iter().any(|(key, _)| key == "AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn down_is_not_run_before_activation() {
        let hooks = LifecycleHooks::new(String::new(), "/definitely/missing/down".into());
        assert!(hooks.down().is_ok());
    }

    #[test]
    fn empty_hooks_are_idempotent() {
        let hooks = LifecycleHooks::new(String::new(), String::new());
        let env = HookEnv { dev: "tap0".into(), ..HookEnv::default() };
        assert!(hooks.up(env.clone()).is_ok());
        assert!(hooks.up(env).is_ok());
        assert!(hooks.down().is_ok());
        assert!(hooks.down().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn executable_hooks_run_through_the_real_process_path() {
        let path = std::path::PathBuf::from(std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into()))
            .join("System32")
            .join("whoami.exe");
        if !path.is_file() {
            return;
        }
        let hooks = LifecycleHooks::new(
            path.to_string_lossy().into_owned(),
            path.to_string_lossy().into_owned(),
        );
        let env = HookEnv { mode: "client".into(), dev: "tap0".into(), ..HookEnv::default() };
        hooks.up(env).unwrap();
        hooks.down().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn executable_hooks_run_once_with_stable_environment() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join(format!("tlsvpn-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let events = dir.join("events");
        let script = dir.join("hook.sh");
        let config = dir.join("client.json");
        std::fs::write(&config, "{}").unwrap();
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$script_type\" \"$dev\" \"$ifconfig_local\" \"$TLSVPN_IPV4\" >> '{}'\n",
                events.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hooks = Arc::new(LifecycleHooks::new(
            script.to_string_lossy().into_owned(),
            script.to_string_lossy().into_owned(),
        ));
        let env = HookEnv {
            mode: "client".into(), dev: "tap7".into(),
            config: config.to_string_lossy().into_owned(), ipv4: "10.5.8.2/24".into(),
            ipv6: "fd00::2/64".into(), gateway_v4: "10.5.8.1".into(),
            gateway_v6: "fd00::1".into(),
        };
        let mut threads = Vec::new();
        for _ in 0..8 {
            let hooks = hooks.clone();
            let env = env.clone();
            threads.push(std::thread::spawn(move || hooks.up(env)));
        }
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        hooks.down().unwrap();
        hooks.down().unwrap();

        let lines = std::fs::read_to_string(&events).unwrap();
        assert_eq!(
            lines.lines().collect::<Vec<_>>(),
            vec!["up|tap7|10.5.8.2|10.5.8.2/24", "down|tap7|10.5.8.2|10.5.8.2/24"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
