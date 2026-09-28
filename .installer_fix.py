from pathlib import Path

p = Path('scripts/install.sh')
s = p.read_text()
old = '''  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
'''
new = '''  # Read os-release in a subshell so keys such as VERSION= cannot clobber
  # installer options like --version/latest.
  local os_id os_id_like
  os_id="$(. /etc/os-release; printf '%s' "${ID:-unknown}")"
  os_id_like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
  DISTRO="$os_id"
  DISTRO_LIKE="$os_id_like"
'''
assert s.count(old) == 1, f'detect_platform source block count={s.count(old)}'
s = s.replace(old, new)
old = '''  [[ -n "$RELEASE_TAG" ]] || die "Could not resolve a TLSVPN release tag."
  [[ "$RELEASE_TAG" == v* ]] || RELEASE_TAG="v$RELEASE_TAG"
  release_arch
'''
new = '''  [[ -n "$RELEASE_TAG" ]] || die "Could not resolve a TLSVPN release tag."
  [[ "$RELEASE_TAG" == v* ]] || RELEASE_TAG="v$RELEASE_TAG"
  [[ "$RELEASE_TAG" =~ ^v[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || die "Invalid TLSVPN release tag: $RELEASE_TAG"
  release_arch
'''
assert s.count(old) == 1, f'resolve_release block count={s.count(old)}'
s = s.replace(old, new)
old = '''start_service() {
  [[ "$NO_START" == "yes" ]] && return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then run systemctl restart tlsvpn.service;
  else run rc-service tlsvpn restart; fi
}
'''
new = '''start_service() {
  [[ "$NO_START" == "yes" ]] && return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    # A failed fresh install or a rollback after uninstall may legitimately have
    # no service unit to restart. Do not turn recovery into a second error.
    if [[ ! -e "$SYSTEMD_SERVICE" ]] && ! systemctl cat tlsvpn.service >/dev/null 2>&1; then return 0; fi
    run systemctl restart tlsvpn.service
  else
    [[ -e "$OPENRC_SERVICE" ]] || return 0
    run rc-service tlsvpn restart
  fi
}
'''
assert s.count(old) == 1, f'start_service block count={s.count(old)}'
s = s.replace(old, new)
p.write_text(s)

p = Path('tests/dashboard_script_test.rs')
s = p.read_text()
anchor = '''        "--non-interactive",
        "back",
'''
replacement = '''        "--non-interactive",
        "back",
        "os_id=\"$(. /etc/os-release; printf",
        "Invalid TLSVPN release tag:",
        "systemctl cat tlsvpn.service",
'''
assert s.count(anchor) == 1
s = s.replace(anchor, replacement)
anchor = '''    for marker in [
        "install_action",
'''
# Add a direct namespace-pollution regression assertion after the marker loop.
needle = '''        assert!(installer.contains(marker), "installer missing {marker}");
    }
}
'''
replacement2 = '''        assert!(installer.contains(marker), "installer missing {marker}");
    }
    assert!(
        !installer.contains("\\n  . /etc/os-release\\n"),
        "installer must not source /etc/os-release into its global namespace"
    );
}
'''
assert s.count(needle) >= 1
s = s.replace(needle, replacement2, 1)
p.write_text(s)
