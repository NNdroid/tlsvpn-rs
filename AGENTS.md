# Agent instructions for tlsvpn-rs

Rust port of the Go `tlsvpn` VPN (TLS-over-UDP-style tunnel with an inner
cipher layer and a virtual switch). The sibling checkout `../tlsvpn` is the
**authoritative parity reference**: when the two implementations disagree, the
Go one defines the intended behavior. Read `../tlsvpn/config.go` and
`../tlsvpn/interop/` before changing the wire or config contract.

## Do not touch the sibling repo

`../tlsvpn` contains the user's own uncommitted work. Never edit, stage, or
commit there. The only write allowed is `../tlsvpn/bin/tlsvpn.exe` (a Linux
cross-build artifact is expected to be dropped there). Its CI is where Go-side
breaks get caught, not this repo's.

## What CI actually runs

`.github/workflows/rust.yml` has two jobs and nothing else:

- `test-and-bench`: `cargo build`, `cargo test`, golden-vector contract check,
  one `--ignored` throughput benchmark, then the cross-language e2e matrix.
- `net-perf`: builds both implementations and runs
  `scripts/net_perf_test.sh` three times (rs/rs, rs/go, go/rs).

There is **no fmt job and no clippy job**.

## Do not run rustfmt

The repo is not rustfmt-clean and has never been formatted:
`cargo fmt --check` reports 14 pre-existing hunks across `server.rs` (6),
`client.rs` (4), `api.rs` (3), `main.rs` (1). Run it once and you produce a
hundreds-of-line diff that hides any real change and cannot be reviewed.
Write code that matches the surrounding style by hand instead. (Verified
2026-09-21: the new `close_session_tls` in `server.rs` and the client teardown
in `client.rs` add zero hunks — keep it that way.)

## Verify with a real negative control

This codebase has a trap that has bitten verification twice. rustls and Go's
`crypto/tls` report an EOF-without-`close_notify` **differently**: rustls
returns `UnexpectedEof` (`peer closed connection without sending TLS
close_notify`), Go returns a plain `io.EOF`. So a test that watches the Go
side cannot observe a bug that only shows on the Rust side. Rule: **observe
the side that actually changed**, and to prove a fix, rebuild the pre-fix
binary (`git stash push <file>`, build, test, `git stash pop`, rebuild) and
show the two outputs differ. A suite that passes after the fix is not evidence
that the fix did anything.

## Config contract

Since 2026-09-19 both binaries are config-file-only; their CLI flags were
removed. Launch with `-c <file>`, never with flags. Top-level keys shared by
both implementations: `mode`, `addr`, `psk`, `log_level`, `encrypt`, `tap`,
plus a `server` or `client` block.

- `psk` is required by both. Validation rejects only the empty string and four
  placeholders (`quic_secret`, `change-me`, `change-me-please`,
  `replace-with-a-random-secret`) — there is no length or entropy check.
- Rust rejects `client.insecure` together with `client.cert_sha256`
  (`src/main.rs`). Go tolerates the pair. When a config must work for both,
  pick one.
- If you add a required field, add it in `impl_config` in
  `scripts/net_perf_test.sh` or in `e2e_lib.sh` — never as a fragment at
  three call sites. That is exactly how `psk` was dropped and this script was
  silently dead for two days.

## e2e suite

Driver is `scripts/e2e_test.sh`, which runs five suites: `accept`, `tok`, `pad`,
`minenc`, `cfg`. Shared helpers and cert generation are in `scripts/e2e_lib.sh`.
Fresh-checkout reference run: 86 pass / 0 fail / 7 skip (the skips are
mixed-version cases gated on `E2E_RS_OLD_BIN`, `E2E_RS_OLD_PROBE`,
`E2E_GO_OLD_BIN`, which are absent on a clean checkout by design), ~850s.

`e2e_reap_all` kills **every** process matching `tlsvpn|probe|interop_client`
on the machine. Do not run standalone `tlsvpn` verification at the same time as
the suite, or the suite will kill your process mid-observation.

## Environment gotchas on this Windows + Git Bash host

- `python3` is a Windows Store stub that silently exits 0 and prints nothing.
  Use bash/awk/sed, or PowerShell for JSON (`ConvertFrom-Json`). `jq` is not
  installed.
- Passing a POSIX path to a native Windows binary or to `openssl` fails unless
  you convert it first (drive-letter form). `e2e_lib.sh:24` already exports
  `MSYS_NO_PATHCONV=1`, which is also why `-subj "/CN=tlsvpn-e2e"` works and
  why a bare `/tmp/...` path is passed through untouched.
- `grep` here is `ugrep`, and `-v` does not behave like GNU `grep -v`.
  Prefer `awk` for inverted matching.
- `pgrep` is unavailable. `kill <pid>` is unreliable on Windows; use
  PowerShell `Stop-Process -Id <pid> -Force`, and `Get-NetTCPConnection` /
  `Get-CimInstance Win32_Process` to find PIDs by port or command line.
- Invoking `powershell -File` from Git Bash needs a forward-slash path
  (`-File E:/tmp/x/y.ps1`); backslashes get stripped from the argument.
- `gh` is not installed, so CI runs cannot be inspected from this host. Report
  CI state only from what the user pastes.

## Committing and pushing

Commits here are unavoidably **unsigned** (`gpg: signing failed: Timeout` on a
passphrase prompt with no TTY). Use a repo-relative forward-slash path for the
message file, not `/tmp/...`:

```
git -c commit.gpgsign=false commit -F .zcode/cmsg.txt
```

Report the signed commit count (usually `signed: 0`) in your summary so the
user is not surprised. Never commit `.zcode/` — it is gitignored along with
`*.pem`, `dist/`, `debug/`, `target/`. The `e2e_cert.pem` / `e2e_key.pem`
pair is generated on demand by `e2e_ensure_cert`; do not check one in.

GitHub HTTPS from this host is flaky. Push with a retry loop and then confirm
sync with `git rev-list --left-right --count origin/main...HEAD` (expect `0 0`):

```
for i in 1 2 3 4 5; do
  git push origin main 2>&1 && break
  sleep 4
done
git fetch origin --quiet && git rev-list --left-right --count origin/main...HEAD
```

## Writing the report back

Work in this repo is reported in **Chinese**. Separate root cause from
symptom. State verification limits honestly — say when something is unverified
rather than implying it was checked. Flag things you deliberately did not fix
instead of leaving them for the user to discover. When you find that an earlier
prediction of yours was wrong, say so explicitly and correct it; do not paper
over it.

## Standing decision that is the user's, not yours

The `net-perf` job's `runs-on` is `ubuntu-latest`, where it SKIPs (RTNL is
refused even though TUNSETIFF is allowed) and exits 0. Running it for real
needs a privileged self-hosted runner. That is an infrastructure choice the
user makes; do not change `runs-on` on your own initiative.
