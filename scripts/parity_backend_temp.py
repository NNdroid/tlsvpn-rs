#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

# Self-signed server TLS generation/persistence: align the empty cert/key behavior
# with Go. rcgen stays entirely control-plane/cold-path.
replace_once(
    "Cargo.toml",
    'rustls-pemfile = "2"\n',
    'rustls-pemfile = "2"\nrcgen = "0.14.10"\n',
)

p = Path("src/server.rs")
s = p.read_text()
start = s.index("// ======================= TLS 材料 =======================")
end = s.index("// ======================= 服务端主流程 =======================", start)
new_tls = r'''// ======================= TLS 材料 =======================

const SELF_SIGNED_CERT_FILE: &str = "tlsvpn-selfsigned-cert.pem";
const SELF_SIGNED_KEY_FILE: &str = "tlsvpn-selfsigned-key.pem";

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("cannot open server.cert {path}: {e}"))?;
    let mut r = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot parse server.cert {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("server.cert {path} contains no certificates"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let f = std::fs::File::open(path)
        .map_err(|e| format!("cannot open server.key {path}: {e}"))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("cannot parse server.key {path}: {e}"))?
        .ok_or_else(|| format!("server.key {path} contains no supported private key"))
}

fn build_server_tls_from_paths(cert: &str, key: &str) -> Result<Arc<ServerConfig>, String> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| format!("invalid TLS cert/key pair ({cert}, {key}): {e}"))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn generate_persistent_self_signed(cert_path: &str, key_path: &str) -> Result<(), String> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("generate self-signed TLS certificate: {e}"))?;
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    // Match Go's persistence contract: key 0600, certificate 0644. A write
    // failure is surfaced in Rust instead of silently rotating the pin on the
    // next restart; a stable cert_sha256 identity is more important than
    // limping forward with an ephemeral certificate.
    std::fs::write(key_path, key_pem.as_bytes())
        .map_err(|e| format!("persist self-signed key {key_path}: {e}"))?;
    std::fs::write(cert_path, cert_pem.as_bytes())
        .map_err(|e| format!("persist self-signed cert {cert_path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod self-signed key {key_path}: {e}"))?;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod self-signed cert {cert_path}: {e}"))?;
    }
    Ok(())
}

/// Server TLS behavior follows Go: an explicit pair is loaded verbatim; when
/// both fields are empty a persistent self-signed pair is reused from the
/// working directory or generated once under the same filenames Go uses.
fn build_server_tls(cert: &str, key: &str) -> Result<Arc<ServerConfig>, String> {
    if !cert.is_empty() || !key.is_empty() {
        return build_server_tls_from_paths(cert, key);
    }

    match build_server_tls_from_paths(SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE) {
        Ok(cfg) => {
            info!("Loaded existing self-signed certificate from {}", SELF_SIGNED_CERT_FILE);
            return Ok(cfg);
        }
        Err(e) => {
            if std::path::Path::new(SELF_SIGNED_CERT_FILE).exists()
                || std::path::Path::new(SELF_SIGNED_KEY_FILE).exists()
            {
                warn!("Failed to load existing self-signed pair ({e}); regenerating");
            }
        }
    }

    generate_persistent_self_signed(SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE)?;
    info!("Generated self-signed certificate and persisted it to {} / {}", SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE);
    build_server_tls_from_paths(SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE)
}

'''
p.write_text(s[:start] + new_tls + s[end:])

# Go tolerates insecure + cert_sha256; insecure wins in both clients. Rust's
# actual TLS builder already has that precedence, so remove only the extra
# validation rejection.
main = Path("src/main.rs")
ms = main.read_text()
old = '''        if args.insecure && !args.cert_sha256.is_empty() {
            return Err("client.insecure and client.cert_sha256 cannot be enabled together".into());
        }
'''
if old not in ms:
    raise SystemExit("insecure/cert_sha256 validation marker not found")
main.write_text(ms.replace(old, "", 1))

# Update local maintainer notes/documentation that described the old deliberate
# differences. Keep Rust-only workers/mtu caveat intact.
ag = Path("AGENTS.md")
a = ag.read_text()
a = a.replace('''- Rust rejects `client.insecure` together with `client.cert_sha256`
  (`src/main.rs`). Go tolerates the pair. When a config must work for both,
  pick one.
''', '')
ag.write_text(a)

rd = Path("README.md")
r = rd.read_text()
r = r.replace('''# generate a TLS pair once, then pin it on clients via cert_sha256
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \\
            -days 3650 -nodes -subj "/CN=tlsvpn"
''', '''# explicit TLS pairs are supported; when server.cert/key are empty, tlsvpn-rs
# generates tlsvpn-selfsigned-cert.pem / tlsvpn-selfsigned-key.pem once and reuses them
''')
r = r.replace('''`client.interface_manager=netifd` is a Go/OpenWrt integration and is currently rejected by Rust (use `self`). Rust server mode also requires explicit `server.cert`/`server.key`, whereas Go can generate and persist a self-signed pair.''', '''`client.interface_manager=netifd` is a Go/OpenWrt integration and is currently rejected by Rust (use `self`). Rust server mode now matches Go when `server.cert`/`server.key` are empty: it generates and persists a reusable self-signed pair.''')
rd.write_text(r)
