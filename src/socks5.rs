// SOCKS5 client support (RFC 1928 + RFC 1929 user/pass auth).
//
// This is a client-only feature: the tlsvpn *client* dials the remote server
// through a SOCKS5 proxy. The server is completely unaware of the proxy.
//
// Implemented with std only (no extra dependency) so the musl release stays
// self-contained, and to mirror the Go implementation's behaviour (remote DNS
// resolution via the proxy — `socks5h` semantics).
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::debug;

#[derive(Clone, Debug)]
pub struct Socks5Proxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Socks5Proxy {
    /// Parse a proxy spec. Accepted forms:
    ///   host:port
    ///   user:pass@host:port
    ///   socks5://host:port
    ///   socks5://user:pass@host:port
    ///   socks5h://...   (remote DNS; we always resolve remotely anyway)
    pub fn parse(spec: &str) -> Option<Socks5Proxy> {
        let s = spec.trim();
        let s = if let Some(rest) = s.strip_prefix("socks5h://") {
            rest
        } else if let Some(rest) = s.strip_prefix("socks5://") {
            rest
        } else {
            // Reject any other scheme (e.g. http://, socks4://).
            if s.contains("://") {
                return None;
            }
            s
        };

        let (username, password, hostport) = match s.rsplit_once('@') {
            Some((auth, hp)) => {
                let (u, p) = auth.split_once(':').unwrap_or((auth, ""));
                (Some(u.to_string()), Some(p.to_string()), hp)
            }
            None => (None, None, s),
        };

        let (host, port) = hostport.rsplit_once(':')?;
        let port = port.parse::<u16>().ok()?;
        let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
        if host.is_empty() {
            return None;
        }

        Some(Socks5Proxy {
            host,
            port,
            username,
            password,
        })
    }

    /// Establish a TCP connection to `(target_host, target_port)` *through* this
    /// proxy. DNS for the target is resolved by the proxy (ATYP=3 domain).
    pub fn connect(&self, target_host: &str, target_port: u16) -> std::io::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.host.as_str(), self.port))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // ---- handshake: methods ----
        let methods: Vec<u8> = if self.username.is_some() {
            vec![0x00, 0x02]
        } else {
            vec![0x00]
        };
        let mut greet = vec![0x05u8, methods.len() as u8];
        greet.extend_from_slice(&methods);
        stream.write_all(&greet)?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp)?;
        if resp[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks5: bad version in server greeting",
            ));
        }
        match resp[1] {
            0x00 => {} // no authentication required
            0x02 => {
                let u = self.username.as_deref().unwrap_or("");
                let p = self.password.as_deref().unwrap_or("");
                let mut auth = vec![0x01u8, u.len() as u8];
                auth.extend_from_slice(u.as_bytes());
                auth.push(p.len() as u8);
                auth.extend_from_slice(p.as_bytes());
                stream.write_all(&auth)?;
                let mut aresp = [0u8; 2];
                stream.read_exact(&mut aresp)?;
                if aresp[0] != 0x01 || aresp[1] != 0x00 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "socks5: username/password auth failed",
                    ));
                }
                debug!("socks5: authenticated to proxy");
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("socks5: unsupported auth method {other}"),
                ))
            }
        }

        // ---- CONNECT request ----
        let mut req = vec![0x05u8, 0x01, 0x00];
        if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = target_host.parse::<std::net::Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        } else {
            // domain — proxy performs the DNS resolution (socks5h semantics)
            let bytes = target_host.as_bytes();
            req.push(0x03);
            req.push(bytes.len() as u8);
            req.extend_from_slice(bytes);
        }
        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req)?;

        // ---- CONNECT reply ----
        let mut head = [0u8; 4];
        stream.read_exact(&mut head)?;
        if head[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks5: bad version in connect reply",
            ));
        }
        if head[1] != 0x00 {
            let reason = match head[1] {
                0x01 => "general failure",
                0x02 => "connection not allowed by ruleset",
                0x03 => "network unreachable",
                0x04 => "host unreachable",
                0x05 => "connection refused",
                0x06 => "TTL expired",
                0x07 => "command not supported",
                0x08 => "address type not supported",
                _ => "unknown",
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("socks5: CONNECT failed ({reason})"),
            ));
        }
        // consume the bound address the proxy sends back
        match head[3] {
            0x01 => {
                let mut b = [0u8; 6];
                stream.read_exact(&mut b)?;
            }
            0x04 => {
                let mut b = [0u8; 18];
                stream.read_exact(&mut b)?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                let mut b = vec![0u8; len[0] as usize];
                stream.read_exact(&mut b)?;
            }
            _ => {}
        }

        debug!(
            "socks5: tunnel established to {}:{} via {}:{}",
            target_host, target_port, self.host, self.port
        );
        Ok(stream)
    }
}

/// Split a `host:port` (optionally `[ipv6]:port`) address into its parts.
pub fn split_host_port(addr: &str) -> (String, u16) {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port
        if let Some((host, port)) = rest.split_once("]:") {
            if let Ok(p) = port.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
        return (addr.to_string(), 0);
    }
    match addr.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (addr.to_string(), 0),
        },
        None => (addr.to_string(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Case {
        name: &'static str,
        in_spec: &'static str,
        want_host: &'static str,
        want_port: u16,
        want_user: Option<&'static str>,
        want_pass: Option<&'static str>,
        want_err: bool,
    }

    #[test]
    fn parse_socks5() {
        let cases = vec![
            Case {
                name: "bare host:port",
                in_spec: "127.0.0.1:1080",
                want_host: "127.0.0.1",
                want_port: 1080,
                want_user: None,
                want_pass: None,
                want_err: false,
            },
            Case {
                name: "with auth",
                in_spec: "alice:s3cret@127.0.0.1:1080",
                want_host: "127.0.0.1",
                want_port: 1080,
                want_user: Some("alice"),
                want_pass: Some("s3cret"),
                want_err: false,
            },
            Case {
                name: "socks5 scheme",
                in_spec: "socks5://1.2.3.4:1080",
                want_host: "1.2.3.4",
                want_port: 1080,
                want_user: None,
                want_pass: None,
                want_err: false,
            },
            Case {
                name: "socks5h scheme",
                in_spec: "socks5h://1.2.3.4:1080",
                want_host: "1.2.3.4",
                want_port: 1080,
                want_user: None,
                want_pass: None,
                want_err: false,
            },
            Case {
                name: "scheme with auth",
                in_spec: "socks5://bob:pw@1.2.3.4:1080",
                want_host: "1.2.3.4",
                want_port: 1080,
                want_user: Some("bob"),
                want_pass: Some("pw"),
                want_err: false,
            },
            Case {
                name: "ipv6",
                in_spec: "[::1]:1080",
                want_host: "::1",
                want_port: 1080,
                want_user: None,
                want_pass: None,
                want_err: false,
            },
            Case {
                name: "empty password",
                in_spec: "user:@127.0.0.1:1080",
                want_host: "127.0.0.1",
                want_port: 1080,
                want_user: Some("user"),
                want_pass: Some(""),
                want_err: false,
            },
            Case {
                name: "surrounding whitespace",
                in_spec: "  127.0.0.1:1080  ",
                want_host: "127.0.0.1",
                want_port: 1080,
                want_user: None,
                want_pass: None,
                want_err: false,
            },
            Case {
                name: "empty string",
                in_spec: "",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
            Case {
                name: "whitespace only",
                in_spec: "   ",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
            Case {
                name: "missing port",
                in_spec: "127.0.0.1",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
            Case {
                name: "http scheme must be rejected",
                in_spec: "http://1.2.3.4:8080",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
            Case {
                name: "socks4 scheme must be rejected",
                in_spec: "socks4://1.2.3.4:1080",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
            Case {
                name: "scheme missing host",
                in_spec: "socks5://",
                want_host: "",
                want_port: 0,
                want_user: None,
                want_pass: None,
                want_err: true,
            },
        ];

        for c in cases {
            let parsed = Socks5Proxy::parse(c.in_spec);
            if c.want_err {
                assert!(
                    parsed.is_none(),
                    "case '{}': expected err, got {:?}",
                    c.name,
                    parsed
                );
                continue;
            }
            let p = parsed.unwrap_or_else(|| panic!("case '{}': expected ok, got None", c.name));
            assert_eq!(p.host, c.want_host, "case '{}': host", c.name);
            assert_eq!(p.port, c.want_port, "case '{}': port", c.name);
            assert_eq!(
                p.username.as_deref(),
                c.want_user,
                "case '{}': user",
                c.name
            );
            assert_eq!(
                p.password.as_deref(),
                c.want_pass,
                "case '{}': pass",
                c.name
            );
        }
    }

    #[test]
    fn split_host_port_ok() {
        assert_eq!(
            split_host_port("1.2.3.4:4000"),
            ("1.2.3.4".to_string(), 4000)
        );
        assert_eq!(split_host_port("[::1]:4000"), ("::1".to_string(), 4000));
        assert_eq!(
            split_host_port("host.example.com:9000"),
            ("host.example.com".to_string(), 9000)
        );
    }
}
