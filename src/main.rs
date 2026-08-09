use aes::Aes256;
use clap::Parser;
use tracing::error;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub mod api;
pub mod buffer;
pub mod client;
pub mod crypto;
pub mod frame;
pub mod net;
pub mod server;
pub mod socks5;
pub mod tap;
pub mod utils;

use crate::buffer::*;
use crate::client::*;
use crate::server::*;
use crate::utils::*;

#[derive(Parser, Debug)]
#[command(name = "tlsvpn", about = "Rust Implementation of TLSVPN", long_about = None)]
pub struct Args {
    #[arg(long, default_value = "", help = "server or client")]
    mode: String,
    #[arg(long, default_value = "quic_secret", help = "Pre-shared key")]
    psk: String,
    #[arg(long, default_value = "tap0", help = "Name of the TAP device")]
    tap: String,
    #[arg(long, default_value = "", help = "Specify MAC address for TAP device")]
    mac: String,
    #[arg(long, default_value = "0.0.0.0:4000", help = "Listen/Target address")]
    addr: String,
    #[arg(
        long,
        default_value = "info",
        help = "Log level (trace, debug, info, warn, error)"
    )]
    loglevel: String,
    #[arg(
        long,
        default_value = "10.0.0.0/24",
        help = "IPv4 CIDR block (Server only)"
    )]
    v4cidr: String,
    #[arg(
        long,
        default_value = "fd00::/64",
        help = "IPv6 CIDR block (Server only)"
    )]
    v6cidr: String,
    #[arg(long, default_value = "", help = "TLS Certificate file (Server only)")]
    cert: String,
    #[arg(long, default_value = "", help = "TLS Key file (Server only)")]
    key: String,
    #[arg(long, default_value = "", help = "Requested IPv4 (Client only)")]
    req_v4: String,
    #[arg(long, default_value = "", help = "Requested IPv6 (Client only)")]
    req_v6: String,
    #[arg(
        long,
        default_value = "www.cloudflare.com",
        help = "SNI for TLS (Client only)"
    )]
    sni: String,
    #[arg(long, default_value_t = false, help = "Skip TLS verify (Client only)")]
    insecure: bool,
    #[arg(
        long,
        default_value = "",
        help = "Verify server cert SHA256 (Client only)"
    )]
    cert_sha256: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "Policy routing fwmark (Client only)"
    )]
    fwmark: i32,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable TCP Brutal congestion control"
    )]
    brutal: bool,
    #[arg(long, default_value_t = 100, help = "Brutal upload rate limit in Mbps")]
    brutal_up: u64,
    #[arg(
        long,
        default_value_t = 500,
        help = "Brutal download rate limit in Mbps"
    )]
    brutal_down: u64,
    #[arg(
        long,
        default_value_t = 1,
        help = "Number of concurrent TCP connections"
    )]
    conns: i32,
    #[arg(long, default_value_t = false, help = "Enable Packet Duplication FEC")]
    fec: bool,
    #[arg(
        long,
        default_value = "",
        help = "Start Web Dashboard on specified address"
    )]
    web: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable inner payload AES-CTR XOR encryption"
    )]
    encrypt: bool,
    #[arg(
        long,
        default_value = "",
        help = "Use SOCKS5 proxy for the outbound connection (Client only). \
                Format: [user:pass@]host:port, socks5://host:port or socks5h://host:port"
    )]
    socks5: String,
}

fn main() {
    let args = Args::parse();
    init_logger(&args.loglevel);

    lazy_static::initialize(&PADDING_CACHE);

    if args.mode == "server" {
        start_server(&args);
    } else if args.mode == "client" {
        start_client(&args);
    } else {
        error!("Usage: tlsvpn --mode <server|client> [OPTIONS]");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;
    use crate::frame::*;

    #[test]
    #[ignore = "benchmark: long-running (1M iterations); run with `cargo test -- --ignored`"]
    fn bench_protocol_throughput() {
        use std::time::Instant;
        let (key, iv) = get_cipher_context("benchmark_secret_key");
        let payload = vec![0u8; 1400];

        let mut frame_buf = Vec::new();
        append_tls_frame(&mut frame_buf, 1, &payload, &key, &iv);

        struct InfiniteReader {
            data: Vec<u8>,
            pos: usize,
            reads: usize,
        }

        impl std::io::Read for InfiniteReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.reads > 0 {
                    self.reads = 0;
                    return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
                }
                let available = self.data.len() - self.pos;
                let to_copy = std::cmp::min(buf.len(), available);
                buf[..to_copy].copy_from_slice(&self.data[self.pos..self.pos + to_copy]);
                self.pos += to_copy;
                if self.pos >= self.data.len() {
                    self.pos = 0;
                }
                self.reads += 1;
                Ok(to_copy)
            }
        }

        let mut scanner = FrameScanner::new();
        let mut reader = InfiniteReader {
            data: frame_buf.clone(),
            pos: 0,
            reads: 0,
        };

        let iter_count = 1_000_000;
        let start = Instant::now();
        for _ in 0..iter_count {
            let (mut data, seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
            xor_crypt_in_place(&mut data, seq, &key, &iv);
            put_frame(data);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total_bytes = (iter_count as f64) * (payload.len() as f64);
        let mb_per_sec = (total_bytes / 1024.0 / 1024.0) / elapsed;
        println!("Protocol Throughput: {:.2} MB/s", mb_per_sec);
    }
}
