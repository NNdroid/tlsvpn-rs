//! MCP 访问日志（对齐 Go mcp_access.go）。
//!
//! WebUI"近期 MCP 访问日志"面板与 SSE 通道共用的记录。与 LogRing/EventHub
//! 同构：seq 单调递增供断线增量续传，内存只留最近 500 条，长期留痕归日志
//! 文件，内存不随进程运行时长线性增长。
//!
//! 认证失败也入日志：谁在撞路径、撞凭据是公网暴露面最重要的审计信号。

use std::sync::Mutex;

const MCP_ACCESS_CAP: usize = 500;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct McpAccessLine {
    pub seq: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub time: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote: String,
    pub level: String, // info | warn | error
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub msg: String,
}

struct McpAccessRing {
    seq: u64,
    lines: Vec<McpAccessLine>,
    cap: usize,
}

impl McpAccessRing {
    fn new(cap: usize) -> Self {
        Self {
            seq: 0,
            lines: Vec::new(),
            cap,
        }
    }

    fn add(&mut self, mut line: McpAccessLine) {
        self.seq += 1;
        line.seq = self.seq;
        if line.time.is_empty() {
            line.time = crate::api::wall_clock_hms();
        }
        self.lines.push(line);
        if self.lines.len() > self.cap {
            let drop = self.lines.len() - self.cap;
            self.lines.drain(..drop);
        }
    }

    fn snapshot(&self, after: u64) -> Vec<McpAccessLine> {
        self.lines.iter().filter(|l| l.seq > after).cloned().collect()
    }
}

lazy_static::lazy_static! {
    static ref MCP_ACCESS: Mutex<McpAccessRing> = Mutex::new(McpAccessRing::new(MCP_ACCESS_CAP));
}

/// 追加一条 MCP 访问日志（线程安全；满则丢最旧）。
pub fn add_mcp_access(line: McpAccessLine) {
    MCP_ACCESS.lock().unwrap().add(line);
}

/// 返回 seq 大于 after 的记录，供面板首次打开或断线重连补齐空档。
pub fn mcp_access_snapshot(after: u64) -> Vec<McpAccessLine> {
    MCP_ACCESS.lock().unwrap().snapshot(after)
}

/// 提取 RemoteAddr 的主机部分（去端口），供访问日志审计"谁在访问"。
pub fn remote_host(remote: &str) -> String {
    if let Some((host, _)) = remote.rsplit_once(':') {
        // IPv6 的 [::1]:port 需要去掉方括号；简单场景只取最后一段冒号前。
        host.trim_start_matches('[').trim_end_matches(']').to_string()
    } else {
        remote.to_string()
    }
}

/// best-effort 解析 JSON-RPC 请求体，提取 method 与 tools/call 的工具名。
/// 解析失败返回 (空, 空)（不阻断请求）。
pub fn mcp_request_method(body: &[u8]) -> (String, String) {
    #[derive(serde::Deserialize)]
    struct Msg {
        #[serde(default)]
        method: String,
        #[serde(default)]
        params: Params,
    }
    #[derive(serde::Deserialize, Default)]
    struct Params {
        #[serde(default)]
        name: String,
    }
    if body.is_empty() {
        return (String::new(), String::new());
    }
    let Ok(msg) = serde_json::from_slice::<Msg>(body) else {
        return (String::new(), String::new());
    };
    let method = msg.method;
    if method == "tools/call" {
        return (method, msg.params.name);
    }
    (method, String::new())
}
