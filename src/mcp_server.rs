//! MCP 服务端（对齐 Go mcp_server.go）。
//!
//! 与 Go 的 mark3labs/mcp-go 不同，这里在 tiny_http 的同步请求循环里手写
//! JSON-RPC 分发：Rust 的 Web 层是同步单线程 tiny_http，引入 tokio 异步
//! transport 需要另起运行时与 HTTP 栈，与现有架构不符。MCP streamable-http
//! 的最小契约是 POST 单请求→单响应，这里实现该子集（无 SSE 长连接）。
//!
//! 数据源与 Go WebManager 对齐：`WebStatsProvider`（stats_json/control）、
//! `RuntimeCtx`（config/events/diagnostics/trend）、`log_ring_snapshot`、
//! `EventHub`、`DiagnosticHistory`。写工具经由 `provider.control()`，与
//! WebUI /api/control 复用同一动作面。

use std::sync::Arc;

use serde_json::{json, Value};

use crate::api::{log_ring_snapshot, RuntimeCtx, WebStatsProvider};
use crate::web_parity::DashboardEvent;

/// MCP 上下文：web 层把 provider 与 RuntimeCtx 传给 MCP 分发器。
pub struct McpCtx {
    pub provider: Arc<dyn WebStatsProvider>,
    pub ctx: Arc<RuntimeCtx>,
}

/// 单个 MCP 工具描述（tools/list 返回）。
struct Tool {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    handler: fn(&McpCtx, &Value) -> Result<Value, String>,
}

fn empty_schema() -> Value {
    json!({"type": "object", "properties": {}, "additionalProperties": false})
}

fn range_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"range": {"type": "string", "description": "2m, 1h or 24h (default 1h)"}},
        "additionalProperties": false,
    })
}

fn cursor_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "after": {"type": "integer", "description": "incremental sequence cursor"},
            "limit": {"type": "integer", "description": "1..1000 (default 200)"},
        },
        "additionalProperties": false,
    })
}

fn client_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"client_id": {"type": "string", "description": "client identifier"}},
        "required": ["client_id"],
        "additionalProperties": false,
    })
}

fn ban_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "client_id": {"type": "string", "description": "client identifier"},
            "ttl_minutes": {"type": "integer", "description": "0 (permanent) or 1..10080"},
        },
        "required": ["client_id"],
        "additionalProperties": false,
    })
}

fn log_level_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"level": {"type": "string", "description": "trace|debug|info|warn|error"}},
        "required": ["level"],
        "additionalProperties": false,
    })
}

fn config_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "config": {"type": "object", "description": "complete configuration"},
            "apply": {"type": "boolean", "description": "hot-apply settings that support runtime reload"},
        },
        "required": ["config"],
        "additionalProperties": false,
    })
}

fn mcp_range(v: &str) -> Result<String, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" | "1h" => Ok("1h".into()),
        "2m" => Ok("2m".into()),
        "24h" => Ok("24h".into()),
        other => Err(format!("range must be one of 2m, 1h or 24h (got {other:?})")),
    }
}

fn mcp_limit(v: Option<i64>) -> Result<usize, String> {
    match v.unwrap_or(0) {
        0 => Ok(200),
        n if (1..=1000).contains(&n) => Ok(n as usize),
        n => Err(format!("limit must be between 1 and 1000 (got {n})")),
    }
}

/// 读工具：tlsvpn_status（完整运行状态快照）。
fn tool_status(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    Ok(ctx.provider.stats_json())
}

/// 读工具：tlsvpn_connections（连接/会话/物理连接信息）。
fn tool_connections(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    let stats = ctx.provider.stats_json();
    let get = |key: &str| stats.get(key).cloned().unwrap_or(Value::Null);
    Ok(json!({
        "mode": get("mode"),
        "active_clients": get("active_clients"),
        "live_conns": get("live_conns"),
        "clients": get("clients"),
        "client_conns": get("conns"),
        "server_conns": get("server_conns"),
        "mac_table": get("mac_table"),
        "banned": get("banned"),
        "peer": get("peer"),
    }))
}

/// 读工具：tlsvpn_config_get（当前生效配置，敏感项已脱敏）。
fn tool_config_get(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    Ok(ctx.ctx.web.redacted_config())
}

/// 读工具：tlsvpn_diagnostics（诊断历史快照）。
fn tool_diagnostics(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let range = params.get("range").and_then(|v| v.as_str()).unwrap_or("");
    let rng = mcp_range(range)?;
    Ok(ctx.ctx.web.diagnostics_json(&rng))
}

/// 读工具：tlsvpn_traffic（吞吐与 RTT 趋势快照）。
fn tool_traffic(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let range = params.get("range").and_then(|v| v.as_str()).unwrap_or("");
    let rng = mcp_range(range)?;
    Ok(ctx.ctx.web.trend_json(&rng))
}

/// 读工具：tlsvpn_logs（内存日志环形缓冲，增量游标）。
fn tool_logs(_: &McpCtx, params: &Value) -> Result<Value, String> {
    let after = params.get("after").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = mcp_limit(params.get("limit").and_then(|v| v.as_i64()))?;
    let mut items = log_ring_snapshot(after);
    if items.len() > limit {
        items.truncate(limit);
    }
    let next = items.last().and_then(|l| l.get("seq").and_then(|s| s.as_u64())).unwrap_or(after);
    Ok(json!({"items": items, "next_after": next}))
}

/// 读工具：tlsvpn_events（生命周期/管理事件，增量游标）。
fn tool_events(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let after = params.get("after").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = mcp_limit(params.get("limit").and_then(|v| v.as_i64()))?;
    let events = ctx.ctx.web.events.snapshot(after);
    let items: Vec<Value> = events
        .into_iter()
        .map(event_to_json)
        .collect();
    let mut items = items;
    if items.len() > limit {
        items.truncate(limit);
    }
    let next = items
        .last()
        .and_then(|e| e.get("seq").and_then(|s| s.as_u64()))
        .unwrap_or(after);
    Ok(json!({"items": items, "next_after": next}))
}

fn event_to_json(ev: DashboardEvent) -> Value {
    json!({
        "seq": ev.seq,
        "kind": ev.kind,
        "level": ev.level,
        "time": ev.time,
        "client": ev.client,
        "msg": ev.msg,
    })
}

/// 读工具：tlsvpn_config_validate（校验配置但不写入，空脱敏值保留当前）。
fn tool_config_validate(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let Some(cfg) = params.get("config") else {
        return Err("config is required".into());
    };
    if !cfg.is_object() {
        return Err("config must be an object".into());
    }
    let merged = ctx.ctx.web.merge_preserving_secrets(cfg.clone());
    // 校验：这里做最小一致性检查（必须有 mode/psk 等关键字段），完整校验
    // 走 config 解析路径（Rust 无热更，config_validate 只做结构检查）。
    let missing: Vec<String> = ["mode", "psk"]
        .iter()
        .filter(|k| merged.get(**k).is_none())
        .map(|s| s.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(format!("config missing required fields: {}", missing.join(", ")));
    }
    let needs_restart = ctx.ctx.web.needs_restart();
    Ok(json!({
        "valid": true,
        "needs_restart": needs_restart,
        "config": ctx.ctx.web.redacted_config(),
    }))
}

/// 写工具：tlsvpn_set_log_level。
fn tool_set_log_level(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let level = params.get("level").and_then(|v| v.as_str()).unwrap_or("").trim();
    crate::api::set_runtime_log_level(level)?;
    let current = crate::api::current_log_level_name();
    ctx.ctx.web.events.emit("loglevel", "info", "", &format!("log level set to {current}"));
    Ok(json!({"level": current}))
}

/// 写工具：tlsvpn_force_reconnect（仅 client 模式）。
fn tool_force_reconnect(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    ctx.provider
        .control("reconnect", "", "", 0)
        .map_err(|e| if e == "Unknown action" {
            "force reconnect is only available in client mode".to_string()
        } else {
            e
        })?;
    ctx.ctx.web.events.emit("reconnect", "warn", "", "all tunnels torn down and re-dialed by MCP");
    Ok(json!({"reconnect_requested": true}))
}

/// 写工具：tlsvpn_kick_client（仅 server 模式）。
fn tool_kick_client(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let id = params.get("client_id").and_then(|v| v.as_str()).unwrap_or("").trim();
    if id.is_empty() {
        return Err("client_id is required".into());
    }
    ctx.provider
        .control("kick", id, "", 0)
        .map_err(|e| if e == "Unknown action" {
            "kick client is only available in server mode".to_string()
        } else {
            e
        })?;
    ctx.ctx.web.events.emit("kick", "warn", id, "all connections closed and the session dropped by MCP");
    Ok(json!({"client_id": id, "kicked": true}))
}

/// 写工具：tlsvpn_ban_client（仅 server 模式）。
fn tool_ban_client(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let id = params.get("client_id").and_then(|v| v.as_str()).unwrap_or("").trim();
    if id.is_empty() {
        return Err("client_id is required".into());
    }
    let ttl = params.get("ttl_minutes").and_then(|v| v.as_i64()).unwrap_or(0);
    if ttl < 0 || ttl > 7 * 24 * 60 {
        return Err("ttl_minutes must be 0 (permanent) or between 1 and 10080".into());
    }
    ctx.provider
        .control("ban", id, "", ttl)
        .map_err(|e| if e == "Unknown action" {
            "ban client is only available in server mode".to_string()
        } else {
            e
        })?;
    ctx.ctx.web.events.emit("ban", "warn", id, &format!("banned by MCP (ttl={ttl}m)"));
    Ok(json!({"client_id": id, "banned": true, "ttl_minutes": ttl}))
}

/// 写工具：tlsvpn_unban_client（仅 server 模式）。
fn tool_unban_client(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let id = params.get("client_id").and_then(|v| v.as_str()).unwrap_or("").trim();
    if id.is_empty() {
        return Err("client_id is required".into());
    }
    ctx.provider
        .control("unban", id, "", 0)
        .map_err(|e| if e == "Unknown action" {
            "unban client is only available in server mode".to_string()
        } else {
            e
        })?;
    ctx.ctx.web.events.emit("ban", "info", id, "unbanned by MCP");
    Ok(json!({"client_id": id, "banned": false}))
}

/// 写工具：tlsvpn_kick_all_clients（仅 server 模式）。
fn tool_kick_all(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    ctx.provider
        .control("kickall", "", "", 0)
        .map_err(|e| if e == "Unknown action" {
            "kick all clients is only available in server mode".to_string()
        } else {
            e
        })?;
    ctx.ctx.web.events.emit("kick", "warn", "", "all sessions dropped by MCP");
    Ok(json!({"kicked": true}))
}

/// 写工具：tlsvpn_gc（主动回收内存；Rust 侧为 no-op，与 /api/control 对齐）。
fn tool_gc(ctx: &McpCtx, _: &Value) -> Result<Value, String> {
    ctx.provider.control("gc", "", "", 0)?;
    ctx.ctx.web.events.emit("gc", "info", "", "manual memory reclaim by MCP");
    Ok(json!({"gc_triggered": true}))
}

/// 写工具：tlsvpn_config_save（校验并原子保存；Rust 无热更，apply 仅保留标记）。
fn tool_config_save(ctx: &McpCtx, params: &Value) -> Result<Value, String> {
    let Some(cfg) = params.get("config") else {
        return Err("config is required".into());
    };
    if !cfg.is_object() {
        return Err("config must be an object".into());
    }
    let apply = params.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
    let merged = ctx.ctx.web.merge_preserving_secrets(cfg.clone());
    let missing: Vec<String> = ["mode", "psk"]
        .iter()
        .filter(|k| merged.get(**k).is_none())
        .map(|s| s.to_string())
        .collect();
    if !missing.is_empty() {
        return Err(format!("config missing required fields: {}", missing.join(", ")));
    }
    // 原子写配置文件（对齐 Go SaveConfigFile）。
    let path = ctx.ctx.web.config_path();
    crate::web_parity::atomic_write_json(path, &merged)?;
    ctx.ctx.web.replace_config(merged);
    let needs_restart = ctx.ctx.web.needs_restart();
    ctx.ctx.web.events.emit(
        "config",
        "info",
        "",
        &format!("mcp save (apply={apply}, needs_restart={})", needs_restart.is_empty()),
    );
    Ok(json!({
        "saved": true,
        "applied": false,
        "needs_restart": needs_restart,
        "config": ctx.ctx.web.redacted_config(),
    }))
}

fn tool_registry() -> Vec<Tool> {
    vec![
        Tool {
            name: "tlsvpn_status",
            description: "Return the complete live tlsvpn status snapshot for the current server or client process.",
            input_schema: empty_schema(),
            handler: tool_status,
        },
        Tool {
            name: "tlsvpn_connections",
            description: "Return active client/session/physical-connection information, including bans and MAC table state where available. Each connection detail carries its negotiated TLS fingerprint (fingerprint_sha256) and, on the client side, the server certificate SHA-256 (cert_sha256).",
            input_schema: empty_schema(),
            handler: tool_connections,
        },
        Tool {
            name: "tlsvpn_config_get",
            description: "Return the currently effective configuration with PSK, Web authentication and SOCKS5 credentials redacted.",
            input_schema: empty_schema(),
            handler: tool_config_get,
        },
        Tool {
            name: "tlsvpn_diagnostics",
            description: "Return sampled diagnostic history for 2m, 1h or 24h.",
            input_schema: range_schema(),
            handler: tool_diagnostics,
        },
        Tool {
            name: "tlsvpn_traffic",
            description: "Return throughput and RTT trend samples for 2m, 1h or 24h.",
            input_schema: range_schema(),
            handler: tool_traffic,
        },
        Tool {
            name: "tlsvpn_logs",
            description: "Read the in-memory log ring using an incremental sequence cursor.",
            input_schema: cursor_schema(),
            handler: tool_logs,
        },
        Tool {
            name: "tlsvpn_events",
            description: "Read tlsvpn lifecycle and administration events using an incremental sequence cursor.",
            input_schema: cursor_schema(),
            handler: tool_events,
        },
        Tool {
            name: "tlsvpn_config_validate",
            description: "Validate a complete configuration without writing or applying it. Empty redacted secrets preserve the current values.",
            input_schema: config_schema(),
            handler: tool_config_validate,
        },
        Tool {
            name: "tlsvpn_set_log_level",
            description: "Change the process runtime log level.",
            input_schema: log_level_schema(),
            handler: tool_set_log_level,
        },
        Tool {
            name: "tlsvpn_force_reconnect",
            description: "Client mode only: tear down all current tunnel connections and redial them.",
            input_schema: empty_schema(),
            handler: tool_force_reconnect,
        },
        Tool {
            name: "tlsvpn_kick_client",
            description: "Server mode only: disconnect one client session.",
            input_schema: client_schema(),
            handler: tool_kick_client,
        },
        Tool {
            name: "tlsvpn_ban_client",
            description: "Server mode only: ban a client identifier for a bounded TTL and disconnect it if active.",
            input_schema: ban_schema(),
            handler: tool_ban_client,
        },
        Tool {
            name: "tlsvpn_unban_client",
            description: "Server mode only: remove a client identifier from the ban list.",
            input_schema: client_schema(),
            handler: tool_unban_client,
        },
        Tool {
            name: "tlsvpn_kick_all_clients",
            description: "Server mode only: disconnect every active client session.",
            input_schema: empty_schema(),
            handler: tool_kick_all,
        },
        Tool {
            name: "tlsvpn_gc",
            description: "Force as much unused memory as possible to be reclaimed. In Rust this is a no-op aligned with the WebUI control surface.",
            input_schema: empty_schema(),
            handler: tool_gc,
        },
        Tool {
            name: "tlsvpn_config_save",
            description: "Validate and atomically save a complete configuration. Hot-apply of reloadable settings is not available in the Rust port.",
            input_schema: config_schema(),
            handler: tool_config_save,
        },
    ]
}

// ======================= 资源与提示词 =======================

const RESOURCES: [(&str, &str); 5] = [
    ("tlsvpn://status", "live status snapshot"),
    ("tlsvpn://connections", "connection details snapshot"),
    ("tlsvpn://config", "redacted effective configuration"),
    ("tlsvpn://diagnostics", "diagnostic history (1h)"),
    ("tlsvpn://traffic", "throughput and RTT trend (1h)"),
];

fn read_resource(ctx: &McpCtx, uri: &str) -> Result<Value, String> {
    let value = match uri {
        "tlsvpn://status" => ctx.provider.stats_json(),
        "tlsvpn://connections" => tool_connections(ctx, &json!({}))?,
        "tlsvpn://config" => ctx.ctx.web.redacted_config(),
        "tlsvpn://diagnostics" => ctx.ctx.web.diagnostics_json("1h"),
        "tlsvpn://traffic" => ctx.ctx.web.trend_json("1h"),
        other => return Err(format!("unknown resource {other:?}")),
    };
    Ok(json!({
        "contents": [{"uri": uri, "mimeType": "application/json", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())}],
    }))
}

struct Prompt {
    name: &'static str,
    description: &'static str,
    argument: (&'static str, &'static str),
    body: &'static str,
    focus: &'static str,
}

const PROMPTS: [Prompt; 3] = [
    Prompt {
        name: "diagnose_tlsvpn",
        description: "Evidence-driven tlsvpn diagnosis",
        argument: ("focus", "optional symptom or subsystem to focus on"),
        body: "Diagnose this tlsvpn instance. Read tlsvpn_status, tlsvpn_diagnostics, tlsvpn_events and relevant recent tlsvpn_logs first. Correlate tunnel, FEC, scheduler, TCP, route, TAP, memory and protection signals. Explain evidence, likely root cause and the least disruptive next action. Do not mutate state unless the user explicitly asks.",
        focus: " Focus especially on: ",
    },
    Prompt {
        name: "optimize_tlsvpn",
        description: "Conservative tlsvpn optimization workflow",
        argument: ("goal", "optional optimization goal such as throughput, latency, reliability, or memory"),
        body: "Optimize this tlsvpn instance conservatively. Inspect tlsvpn_status, tlsvpn_traffic, tlsvpn_diagnostics and tlsvpn_config_get. Separate observed bottlenecks from guesses. For configuration changes, call tlsvpn_config_validate before tlsvpn_config_save, explain any needs_restart fields, and avoid disruptive actions without explicit approval.",
        focus: " Primary goal: ",
    },
    Prompt {
        name: "security_audit_tlsvpn",
        description: "Read-only tlsvpn security audit",
        argument: ("scope", "optional security audit scope"),
        body: "Audit this tlsvpn instance for operational security. Inspect the redacted effective configuration, protection counters, bans, connections, recent events and logs. Pay attention to exposed Web/MCP binding, TLS, authentication, PSK failures, spoofing/drop counters and unexpected peers. Do not reveal secrets or change state unless explicitly requested.",
        focus: " Scope: ",
    },
];

fn get_prompt(ctx: &McpCtx, name: &str, args: &Value) -> Result<Value, String> {
    let prompt = PROMPTS
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("unknown prompt {name:?}"))?;
    let arg_name = prompt.argument.0;
    let arg_value = args
        .get(arg_name)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let mut text = prompt.body.to_string();
    if !arg_value.is_empty() {
        text.push_str(prompt.focus);
        text.push_str(arg_value);
        text.push('.');
    }
    let _ = ctx; // prompts 不需要数据源
    Ok(json!({
        "description": prompt.description,
        "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
    }))
}

// ======================= JSON-RPC 分发 =======================

#[derive(serde::Deserialize)]
struct RpcRequest {
    #[serde(default)]
    #[allow(dead_code)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    method: String,
    #[serde(default)]
    params: Value,
}

fn tools_list() -> Value {
    let tools: Vec<Value> = tool_registry()
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    json!({"tools": tools})
}

fn resources_list() -> Value {
    let resources: Vec<Value> = RESOURCES
        .iter()
        .map(|(uri, desc)| json!({"uri": uri, "name": uri, "description": desc, "mimeType": "application/json"}))
        .collect();
    json!({"resources": resources})
}

fn prompts_list() -> Value {
    let prompts: Vec<Value> = PROMPTS
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "description": p.description,
                "arguments": [{"name": p.argument.0, "description": p.argument.1, "required": false}],
            })
        })
        .collect();
    json!({"prompts": prompts})
}

fn dispatch(ctx: &McpCtx, method: &str, params: &Value) -> Result<Value, String> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {},
            },
            "serverInfo": {"name": "tlsvpn-rs", "version": "0.1.0"},
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools_list()),
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let tool = tool_registry()
                .into_iter()
                .find(|t| t.name == name)
                .ok_or_else(|| format!("unknown tool {name:?}"))?;
            let result = (tool.handler)(ctx, &args)?;
            Ok(json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".into())}], "isError": false}))
        }
        "resources/list" => Ok(resources_list()),
        "resources/read" => {
            let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            read_resource(ctx, uri)
        }
        "prompts/list" => Ok(prompts_list()),
        "prompts/get" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            get_prompt(ctx, name, &args)
        }
        other => Err(format!("unsupported MCP method {other:?}")),
    }
}

/// 处理一个 MCP JSON-RPC 请求体，返回序列化响应体。
pub fn handle_mcp_request(ctx: &McpCtx, body: &[u8]) -> String {
    let req: RpcRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": format!("parse error: {e}")},
            }))
            .unwrap_or_default();
        }
    };
    // 通知（无 id）不要求响应；但为简化，这里统一返回响应（id 为 null 时仍应答）。
    match dispatch(ctx, &req.method, &req.params) {
        Ok(result) => serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "result": result,
        }))
        .unwrap_or_default(),
        Err(e) => serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": req.id,
            "error": {"code": -32603, "message": e},
        }))
        .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubProvider;
    impl WebStatsProvider for StubProvider {
        fn stats_json(&self) -> Value {
            json!({
                "mode": "server",
                "active_clients": 2,
                "live_conns": 4,
                "clients": json!([{"client_id": "c1"}]),
                "conns": json!([{"conn_id": "p1"}]),
                "server_conns": json!([]),
                "mac_table": json!({}),
                "banned": json!({}),
                "peer": Value::Null,
            })
        }
        fn metrics_text(&self) -> String {
            String::new()
        }
        fn control(&self, action: &str, _client_id: &str, _level: &str, _ttl: i64) -> Result<(), String> {
            match action {
                "kick" | "ban" | "unban" | "kickall" | "reconnect" | "gc" | "loglevel" | "pad_mode" => Ok(()),
                _ => Err("Unknown action".into()),
            }
        }
    }

    fn test_ctx() -> McpCtx {
        McpCtx {
            provider: Arc::new(StubProvider),
            ctx: Arc::new(RuntimeCtx::default()),
        }
    }

    #[test]
    fn registry_has_all_sixteen_tools() {
        let tools = tool_registry();
        assert_eq!(tools.len(), 16, "expected 16 tools, got {}", tools.len());
        let names: Vec<&str> = tools.iter().map(|t| t.name).collect();
        for want in [
            "tlsvpn_status", "tlsvpn_connections", "tlsvpn_config_get",
            "tlsvpn_diagnostics", "tlsvpn_traffic", "tlsvpn_logs", "tlsvpn_events",
            "tlsvpn_config_validate", "tlsvpn_set_log_level", "tlsvpn_force_reconnect",
            "tlsvpn_kick_client", "tlsvpn_ban_client", "tlsvpn_unban_client",
            "tlsvpn_kick_all_clients", "tlsvpn_gc", "tlsvpn_config_save",
        ] {
            assert!(names.contains(&want), "missing tool {want}");
        }
    }

    #[test]
    fn dispatch_initialize_and_ping() {
        let ctx = test_ctx();
        let init = dispatch(&ctx, "initialize", &json!({})).unwrap();
        assert_eq!(init["serverInfo"]["name"], "tlsvpn-rs");
        let ping = dispatch(&ctx, "ping", &json!({})).unwrap();
        assert!(ping.is_object());
    }

    #[test]
    fn dispatch_tools_list_lists_all() {
        let ctx = test_ctx();
        let list = dispatch(&ctx, "tools/list", &json!({})).unwrap();
        let tools = list["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 16);
    }

    #[test]
    fn dispatch_tools_call_status() {
        let ctx = test_ctx();
        let result = dispatch(&ctx, "tools/call", &json!({"name": "tlsvpn_status", "arguments": {}})).unwrap();
        assert_eq!(result["isError"], false);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"mode\": \"server\""));
    }

    #[test]
    fn dispatch_unknown_tool_errors() {
        let ctx = test_ctx();
        let err = dispatch(&ctx, "tools/call", &json!({"name": "no_such_tool", "arguments": {}})).unwrap_err();
        assert!(err.contains("unknown tool"));
    }

    #[test]
    fn dispatch_unknown_method_errors() {
        let ctx = test_ctx();
        let err = dispatch(&ctx, "not/a/method", &json!({})).unwrap_err();
        assert!(err.contains("unsupported MCP method"));
    }

    #[test]
    fn jsonrpc_parse_error_returns_error_object() {
        let ctx = test_ctx();
        let resp = handle_mcp_request(&ctx, b"{not json");
        assert!(resp.contains("\"error\""));
        assert!(resp.contains("-32700"));
    }

    #[test]
    fn resources_and_prompts_list() {
        let ctx = test_ctx();
        let res = dispatch(&ctx, "resources/list", &json!({})).unwrap();
        assert_eq!(res["resources"].as_array().unwrap().len(), 5);
        let prompts = dispatch(&ctx, "prompts/list", &json!({})).unwrap();
        assert_eq!(prompts["prompts"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn write_tools_route_through_control() {
        let ctx = test_ctx();
        let r = dispatch(&ctx, "tools/call", &json!({"name": "tlsvpn_gc", "arguments": {}})).unwrap();
        assert_eq!(r["isError"], false);
        let r = dispatch(&ctx, "tools/call", &json!({"name": "tlsvpn_set_log_level", "arguments": {"level": "info"}})).unwrap();
        assert_eq!(r["isError"], false);
    }
}
