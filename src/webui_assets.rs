// WebUI asset embedding, synced byte-for-byte with the Go side (webui/webui.go
// + embed). Keep assets local and embedded; do not replace these with CDN URLs.
//
// 文件命名与 Go 完全一致（历史上的 metrics.js、stream.js、frameviz.js 是
// metric-corrections.js、sse.js、frame-visualizer.js 的改名旧副本，已归位）。

use std::sync::OnceLock;

fn index_html() -> &'static [u8] {
    static INDEX: OnceLock<Vec<u8>> = OnceLock::new();
    INDEX
        .get_or_init(|| {
            // 注入脚本列表与 Go webui.go 逐字对齐（顺序即加载顺序）。
            include_str!("../webui/index.html")
                .replace(
                    "</body>",
                    "<script src=\"frame-visualizer.js\"></script>\n<script src=\"metric-corrections.js\"></script>\n<script src=\"sse.js\"></script>\n<script src=\"scheduler-settings.js\"></script>\n<script src=\"mcp-settings.js\"></script>\n<script src=\"mcp-examples.js\"></script>\n</body>",
                )
                .into_bytes()
        })
        .as_slice()
}

pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    match path {
        "/i18n.js" => Some((
            include_bytes!("../webui/i18n.js"),
            "application/javascript; charset=utf-8",
        )),
        "/app.js" => Some((
            include_bytes!("../webui/app.js"),
            "application/javascript; charset=utf-8",
        )),
        "/metric-corrections.js" => Some((
            include_bytes!("../webui/metric-corrections.js"),
            "application/javascript; charset=utf-8",
        )),
        "/sse.js" => Some((
            include_bytes!("../webui/sse.js"),
            "application/javascript; charset=utf-8",
        )),
        "/frame-visualizer.js" => Some((
            include_bytes!("../webui/frame-visualizer.js"),
            "application/javascript; charset=utf-8",
        )),
        "/scheduler-settings.js" => Some((
            include_bytes!("../webui/scheduler-settings.js"),
            "application/javascript; charset=utf-8",
        )),
        "/mcp-settings.js" => Some((
            include_bytes!("../webui/mcp-settings.js"),
            "application/javascript; charset=utf-8",
        )),
        "/mcp-examples.js" => Some((
            include_bytes!("../webui/mcp-examples.js"),
            "application/javascript; charset=utf-8",
        )),
        "/tcp.js" => Some((
            include_bytes!("../webui/tcp.js"),
            "application/javascript; charset=utf-8",
        )),
        "/diagnostics.js" => Some((
            include_bytes!("../webui/diagnostics.js"),
            "application/javascript; charset=utf-8",
        )),
        "/favicon.ico" => Some((include_bytes!("../webui/favicon.ico"), "image/x-icon")),
        "/icons/arch-arm.svg" => Some((
            include_bytes!("../webui/icons/arch-arm.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-arm64.svg" => Some((
            include_bytes!("../webui/icons/arch-arm64.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-generic.svg" => Some((
            include_bytes!("../webui/icons/arch-generic.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-loong64.svg" => Some((
            include_bytes!("../webui/icons/arch-loong64.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-mips.svg" => Some((
            include_bytes!("../webui/icons/arch-mips.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-riscv64.svg" => Some((
            include_bytes!("../webui/icons/arch-riscv64.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-x86.svg" => Some((
            include_bytes!("../webui/icons/arch-x86.svg"),
            "image/svg+xml",
        )),
        "/icons/arch-x86_64.svg" => Some((
            include_bytes!("../webui/icons/arch-x86_64.svg"),
            "image/svg+xml",
        )),
        "/icons/os-android.svg" => Some((
            include_bytes!("../webui/icons/os-android.svg"),
            "image/svg+xml",
        )),
        "/icons/os-bsd.svg" => Some((include_bytes!("../webui/icons/os-bsd.svg"), "image/svg+xml")),
        "/icons/os-generic.svg" => Some((
            include_bytes!("../webui/icons/os-generic.svg"),
            "image/svg+xml",
        )),
        "/icons/os-linux.svg" => Some((
            include_bytes!("../webui/icons/os-linux.svg"),
            "image/svg+xml",
        )),
        "/icons/os-macos.svg" => Some((
            include_bytes!("../webui/icons/os-macos.svg"),
            "image/svg+xml",
        )),
        "/icons/os-windows.svg" => Some((
            include_bytes!("../webui/icons/os-windows.svg"),
            "image/svg+xml",
        )),
        "/" | "/index.html" => Some((index_html(), "text/html; charset=utf-8")),
        "/login" | "/login.html" => Some((
            include_bytes!("../webui/login.html"),
            "text/html; charset=utf-8",
        )),
        "/style.css" => Some((
            include_bytes!("../webui/style.css"),
            "text/css; charset=utf-8",
        )),
        _ => None,
    }
}
