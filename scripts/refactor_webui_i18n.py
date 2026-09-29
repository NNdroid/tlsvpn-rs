from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def p(rel): return ROOT / rel
def read(rel): return p(rel).read_text(encoding='utf-8')
def write(rel, data): p(rel).write_text(data, encoding='utf-8')

app = read('webui/app.js')
marker = '\n// 浏览器语言'
if not app.startswith('const I18N={') or marker not in app:
    raise SystemExit('unexpected app.js i18n layout')
mi = app.index(marker)
dict_src = app[:mi].rstrip()
setseg = app.index('function setSeg(', mi)
setlang = app.index('function setLang(', setseg)
fmtdur = app.index('function fmtDur(', setlang)
helper_src = app[mi+1:setseg].rstrip() + '\n\n' + app[setlang:fmtdur].rstrip()
app_new = app[setseg:setlang] + app[fmtdur:]

metrics = read('webui/metrics.js')
ms = metrics.index('  function setSchedWords(')
me = metrics.rindex('\n})();')
metric_i18n = metrics[ms:me].rstrip()
metrics_new = metrics[:ms].rstrip() + '\n})();\n'

frame = read('webui/frameviz.js')
ls = frame.index('  const L={')
le = frame.index('  const s=L[lang]||L.en;')
frame_i18n = frame[ls:le].replace('  const L=', 'const FRAMEVIZ_I18N=', 1).rstrip()
fstart = frame.index('  const lang=')
send = frame.index('\n', le) + 1
frame_new = frame[:fstart] + '  const s=FRAMEVIZ_I18N[LANG]||FRAMEVIZ_I18N.en;\n' + frame[send:]

zh_tw = read('webui/zh-tw.js').rstrip()
i18n = ('// TLSVPN WebUI internationalization: single source of truth for all locales.\n'
        '// Loaded before app.js, metrics.js and frameviz.js.\n'
        + dict_src + '\n\n' + zh_tw + '\n\n'
        + '(() => {\n' + metric_i18n + '\n})();\n\n'
        + frame_i18n + '\n\n' + helper_src + '\n')
write('webui/i18n.js', i18n)
write('webui/app.js', app_new)
write('webui/metrics.js', metrics_new)
write('webui/frameviz.js', frame_new)

idx = read('webui/index.html')
if '<script src="i18n.js"></script>' not in idx:
    idx = idx.replace('<script src="app.js"></script>', '<script src="i18n.js"></script>\n<script src="app.js"></script>', 1)
idx = idx.replace('<script src="zh-tw.js"></script>\n', '')
idx = idx.replace('<script src="frameviz-zh-tw.js"></script>\n', '')
write('webui/index.html', idx)

assets = read('src/webui_assets.rs')
if '"/i18n.js"' not in assets:
    needle = '    match path {\n        "/app.js" => Some((\n'
    repl = '    match path {\n        "/i18n.js" => Some((\n            include_bytes!("../webui/i18n.js"),\n            "application/javascript; charset=utf-8",\n        )),\n        "/app.js" => Some((\n'
    if needle not in assets: raise SystemExit('webui_assets app route layout changed')
    assets = assets.replace(needle, repl, 1)
assets = re.sub(r'\n        "/frameviz-zh-tw\.js" => Some\(\(\n            include_bytes!\("\.\./webui/frameviz-zh-tw\.js"\),\n            "application/javascript; charset=utf-8",\n        \)\),', '', assets)
assets = re.sub(r'\n        "/zh-tw\.js" => Some\(\(\n            include_bytes!\("\.\./webui/zh-tw\.js"\),\n            "application/javascript; charset=utf-8",\n        \)\),', '', assets)
write('src/webui_assets.rs', assets)

ds = read('tests/dashboard_script_test.rs')
start = ds.index('#[test]\nfn webui_matches_shared_static_asset_contract()')
mid = ds.index('#[test]\nfn rust_embed_table_covers_primary_assets()', start)
end = ds.index('#[test]\nfn rust_webui_backend_matches_go_management_contract()', mid)
first = r'''#[test]
fn webui_matches_shared_static_asset_contract() {
    let root = webui();
    let index = fs::read_to_string(root.join("index.html")).expect("index.html");
    let app = fs::read_to_string(root.join("app.js")).expect("app.js");
    let i18n = fs::read_to_string(root.join("i18n.js")).expect("i18n.js");
    let css = fs::read_to_string(root.join("style.css")).expect("style.css");
    let frameviz = fs::read_to_string(root.join("frameviz.js")).expect("frameviz.js");
    assert!(index.contains("/favicon.ico"));
    let i18n_pos = index.find("src=\"i18n.js\"").expect("i18n.js script");
    let app_pos = index.find("src=\"app.js\"").expect("app.js script");
    assert!(i18n_pos < app_pos, "i18n.js must load before app.js");
    assert!(index.contains("data-v=\"zh-TW\""));
    assert!(!index.contains("zh-tw.js") && !index.contains("frameviz-zh-tw.js"));
    assert!(!app.contains("const I18N={"));
    for marker in ["const I18N={", "const FRAMEVIZ_I18N=", "'zh-CN'", "'zh-TW'", "'de'", "'fr'", "'ja'", "Frame format example", "FEC recovery rate"] {
        assert!(i18n.contains(marker), "i18n.js missing {marker:?}");
    }
    assert!(app.contains("platformAssetName"));
    assert!(app.contains("/api/stats"));
    assert!(css.contains("platform-badge"));
    for marker in ["FRAMEVIZ_I18N[LANG]", "AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305", "1514 B", "1530 B", "12 KiB", "16 KiB", "padLen=0", "4 B BE", "seq=0", "1 MiB"] {
        assert!(frameviz.contains(marker), "frameviz missing {marker:?}");
    }
    for file in ["favicon.ico", "i18n.js", "frameviz.js", "icons/os-linux.svg", "icons/os-windows.svg", "icons/os-macos.svg", "icons/os-android.svg", "icons/arch-x86_64.svg", "icons/arch-arm64.svg", "icons/arch-riscv64.svg"] {
        let meta = fs::metadata(root.join(file)).unwrap_or_else(|e| panic!("missing {file}: {e}"));
        assert!(meta.len() > 0, "empty asset: {file}");
    }
    for old in ["zh-tw.js", "frameviz-zh-tw.js"] { assert!(!root.join(old).exists(), "obsolete asset remains: {old}"); }
}

'''
second = r'''#[test]
fn rust_embed_table_covers_primary_assets() {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui_assets.rs")).expect("webui_assets.rs");
    for route in ["/", "/index.html", "/style.css", "/i18n.js", "/app.js", "/frameviz.js", "/metrics.js", "/favicon.ico", "/icons/os-linux.svg"] {
        assert!(src.contains(&format!("\"{route}\"")), "embed table missing {route}");
    }
    assert!(!src.contains("/zh-tw.js") && !src.contains("/frameviz-zh-tw.js"));
}

'''
write('tests/dashboard_script_test.rs', ds[:start] + first + second + ds[end:])

wm = read('tests/webui_metrics_test.rs')
old = 'let app = html.find("<script src=\\"app.js\\"></script>").expect("app.js script");'
if old in wm:
    wm = wm.replace(old, 'let i18n = html.find("<script src=\\"i18n.js\\"></script>").expect("i18n.js script");\n    let app = html.find("<script src=\\"app.js\\"></script>").expect("app.js script");\n    assert!(i18n < app, "i18n.js must load before app.js");', 1)
write('tests/webui_metrics_test.rs', wm)

for rel in ['webui/zh-tw.js', 'webui/frameviz-zh-tw.js']:
    q = p(rel)
    if q.exists(): q.unlink()

print('WebUI i18n refactor generated successfully')
