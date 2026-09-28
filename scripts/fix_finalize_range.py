from pathlib import Path

p = Path("src/api.rs")
s = p.read_text()
old = '''                    .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("range=")))
                    .unwrap_or("2m");
                respond_json(request, ctx.web.trend_json(range).to_string(), 200);
'''
new = '''                    .and_then(|(_, q)| q.split('&').find_map(|kv| kv.strip_prefix("range=")))
                    .unwrap_or("2m")
                    .to_string();
                respond_json(request, ctx.web.trend_json(&range).to_string(), 200);
'''
if s.count(old) != 1:
    raise SystemExit(f"expected one borrowed range block, got {s.count(old)}")
p.write_text(s.replace(old, new, 1))

p = Path("tests/dashboard_script_test.rs")
s = p.read_text()
old = '        "trend_json(range)",\n'
new = '        "trend_json(&range)",\n'
if s.count(old) != 1:
    raise SystemExit(f"expected one old trend marker, got {s.count(old)}")
s = s.replace(old, new, 1)
old = '    assert!(server.contains("global_tx_bytes: global_tx_bytes"));\n'
new = '    assert!(server.contains("\\\"global_tx_bytes\\\": global_tx_bytes"));\n'
if s.count(old) != 1:
    raise SystemExit(f"expected one old global counter marker, got {s.count(old)}")
p.write_text(s.replace(old, new, 1))
