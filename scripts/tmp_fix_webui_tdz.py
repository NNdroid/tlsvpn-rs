from pathlib import Path

p = Path('webui/i18n.js')
s = p.read_text(encoding='utf-8')
old = """  I18N['zh-TW'] = clone(I18N['zh-CN']);\n  if (typeof LANG !== 'undefined' && LANG === 'zh-TW' && typeof applyI18n === 'function') {\n    applyI18n();\n  }\n})();"""
new = """  I18N['zh-TW'] = clone(I18N['zh-CN']);\n})();"""
if s.count(old) != 1:
    raise SystemExit(f'expected exactly one TDZ block, found {s.count(old)}')
p.write_text(s.replace(old, new), encoding='utf-8')
Path('scripts/tmp_fix_webui_tdz.py').unlink()
Path('.github/workflows/tmp-fix-webui-tdz.yml').unlink()
