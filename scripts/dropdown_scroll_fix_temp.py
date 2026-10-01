#!/usr/bin/env python3
from pathlib import Path
p=Path('webui/app.js')
s=p.read_text()
old="""// 页面滚动时 fixed 弹层不会跟着动，收起比留一个错位菜单强；菜单自己滚动不算
function dlScroll(ev){
  if(!dlCur)return;
  const st=DL.get(dlCur);
  if(st&&ev&&ev.target===st.menu)return;
  dlClose(dlCur);
}
"""
new="""// 页面滚动时重新计算 fixed 弹层位置；菜单自身滚动保持展开。
// 浏览器/辅助技术可能在展开后为目标选项自动滚动页面，若此处直接关闭会形成
// \"已打开 -> 自动滚动 -> 点击前关闭\" 的竞态，真实键盘/窄屏交互同样可能触发。
function dlScroll(ev){
  if(!dlCur)return;
  const sel=dlCur,st=DL.get(sel);
  if(!st)return;
  if(ev&&(ev.target===st.menu||st.menu.contains(ev.target)))return;
  requestAnimationFrame(function(){if(dlCur===sel)dlPlace(sel);});
}
"""
if old not in s:
    raise SystemExit('dropdown scroll block not found')
s=s.replace(old,new,1)
p.write_text(s)
print('patched dropdown scroll handling')
