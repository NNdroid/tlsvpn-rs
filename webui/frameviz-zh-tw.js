(() => {
  'use strict';
  if ((localStorage.getItem('tlsvpn_lang') || 'zh-CN') !== 'zh-TW') return;
  const root = document.getElementById('frameviz-card');
  if (!root) return;
  const map = new Map([
    ['Frame format example','訊框格式範例'],['Example data · not a live capture','範例資料 · 非即時封包擷取'],
    ['Original payload','原始承載資料'],['Enabled · Tag 16 B','啟用 · 標籤 16 B'],['Bucket padding','Bucket 填充'],
    ['TLSVPN frame inside TLS plaintext','TLS 明文中的 TLSVPN 訊框'],['Click a block to inspect its fields','點選區塊查看欄位詳情'],
    ['Example frame','範例訊框'],['Header','訊框標頭'],['AES-GCM ciphertext','AES-GCM 密文'],
    ['GCM authentication tag','GCM 驗證標籤'],['Random-pool padding','隨機池填充'],
    ['Original payload → AES-GCM → 10B header → pad to bucket → TLS','原始承載資料 → AES-GCM → 10B 訊框標頭 → 填充至 bucket → TLS']
  ]);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const s = n.nodeValue.trim();
    if (map.has(s)) n.nodeValue = n.nodeValue.replace(s, map.get(s));
  }
  const desc = root.querySelector('#fv-desc');
  if (desc) desc.textContent = '10 位元組訊框標頭描述後續資料與填充邊界。dataLen 包含 GCM tag，但不包含 padding。';
})();
