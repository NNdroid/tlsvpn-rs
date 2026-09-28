(() => {
  'use strict';
  // frameviz.js now ships native zh-TW strings together with the other locales.
  // Keep this tiny compatibility asset because older rendered index pages may still
  // reference it; it deliberately does not rewrite text anymore.
  if ((localStorage.getItem('tlsvpn_lang') || 'zh-CN') !== 'zh-TW') return;
  const root = document.getElementById('frameviz-card');
  if (root) root.dataset.framevizLocale = 'zh-TW';
})();
