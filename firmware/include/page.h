#pragma once

// Served at "/". Shows only the wafq of each message; `decode <passphrase>`
// decrypts in the browser (plain HTTP has no WebCrypto, so noble from jsDelivr).
static const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wafq</title>
<style>
:root { --ink:#10122b; --gold:#e8c170; --dim:#8a7a55; }
* { box-sizing:border-box; }
body { margin:0; background:var(--ink); color:var(--gold); font:16px/1.5 ui-monospace,Consolas,monospace; }
main { max-width:560px; margin:0 auto; padding:24px 16px 96px; }
h1 { font-size:14px; font-weight:normal; color:var(--dim); letter-spacing:.2em; margin:0 0 24px; }
.msg { margin:0 0 32px; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); max-width:320px; border:1px solid var(--gold); }
.grid div { aspect-ratio:4/3; display:flex; align-items:center; justify-content:center; border:1px solid color-mix(in srgb,var(--gold) 40%,transparent); font-size:20px; }
.meta { color:var(--dim); font-size:13px; margin-top:6px; }
.text { margin-top:10px; font-size:18px; unicode-bidi:plaintext; overflow-wrap:anywhere; }
.empty { color:var(--dim); }
form { position:fixed; left:0; right:0; bottom:0; background:var(--ink); border-top:1px solid var(--dim); }
form div { max-width:560px; margin:0 auto; padding:12px 16px; display:flex; gap:8px; align-items:baseline; }
input { flex:1; min-width:0; background:transparent; border:0; color:var(--gold); font:inherit; outline:none; }
#out { color:var(--dim); font-size:13px; }
</style>
</head>
<body>
<main>
<h1>وفق · WAFQ</h1>
<div id="list"><p class="empty">No messages yet.</p></div>
</main>
<form id="f"><div><span>&gt;</span><input id="cmd" autocomplete="off" spellcheck="false" autofocus aria-label="command"><span id="out"></span></div></form>
<script type="module">
import { gcm } from 'https://cdn.jsdelivr.net/npm/@noble/ciphers@1.3.0/aes.js/+esm';
import { pbkdf2Async } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/pbkdf2.js/+esm';
import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.8.0/sha2.js/+esm';

const SALT = 'abjad-talisman-v1', ITER = 50000, MAGIC = new TextEncoder().encode('ABJ1');
const BASE = [8,11,14,1,13,2,7,12,3,16,9,6,10,5,4,15];
const wafq = (t) => t < 30 ? null : BASE.map((k) => k - 1 + Math.floor((t - 30) / 4) + (k >= 13 ? (t - 30) % 4 : 0));
const ar = (n) => String(n).replace(/\d/g, (d) => '٠١٢٣٤٥٦٧٨٩'[d]);
const hex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
const $ = (id) => document.getElementById(id);

let msgs = [], key = null, seen = '';

function reveal(m) {
  try {
    const p = hex(m.packet);
    const s = new TextDecoder().decode(gcm(key, p.slice(4, 16), MAGIC).decrypt(p.slice(16)));
    const i = s.indexOf('\n');
    return s.slice(0, i) + ': ' + s.slice(i + 1);
  } catch { return null; }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function render() {
  const list = $('list');
  list.replaceChildren();
  if (!msgs.length) return list.append(el('p', 'empty', 'No messages yet.'));
  for (const m of [...msgs].reverse()) {
    const box = el('section', 'msg'), sq = wafq(m.total);
    if (sq) {
      const g = el('div', 'grid');
      for (const n of sq) g.append(el('div', null, ar(n)));
      box.append(g);
    }
    box.append(el('div', 'meta', 'الجمل ' + ar(m.total) + (sq ? '' : ' · below 30, no wafq')));
    if (key) box.append(el('div', 'text', reveal(m) ?? '(sealed with another passphrase)'));
    list.append(box);
  }
}

async function poll() {
  try {
    const r = await fetch('/messages.json');
    const txt = await r.text();
    if (txt !== seen) { seen = txt; msgs = JSON.parse(txt); render(); }
  } catch {}
  setTimeout(poll, 3000);
}

$('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const line = $('cmd').value.trim();
  $('cmd').value = '';
  const [cmd, ...rest] = line.split(' ');
  if (cmd === 'decode' && rest.length) {
    $('out').textContent = 'deriving key…';
    const k = await pbkdf2Async(sha256, rest.join(' '), SALT, { c: ITER, dkLen: 32 });
    const prev = key; key = k;
    if (msgs.length && !msgs.some((m) => reveal(m))) { key = prev; $('out').textContent = 'wrong passphrase'; return; }
    $('out').textContent = '';
    render();
  } else if (cmd === 'hide') {
    key = null; $('out').textContent = ''; render();
  } else {
    $('out').textContent = 'decode <passphrase> · hide';
  }
});

poll();
</script>
</body>
</html>
)HTML";
