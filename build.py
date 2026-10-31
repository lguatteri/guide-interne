#!/usr/bin/env python3
"""Génère index.html (chiffré) à partir de src/guide.html (en clair, jamais publié).

Usage :  ./.venv/bin/python build.py            (le code est demandé)
         GUIDE_CODE=... ./.venv/bin/python build.py

Tout le contenu (texte, liens, captures) est chiffré en AES-GCM avec une clé
dérivée du code d'accès (PBKDF2-SHA256). Sans le code, index.html est illisible.
"""
import base64, getpass, json, mimetypes, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).parent
SRC = ROOT / "src" / "guide.html"
OUT = ROOT / "index.html"
ITER = 600_000

code = os.environ.get("GUIDE_CODE") or getpass.getpass("Code d'accès : ")
if len(code) < 4:
    sys.exit("Code trop court.")

src = SRC.read_text(encoding="utf-8")

# Captures intégrées en data: URI pour qu'elles soient chiffrées elles aussi
def inline(m):
    p = ROOT / "src" / m.group(1)
    mime = mimetypes.guess_type(p.name)[0] or "image/png"
    return f'src="data:{mime};base64,{base64.b64encode(p.read_bytes()).decode()}"'
src = re.sub(r'src="(img/[^"]+)"', inline, src)

# En-tête en clair : <title>, meta, polices, <style>
split = src.index("</style>") + len("</style>")
head, body = src[:split], src[split:]
m = re.search(r"<script>(.*)</script>\s*$", body, re.S)
js, html = m.group(1), body[: m.start()]

payload = json.dumps({"html": html, "js": js}).encode()
salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(code.encode())
ct = AESGCM(key).encrypt(iv, payload, None)
blob = {k: base64.b64encode(v).decode() for k, v in (("s", salt), ("i", iv), ("c", ct))}
blob["n"] = ITER

LOCK = """
<style>
.lock{min-height:80vh;display:flex;align-items:center;justify-content:center;padding-inline:18px}
.lock form{width:100%;max-width:340px;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:24px 20px}
.lock h1{font-family:var(--serif);font-weight:600;font-size:28px;margin:0 0 6px}
.lock p{margin:0 0 16px;color:var(--muted);font-size:15px}
.lock input{width:100%;font:18px var(--sans);padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--paper);color:var(--ink);margin:0 0 10px}
.lock button{width:100%;font:700 16px var(--sans);padding:12px;border:0;border-radius:10px;background:var(--solid);color:var(--solid-ink);cursor:pointer}
.lock .err{color:var(--warn);font-size:14.5px;min-height:1.4em;margin:8px 0 0}
</style>
<div class="lock" id="lock">
  <form id="lockform" autocomplete="off">
    <p class="eyebrow">Psychiatrie · Intra · ACH</p>
    <h1>Guide de l'interne</h1>
    <p>Entrez le code d'accès communiqué par le service.</p>
    <input id="code" type="password" autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="Code d'accès" required>
    <button type="submit" id="go">Entrer</button>
    <p class="err" id="err" role="alert"></p>
  </form>
</div>
<script>
const BLOB = __BLOB__;
(function(){
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function open(code){
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:b64(BLOB.s), iterations:BLOB.n, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:b64(BLOB.i)}, key, b64(BLOB.c));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  function show(p){
    document.getElementById('lock').remove();
    document.body.insertAdjacentHTML('beforeend', p.html);
    new Function(p.js)();
  }
  const form = document.getElementById('lockform'), err = document.getElementById('err'), btn = document.getElementById('go');
  let saved = null; try { saved = localStorage.getItem('guide-code'); } catch(e){}
  if (saved) open(saved).then(show).catch(() => { try { localStorage.removeItem('guide-code'); } catch(e){} });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const code = document.getElementById('code').value.trim();
    btn.disabled = true; btn.textContent = 'Ouverture…'; err.textContent = '';
    try {
      const p = await open(code);
      try { localStorage.setItem('guide-code', code); } catch(e){}
      show(p);
    } catch(x) {
      err.textContent = 'Code incorrect.'; btn.disabled = false; btn.textContent = 'Entrer';
    }
  });
})();
</script>
"""

PRE = '<!doctype html>\n<html lang="fr">\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover">\n<link rel="manifest" href="manifest.webmanifest">\n<link rel="apple-touch-icon" href="apple-touch-icon.png">\n<link rel="icon" href="icon-192.png">\n<meta name="apple-mobile-web-app-capable" content="yes">\n<meta name="mobile-web-app-capable" content="yes">\n<meta name="apple-mobile-web-app-status-bar-style" content="default">\n<meta name="apple-mobile-web-app-title" content="Guide interne">\n'
OUT.write_text(PRE + head + LOCK.replace("__BLOB__", json.dumps(blob)), encoding="utf-8")
print(f"OK : {OUT.name} ({OUT.stat().st_size // 1024} Ko)")
