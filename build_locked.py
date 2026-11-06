#!/usr/bin/env python3
"""Tạo index.html có màn hình khóa mật khẩu từ omd8_source.html.
Cách dùng:  python build_locked.py "MẬT_KHẨU_CỦA_BẠN"
Cần:        pip install cryptography
Toàn bộ nội dung trang được MÃ HÓA AES-256-GCM (khóa sinh từ mật khẩu qua PBKDF2),
nên người xem mã nguồn trên GitHub cũng không đọc được nội dung nếu không có mật khẩu."""
import sys, os, re, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PASSWORD = sys.argv[1] if len(sys.argv) > 1 else "2026"   # <-- MẬT KHẨU MẶC ĐỊNH
ITER = 600000
src = open("omd8_source.html", encoding="utf-8").read()

style = re.search(r"<style>(.*?)</style>", src, re.S).group(1)
body = re.search(r"<body>(.*)</body>", src, re.S).group(1)
js = re.search(r"<script>(.*)</script>", body, re.S).group(1)
html = body[:body.rfind("<script>")].strip()

salt, iv = os.urandom(16), os.urandom(12)
key = PBKDF2HMAC(hashes.SHA256(), 32, salt, ITER).derive(PASSWORD.encode("utf-8"))
payload = json.dumps({"html": html, "js": js}, ensure_ascii=False).encode("utf-8")
ct = AESGCM(key).encrypt(iv, payload, None)  # ciphertext + tag
b64 = lambda b: base64.b64encode(b).decode()

LOCK_CSS = """
#lock{position:fixed;inset:0;z-index:9999;display:grid;place-items:center;padding:20px;
 background:radial-gradient(circle at 50% 0,#13306f,#07163a 65%);transition:opacity .6s ease,visibility .6s}
#lock.gone{opacity:0;visibility:hidden;pointer-events:none}
.lbox{width:100%;max-width:380px;text-align:center;background:rgba(12,33,82,.85);border:1px solid #b8923a;
 border-radius:18px;padding:34px 26px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.lbox .ico{width:76px;height:76px;margin:0 auto 14px;border-radius:50%;display:grid;place-items:center;font-size:34px;
 background:#0a1a45;border:2px solid #f5c542}
.lbox h1{margin:0 0 4px;font-size:22px;color:#f5c542;letter-spacing:.04em}
.lbox p{margin:0 0 20px;color:#9fb0d6;font-size:14px}
.lrow{position:relative}
#pw{width:100%;padding:13px 46px 13px 14px;border-radius:12px;border:1.5px solid #b8923a;background:#07163a;color:#eaf0ff;font-size:16px;outline:none}
#pw:focus{border-color:#f5c542;box-shadow:0 0 0 3px rgba(245,197,66,.25)}
#eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:#9fb0d6;font-size:18px;cursor:pointer;padding:6px 8px}
#go{width:100%;margin-top:14px;padding:13px;border:0;border-radius:24px;background:#f5c542;color:#1b1b1b;font-weight:800;font-size:16px;cursor:pointer}
#go:disabled{opacity:.6;cursor:wait}
#err{min-height:20px;margin-top:12px;color:#ff7a7a;font-size:14px;font-weight:600}
.shake{animation:shake .4s}
@keyframes shake{20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}
#app{opacity:0;transition:opacity .8s ease}
#app.show{opacity:1}
"""

LOCK_HTML = """<div id="lock"><form class="lbox" id="lf" autocomplete="off">
<div class="ico">🔒</div><h1>OMD8 PORTAL</h1><p>This page is protected.<br>Please enter the password to continue.</p>
<div class="lrow"><input id="pw" type="password" placeholder="Password" autocomplete="current-password" autofocus>
<button type="button" id="eye" aria-label="Show password">👁</button></div>
<button id="go" type="submit">Unlock</button><div id="err" role="alert"></div></form></div>
<div id="app"></div>"""

LOCK_JS = r"""
var D={s:"%s",i:"%s",c:"%s",n:%d};
function u8(b){var r=atob(b),a=new Uint8Array(r.length);for(var i=0;i<r.length;i++)a[i]=r.charCodeAt(i);return a;}
async function decrypt(pw){
  var base=await crypto.subtle.importKey("raw",new TextEncoder().encode(pw),"PBKDF2",false,["deriveKey"]);
  var key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:u8(D.s),iterations:D.n,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
  var buf=await crypto.subtle.decrypt({name:"AES-GCM",iv:u8(D.i)},key,u8(D.c));
  return JSON.parse(new TextDecoder().decode(buf));
}
function open(p){
  var app=document.getElementById("app");
  app.innerHTML=p.html;
  var s=document.createElement("script");s.text=p.js;document.body.appendChild(s);
  document.getElementById("lock").classList.add("gone");
  requestAnimationFrame(function(){app.classList.add("show");});
}
var f=document.getElementById("lf"),pw=document.getElementById("pw"),err=document.getElementById("err"),go=document.getElementById("go");
document.getElementById("eye").onclick=function(){pw.type=pw.type==="password"?"text":"password";};
f.addEventListener("submit",async function(e){
  e.preventDefault();err.textContent="";go.disabled=true;go.textContent="Checking…";
  try{
    var p=await decrypt(pw.value);
    try{sessionStorage.setItem("omd8k",pw.value);}catch(x){}
    open(p);
  }catch(x){
    err.textContent=(window.crypto&&crypto.subtle)?"Incorrect password. Please try again.":"This page must be opened over HTTPS.";
    f.classList.remove("shake");void f.offsetWidth;f.classList.add("shake");pw.select();
  }
  go.disabled=false;go.textContent="Unlock";
});
(async function(){try{var k=sessionStorage.getItem("omd8k");if(k){open(await decrypt(k));}}catch(x){}})();
""" % (b64(salt), b64(iv), b64(ct), ITER)

out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>OMD8</title>
<style>{style}{LOCK_CSS}</style>
</head>
<body>
{LOCK_HTML}
<script>{LOCK_JS}</script>
</body>
</html>"""
open("index.html", "w", encoding="utf-8").write(out)
print("OK index.html", round(len(out)/1048576, 2), "MB | mật khẩu:", PASSWORD)
