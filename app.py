#!/usr/bin/env python3
"""
app.py — Local web UI for the SonicWall EXP audit tool.

Run:
    python3 app.py
then open the printed URL (default http://127.0.0.1:8765).

What it does:
- Home page: analysis history, newest first, with a search bar and the
  processed date for each analysis.
- "New Analysis" wizard: name the analysis, drag & drop the EXP .zip files
  (10+ supported), press Process.
- Report screen: shows the Differences report first, with a left-hand menu
  for Compliance, Findings, and Remediation tickets.

Everything stays local: uploads, decoded configs, per-analysis SQLite DBs and
reports live under data/analyses/<id>/. No dependencies beyond the stdlib.
"""

import base64
import html
import json
import os
import re
import shutil
import sqlite3
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sonicwall_compare as engine

HOST = "127.0.0.1"
PORTS = range(8765, 8790)
APP_DB = os.path.join("data", "app.db")
ANALYSES_DIR = os.path.join("data", "analyses")
# key, label, one-line description (shown as numbered audit steps)
REPORTS = [
    ("differences", "Differences",
     "What differs between the firewalls, side by side"),
    ("compliance", "Compliance",
     "Pass / fail against every rule (green / red matrix)"),
    ("findings", "Findings",
     "Risky rules, open ports, content filter & geo"),
    ("remediation", "Remediation",
     "Per-firewall fix tickets — tasks, steps & options"),
]
REPORT_KEYS = {r[0] for r in REPORTS}
_LOCK = threading.Lock()
esc = html.escape


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------
def db():
    conn = sqlite3.connect(APP_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS analyses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        processed_at TEXT,
        num_firewalls INTEGER,
        firewalls TEXT,
        errors TEXT)""")
    return conn


# ---------------------------------------------------------------------------
# Shared page chrome
# ---------------------------------------------------------------------------
APP_CSS = """
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
     margin:0;background:#f6f7f9;color:#1c2530}
header{background:#0b2540;color:#fff;padding:18px 28px;display:flex;
       align-items:baseline;gap:14px}
header h1{margin:0;font-size:19px}
header a{color:#9fc3ec;text-decoration:none;font-size:13px}
header .sub{opacity:.75;font-size:13px}
main{max-width:1000px;margin:0 auto;padding:26px 28px 60px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;
      box-shadow:0 1px 2px rgba(0,0,0,.06)}
th,td{border:1px solid #e2e6ea;padding:9px 12px;text-align:left}
th{background:#eef1f4;font-weight:600}
tr:nth-child(even) td{background:#fafbfc}
a{color:#0b5cad}
.btn{display:inline-block;background:#0b2540;color:#fff;border:0;
     padding:10px 18px;border-radius:6px;cursor:pointer;font-size:14px;
     text-decoration:none}
.btn:hover{background:#123a63}
.btn[disabled]{opacity:.5;cursor:default}
.bar{display:flex;gap:12px;margin-bottom:18px;align-items:center}
.bar input{flex:1;padding:10px 12px;border:1px solid #cdd5dd;border-radius:6px;
           font-size:14px}
.del{background:none;border:0;color:#c0392b;cursor:pointer;font-size:12px}
.muted{color:#7a8794}
#drop{border:2px dashed #9db2c6;border-radius:10px;padding:46px 20px;
      text-align:center;color:#5a6b7c;background:#fff;cursor:pointer;
      margin:14px 0;font-size:15px}
#drop.hov{border-color:#0b5cad;background:#eef5fc;color:#0b5cad}
#list{list-style:none;padding:0;margin:0 0 14px}
#list li{background:#fff;border:1px solid #e2e6ea;border-radius:6px;
         padding:8px 12px;margin-bottom:6px;display:flex;
         justify-content:space-between;align-items:center;font-size:13px}
#list button{background:none;border:0;color:#c0392b;cursor:pointer}
label{display:block;margin:14px 0 6px;font-weight:600;font-size:14px}
input[type=text]{width:100%;padding:10px 12px;border:1px solid #cdd5dd;
                 border-radius:6px;font-size:14px}
#status{margin-top:14px;font-size:14px;color:#b8860b;min-height:20px}
.summary{background:#fff;border-bottom:1px solid #e2e6ea;padding:12px 22px;
         display:flex;flex-wrap:wrap;gap:10px 26px;align-items:center;
         font-size:13px;color:#3a4a5a}
.summary .nm{font-weight:700;color:#0b2540;font-size:15px}
.summary .fw{background:#eef1f4;border-radius:20px;padding:3px 12px;
             font-weight:600;color:#123a63}
.summary .meta{color:#7a8794}
.layout{display:flex;height:calc(100vh - 108px)}
nav{width:270px;background:#0e2a49;padding:16px 12px;flex-shrink:0;
    overflow-y:auto}
nav .navhead{color:#7fa8d4;font-size:11px;text-transform:uppercase;
             letter-spacing:.08em;font-weight:700;margin:4px 10px 12px}
.step{display:flex;gap:12px;align-items:flex-start;color:#cfe0f2;
      text-decoration:none;padding:12px 12px;border-radius:8px;margin-bottom:6px;
      transition:background .12s}
.step:hover{background:#173d63}
.step.active{background:#1f4d7a;box-shadow:inset 3px 0 0 #6db3f2}
.step .num{flex-shrink:0;width:26px;height:26px;border-radius:50%;
           background:#274e75;color:#cfe0f2;font-weight:700;font-size:13px;
           display:flex;align-items:center;justify-content:center}
.step.active .num{background:#6db3f2;color:#0b2540}
.step .txt b{display:block;color:#fff;font-size:14px;margin-bottom:2px}
.step .txt small{color:#9fbad8;font-size:11.5px;line-height:1.35;display:block}
nav .home{display:block;color:#9fbad8;text-decoration:none;font-size:13px;
          padding:10px 12px;margin-top:8px;border-top:1px solid #274e75}
nav .home:hover{color:#fff}
iframe{flex:1;border:0;background:#f6f7f9}
.banner{background:#fdf3e3;border:1px solid #d98324;color:#8a5a10;
        padding:10px 16px;font-size:13px}
.homecard{display:block;background:#0b2540;color:#fff;border-radius:10px;
          padding:18px 22px;text-decoration:none;margin-bottom:22px}
.homecard:hover{background:#123a63}
.homecard b{font-size:17px;display:block}
.homecard small{opacity:.8;font-size:13px}
.homecard .tags{margin-top:10px}
.homecard .tags span{display:inline-block;background:#1f4d7a;border-radius:20px;
                     padding:3px 11px;font-size:12px;margin:3px 4px 0 0}
.stdcat{background:#fff;border:1px solid #e2e6ea;border-radius:10px;
        margin:18px 0;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.stdcat h2{margin:0;padding:14px 20px;background:#0b2540;color:#fff;
           font-size:16px;display:flex;gap:10px;align-items:center}
.stdcat ul{list-style:none;margin:0;padding:4px 0}
.stdcat li{padding:13px 20px;border-top:1px solid #eef1f4}
.stdcat li:first-child{border-top:0}
.stdcat .req{font-size:14px;color:#20303f;line-height:1.55}
.stdcat .req b{color:#0b2540}
.stdcat .ref{font-size:11.5px;color:#8a97a4;margin-top:5px}
.stdcat .ref b{color:#5a6b7c}
</style>
"""


def page(title, body, header_extra=""):
    return (f"<!doctype html><meta charset='utf-8'><title>{esc(title)}</title>"
            f"{APP_CSS}<header><h1>AuditHat.com</h1>"
            f"<span class='sub'>SonicWall EXP Audit</span>"
            f"{header_extra}</header>{body}")


# ---------------------------------------------------------------------------
# Firewall standards / rules
# ---------------------------------------------------------------------------
def _rules_json():
    try:
        with open("compliance_rules.json") as fh:
            return {k: v for k, v in json.load(fh).items()
                    if not k.startswith("_")}
    except Exception:
        return {}


STD_CATEGORIES = [
    ("Firewall Management & Admin Access", "&#128273;"),
    ("Threat Protection — IPS & Content Filtering", "&#128737;"),
    ("Network Segmentation — VLANs & Trusted LAN", "&#129521;"),
    ("VPN & Remote Access", "&#128274;"),
    ("Perimeter & External Exposure", "&#127760;"),
    ("Geo-IP Filtering", "&#127758;"),
]


def _standards_content():
    r = _rules_json()
    mgmt = r.get("management", {})
    vpn = r.get("vpn", {})
    max_ips = mgmt.get("max_source_ips", 2)
    jb = mgmt.get("admin_source_object", "Mgmt-Jumpbox")
    admin_zones = "/".join(mgmt.get("admin_allowed_zones", ["LAN"]))
    ssh = r.get("ssh", {})
    ssh_zones = "/".join(ssh.get("allowed_zones", ["LAN"]))
    ssh_max = ssh.get("max_source_ips", 2)
    tz = r.get("trusted_zone", "LAN")
    trusted = ", ".join(r.get("trusted_zones", ["LAN", "SSLVPN"]))
    vuz = ", ".join(r.get("vpn_user_zones", ["SSLVPN"]))
    mfa = " or ".join(vpn.get("accepted_mfa", ["DUO", "Entra"]))
    vlans = r.get("expected_vlan_roles", {})
    vlan_list = ", ".join(vlans.keys()) if vlans else (
        "Printers, Phones, ATM, Camera, IOT/HVAC/Postage, "
        "ASI/DCI Core Router, Fedline Router")

    N53 = "NIST SP 800-53"
    # (category-title, [ (requirement_html, standard_ref), ... ])
    return {
        "Firewall Management & Admin Access": [
            (f"The admin interface (HTTPS/HTTP/SNMP) <b>and</b> SSH may only be "
             f"reached from the <b>{admin_zones}</b> zone. VPN, WAN, and all "
             "other VLANs must be denied management access.",
             f"{N53} AC-6, SC-7; CIS Control 12.6; PCI DSS 1.3, 2.2.7; FFIEC"),
            (f"SSH must be <b>enabled</b>, reachable only from <b>{ssh_zones}</b>"
             f", and restricted to at most <b>{ssh_max}</b> admin IP(s).",
             f"{N53} AC-6; CIS Control 12; PCI DSS 1.3, 2.2.7"),
            (f"Admin/SSH source must be the jumpbox object <b>{jb}</b> (the host "
             f"running the Connect Secure agent) — max <b>{max_ips}</b> IPs. "
             "Unrestricted (Any-source) management access is a red flag.",
             f"{N53} AC-6, SC-7; CIS Control 12; PCI DSS 1.3"),
            ("Cleartext <b>HTTP</b> management must be disabled — HTTPS only.",
             f"{N53} SC-8; PCI DSS 2.2.7; CIS Control 4"),
            ("Legacy <b>GMS</b> must not be configured — the fleet is managed "
             "by <b>NSM</b>.",
             f"{N53} CM-6, CM-7; CIS Control 4; client NSM standard"),
        ],
        "Threat Protection — IPS & Content Filtering": [
            (f"<b>IPS/IDS</b> (Intrusion Prevention) must be enabled globally "
             f"and applied to the <b>{tz}</b> zone.",
             "PCI DSS 11.5.1; " + N53 + " SI-4; CIS Control 13; FFIEC"),
            (f"<b>Content Filtering</b> must be enabled on the <b>{tz}</b> zone.",
             "PCI DSS 5; CIS Control 9; FFIEC"),
            ("Blocked content-filter categories must be <b>consistent across "
             "all firewalls</b> — if one firewall blocks a category, all must "
             "(strictest firewall is the baseline).",
             "Client standardization policy; CIS Control 9; FFIEC"),
        ],
        "Network Segmentation — VLANs & Trusted LAN": [
            (f"<b>{tz}</b> is the trusted / main internal network. Only trusted "
             f"zones (<b>{trusted}</b>) may reach it. Any other VLAN/zone into "
             f"the {tz} is a red flag.",
             "PCI DSS 1.3, 1.4; " + N53 + " SC-7; CIS Control 12; FFIEC"),
            (f"Expected VLANs to inventory: <b>{vlan_list}</b>.",
             "Client asset/segmentation standard"),
        ],
        "VPN & Remote Access": [
            ("VPN authentication must integrate with <b>Active Directory / "
             "LDAP</b> or <b>Entra ID</b> (no local-only accounts).",
             "FFIEC; " + N53 + " AC-2; CIS Control 6"),
            (f"If SSL VPN is configured, <b>{mfa}</b> MFA is required. If MFA "
             "will not be added, <b>disable SSL VPN</b> until it is.",
             "FFIEC Authentication (2021); PCI DSS 8.4.2, 8.5; " + N53
             + " IA-2(1)"),
            (f"<b>VPN user-to-user traffic is blocked</b> (intra-zone "
             f"communication off on {vuz}).",
             N53 + " SC-7, AC-4; CIS Control 12; PCI DSS 1.3"),
            (f"The <b>{tz} must not initiate</b> connections to VPN users "
             f"({tz} &rarr; {vuz} blocked). VPN users may reach the {tz} and "
             "specific resources, not the reverse.",
             N53 + " SC-7, AC-4; CIS Control 12"),
        ],
        "Perimeter & External Exposure": [
            ("<b>No WAN-inbound service</b> may be open to any source, except "
             "expected VPN listeners (IKE, SSL VPN).",
             "PCI DSS 1.2, 1.3, 1.4; " + N53 + " SC-7; CIS Control 12"),
            ("The firewall must <b>not answer ping from the Internet (WAN)</b>. "
             "Internal (LAN) ping is allowed and useful for monitoring.",
             N53 + " SC-7; CIS Control 12"),
            (f"Branch-to-branch (<b>WAN &rarr; {tz}</b>) rules must be pinned "
             "to the known branch LAN subnets on both ends (source = other "
             f"branches' LANs, destination = this branch's {tz}) — never 'Any'.",
             "PCI DSS 1.2, 1.3; " + N53 + " SC-7; CIS Control 12"),
        ],
        "Geo-IP Filtering": [
            ("Geo-IP enforcement enabled, with <b>block unknown/unclassified "
             "IPs</b> and <b>botnet filtering</b> on.",
             "FFIEC risk-based controls; defense-in-depth"),
            ("Blocked countries must be <b>consistent across all firewalls</b> "
             "(strictest baseline). Includes high-risk / OFAC-relevant regions.",
             "OFAC sanctions awareness; FFIEC; client standardization"),
        ],
    }


def standards_page():
    content = _standards_content()
    b = ["<main>",
         "<p style='color:#3a4a5a;font-size:14px'>These are the firewall "
         "configuration standards this audit checks against. Values shown "
         "(IP limits, zones, the jumpbox object, expected VLANs) come from "
         "<b>compliance_rules.json</b> — edit that file to change the policy.</p>"]
    for cat, icon in STD_CATEGORIES:
        items = content.get(cat, [])
        b.append(f"<div class='stdcat'><h2>{icon} {esc(cat)}</h2><ul>")
        for req, ref in items:
            b.append(f"<li><div class='req'>{req}</div>"
                     f"<div class='ref'><b>Standards:</b> {esc(ref)}</div></li>")
        b.append("</ul></div>")
    b.append("</main>")
    return page("Firewall Standards / Rules", "".join(b),
                "<span class='sub'>Firewall standards / rules</span>"
                "<span style='flex:1'></span><a href='/'>Home</a>")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def home_page():
    conn = db()
    rows = conn.execute(
        "SELECT id,name,processed_at,num_firewalls,firewalls FROM analyses "
        "ORDER BY processed_at DESC, id DESC").fetchall()
    conn.close()
    trs = []
    for rid, name, ts, nf, fws in rows:
        fws = fws or ""
        search = esc((name + " " + fws + " " + (ts or "")).lower(), quote=True)
        trs.append(
            f"<tr data-s=\"{search}\">"
            f"<td><a href='/analysis/{rid}'>{esc(name)}</a></td>"
            f"<td>{esc(ts or '—')}</td><td>{nf or 0}</td>"
            f"<td class='muted'>{esc(fws)}</td>"
            f"<td><button class='del' onclick='delA({rid})'>delete</button>"
            "</td></tr>")
    if not trs:
        trs.append("<tr><td colspan='5' class='muted'>No analyses yet — "
                   "click <b>New Analysis</b> to start.</td></tr>")
    cats = "".join(f"<span>{lbl}</span>" for lbl, _ in STD_CATEGORIES)
    body = f"""
<main>
<a class='homecard' href='/standards'>
  <b>&#128220; Firewall Standards / Rules</b>
  <small>The full set of configuration standards every firewall is audited
  against — categorized and mapped to PCI DSS, NIST 800-53, CIS &amp; FFIEC.</small>
  <div class='tags'>{cats}</div>
</a>

<h2 style='margin:0 0 10px;font-size:16px'>Analyses</h2>
<div class='bar'>
  <input id='q' placeholder='Search analyses by name, firewall, date…'
         oninput='flt()'>
  <a class='btn' href='/new'>+ New Analysis</a>
</div>
<table id='hist'>
<tr><th>Analysis</th><th>Processed</th><th># Firewalls</th><th>Firewalls</th>
<th></th></tr>
{''.join(trs)}
</table>
</main>
<script>
function flt(){{var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#hist tr[data-s]').forEach(function(r){{
r.style.display=r.dataset.s.indexOf(q)>=0?'':'none';}});}}
function delA(id){{if(!confirm('Delete this analysis and its reports?'))return;
fetch('/api/delete/'+id,{{method:'POST'}}).then(function(){{location.reload();}});}}
</script>"""
    return page("AuditHat.com — SonicWall EXP Audit", body,
                "<span class='sub'>Analysis history</span>")


def wizard_page():
    body = """
<main>
<h2 style='margin-top:0'>New analysis</h2>
<label for='name'>1&#41; Name the analysis</label>
<input type='text' id='name' placeholder='e.g. Fidelity — July 2026 audit'>
<label>2&#41; Add the EXP config files (.zip downloads — 10+ supported)</label>
<div id='drop'>Drag &amp; drop the EXP .zip files here, or click to browse</div>
<ul id='list'></ul>
<div class='bar'>
  <span id='count' class='muted'>0 file(s)</span>
  <span style='flex:1'></span>
  <a href='/' style='margin-right:14px'>cancel</a>
  <button class='btn' id='go'>3&#41; Process &amp; build reports</button>
</div>
<div id='status'></div>
</main>
<script>
var files=[];
var drop=document.getElementById('drop');
var picker=document.createElement('input');
picker.type='file';picker.multiple=true;picker.accept='.zip,.exp';
drop.addEventListener('dragover',function(e){e.preventDefault();
drop.classList.add('hov');});
drop.addEventListener('dragleave',function(){drop.classList.remove('hov');});
drop.addEventListener('drop',function(e){e.preventDefault();
drop.classList.remove('hov');addF(e.dataTransfer.files);});
drop.addEventListener('click',function(){picker.click();});
picker.addEventListener('change',function(){addF(picker.files);
picker.value='';});
function addF(fl){for(var i=0;i<fl.length;i++){files.push(fl[i]);}render();}
function rm(i){files.splice(i,1);render();}
function render(){var ul=document.getElementById('list');ul.innerHTML='';
files.forEach(function(f,i){var li=document.createElement('li');
var s=document.createElement('span');
s.textContent=f.name+'  ('+Math.round(f.size/1024)+' KB)';
var b=document.createElement('button');b.textContent='remove';
b.onclick=function(){rm(i);};li.appendChild(s);li.appendChild(b);
ul.appendChild(li);});
document.getElementById('count').textContent=files.length+' file(s)';}
function b64(buf){var s='',b=new Uint8Array(buf);
for(var i=0;i<b.length;i+=32768){
s+=String.fromCharCode.apply(null,b.subarray(i,i+32768));}
return btoa(s);}
document.getElementById('go').addEventListener('click',async function(){
var st=document.getElementById('status');
if(!files.length){st.textContent='Add at least one EXP .zip file first.';
return;}
var btn=this;btn.disabled=true;
st.textContent='Processing '+files.length+' file(s)… this can take a '+
'few seconds per firewall.';
try{
var payload={name:document.getElementById('name').value,files:[]};
for(var i=0;i<files.length;i++){
payload.files.push({name:files[i].name,
data:b64(await files[i].arrayBuffer())});}
var r=await fetch('/api/analyze',{method:'POST',
headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
var j=await r.json();
if(j.id){location='/analysis/'+j.id;}
else{st.textContent='Error: '+(j.error||'unknown');btn.disabled=false;}
}catch(e){st.textContent='Error: '+e;btn.disabled=false;}
});
</script>"""
    return page("New Analysis", body, "<span class='sub'>New analysis</span>")


def _date_str(ts):
    """Analysis processed_at ('YYYY-MM-DD HH:MM') -> 'Sep-04-2026'.
    Falls back to today when the timestamp is missing/unparseable."""
    try:
        dt = datetime.strptime(ts or "", "%Y-%m-%d %H:%M")
    except ValueError:
        dt = datetime.now()
    return dt.strftime("%b-%d-%Y")


def shell_page(rid):
    conn = db()
    row = conn.execute(
        "SELECT name,processed_at,num_firewalls,firewalls,errors "
        "FROM analyses WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        return None
    name, ts, nf, fws, errors = row
    try:
        errors = json.loads(errors or "[]")
    except Exception:
        errors = []
    banner = ""
    if errors:
        banner = ("<div class='banner'>&#9888; Skipped files: "
                  + esc("; ".join(errors)) + "</div>")

    fw_chips = "".join(f"<span class='fw'>{esc(f.strip())}</span>"
                       for f in (fws or "").split(",") if f.strip())
    summary = (f"<div class='summary'>"
               f"<span class='nm'>{esc(name)}</span>"
               f"<span class='meta'>{nf or 0} firewall(s)</span>"
               f"{fw_chips}"
               f"<span class='meta'>processed {esc(ts or '—')}</span>"
               f"<span style='flex:1'></span>"
               f"<button class='btn' id='printr' style='padding:7px 14px;"
               f"font-size:13px'>&#128424; Print report</button>"
               f"<button class='btn' id='rerun' style='padding:7px 14px;"
               f"font-size:13px'>&#8635; Re-run report</button></div>")

    steps = ""
    for i, (t, lbl, desc) in enumerate(REPORTS, 1):
        active = " active" if t == "differences" else ""
        steps += (f"<a href='#' class='step{active}' data-t='{t}'>"
                  f"<span class='num'>{i}</span>"
                  f"<span class='txt'><b>{esc(lbl)}</b>"
                  f"<small>{esc(desc)}</small></span></a>")

    body = f"""
{banner}
{summary}
<div class='layout'>
<nav><div class='navhead'>Audit steps</div>{steps}
<a class='home' href='/'>&larr; All analyses</a></nav>
<iframe id='fr' src='/analysis/{rid}/report/differences'></iframe>
</div>
<script>
document.querySelectorAll('a.step').forEach(function(a){{
a.addEventListener('click',function(e){{e.preventDefault();
document.querySelectorAll('a.step').forEach(function(x){{
x.classList.remove('active');}});
a.classList.add('active');
document.getElementById('fr').src='/analysis/{rid}/report/'+a.dataset.t;}});
}});
document.getElementById('printr').addEventListener('click',function(){{
var w=document.getElementById('fr').contentWindow;
try{{if(w.pdfSave){{w.pdfSave();}}else{{w.focus();w.print();}}}}
catch(e){{alert('Print failed: '+e);}}
}});
document.getElementById('rerun').addEventListener('click',function(){{
var b=this;b.disabled=true;b.textContent='Re-running…';
fetch('/api/rerun/{rid}',{{method:'POST'}}).then(function(r){{
return r.json();}}).then(function(j){{
if(j.ok){{location.reload();}}
else{{alert('Re-run failed: '+(j.error||'unknown'));
b.disabled=false;b.innerHTML='&#8635; Re-run report';}}
}}).catch(function(e){{alert('Re-run failed: '+e);
b.disabled=false;b.innerHTML='&#8635; Re-run report';}});
}});
</script>"""
    return page(f"{name} — reports — {_date_str(ts)}", body,
                "<span class='sub'>Audit report</span>"
                "<span style='flex:1'></span><a href='/'>Home</a>")


# ---------------------------------------------------------------------------
# PDF export (all reports)
# ---------------------------------------------------------------------------
REPORT_SUMMARIES = {
    "differences":
        "A side-by-side comparison of the audited SonicWall firewalls — "
        "device details, per-zone security services, VLANs, management "
        "access, VPN authentication &amp; MFA, local users, licensing, "
        "content filtering and Geo-IP — with every difference highlighted.",
    "compliance":
        "Pass / fail results for each firewall against every standard in "
        "this audit's firewall configuration policy.",
    "findings":
        "Risky and loose firewall rules, externally open ports, and "
        "content-filter &amp; Geo-IP gaps found on each firewall.",
    "remediation":
        "Per-firewall remediation tickets — the concrete tasks, steps and "
        "options to bring each firewall up to standard.",
}


def with_print_cover(doc, rid, key):
    """Inject print CSS plus a print-only AuditHat.com title page (analysis
    name, report title, a short summary of the report, processed date) into
    a stored report page as it is served — so printing always reflects the
    latest re-run. Defines pdfSave() for the shell's Print button; the
    remediation report also keeps its visible Save-as-PDF toolbar."""
    conn = db()
    row = conn.execute("SELECT name,processed_at,firewalls FROM analyses "
                       "WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        return doc
    name, ts, fws = row
    ts = ts or "—"
    lbl = next((l for k, l, _ in REPORTS if k == key), key.title())
    summary = REPORT_SUMMARIES.get(key, "")
    js_title = json.dumps(f"AuditHat - {name} - {lbl} - {_date_str(ts)}")
    fw_line = (f"<div style='font-size:14px;color:#7a8794;margin-bottom:8px'>"
               f"Firewalls: {esc(fws)}</div>" if fws else "")
    bar = ""
    if key == "remediation":
        bar = """
<div id='pdfbar'>
<button onclick='pdfSave()'>&#8681; Save as PDF</button>
<span>Adds a title page with the audit name &amp; processed date — choose
&ldquo;Save as PDF&rdquo; as the destination in the print dialog.</span>
</div>"""
    inj = f"""
<style>
#pdfbar{{position:sticky;top:0;z-index:60;display:flex;align-items:center;
  gap:14px;background:#fff;border-bottom:1px solid #e2e6ea;padding:10px 28px}}
#pdfbar button{{background:#0b2540;color:#fff;border:0;border-radius:6px;
  padding:9px 18px;font-size:13.5px;font-weight:600;cursor:pointer}}
#pdfbar button:hover{{background:#123a63}}
#pdfbar span{{font-size:12px;color:#7a8794}}
#pdfcover{{display:none}}
@media print{{
  #pdfbar{{display:none}}
  button{{display:none !important}}
  body{{background:#fff}}
  *{{-webkit-print-color-adjust:exact !important;
     print-color-adjust:exact !important}}
  #pdfcover{{display:flex;flex-direction:column;justify-content:center;
    align-items:center;text-align:center;height:92vh;page-break-after:always}}
  main div[style*='border-radius:10px']{{break-inside:avoid}}
}}
@page{{margin:12mm}}
</style>
{bar}
<div id='pdfcover'>
<div style='font-size:14px;letter-spacing:3px;font-weight:700;color:#0b5cad;
  text-transform:uppercase'>AuditHat.com</div>
<div style='font-size:36px;font-weight:700;color:#0b2540;margin:16px 0 8px'>
{esc(name)}</div>
<div style='font-size:19px;color:#33465a;margin-bottom:18px'>
Firewall {esc(lbl)} Report</div>
<div style='font-size:14px;color:#3a4a5a;max-width:560px;line-height:1.6;
  margin-bottom:26px'>{summary}</div>
{fw_line}
<div style='font-size:14px;color:#7a8794'>Processed {esc(ts)}</div>
</div>
<script>function pdfSave(){{document.title={js_title};window.print();}}</script>
"""
    return doc.replace("</style>", "</style>" + inj, 1)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def api_analyze(body):
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "bad JSON"}
    name = (data.get("name") or "").strip() \
        or "Untitled " + datetime.now().strftime("%Y-%m-%d %H:%M")
    files = data.get("files") or []
    if not files:
        return 400, {"error": "no files uploaded"}

    with _LOCK:
        conn = db()
        cur = conn.execute(
            "INSERT INTO analyses(name,processed_at,num_firewalls,firewalls,"
            "errors) VALUES(?,?,?,?,?)", (name, None, 0, "", "[]"))
        rid = cur.lastrowid
        conn.commit()
        conn.close()

        adir = os.path.join(ANALYSES_DIR, str(rid))
        indir = os.path.join(adir, "input")
        repdir = os.path.join(adir, "reports")
        decdir = os.path.join(adir, "decoded")
        for d in (indir, repdir, decdir):
            os.makedirs(d, exist_ok=True)
        try:
            paths = []
            for i, f in enumerate(files):
                fn = re.sub(r"[^A-Za-z0-9._-]", "_",
                            os.path.basename(f.get("name") or "")) \
                    or f"file{i}.zip"
                p = os.path.join(indir, f"{i:02d}_{fn}")
                with open(p, "wb") as fh:
                    fh.write(base64.b64decode(f["data"]))
                paths.append(p)

            engine.setup_rules()
            configs, errors = engine.process_paths(
                paths, decoded_dir=decdir,
                db_path=os.path.join(adir, "sonicwall.db"))
            if not configs:
                raise RuntimeError(
                    "no valid EXP configs — "
                    + "; ".join(f"{a}: {b}" for a, b in errors))
            for t, doc in engine.generate_reports(configs).items():
                with open(os.path.join(repdir, t + ".html"), "w") as fh:
                    fh.write(doc)

            conn = db()
            conn.execute(
                "UPDATE analyses SET processed_at=?,num_firewalls=?,"
                "firewalls=?,errors=? WHERE id=?",
                (datetime.now().strftime("%Y-%m-%d %H:%M"), len(configs),
                 ", ".join(c["fw_name"] for c in configs),
                 json.dumps([f"{a}: {b}" for a, b in errors]), rid))
            conn.commit()
            conn.close()
            return 200, {"id": rid}
        except Exception as e:
            shutil.rmtree(adir, ignore_errors=True)
            conn = db()
            conn.execute("DELETE FROM analyses WHERE id=?", (rid,))
            conn.commit()
            conn.close()
            return 400, {"error": str(e)}


def api_rerun(rid):
    """Re-process an analysis's stored EXP files with the current engine
    code and rewrite its reports in place."""
    adir = os.path.join(ANALYSES_DIR, str(rid))
    indir = os.path.join(adir, "input")
    if not os.path.isdir(indir):
        return 404, {"error": "analysis not found"}
    paths = [os.path.join(indir, f) for f in sorted(os.listdir(indir))
             if not f.startswith(".")]
    if not paths:
        return 400, {"error": "no stored input files for this analysis"}
    with _LOCK:
        try:
            engine.setup_rules()
            configs, errors = engine.process_paths(
                paths, decoded_dir=os.path.join(adir, "decoded"),
                db_path=os.path.join(adir, "sonicwall.db"))
            if not configs:
                raise RuntimeError(
                    "no valid EXP configs — "
                    + "; ".join(f"{a}: {b}" for a, b in errors))
            repdir = os.path.join(adir, "reports")
            os.makedirs(repdir, exist_ok=True)
            for t, doc in engine.generate_reports(configs).items():
                with open(os.path.join(repdir, t + ".html"), "w") as fh:
                    fh.write(doc)
            conn = db()
            conn.execute(
                "UPDATE analyses SET processed_at=?,num_firewalls=?,"
                "firewalls=?,errors=? WHERE id=?",
                (datetime.now().strftime("%Y-%m-%d %H:%M"), len(configs),
                 ", ".join(c["fw_name"] for c in configs),
                 json.dumps([f"{a}: {b}" for a, b in errors]), rid))
            conn.commit()
            conn.close()
            return 200, {"ok": True}
        except Exception as e:
            return 400, {"error": str(e)}


def api_delete(rid):
    shutil.rmtree(os.path.join(ANALYSES_DIR, str(rid)), ignore_errors=True)
    conn = db()
    conn.execute("DELETE FROM analyses WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return 200, {"ok": True}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "AuditHat/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj), code, "application/json")

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        buf = b""
        while len(buf) < n:
            chunk = self.rfile.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def do_GET(self):
        try:
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._send(home_page())
            if path == "/new":
                return self._send(wizard_page())
            if path == "/standards":
                return self._send(standards_page())
            m = re.fullmatch(r"/analysis/(\d+)", path)
            if m:
                doc = shell_page(int(m.group(1)))
                if doc is None:
                    return self._send("<h3>Analysis not found. "
                                      "<a href='/'>Home</a></h3>", 404)
                return self._send(doc)
            m = re.fullmatch(r"/analysis/(\d+)/report/([a-z]+)", path)
            if m and m.group(2) in REPORT_KEYS:
                p = os.path.join(ANALYSES_DIR, m.group(1), "reports",
                                 m.group(2) + ".html")
                if os.path.exists(p):
                    with open(p, encoding="utf-8") as fh:
                        doc = fh.read()
                    doc = with_print_cover(doc, int(m.group(1)), m.group(2))
                    return self._send(doc)
                return self._send("<h3>Report not found.</h3>", 404)
            return self._send("", 404)
        except Exception as e:
            self._send(f"<pre>Server error: {esc(str(e))}</pre>", 500)

    def do_POST(self):
        try:
            path = self.path.split("?", 1)[0]
            body = self._read_body()
            if path == "/api/analyze":
                code, obj = api_analyze(body)
                return self._json(obj, code)
            m = re.fullmatch(r"/api/delete/(\d+)", path)
            if m:
                code, obj = api_delete(int(m.group(1)))
                return self._json(obj, code)
            m = re.fullmatch(r"/api/rerun/(\d+)", path)
            if m:
                code, obj = api_rerun(int(m.group(1)))
                return self._json(obj, code)
            return self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def main():
    os.makedirs(ANALYSES_DIR, exist_ok=True)
    db().close()
    srv = None
    for port in PORTS:
        try:
            srv = ThreadingHTTPServer((HOST, port), Handler)
            break
        except OSError:
            continue
    if srv is None:
        raise SystemExit("No free port found in 8765-8789")
    url = f"http://{HOST}:{srv.server_address[1]}"
    print(f"AuditHat.com — SonicWall audit app running at {url}"
          "   (Ctrl+C to stop)")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
