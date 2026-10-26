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
- Report screen: shows the Remediation summary first, with a left-hand menu
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
SETTINGS_FILE = os.path.join("data", "settings.json")
# key, label, one-line description (shown as numbered audit steps)
REPORTS = [
    ("summary", "Remediation summary",
     "Every fix per firewall at a glance — counts & shared fixes"),
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
# Settings / branding
# ---------------------------------------------------------------------------
def load_settings():
    try:
        with open(SETTINGS_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {}


def save_settings(s):
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as fh:
        json.dump(s, fh)


def brand():
    """Branding with defaults: {name, url, logo (data: URI or '')}."""
    b = load_settings().get("branding", {})
    return {"name": (b.get("name") or "").strip() or "AuditHat.com",
            "url": (b.get("url") or "").strip(),
            "logo": b.get("logo") or ""}


def apply_report_branding(doc):
    """Swap the AUDITHAT.COM wordmark in a stored report's header for the
    configured company name/logo — done at serve time so it applies to
    every report, past and future, without a re-run."""
    b = brand()
    if b["name"] == "AuditHat.com" and not b["logo"]:
        return doc
    rep = esc(b["name"]).upper()
    if b["logo"]:
        rep = (f"<img src='{esc(b['logo'])}' style='max-height:36px;"
               f"display:block;margin-bottom:8px'>" + rep)
    return doc.replace("AUDITHAT.COM", rep, 1)


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
.act{display:flex;gap:4px;justify-content:flex-end;white-space:nowrap}
td.acts{width:1%}
.ico{background:none;border:0;padding:5px;border-radius:5px;cursor:pointer;
     color:#5a6b7c;display:inline-flex;align-items:center;line-height:0}
.ico svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;
         stroke-linecap:round;stroke-linejoin:round}
.ico:hover{background:#e8eef5;color:#0b5cad}
.ico.del:hover{background:#fdeeec;color:#c0392b}
.ico[disabled]{opacity:.4;cursor:default}
.ren{display:flex;gap:4px;align-items:center}
#hist th:first-child{width:30%}
.ren input[type=text]{flex:1;width:100%;min-width:0;padding:5px 8px;
                      font-size:13px;border-radius:5px}
.ren .err{color:#c0392b;font-size:12px;margin-left:4px}
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
    b = brand()
    logo = (f"<img src='{esc(b['logo'])}' style='height:28px;"
            f"align-self:center'>" if b["logo"] else "")
    spacer = "" if "flex:1" in header_extra else "<span style='flex:1'></span>"
    gear = ("<a href='/settings' title='Settings' "
            "style='font-size:17px'>&#9881;</a>")
    return (f"<!doctype html><meta charset='utf-8'><title>{esc(title)}</title>"
            f"{APP_CSS}<header>{logo}<h1>{esc(b['name'])}</h1>"
            f"<span class='sub'>SonicWall EXP Audit</span>"
            f"{header_extra}{spacer}{gear}</header>{body}")


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
    dc = mgmt.get("external_mgmt_source", "RT Datacenter")
    dc_legacy = " / ".join(mgmt.get("external_mgmt_legacy_names",
                                    ["GMS Addresses"]))
    ssh = r.get("ssh", {})
    ssh_zones = "/".join(ssh.get("allowed_zones", ["LAN"]))
    ssh_max = ssh.get("max_source_ips", 2)
    tz = r.get("trusted_zone", "LAN")
    trusted = ", ".join(r.get("trusted_zones", ["LAN", "SSLVPN"]))
    vuz = ", ".join(r.get("vpn_user_zones", ["SSLVPN"]))
    mfa = " or ".join(vpn.get("accepted_mfa", ["DUO", "Entra"]))
    vlans = r.get("expected_vlan_roles") or []
    if isinstance(vlans, dict):                      # legacy {role: [...]}
        vlans = [{"role": k} for k in vlans]
    vlan_lines = []
    for e in vlans:
        vid = f"VLAN {e['vlan']} &nbsp;" if e.get("vlan") is not None else ""
        txt = f"{vid}<b>{esc(e['role'])}</b>"
        if e.get("purpose"):
            txt += f" — {esc(e['purpose'])}"
        if e.get("segmentation"):
            txt += f"<br><small>{esc(e['segmentation'])}</small>"
        vlan_lines.append((txt, "Client VLAN segmentation standard"))

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
            (f"<b>NSM management</b> must be implemented — the GMS/NSM "
             f"management channel enabled and firewall management allowed "
             f"from the <b>{esc(dc)}</b> (NSM) addresses. The fleet is managed "
             "centrally by NSM.",
             f"{N53} CM-6, CM-7; CIS Control 4; client NSM standard"),
            (f"Management from outside the LAN is permitted only from the "
             f"<b>{esc(dc)}</b> address object. Those rules are <b>kept</b>; "
             f"a legacy <b>{esc(dc_legacy)}</b> group must be renamed to "
             f"<b>{esc(dc)}</b>, not deleted.",
             f"{N53} CM-6, SC-7; CIS Control 4, 12; client management standard"),
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
            *vlan_lines,
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
ICO_PENCIL = ("<svg viewBox='0 0 24 24'><path d='M17 3a2.83 2.83 0 1 1 4 4"
              "L7.5 20.5 2 22l1.5-5.5L17 3z'/></svg>")
ICO_TRASH = ("<svg viewBox='0 0 24 24'><polyline points='3 6 5 6 21 6'/>"
             "<path d='M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6'/>"
             "<path d='M10 11v6M14 11v6'/>"
             "<path d='M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2'/></svg>")
ICO_CHECK = "<svg viewBox='0 0 24 24'><polyline points='20 6 9 17 4 12'/></svg>"
ICO_X = ("<svg viewBox='0 0 24 24'><line x1='18' y1='6' x2='6' y2='18'/>"
         "<line x1='6' y1='6' x2='18' y2='18'/></svg>")

HOME_JS = """
function flt(){var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#hist tr[data-s]').forEach(function(r){
r.style.display=r.dataset.s.indexOf(q)>=0?'':'none';});}
function delA(id){if(!confirm('Delete this analysis and its reports?'))return;
fetch('/api/delete/'+id,{method:'POST'}).then(function(){location.reload();});}
function renA(id){
  var a=document.getElementById('nm'+id); if(!a)return;
  var td=a.parentNode, tr=td.parentNode, old=a.textContent;
  var box=document.createElement('div'); box.className='ren';
  box.innerHTML="<input type='text' maxlength='120' aria-label='Analysis name'>"
    +"<button class='ico' title='Save (Enter)'>"+ICO_CHECK+"</button>"
    +"<button class='ico' title='Cancel (Esc)'>"+ICO_X+"</button>"
    +"<span class='err'></span>";
  var inp=box.querySelector('input'), btns=box.querySelectorAll('button'),
      err=box.querySelector('.err');
  inp.value=old;
  function done(){td.innerHTML='';td.appendChild(a);}
  function save(){
    var v=inp.value.trim();
    if(!v||v===old){done();return;}
    btns[0].disabled=true; err.textContent='';
    fetch('/api/rename/'+id,{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name:v})})
    .then(function(r){return r.json();})
    .then(function(j){
      if(j.error){err.textContent=j.error;btns[0].disabled=false;return;}
      a.textContent=j.name;
      tr.dataset.s=(j.name+' '+(tr.dataset.rest||'')).toLowerCase();
      done();})
    .catch(function(){err.textContent='Rename failed';btns[0].disabled=false;});
  }
  btns[0].onclick=save; btns[1].onclick=done;
  inp.onkeydown=function(e){
    if(e.key==='Enter'){e.preventDefault();save();}
    else if(e.key==='Escape'){done();}};
  td.innerHTML=''; td.appendChild(box); inp.focus(); inp.select();
}
"""


def home_page():
    conn = db()
    rows = conn.execute(
        "SELECT id,name,processed_at,num_firewalls,firewalls FROM analyses "
        "ORDER BY processed_at DESC, id DESC").fetchall()
    conn.close()
    trs = []
    for rid, name, ts, nf, fws in rows:
        fws = fws or ""
        rest = esc((fws + " " + (ts or "")).lower(), quote=True)
        search = esc(name.lower(), quote=True) + " " + rest
        trs.append(
            f"<tr data-s=\"{search}\" data-rest=\"{rest}\">"
            f"<td><a href='/analysis/{rid}' id='nm{rid}'>{esc(name)}</a></td>"
            f"<td>{esc(ts or '—')}</td><td>{nf or 0}</td>"
            f"<td class='muted'>{esc(fws)}</td>"
            f"<td class='acts'><div class='act'>"
            f"<button class='ico' title='Rename' aria-label='Rename' "
            f"onclick='renA({rid})'>{ICO_PENCIL}</button>"
            f"<button class='ico del' title='Delete' aria-label='Delete' "
            f"onclick='delA({rid})'>{ICO_TRASH}</button>"
            "</div></td></tr>")
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
var ICO_CHECK={json.dumps(ICO_CHECK)}, ICO_X={json.dumps(ICO_X)};
{HOME_JS}
</script>"""
    return page(f"{brand()['name']} — SonicWall EXP Audit", body,
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


def settings_page():
    b = brand()
    logo_prev = (f"<img id='logoImg' src='{esc(b['logo'])}' "
                 f"style='max-height:60px;display:block'>" if b["logo"]
                 else "<img id='logoImg' style='max-height:60px;"
                      "display:none'>")
    none_note = ("" if b["logo"] else
                 "<span id='noLogo' class='muted'>No logo uploaded.</span>")
    body = f"""
<main style='max-width:660px'>
<h2 style='margin-top:0'>Settings</h2>
<div style='background:#fff;border:1px solid #e2e6ea;border-radius:10px;
     padding:20px 22px'>
<h3 style='margin:0 0 4px;font-size:15px'>Branding</h3>
<p class='muted' style='margin:0 0 10px;font-size:13px'>Shown in place of
AuditHat.com across the app, on every report, and on the printed PDF title
page. Applies immediately — no re-run needed.</p>
<label for='bname'>Company name</label>
<input type='text' id='bname' value="{esc(b['name'])}"
       placeholder='AuditHat.com'>
<label for='burl'>Company URL</label>
<input type='text' id='burl' value="{esc(b['url'])}"
       placeholder='https://example.com'>
<label>Logo</label>
<div style='display:flex;gap:14px;align-items:center;min-height:32px'>
{logo_prev}{none_note}
</div>
<div class='bar' style='margin:12px 0 6px'>
<button class='btn' id='pick' style='padding:8px 14px;font-size:13px'>
Upload logo&hellip;</button>
<button class='del' id='rm'>remove logo</button>
</div>
<small>PNG, JPG, SVG or GIF, up to 2&nbsp;MB — automatically converted to
WebP and sized for print on upload. Shown next to the company name in
headers and large on the PDF title page.</small>
</div>
<div class='bar' style='margin-top:18px'>
<span id='status' class='muted'></span>
<span style='flex:1'></span>
<a href='/' style='margin-right:14px'>back</a>
<button class='btn' id='save'>Save settings</button>
</div>
</main>
<script>
var logoVal=null; /* null = keep current, '' = remove, 'data:...' = new */
var picker=document.createElement('input');
picker.type='file';picker.accept='image/*';
document.getElementById('pick').addEventListener('click',function(e){{
e.preventDefault();picker.click();}});
/* re-encode as WebP, capped at 1200x600 (plenty for the print cover);
   falls back to the original data if the browser can't encode WebP */
function toWebp(src,cb){{
var img=new Image();
img.onload=function(){{
try{{
var w=img.naturalWidth||img.width,h=img.naturalHeight||img.height;
if(!w||!h){{cb(src);return;}}
var sc=Math.min(1,1200/w,600/h);
var c=document.createElement('canvas');
c.width=Math.round(w*sc);c.height=Math.round(h*sc);
c.getContext('2d').drawImage(img,0,0,c.width,c.height);
var out=c.toDataURL('image/webp',0.9);
cb(out.indexOf('data:image/webp')===0?out:src);
}}catch(e){{cb(src);}}
}};
img.onerror=function(){{cb(src);}};
img.src=src;
}}
picker.addEventListener('change',function(){{
var f=picker.files[0];if(!f)return;
if(f.size>2*1024*1024){{alert('Logo must be 2 MB or smaller.');return;}}
var r=new FileReader();
r.onload=function(){{toWebp(r.result,function(out){{logoVal=out;
var im=document.getElementById('logoImg');
im.src=logoVal;im.style.display='block';
var n=document.getElementById('noLogo');if(n)n.style.display='none';}});}};
r.readAsDataURL(f);picker.value='';}});
document.getElementById('rm').addEventListener('click',function(e){{
e.preventDefault();logoVal='';
document.getElementById('logoImg').style.display='none';
var n=document.getElementById('noLogo');if(n)n.style.display='';}});
document.getElementById('save').addEventListener('click',function(){{
var p={{name:document.getElementById('bname').value,
url:document.getElementById('burl').value}};
if(logoVal!==null){{p.logo=logoVal;}}
var btn=this;btn.disabled=true;
fetch('/api/settings',{{method:'POST',
headers:{{'Content-Type':'application/json'}},body:JSON.stringify(p)}})
.then(function(r){{return r.json();}}).then(function(j){{
btn.disabled=false;
if(j.ok){{document.getElementById('status').textContent='Saved.';
setTimeout(function(){{location.reload();}},400);}}
else{{alert('Error: '+(j.error||'unknown'));}}
}}).catch(function(e){{btn.disabled=false;alert('Error: '+e);}});
}});
</script>"""
    return page("Settings", body, "<span class='sub'>Settings</span>")


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
               f"<a class='btn' href='/analysis/{rid}/export.html' download "
               f"style='padding:7px 14px;font-size:13px'>&#11015; Export as "
               f"HTML</a>"
               f"<button class='btn' id='rerun' style='padding:7px 14px;"
               f"font-size:13px'>&#8635; Re-run report</button></div>")

    steps = ""
    for i, (t, lbl, desc) in enumerate(REPORTS, 1):
        active = " active" if t == REPORTS[0][0] else ""
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
<iframe id='fr' src='/analysis/{rid}/report/{REPORTS[0][0]}'></iframe>
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
    "summary":
        "An at-a-glance overview of the remediation work — task counts per "
        "firewall, which fixes are shared across the fleet, and a compact "
        "task list per firewall.",
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
    b = brand()
    js_title = json.dumps(f"{b['name']} - {name} - {lbl} - {_date_str(ts)}")
    logo_img = (f"<img src='{esc(b['logo'])}' style='max-height:150px;"
                f"max-width:480px;margin-bottom:26px'>" if b["logo"] else "")
    url_line = (f"<div style='font-size:13px;color:#7a8794;margin-top:6px'>"
                f"{esc(b['url'])}</div>" if b["url"] else "")
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
{logo_img}
<div style='font-size:14px;letter-spacing:3px;font-weight:700;color:#0b5cad;
  text-transform:uppercase'>{esc(b['name'])}</div>
<div style='font-size:36px;font-weight:700;color:#0b2540;margin:16px 0 8px'>
{esc(name)}</div>
<div style='font-size:19px;color:#33465a;margin-bottom:18px'>
Firewall {esc(lbl)} Report</div>
<div style='font-size:14px;color:#3a4a5a;max-width:560px;line-height:1.6;
  margin-bottom:26px'>{summary}</div>
{fw_line}
<div style='font-size:14px;color:#7a8794'>Processed {esc(ts)}</div>
{url_line}
</div>
<script>function pdfSave(){{document.title={js_title};window.print();}}</script>
"""
    return doc.replace("</style>", "</style>" + inj, 1)


def export_page(rid):
    """The whole analysis as ONE self-contained HTML file that looks exactly
    like the analysis page: header, summary bar, left 'Audit steps' nav and
    the report pane. Each report is served the same way the app serves it
    (branding + print cover applied) and embedded via <iframe srcdoc>, so its
    own CSS/scripts stay intact. Only the active report's frame is shown.
    Returns (filename, html) or None if the analysis does not exist."""
    conn = db()
    row = conn.execute("SELECT name,processed_at,num_firewalls,firewalls "
                       "FROM analyses WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        return None
    name, ts, nf, fws = row
    b = brand()
    steps, frames = [], []
    first = True
    for i, (key, lbl, desc) in enumerate(REPORTS, 1):
        p = os.path.join(ANALYSES_DIR, str(rid), "reports", key + ".html")
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as fh:
            doc = fh.read()
        doc = with_print_cover(apply_report_branding(doc), rid, key)
        active = " active" if first else ""
        steps.append(f"<a href='#' class='step{active}' data-t='{key}'>"
                     f"<span class='num'>{i}</span>"
                     f"<span class='txt'><b>{esc(lbl)}</b>"
                     f"<small>{esc(desc)}</small></span></a>")
        frames.append(f"<iframe class='rep{active}' data-t='{key}' "
                      f"title='{esc(lbl)}' "
                      f"srcdoc=\"{esc(doc, quote=True)}\"></iframe>")
        first = False
    logo = (f"<img src='{esc(b['logo'])}' style='height:28px;"
            f"align-self:center'>" if b["logo"] else "")
    fw_chips = "".join(f"<span class='fw'>{esc(f.strip())}</span>"
                       for f in (fws or "").split(",") if f.strip())
    exported = datetime.now().strftime("%Y-%m-%d %H:%M")
    doc = f"""<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>{esc(name)} — reports — {_date_str(ts or '')}</title>
{APP_CSS}
<style>
.layout iframe.rep{{display:none}}
.layout iframe.rep.active{{display:block}}
</style></head><body>
<header>{logo}<h1>{esc(b['name'])}</h1>
<span class='sub'>SonicWall EXP Audit</span><span class='sub'>Audit report</span>
<span style='flex:1'></span>
<span class='sub'>Exported {esc(exported)}</span></header>
<div class='summary'>
<span class='nm'>{esc(name)}</span>
<span class='meta'>{nf or 0} firewall(s)</span>{fw_chips}
<span class='meta'>processed {esc(ts or '—')}</span>
<span style='flex:1'></span>
<button class='btn' id='printr' style='padding:7px 14px;font-size:13px'>
&#128424; Print report</button></div>
<div class='layout'>
<nav><div class='navhead'>Audit steps</div>{''.join(steps)}
<span class='home'>Exported from {esc(b['name'])}</span></nav>
{''.join(frames)}
</div>
<script>
document.querySelectorAll('a.step').forEach(function(a){{
a.addEventListener('click',function(e){{e.preventDefault();
document.querySelectorAll('a.step').forEach(function(x){{
x.classList.remove('active');}});
a.classList.add('active');
document.querySelectorAll('iframe.rep').forEach(function(f){{
f.classList.toggle('active',f.dataset.t===a.dataset.t);}});}});
}});
document.getElementById('printr').addEventListener('click',function(){{
var f=document.querySelector('iframe.rep.active');if(!f)return;
var w=f.contentWindow;
try{{if(w.pdfSave){{w.pdfSave();}}else{{w.focus();w.print();}}}}
catch(e){{alert('Print failed: '+e);}}
}});
</script></body></html>"""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_.") or "analysis"
    return f"{safe}-audit-{_date_str(ts or '')}.html", doc


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


def api_settings(body):
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "bad JSON"}
    logo = data.get("logo")
    if logo:
        if not (logo.startswith("data:image/") and ";base64," in logo[:64]):
            return 400, {"error": "logo must be an image file"}
        if len(logo) > 3_000_000:
            return 400, {"error": "logo too large (2 MB max)"}
    with _LOCK:
        s = load_settings()
        b = s.setdefault("branding", {})
        if "name" in data:
            b["name"] = str(data["name"]).strip()[:80]
        if "url" in data:
            b["url"] = str(data["url"]).strip()[:200]
        if logo is not None:
            b["logo"] = logo
        save_settings(s)
    return 200, {"ok": True}


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


def api_rename(rid, body):
    try:
        data = json.loads(body)
    except Exception:
        return 400, {"error": "bad JSON"}
    name = str(data.get("name") or "").strip()[:120]
    if not name:
        return 400, {"error": "Name cannot be empty"}
    conn = db()
    n = conn.execute("UPDATE analyses SET name=? WHERE id=?",
                     (name, rid)).rowcount
    conn.commit()
    conn.close()
    if not n:
        return 404, {"error": "Analysis not found"}
    return 200, {"ok": True, "name": name}


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

    def _send(self, body, code=200, ctype="text/html; charset=utf-8",
              headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
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
            if path == "/settings":
                return self._send(settings_page())
            m = re.fullmatch(r"/analysis/(\d+)", path)
            if m:
                doc = shell_page(int(m.group(1)))
                if doc is None:
                    return self._send("<h3>Analysis not found. "
                                      "<a href='/'>Home</a></h3>", 404)
                return self._send(doc)
            m = re.fullmatch(r"/analysis/(\d+)/export\.html", path)
            if m:
                res = export_page(int(m.group(1)))
                if res is None:
                    return self._send("<h3>Analysis not found.</h3>", 404)
                fname, doc = res
                return self._send(doc, headers={
                    "Content-Disposition": f'attachment; filename="{fname}"'})
            m = re.fullmatch(r"/analysis/(\d+)/report/([a-z]+)", path)
            if m and m.group(2) in REPORT_KEYS:
                p = os.path.join(ANALYSES_DIR, m.group(1), "reports",
                                 m.group(2) + ".html")
                if os.path.exists(p):
                    with open(p, encoding="utf-8") as fh:
                        doc = fh.read()
                    doc = apply_report_branding(doc)
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
            if path == "/api/settings":
                code, obj = api_settings(body)
                return self._json(obj, code)
            m = re.fullmatch(r"/api/rename/(\d+)", path)
            if m:
                code, obj = api_rename(int(m.group(1)), body)
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
