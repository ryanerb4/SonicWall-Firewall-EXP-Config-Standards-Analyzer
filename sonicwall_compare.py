#!/usr/bin/env python3
"""
sonicwall_compare.py — Compare multiple SonicWall EXP configs for one client.

Usage:
    1. Drop each firewall's EXP download (.zip) into ./input/
    2. Run:  python3 sonicwall_compare.py
    3. Open the reports in ./output/ :
         - differences.html   what differs between the firewalls
         - findings.html      risky / loose rules + the security checklist

Everything stays local. Intermediate data lands in ./data/ :
    - data/decoded/<name>.txt   human-readable key=value dump of each config
    - data/sonicwall.db         SQLite DB of the parsed, structured settings

Audit checklist (per firewall):
    1. IPS/IDS enabled                          (isIDPEnabled + per-zone IDP)
    2. Content filtering enabled on all zones   (per-zone CFS profile)
    3. SSH management enabled + limited to 1 IP  (management access rules)
    4. External (WAN) management limited to 1-2 IPs
    5. Internal (LAN) management limited to 1-2 IPs
    6. VLAN inventory vs expected roles
       (Printers, Phones, ATM, Camera, IOT/HVAC/Postage, ASI/DCI, Fedline)
"""

import html
import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import datetime

from exp_parser import parse_exp_file, exp_member_name

INPUT_DIR = "input"
DATA_DIR = "data"
DECODED_DIR = os.path.join(DATA_DIR, "decoded")
OUTPUT_DIR = "output"
DB_PATH = os.path.join(DATA_DIR, "sonicwall.db")
RULES_FILE = "compliance_rules.json"

DEFAULT_RULES = {
    "trusted_zone": "LAN",
    "trusted_zones": ["LAN", "SSLVPN"],
    "vpn_user_zones": ["SSLVPN"],
    "lan_requirements": {"content_filter_required": True, "ips_required": True,
                         "no_inbound_from_other_zones": True},
    "ssh": {"must_be_enabled": True, "allowed_zones": ["LAN"],
            "max_source_ips": 2},
    "management": {"max_source_ips": 2, "unrestricted_access_is_red_flag": True,
                   "admin_source_object": "Mgmt-Jumpbox",
                   "admin_source_description":
                   "the jumpbox that runs the Connect Secure agent"},
    "vpn": {"sslvpn_requires_mfa": True, "accepted_mfa": ["DUO", "Entra"],
            "accepted_directory": ["Active Directory", "LDAP", "Entra"]},
    "external_services": {"wan_inbound_any_source_is_red_flag": True,
                          "expected_open_listeners":
                          ["IKE", "SSL VPN", "SSLVPN", "SonicpointN", "NAT-T"]},
    "consistency": {"geo_blocking_match_strictest": True,
                    "content_filter_match_strictest": True},
    "expected_vlan_roles": {},
    "content_filter_exempt_zones": ["WAN", "VPN", "SSLVPN", "MULTICAST", "MGMT"],
}


def load_rules():
    rules = dict(DEFAULT_RULES)
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE) as fh:
                loaded = json.load(fh)
            rules.update({k: v for k, v in loaded.items()
                          if not k.startswith("_")})
            print(f"Loaded compliance rules from {RULES_FILE}")
        except Exception as e:
            print(f"WARNING: could not read {RULES_FILE} ({e}); using defaults")
    return rules


# Populated from the rules file at runtime (see main()).
RULES = dict(DEFAULT_RULES)

# Zones that carry user/endpoint traffic and therefore SHOULD enforce content
# filtering. Infrastructure/edge zones (WAN, VPN, etc.) are excluded.
NON_CFS_ZONES = {"WAN", "VPN", "SSLVPN", "MULTICAST", "MGMT"}

# Expected VLAN roles for this client (bank / financial). Patterns matched
# case-insensitively against VLAN name + comment.
VLAN_ROLES = {
    "Printers":               ["print"],
    "Phones":                 ["phone", "voip", "voice"],
    "ATM":                    ["atm"],
    "Camera":                 ["camera", "cctv", "nvr", "dvr", "surveil"],
    "IOT / HVAC / Postage":   ["iot", "hvac", "postage", "pitney", "meter"],
    "ASI / DCI Core Router":  ["asi", "dci", "core"],
    "Fedline Router":         ["fedline", "frb", "federal reserve", "fed line"],
}

ACTION_NAMES = {"0": "Deny", "1": "Discard", "2": "Allow", "3": "Deny"}
MGMT_SERVICES = ("SSH Management", "HTTPS Management", "HTTP Management",
                 "Ping Management", "SNMP Management")

# The main internal / trusted network. Inter-VLAN access is reported relative
# to this zone. Change if the client's trusted zone is named differently.
TRUSTED_ZONE = "LAN"

# Security-service license codes we care about for the audit.
LICENSE_CODES = {
    "IDP": "Gateway AV / IPS / App Control",
    "CFSP": "Content Filtering Service",
    "ADVANCEDDNS": "DNS Filtering",
    "SBX": "Capture ATP (sandbox)",
    "UTMAS": "Anti-Spam",
    "VPNSSL": "SSL VPN",
    "VPNC": "Global VPN Client",
}


def parse_license(flat):
    """Parse the manualLicSummaryData JSON blob into a license summary."""
    info = {"friendly": "", "tenant": "", "registered": "", "services": {},
            "sslvpn": ("", ""), "gvc": ("", "")}
    raw = flat.get("manualLicSummaryData", "")
    if not raw:
        return info
    try:
        j = json.loads(raw).get("data", {})
    except Exception:
        return info
    info["friendly"] = j.get("friendly-name", "")
    info["tenant"] = j.get("tenant-name", "")
    info["registered"] = j.get("registered", "")
    for s in j.get("securityServices", []):
        code = s.get("serviceCode")
        info["services"][code] = {
            "name": s.get("securityService", ""),
            "status": s.get("status", ""),
            "exp": s.get("expiration", ""),
            "count": s.get("count", ""),
            "max": s.get("maxCount", ""),
        }
    ssl = info["services"].get("VPNSSL", {})
    gvc = info["services"].get("VPNC", {})
    info["sslvpn"] = (ssl.get("count", ""), ssl.get("max", ""))
    info["gvc"] = (gvc.get("count", ""), gvc.get("max", ""))
    return info


# ---------------------------------------------------------------------------
# Small helpers for reading SonicWall's indexed arrays (foo_0, foo_1, ...)
# ---------------------------------------------------------------------------
def _iter_indexed(d, key_base):
    i = 0
    while f"{key_base}_{i}" in d:
        yield i
        i += 1


def _g(d, base, i, default=""):
    return d.get(f"{base}_{i}", default)


# ---------------------------------------------------------------------------
# Structured extraction from one flat config dict
# ---------------------------------------------------------------------------
def extract(flat, source_name):
    cfg = {
        "source": source_name,
        "fw_name": flat.get("firewallName", "") or "(unnamed)",
        "serial": flat.get("serialNumber", ""),
        "model": flat.get("shortProdName", ""),
        "build": flat.get("buildNum", ""),
        "ips_global": flat.get("isIDPEnabled", ""),
        "cfs_global": flat.get("cfsEnabled", ""),
        "gms_enabled": flat.get("gmsServerEnable", "").lower() == "on",
        "gms_addr": flat.get("gmsServerAddr", ""),
        "lic": parse_license(flat),
        "cfs_profiles": parse_cfs_categories(flat),
        "geo": parse_geo(flat),
        "zones": [],
        "interfaces": [],
        "rules": [],        # ALL access rules
        "mgmt_rules": [],   # subset: management-service rules
    }

    # Address objects, for resolving rule sources to IP counts
    addr = {}
    for i in _iter_indexed(flat, "addrObjId"):
        name = _g(flat, "addrObjId", i)
        addr[name] = {
            "type": _g(flat, "addrObjType", i),
            "ip1": _g(flat, "addrObjIp1", i) or _g(flat, "addrObjIp", i),
            "ip2": _g(flat, "addrObjIp2", i),
        }
    cfg["_addr"] = addr

    # This branch's LAN (trusted) subnet, as CIDR — used to build the other
    # branches' source object for branch-to-branch VPN rules.
    cfg["lan_subnet"] = ""
    lan_net = addr.get("LAN Primary Subnet")
    if lan_net and lan_net.get("type") == "4":
        try:
            cfg["lan_subnet"] = str(ipaddress.IPv4Network(
                f"{lan_net['ip1']}/{lan_net['ip2']}", strict=False))
        except Exception:
            pass

    # Address GROUPS: addro_atomToGrp_N (member) <-> addro_grpToGrp_N (group)
    groups = {}
    for i in _iter_indexed(flat, "addro_grpToGrp"):
        grp = _g(flat, "addro_grpToGrp", i)
        mem = _g(flat, "addro_atomToGrp", i)
        if grp and mem:
            groups.setdefault(grp, []).append(mem)
    cfg["_groups"] = groups

    # VPN authentication & MFA posture
    cfg["vpn"] = detect_vpn_auth(flat)

    # Local user accounts (built-in admin + any userObjId_N entries)
    cfg["local_users"] = parse_local_users(flat)

    # Zones
    for i in _iter_indexed(flat, "zoneObjId"):
        cfg["zones"].append({
            "name": _g(flat, "zoneObjId", i),
            "ztype": _g(flat, "zoneObjZoneType", i),
            "cfs": _g(flat, "zoneObjCflProfile", i),
            "idp": _g(flat, "zoneObjMyIDPProfile", i),
            "gav": _g(flat, "zoneObjGavProfile", i),
            "asp": _g(flat, "zoneObjASProfile", i),
            "intra": _g(flat, "zoneObjIntraZoneCom", i),
        })

    # Interfaces (VLANs are sub-interfaces with a non-zero vlan_tag)
    for i in _iter_indexed(flat, "iface_name"):
        cfg["interfaces"].append({
            "name": _g(flat, "iface_name", i),
            "comment": _g(flat, "iface_comment", i),
            "vlan": _g(flat, "iface_vlan_tag", i, "0"),
            "parent": _g(flat, "iface_vlan_parent", i),
            "ip": _g(flat, "iface_static_ip", i),
            "mask": _g(flat, "iface_static_mask", i),
            "https": _g(flat, "iface_https_mgmt", i),
            "ssh": _g(flat, "iface_ssh_mgmt", i),
        })

    # All access rules
    for i in _iter_indexed(flat, "policyAction"):
        src = _g(flat, "policySrcNet", i)
        count, desc, iplist = _resolve_source(src, addr)
        dst = _g(flat, "policyDstNet", i) or "Any"
        rule = {
            "enabled": _g(flat, "policyEnabled", i),
            "action": ACTION_NAMES.get(_g(flat, "policyAction", i),
                                       _g(flat, "policyAction", i)),
            "src_zone": _g(flat, "policySrcZone", i),
            "dst_zone": _g(flat, "policyDstZone", i),
            "src_obj": src or "Any",
            "src_desc": desc,
            "src_count": count,      # None = unlimited (Any)
            "src_iplist": iplist,
            "dst_obj": dst,
            "service": _g(flat, "policyDstSvc", i) or "Any",
            "comment": _g(flat, "policyComment", i),
            "geo_block": _g(flat, "policyGeoIpBlock", i) == "1",
        }
        cfg["rules"].append(rule)

    cfg["mgmt_rules"] = [r for r in cfg["rules"]
                         if "Management" in r["service"]]

    # IP groups referenced as a source/destination in access rules, resolved
    referenced = set()
    for r in cfg["rules"]:
        referenced.add(r["src_obj"])
        referenced.add(r["dst_obj"])
    cfg["ip_groups"] = []
    for name in sorted(referenced):
        if name in groups:
            ips = resolve_ips(name, addr, groups)
            cfg["ip_groups"].append({"name": name, "ips": ips,
                                     "members": groups[name]})
    return cfg


def detect_vpn_auth(flat):
    """Detect VPN/user authentication + MFA posture from the flat config.

    Written to fire POSITIVELY when AD/LDAP, Entra/SAML, RADIUS or DUO are
    configured, and to report 'local only / none' when they're absent.
    """
    def truthy(v):
        return str(v).lower() in ("1", "on", "yes", "true", "enabled")

    # --- RADIUS user-login auth (DUO Auth Proxy typically rides RADIUS) ---
    radius_login = truthy(flat.get("userRadiusSelect", ""))
    radius_servers = []
    for k, v in flat.items():
        kl = k.lower()
        if kl.startswith("snwlradius") or "acct" in kl:      # wireless / accounting
            continue
        if "radius" in kl and ("serverip" in kl or "hostname" in kl
                               or kl.endswith("host") or kl.endswith("addr")):
            if v and v not in ("0.0.0.0", "0"):
                radius_servers.append(v)

    # --- LDAP / Active Directory ---
    ldap_ad = False
    ldap_servers = []
    for i in range(0, 64):
        if flat.get(f"zoneObjEnableLDAP_{i}") == "1" \
           or flat.get(f"zoneObjEnableAD_{i}") == "1":
            ldap_ad = True
        dom = flat.get(f"zoneObjADDomain_{i}", "")
        if dom:
            ldap_ad = True
            ldap_servers.append(dom)
    for k, v in flat.items():
        kl = k.lower()
        if (kl.startswith("ldapserver") or "ldaphostname" in kl
                or "ldapbasedn" in kl) and v and v not in ("0",):
            ldap_ad = True
            ldap_servers.append(v)

    # --- Entra / SAML federation ---
    saml_servers = []
    for k, v in flat.items():
        if "saml" in k.lower() and v and v not in ("0", "off"):
            vl = v.lower()
            if ("http" in vl or "windows.net" in vl or "microsoft" in vl
                    or ".com" in vl or "entityid" in vl):
                saml_servers.append(v)
    saml_entra = bool(saml_servers)

    # --- DUO (by name, in any value: hostname/comment/object) ---
    duo = any("duo" in str(v).lower() for v in flat.values())

    # --- TOTP (admin login MFA) ---
    admin_totp = (truthy(flat.get("adminLoginOtpRequire", ""))
                  or truthy(flat.get("adminObjTotpBindState", ""))
                  or truthy(flat.get("adminOtpReq", "")))

    # --- VPN service indicators ---
    sslvpn = flat.get("SslvpnsDnsServer1", "0.0.0.0") not in ("0.0.0.0", "")
    l2tp = truthy(flat.get("L2TPServerEnabled", ""))

    # --- derive human summaries ---
    methods = []
    if radius_login or radius_servers:
        methods.append("RADIUS")
    if ldap_ad:
        methods.append("LDAP/AD")
    auth_method = " + ".join(methods) if methods else "Local users only"

    if ldap_ad:
        directory = "Active Directory / LDAP"
    elif saml_entra:
        directory = "Entra ID / SAML"
    else:
        directory = "None — local accounts only"

    mfa_parts = []
    if duo:
        mfa_parts.append("DUO")
    if saml_entra:
        mfa_parts.append("Entra/SAML")
    if admin_totp:
        mfa_parts.append("TOTP (admin)")
    mfa = ", ".join(mfa_parts) if mfa_parts else "None"

    return {
        "sslvpn": sslvpn, "l2tp": l2tp,
        "auth_method": auth_method,
        "radius_servers": sorted(set(radius_servers)),
        "directory": directory,
        "ldap_servers": sorted(set(ldap_servers)),
        "saml": saml_entra, "saml_servers": sorted(set(saml_servers)),
        "duo": duo, "admin_totp": admin_totp,
        "mfa": mfa,
    }


def _epoch_str(v):
    """SonicWall epoch-seconds timestamp -> 'YYYY-MM-DD HH:MM' (or '')."""
    try:
        t = int(str(v).strip() or "0")
    except ValueError:
        return ""
    if t <= 0:
        return ""
    try:
        return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


def parse_local_users(flat):
    """Local user accounts stored on the firewall itself.

    Two sources:
      - the built-in 'admin' account (its settings live under admin* keys);
      - locally-created users, stored as userObjId_N arrays mirroring the
        userGroupObj* schema (absent when the firewall has no local users).
    Directory (LDAP/AD/Entra) accounts are NOT in the EXP export.

    Each user dict: name, builtin, comment, enabled, last_login, admin,
    vpn (True/False/None=unknown), member_of (list of group names).
    """
    def truthy(v):
        return str(v).lower() in ("1", "on", "yes", "true", "enabled")

    # user groups: name + privilege mask, so a user's PrivMask bits can be
    # translated back to the group names they represent
    mask2group = {}
    for i in _iter_indexed(flat, "userGroupObjId"):
        gname = _g(flat, "userGroupObjId", i)
        try:
            m = int(_g(flat, "userGroupObjPrivMask", i) or "0")
        except ValueError:
            m = 0
        if gname and m:
            mask2group[m] = gname

    def is_admin_group(g):
        gl = g.lower()
        return "admin" in gl and "guest" not in gl

    def is_vpn_group(g):
        return "sslvpn" in g.lower().replace(" ", "").replace("-", "")

    # explicit user -> group membership tables (key names vary by firmware;
    # mirror the addro_atomToGrp/addro_grpToGrp pattern used elsewhere)
    membership = {}
    for mem_base, grp_base in (("usero_atomToGrp", "usero_grpToGrp"),
                               ("userGroupMemberName",
                                "userGroupMemberGroup")):
        for i in _iter_indexed(flat, mem_base):
            m, g = _g(flat, mem_base, i), _g(flat, grp_base, i)
            if m and g:
                membership.setdefault(m, []).append(g)

    users = []

    # built-in administrator — always present, cannot be disabled
    users.append({
        "name": flat.get("adminName", "") or "admin",
        "builtin": True,
        "comment": "Built-in administrator",
        "enabled": True,
        "last_login": _epoch_str(flat.get("adminLastLoginTime", "")),
        "admin": True,
        "vpn": None,                      # not recorded in the export
        "member_of": ["SonicWALL Administrators"],
    })

    # locally-created users (userObjId_N — not present on every firewall)
    for i in _iter_indexed(flat, "userObjId"):
        name = _g(flat, "userObjId", i)
        if not name:
            continue
        try:
            mask = int(_g(flat, "userObjPrivMask", i) or "0")
        except ValueError:
            mask = 0
        member_of = list(membership.get(name, []))
        for m, gname in mask2group.items():
            if (mask & m) == m and gname not in member_of:
                member_of.append(gname)
        disabled = (truthy(_g(flat, "userObjDisabled", i))
                    or str(_g(flat, "userObjEnabled", i, "on")).lower()
                    in ("off", "0", "no"))
        users.append({
            "name": name,
            "builtin": False,
            "comment": _g(flat, "userObjComment", i),
            "enabled": not disabled,
            "last_login": _epoch_str(_g(flat, "userObjLastLoginTime", i)),
            "admin": any(is_admin_group(g) for g in member_of),
            "vpn": (any(is_vpn_group(g) for g in member_of)
                    or bool(_g(flat, "userObjVpnDestNet", i))),
            "member_of": member_of,
        })
    return users


def parse_cfs_categories(flat):
    """Return list of CFS profiles with their BLOCKED category names.

    cfsCategoryStr = master JSON id->name map; cfsProfileUrlCategoryOpt_N =
    per-category 0/1 mask for profile N (1 = blocked). Fully reliable.
    """
    id2name = {}
    raw = flat.get("cfsCategoryStr", "")
    if raw:
        try:
            for e in json.loads(raw).get("entries", []):
                for k, v in e.items():
                    id2name[int(k)] = v
        except Exception:
            pass
    profiles = []
    for i in _iter_indexed(flat, "cfsProfileObjId"):
        mask = _g(flat, "cfsProfileUrlCategoryOpt", i)
        if not mask:
            continue
        flags = mask.split(",")
        blocked = [id2name.get(pos + 1, f"Category {pos + 1}")
                   for pos, f in enumerate(flags) if f == "1"]
        profiles.append({
            "name": _g(flat, "cfsProfileObjId", i),
            "blocked": blocked,
            "total": len(flags),
            "forbidden_urls": _g(flat, "cfsProfileForbiddenUrlsObj", i),
            "allowed_urls": _g(flat, "cfsProfileAllowedUrlsObj", i),
            "safe_search": _g(flat, "cfsProfileEnableSafeSearch", i),
            "https_filter": _g(flat, "cfsProfileEnableHttpsFlting", i),
        })
    return profiles


def parse_geo(flat):
    """Geo-IP filter posture + decoded blocked-country list.

    The blocked countries are a bitmap (geoInitBitmap). Each country's bit
    position is the low byte of its countryObjIndex; MSB-first bit order.
    Validated: Anonymous-Proxy/Other-Country bits set (matches block-unknown),
    and the OFAC/high-risk cluster (China, Iran, N.Korea, Russia, Syria, ...)
    lands on set bits.
    """
    bm = flat.get("geoInitBitmap", "")
    pos2name = {}
    for i in _iter_indexed(flat, "countryObjId"):
        ci = _g(flat, "countryObjIndex", i)
        if ci:
            try:
                pos2name[int(ci) & 0xFF] = _g(flat, "countryObjId", i)
            except ValueError:
                pass
    blocked = []
    if bm:
        bits = bin(int(bm, 16))[2:].zfill(len(bm) * 4)
        for p, ch in enumerate(bits):
            if ch == "1":
                blocked.append(pos2name.get(p, f"(country #{p})"))
    return {
        "enforcement": flat.get("geoEnforcement", "") == "1",
        "block_all": flat.get("geoEnforceBlockAll", "") == "1",
        "block_unknown": flat.get("blockUnknownGeo", "").lower() == "on",
        "botnet": flat.get("botnetBlock", "") == "1",
        "policy_based": flat.get("geoEnfBasedOnPolicy", "") == "1",
        "blocked_countries": sorted(blocked),
        "blocked_count": len(blocked),
    }


def resolve_ips(name, addr, groups, seen=None):
    """Recursively resolve an address object OR group to a flat list of IP
    strings (hosts, ranges, networks)."""
    seen = seen or set()
    if name in seen:
        return []
    seen.add(name)
    if name in groups:
        out = []
        for m in groups[name]:
            out += resolve_ips(m, addr, groups, seen)
        return out
    obj = addr.get(name)
    if not obj:
        return []
    t = obj["type"]
    if t == "1":
        return [obj["ip1"]]
    if t == "2":
        return [f"{obj['ip1']} - {obj['ip2']}"]
    if t == "4":
        return [f"{obj['ip1']}/{obj['ip2']}"]
    return []


def _resolve_source(src, addr):
    """Return (ip_count, human_desc, ip_list). count None => Any/unlimited."""
    if not src or src.lower() == "any":
        return None, "Any (UNRESTRICTED)", "0.0.0.0/0 (any)"
    obj = addr.get(src)
    if not obj:
        return "?", src, "(named object — see firewall)"
    t = obj["type"]
    try:
        if t == "1":                       # host
            return 1, f"{obj['ip1']} (host)", obj["ip1"]
        if t == "2":                       # range
            a = int(ipaddress.IPv4Address(obj["ip1"]))
            b = int(ipaddress.IPv4Address(obj["ip2"]))
            return (max(0, b - a + 1), f"{obj['ip1']}-{obj['ip2']} (range)",
                    f"{obj['ip1']} - {obj['ip2']}")
        if t == "4":                       # network
            net = ipaddress.IPv4Network(f"{obj['ip1']}/{obj['ip2']}",
                                        strict=False)
            return net.num_addresses, f"{obj['ip1']}/{obj['ip2']} (network)", \
                str(net)
        if t == "8":                       # group
            return "?", f"{src} (group)", "(address group — expand on firewall)"
    except Exception:
        pass
    return "?", src, "(named object)"


# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------
def init_db(conn):
    conn.executescript("""
        DROP TABLE IF EXISTS files;
        DROP TABLE IF EXISTS zones;
        DROP TABLE IF EXISTS interfaces;
        DROP TABLE IF EXISTS rules;
        DROP TABLE IF EXISTS mgmt_rules;
        DROP TABLE IF EXISTS licenses;
        DROP TABLE IF EXISTS vpn_auth;
        CREATE TABLE files(
            id INTEGER PRIMARY KEY, source TEXT, fw_name TEXT, serial TEXT,
            model TEXT, build TEXT, ips_global TEXT, cfs_global TEXT,
            friendly TEXT, tenant TEXT, sslvpn TEXT, gvc TEXT);
        CREATE TABLE rules(
            file_id INT, enabled TEXT, action TEXT, src_zone TEXT,
            dst_zone TEXT, src_obj TEXT, src_iplist TEXT, dst_obj TEXT,
            service TEXT, comment TEXT);
        CREATE TABLE licenses(
            file_id INT, code TEXT, name TEXT, status TEXT, exp TEXT,
            count TEXT, maxc TEXT);
        CREATE TABLE zones(
            file_id INT, name TEXT, ztype TEXT, cfs TEXT, idp TEXT,
            gav TEXT, asp TEXT, intra TEXT);
        CREATE TABLE interfaces(
            file_id INT, name TEXT, comment TEXT, vlan TEXT, parent TEXT,
            ip TEXT, mask TEXT, https TEXT, ssh TEXT);
        CREATE TABLE mgmt_rules(
            file_id INT, enabled TEXT, action TEXT, src_zone TEXT,
            dst_zone TEXT, src_desc TEXT, src_count TEXT, service TEXT);
        CREATE TABLE vpn_auth(
            file_id INT, sslvpn TEXT, l2tp TEXT, auth_method TEXT,
            directory TEXT, radius_servers TEXT, ldap_servers TEXT,
            saml TEXT, duo TEXT, admin_totp TEXT, mfa TEXT);
    """)
    conn.commit()


def store(conn, cfg):
    lic = cfg["lic"]
    cur = conn.execute(
        "INSERT INTO files(source,fw_name,serial,model,build,ips_global,"
        "cfs_global,friendly,tenant,sslvpn,gvc) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (cfg["source"], cfg["fw_name"], cfg["serial"], cfg["model"],
         cfg["build"], cfg["ips_global"], cfg["cfs_global"], lic["friendly"],
         lic["tenant"], "/".join(lic["sslvpn"]), "/".join(lic["gvc"])))
    fid = cur.lastrowid
    conn.executemany(
        "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?)",
        [(fid, r["enabled"], r["action"], r["src_zone"], r["dst_zone"],
          r["src_obj"], r["src_iplist"], r["dst_obj"], r["service"],
          r["comment"]) for r in cfg["rules"]])
    conn.executemany(
        "INSERT INTO licenses VALUES(?,?,?,?,?,?,?)",
        [(fid, code, s["name"], s["status"], s["exp"], s["count"], s["max"])
         for code, s in lic["services"].items()])
    conn.executemany(
        "INSERT INTO zones VALUES(?,?,?,?,?,?,?,?)",
        [(fid, z["name"], z["ztype"], z["cfs"], z["idp"], z["gav"],
          z["asp"], z["intra"]) for z in cfg["zones"]])
    conn.executemany(
        "INSERT INTO interfaces VALUES(?,?,?,?,?,?,?,?,?)",
        [(fid, x["name"], x["comment"], x["vlan"], x["parent"], x["ip"],
          x["mask"], x["https"], x["ssh"]) for x in cfg["interfaces"]])
    conn.executemany(
        "INSERT INTO mgmt_rules VALUES(?,?,?,?,?,?,?,?)",
        [(fid, r["enabled"], r["action"], r["src_zone"], r["dst_zone"],
          r["src_desc"], str(r["src_count"]), r["service"])
         for r in cfg["mgmt_rules"]])
    v = cfg["vpn"]
    conn.execute(
        "INSERT INTO vpn_auth VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (fid, str(v["sslvpn"]), str(v["l2tp"]), v["auth_method"],
         v["directory"], ", ".join(v["radius_servers"]),
         ", ".join(v["ldap_servers"]), str(v["saml"]), str(v["duo"]),
         str(v["admin_totp"]), v["mfa"]))
    conn.commit()
    return fid


# ---------------------------------------------------------------------------
# Findings engine
# ---------------------------------------------------------------------------
def vlans_of(cfg):
    return [x for x in cfg["interfaces"] if x["vlan"] not in ("0", "")]


def analyze(cfg):
    """Return (checklist, findings). Severity: CRITICAL/HIGH/MEDIUM/LOW."""
    findings = []
    def add(sev, title, detail):
        findings.append({"sev": sev, "title": title, "detail": detail})

    lan = next((z for z in cfg["zones"] if z["name"] == TRUSTED_ZONE), None)
    lan_cfs = bool(lan) and lan["cfs"] not in ("0", "")
    lan_idp = bool(lan) and lan["idp"] not in ("0", "")

    # 1. IPS/IDS — REQUIRED on the trusted LAN
    ips_on = cfg["ips_global"].lower() == "on"
    if not ips_on:
        add("HIGH", "IPS/IDS globally disabled",
            f"isIDPEnabled = '{cfg['ips_global'] or '(unset)'}'. Intrusion "
            "Prevention is OFF for the whole firewall.")
    if not lan_idp:
        add("HIGH", f"IPS/IDS not enabled on {TRUSTED_ZONE} (required)",
            f"The {TRUSTED_ZONE} zone has no IPS/IDP profile applied "
            "(zoneObjMyIDPProfile = 0).")

    # 2. Content filtering — REQUIRED on the trusted LAN
    cfs_on = cfg["cfs_global"].lower() == "on"
    if not cfs_on:
        add("HIGH", "Content Filtering Service globally disabled",
            f"cfsEnabled = '{cfg['cfs_global'] or '(unset)'}'.")
    if not lan_cfs:
        add("HIGH", f"Content filtering not enabled on {TRUSTED_ZONE} "
            "(required)",
            f"The {TRUSTED_ZONE} zone has no CFS profile applied "
            "(zoneObjCflProfile = 0).")
    zones_missing_cfs = [z["name"] for z in cfg["zones"]
                         if z["name"] not in NON_CFS_ZONES | {TRUSTED_ZONE}
                         and z["cfs"] in ("0", "")]
    if zones_missing_cfs:
        add("MEDIUM", "Content filtering not enforced on other internal zones",
            "Zones without a CFS profile: " + ", ".join(zones_missing_cfs))

    # License coverage for the core services
    for code in ("IDP", "CFSP"):
        s = cfg["lic"]["services"].get(code)
        if s and s["status"] != "licensed":
            add("HIGH", f"{s['name']} license {s['status']}",
                f"Service '{code}' status = {s['status']} "
                f"(expiry {s['exp'] or 'n/a'}). The control cannot enforce "
                "without a valid license.")
    for code, s in cfg["lic"]["services"].items():
        if s["status"] == "expired" and code not in ("IDP", "CFSP"):
            add("LOW", f"Security service expired: {s['name']}",
                f"{code} expired {s['exp']}.")

    # per-zone IPS profile (only meaningful when global IPS on)
    zones_missing_idp = [z["name"] for z in cfg["zones"]
                         if z["name"] not in ("VPN", "SSLVPN", "MULTICAST")
                         and z["idp"] in ("0", "")]
    if ips_on and zones_missing_idp:
        add("MEDIUM", "IPS profile not applied to all zones",
            "Zones without an IPS/IDP profile: " + ", ".join(zones_missing_idp))

    # intra-zone communication (loose east-west / inter-VLAN comm)
    intra_zones = [z["name"] for z in cfg["zones"]
                   if z["intra"] == "1" and z["name"] not in ("WAN",)]
    if intra_zones:
        add("LOW", "Intra-zone communication allowed",
            "Devices within these zones can talk to each other unrestricted "
            "(no inter-VLAN isolation inside the zone): "
            + ", ".join(intra_zones))

    # 3/4/5. Management access rules
    mgmt = [r for r in cfg["mgmt_rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"]

    def open_rules(zone_pred):
        return [r for r in mgmt if zone_pred(r) and r["src_count"] is None]

    def wide_rules(zone_pred):
        out = []
        for r in mgmt:
            if not zone_pred(r):
                continue
            c = r["src_count"]
            if isinstance(c, int) and c > 2:
                out.append(r)
        return out

    is_wan = lambda r: r["src_zone"] == "WAN"
    is_lan = lambda r: r["src_zone"] not in ("WAN", "VPN")

    # External (WAN) management open to Any
    for r in open_rules(is_wan):
        add("CRITICAL", "External management open to the Internet",
            f"WAN rule allows {r['service']} from {r['src_desc']} "
            f"(-> {r['dst_zone']}). Restrict to 1-2 admin IPs.")
    # Cleartext HTTP management on WAN (even if restricted)
    for r in mgmt:
        if is_wan(r) and r["service"].startswith("HTTP Management"):
            add("HIGH", "Cleartext (HTTP) management enabled on WAN",
                f"WAN rule allows HTTP Management from {r['src_desc']}. "
                "Use HTTPS only.")
    for r in wide_rules(is_wan):
        add("MEDIUM", "External management allowed from more than 2 IPs",
            f"WAN {r['service']} from {r['src_desc']} "
            f"({r['src_count']} addresses).")

    # Internal (LAN-side) management from Any
    lan_open = open_rules(is_lan)
    if lan_open:
        svcs = sorted({r["service"] for r in lan_open})
        add("MEDIUM", "Internal management not limited to specific IPs",
            "Internal zones allow " + ", ".join(svcs)
            + " from Any source. Limit to 1-2 admin workstation IPs.")

    # SSH specifically
    ssh_rules = [r for r in mgmt if r["service"].startswith("SSH Management")]
    ssh_open = [r for r in ssh_rules if r["src_count"] is None]
    if ssh_open:
        add("MEDIUM", "SSH management not limited to a single IP",
            "SSH Management allowed from Any in zones: "
            + ", ".join(sorted({r["src_zone"] for r in ssh_open})))

    # Exposed external (WAN-inbound) services open to any source
    for r in external_open_ports(cfg):
        if compliance(r)[0] == "red":
            add("HIGH", "External port open to the Internet (any source)",
                f"WAN allows {r['service']} -> {r['dst_zone']} "
                f"({r['dst_obj']}) from ANY source. Restrict to known IPs."
                + (f" [{r['comment']}]" if r["comment"] else ""))

    # VPN authentication & MFA
    vpn = cfg["vpn"]
    vpn_active = vpn["sslvpn"] or vpn["l2tp"]
    has_directory = vpn["directory"].startswith(("Active", "Entra"))
    has_mfa = vpn["mfa"] != "None"
    if not has_mfa:
        add("HIGH" if vpn_active else "MEDIUM",
            "No multi-factor authentication (MFA) configured",
            "No DUO (RADIUS), Entra/SAML, or TOTP MFA detected. "
            f"Login authentication = {vpn['auth_method']}."
            + (" SSL VPN appears configured." if vpn["sslvpn"] else ""))
    if not has_directory:
        add("MEDIUM", "Authentication not integrated with AD / Entra",
            "No Active Directory / LDAP or Entra ID / SAML integration "
            f"detected; authentication is '{vpn['auth_method']}'. Bank policy "
            "typically requires directory-backed accounts.")
    elif not vpn["duo"]:
        add("LOW", "Directory integrated but DUO MFA not detected",
            f"Directory = {vpn['directory']}, but no DUO reference found. "
            "Confirm MFA is enforced for VPN logins.")

    # ---- checklist ----
    def status(ok, review=False):
        return "REVIEW" if review else ("PASS" if ok else "FAIL")

    wan_mgmt = [r for r in mgmt if is_wan(r)]
    wan_open = any(r["src_count"] is None for r in wan_mgmt)
    wan_wide = any(isinstance(r["src_count"], int) and r["src_count"] > 2
                   for r in wan_mgmt)
    lan_mgmt = [r for r in mgmt if is_lan(r)]
    lan_open2 = any(r["src_count"] is None for r in lan_mgmt)

    ssh_ok = bool(ssh_rules) and all(
        (r["src_count"] == 1) for r in ssh_rules if is_lan(r) or is_wan(r)) \
        and not any(r["src_count"] is None for r in ssh_rules)

    checklist = [
        (f"1. IPS/IDS enabled on {TRUSTED_ZONE} (required)",
         status(ips_on and lan_idp),
         f"global isIDPEnabled = {cfg['ips_global'] or '(unset)'}; "
         f"{TRUSTED_ZONE} IPS profile = {'yes' if lan_idp else 'no'}"),
        (f"2. Content filtering enabled on {TRUSTED_ZONE} (required)",
         status(cfs_on and lan_cfs),
         f"global cfsEnabled = {cfg['cfs_global'] or '(unset)'}; "
         f"{TRUSTED_ZONE} CFS profile = {'yes' if lan_cfs else 'no'}"),
        ("3. SSH management enabled & limited to 1 IP",
         status(ssh_ok, review=not ssh_rules),
         f"{len(ssh_rules)} SSH mgmt rule(s); "
         + ("some allow Any" if ssh_open else "all restricted")),
        ("4. External (WAN) management limited to 1-2 IPs",
         status(bool(wan_mgmt) and not wan_open and not wan_wide,
                review=not wan_mgmt),
         "WAN mgmt from Any present" if wan_open else
         (">2 IPs allowed" if wan_wide else "restricted / none")),
        ("5. Internal management limited to 1-2 IPs",
         status(bool(lan_mgmt) and not lan_open2, review=not lan_mgmt),
         "Internal mgmt from Any present" if lan_open2 else "restricted"),
        ("6. VPN auth via AD/Entra + MFA (DUO)",
         status(has_directory and has_mfa),
         f"auth={vpn['auth_method']}; directory={vpn['directory']}; "
         f"MFA={vpn['mfa']}"),
    ]

    # 6. VLAN role coverage
    vlan_list = vlans_of(cfg)
    coverage = []
    for role, pats in VLAN_ROLES.items():
        matches = [v for v in vlan_list
                   if any(p in (v["name"] + " " + v["comment"]).lower()
                          for p in pats)]
        coverage.append((role, matches))

    return checklist, findings, coverage, vlan_list


def evaluate_compliance(cfg, union_cats, union_countries):
    """Evaluate every compliance rule for one firewall. Always emits the same
    ordered rule set (so the cross-firewall matrix lines up). Each result:
    {rule, status: PASS/FAIL/WARN/NA, detail}."""
    R = RULES
    tz = TRUSTED_ZONE
    out = []

    def rule(name, status, detail):
        out.append({"rule": name, "status": status, "detail": detail})

    zones = {z["name"]: z for z in cfg["zones"]}
    lan = zones.get(tz)
    lan_cfs = bool(lan) and lan["cfs"] not in ("0", "")
    lan_idp = bool(lan) and lan["idp"] not in ("0", "")
    ips_on = cfg["ips_global"].lower() == "on"
    cfs_on = cfg["cfs_global"].lower() == "on"
    mgmt = [r for r in cfg["mgmt_rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"]
    ssh = [r for r in mgmt if r["service"].startswith("SSH Management")]
    maxm = R["management"].get("max_source_ips", 2)

    def too_broad(r, mx):
        c = r["src_count"]
        return c is None or c == "?" or (isinstance(c, int) and c > mx)

    # LAN content filter + IPS
    rule(f"Content filtering enabled on {tz}",
         "PASS" if (cfs_on and lan_cfs) else "FAIL",
         f"global cfsEnabled={cfg['cfs_global'] or 'unset'}; "
         f"{tz} CFS profile={'yes' if lan_cfs else 'no'}")
    rule(f"IPS/IDS enabled on {tz}",
         "PASS" if (ips_on and lan_idp) else "FAIL",
         f"global isIDPEnabled={cfg['ips_global'] or 'unset'}; "
         f"{tz} IPS profile={'yes' if lan_idp else 'no'}")

    # SSH: must be enabled, only on LAN, <= N IPs
    scfg = R["ssh"]
    allowed = set(scfg.get("allowed_zones", ["LAN"]))
    maxssh = scfg.get("max_source_ips", 2)
    rule("SSH management enabled",
         "PASS" if ssh else "FAIL",
         f"{len(ssh)} enabled SSH-management allow rule(s)")
    if not ssh:
        rule(f"SSH reachable only from {'/'.join(sorted(allowed))}", "NA",
             "SSH not enabled")
        rule(f"SSH restricted to <= {maxssh} IPs", "NA", "SSH not enabled")
    else:
        bad_zone = sorted({r["src_zone"] for r in ssh
                           if r["src_zone"] not in allowed})
        rule(f"SSH reachable only from {'/'.join(sorted(allowed))}",
             "PASS" if not bad_zone else "FAIL",
             "OK" if not bad_zone else "also allowed from: " + ", ".join(bad_zone))
        # Only judge SSH rules in the allowed zone(s); SSH from other zones is
        # a separate rule (must be removed, not merely IP-restricted).
        ssh_in = [r for r in ssh if r["src_zone"] in allowed]
        ssh_bad = [r for r in ssh_in if too_broad(r, maxssh)]
        rule(f"{'/'.join(sorted(allowed))} SSH restricted to <= {maxssh} IPs",
             "PASS" if not ssh_bad else "FAIL",
             "OK" if not ssh_bad else "; ".join(
                 f"{r['src_zone']}: {r['src_desc']}" for r in ssh_bad[:5]))

    # No unrestricted management access (internal or external)
    anym = [r for r in mgmt if r["src_count"] is None]
    anym_lbl = sorted({f"{r['src_zone']} {r['service']}" for r in anym})
    rule("No unrestricted (Any-source) firewall management",
         "PASS" if not anym else "FAIL",
         "OK" if not anym else f"{len(anym)} rule(s) allow Any: "
         + ", ".join(anym_lbl)[:220])

    # External / internal management <= N IPs
    wanm = [r for r in mgmt if r["src_zone"] == "WAN"]
    wan_bad = [r for r in wanm if too_broad(r, maxm)]
    rule(f"External (WAN) management restricted to <= {maxm} IPs",
         "WARN" if not wanm else ("PASS" if not wan_bad else "FAIL"),
         "no WAN management rules" if not wanm else
         ("OK" if not wan_bad else f"{len(wan_bad)} WAN mgmt rule(s) Any/too broad"))
    lanm = [r for r in mgmt if r["src_zone"] not in ("WAN", "VPN")]
    lan_bad = [r for r in lanm if too_broad(r, maxm)]
    rule(f"Internal management restricted to <= {maxm} IPs",
         "WARN" if not lanm else ("PASS" if not lan_bad else "FAIL"),
         "no internal mgmt rules" if not lanm else
         ("OK" if not lan_bad else f"{len(lan_bad)} internal mgmt rule(s) Any/too broad"))

    # Admin interface + SSH may ONLY come from LAN/WAN (never VPN or other VLANs)
    admin_zones = set(R["management"].get("admin_allowed_zones",
                                          ["LAN", "WAN"]))
    off_zone = [r for r in mgmt if r["src_zone"] not in admin_zones]
    off_lbl = sorted({f"{r['src_zone']} -> {r['service']}" for r in off_zone})
    rule("Admin/SSH access blocked from VPN & non-"
         + "/".join(sorted(admin_zones)) + " zones",
         "PASS" if not off_zone else "FAIL",
         "OK" if not off_zone else f"{len(off_zone)} rule(s) expose mgmt to "
         "other zones: " + ", ".join(off_lbl)[:240])

    # VPN user isolation: no user-to-user, and LAN cannot initiate to users
    vpn_user_zones = RULES.get("vpn_user_zones", ["SSLVPN"])
    u2u_bad = [z for z in vpn_user_zones
               if zones.get(z) and zones[z]["intra"] == "1"]
    rule("VPN user-to-user traffic blocked",
         "PASS" if not u2u_bad else "FAIL",
         "OK — intra-zone communication off" if not u2u_bad
         else "intra-zone comm ON for: " + ", ".join(u2u_bad))
    lan_to_vpn = [r for r in cfg["rules"]
                  if r["enabled"] == "1" and r["action"] == "Allow"
                  and r["src_zone"] == tz and r["dst_zone"] in vpn_user_zones]
    rule(f"{tz} does not initiate to VPN users",
         "PASS" if not lan_to_vpn else "FAIL",
         "OK" if not lan_to_vpn
         else f"{len(lan_to_vpn)} {tz}->{'/'.join(vpn_user_zones)} rule(s)")

    # No UNTRUSTED zone allowed INTO the trusted LAN (SSLVPN etc. are trusted)
    trusted = "/".join(RULES.get("trusted_zones", [tz]))
    inbound = untrusted_into_lan(cfg)
    in_lbl = sorted({f"{r['src_zone']} ({r['service']})" for r in inbound})
    rule(f"Only trusted zones ({trusted}) may reach {tz}",
         "PASS" if not inbound else "FAIL",
         "OK" if not inbound else "non-trusted access in from: "
         + ", ".join(in_lbl)[:240])

    # No external ports open to any (except expected VPN listeners)
    ext_red = [r for r in external_open_ports(cfg) if compliance(r)[0] == "red"]
    rule("No external ports open to any source",
         "PASS" if not ext_red else "FAIL",
         "OK" if not ext_red else f"{len(ext_red)} WAN service(s) open to any: "
         + ", ".join(sorted({r['service'] for r in ext_red})))

    # Branch-to-branch WAN->LAN rules must be pinned to known branch subnets
    wla = wan_lan_any_source(cfg)
    rule("Branch (WAN->LAN) rules scoped to known subnets",
         "PASS" if not wla else "FAIL",
         "OK — no WAN->LAN 'Any' source" if not wla
         else f"{len(wla)} WAN->LAN rule(s) accept ANY source")

    # Firewall must not answer ping from the Internet (internal ping is fine)
    wanping = wan_ping_rules(cfg)
    rule("No ping response from the Internet (WAN)",
         "PASS" if not wanping else "FAIL",
         "OK — internal ping only" if not wanping
         else f"{len(wanping)} WAN Ping rule(s) answer any source")

    # SSL VPN -> DUO/Entra MFA required
    vpn = cfg["vpn"]
    if vpn["sslvpn"]:
        accepted = R["vpn"].get("accepted_mfa", ["DUO", "Entra"])
        has = any(m.lower() in vpn["mfa"].lower() for m in accepted)
        rule("SSL VPN configured -> DUO/Entra MFA required",
             "PASS" if has else "FAIL", f"SSL VPN on; MFA in use = {vpn['mfa']}")
    else:
        rule("SSL VPN configured -> DUO/Entra MFA required", "NA",
             "SSL VPN not configured on this firewall")
    rule("VPN authentication integrated with AD/Entra",
         "PASS" if vpn["directory"].startswith(("Active", "Entra")) else "FAIL",
         f"directory = {vpn['directory']}")

    # GMS is legacy — must be replaced by NSM
    rule("Legacy GMS management not configured (use NSM)",
         "FAIL" if cfg["gms_enabled"] else "PASS",
         "gmsServerEnable = on" if cfg["gms_enabled"]
         else "GMS not enabled")

    # Consistency: match the strictest firewall
    if union_cats is not None:
        mine = set(cfg["cfs_profiles"][0]["blocked"]) if cfg["cfs_profiles"] else set()
        missing = sorted(union_cats - mine)
        rule("Content filter matches strictest firewall",
             "PASS" if not missing else "FAIL",
             "matches" if not missing else f"missing {len(missing)}: "
             + ", ".join(missing))
    if union_countries is not None:
        mine = set(cfg["geo"]["blocked_countries"])
        missing = sorted(union_countries - mine)
        rule("Geo-blocking matches strictest firewall",
             "PASS" if not missing else "FAIL",
             "matches" if not missing else f"missing {len(missing)}: "
             + ", ".join(missing))

    return out


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
def esc(x):
    return html.escape(str(x))


CSS = """
<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
     margin:0;background:#f6f7f9;color:#1c2530}
header{background:#0b2540;color:#fff;padding:22px 28px}
header h1{margin:0;font-size:20px}
header .sub{opacity:.8;font-size:13px;margin-top:4px}
main{max-width:1150px;margin:0 auto;padding:24px 28px 60px}
h2{font-size:16px;margin:32px 0 10px;border-bottom:2px solid #e2e6ea;
   padding-bottom:6px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;
      box-shadow:0 1px 2px rgba(0,0,0,.06);margin-bottom:8px}
th,td{border:1px solid #e2e6ea;padding:7px 10px;text-align:left;
      vertical-align:top}
th{background:#eef1f4;font-weight:600}
tr:nth-child(even) td{background:#fafbfc}
.diff{background:#fff4e0 !important}
.pass{color:#0a7f3f;font-weight:700}.fail{color:#c0392b;font-weight:700}
.review{color:#b8860b;font-weight:700}
.pill{display:inline-block;padding:3px 11px;border-radius:12px;font-size:11px;
      font-weight:700;color:#fff;white-space:nowrap}
.green{background:#0a7f3f}.red{background:#c0392b}.orange{background:#d98324}
.gray{background:#6b7a8f}
td.cell{text-align:center;font-weight:700;font-size:20px;line-height:1;
        width:130px;background:#fff !important}
.sym-green{color:#0a7f3f}.sym-red{color:#c0392b}
.sym-orange{color:#d98324}.sym-gray{color:#aab4bf}
.lg{display:inline-block;width:20px;text-align:center;font-weight:700;
    font-size:16px;vertical-align:middle}
.score{display:inline-block;padding:4px 12px;border-radius:14px;font-weight:700;
       color:#fff;margin-right:6px;font-size:13px}
.copybtn{background:#0b2540;color:#fff;border:0;padding:8px 14px;
         border-radius:6px;cursor:pointer;font-size:13px;margin-top:8px}
.copybtn:hover{background:#123a63}
tr.r-red td{background:#fdecea !important}
tr.r-orange td{background:#fdf3e3 !important}
tr.r-green td{background:#eaf6ef !important}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
       font-weight:700;color:#fff}
.CRITICAL{background:#7b1113}.HIGH{background:#c0392b}
.MEDIUM{background:#d98324}.LOW{background:#6b7a8f}
.on{color:#0a7f3f;font-weight:600}.off{color:#c0392b;font-weight:600}
.muted{color:#7a8794}
.card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:16px;
      margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.05)}
.card h3{margin:0 0 12px;font-size:15px}
small{color:#7a8794}
</style>
"""


def _page(title, subtitle, body):
    return (f"<!doctype html><meta charset='utf-8'><title>{esc(title)}</title>"
            f"{CSS}<header>"
            f"<div style='font-size:11px;letter-spacing:2.5px;font-weight:700;"
            f"color:#9fc3ec;margin-bottom:6px'>AUDITHAT.COM</div>"
            f"<h1>{esc(title)}</h1>"
            f"<div class='sub'>{esc(subtitle)}</div></header><main>{body}</main>")


def onoff(v):
    v = (v or "").lower()
    if v in ("on", "1"):
        return "<span class='on'>on</span>"
    return "<span class='off'>off</span>"


def label(cfg):
    """Prefer the configured firewall name; fall back to serial."""
    name = cfg.get("fw_name") or ""
    if name and name != "(unnamed)":
        return f"{name} ({cfg['model']})"
    return f"{cfg['model'] or '?'} · {cfg['serial'] or cfg['source']}"


def trusted_inbound(cfg):
    """Enabled rules granting other zones access INTO the trusted zone."""
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["dst_zone"] == TRUSTED_ZONE
            and r["src_zone"] != TRUSTED_ZONE]


def wan_lan_any_source(cfg):
    """Enabled WAN -> LAN Allow rules with an 'Any' source. These are branch-
    to-branch paths that must be pinned to the known branch subnets."""
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"
            and r["src_zone"] == "WAN" and r["dst_zone"] == TRUSTED_ZONE
            and r["src_count"] is None]


def vpn_user_access(cfg):
    """Enabled Allow rules sourced from a VPN-user zone = what remote VPN
    users can reach (should be LAN + specific resources, and nothing else)."""
    zones = RULES.get("vpn_user_zones", ["SSLVPN"])
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"
            and r["src_zone"] in zones]


def untrusted_into_lan(cfg):
    """Enabled Allow rules that let a NON-trusted zone reach the trusted LAN,
    excluding management-service rules (those are handled by the management-
    isolation rule). Trusted zones (e.g. SSLVPN remote users) are allowed."""
    trusted = set(RULES.get("trusted_zones", [TRUSTED_ZONE]))
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"
            and r["dst_zone"] == TRUSTED_ZONE
            and r["src_zone"] not in trusted
            and "Management" not in r["service"]]


def trusted_outbound(cfg):
    """Enabled rules granting the trusted zone access OUT to other zones."""
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["src_zone"] == TRUSTED_ZONE
            and r["dst_zone"] != TRUSTED_ZONE]


def external_open_ports(cfg):
    """Enabled Allow rules sourced from WAN = ports open from the Internet."""
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"
            and r["src_zone"] == "WAN"]


def internal_open_ports(cfg):
    """Enabled Allow rules that open a firewall-listening service (management
    or SSL VPN) from an INTERNAL (non-WAN) zone."""
    out = []
    for r in cfg["rules"]:
        if r["enabled"] != "1" or r["action"] != "Allow":
            continue
        if r["src_zone"] in ("WAN",):
            continue
        svc = r["service"]
        if "Management" in svc or "SSL VPN" in svc or "SSLVPN" in svc:
            out.append(r)
    return out


def wan_ping_rules(cfg):
    """Enabled Allow rules that make the firewall answer ping from the WAN
    (Internet). Internal (LAN) ping is intentionally left alone."""
    return [r for r in cfg["rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"
            and r["src_zone"] == "WAN" and "Ping" in r["service"]]


def compliance(r):
    """Traffic-light verdict for an open-port rule -> (color, text).
    green = restricted to 1-2 IPs; orange = restricted-but-broad / cleartext /
    expected VPN listener; red = open to any source (no IP restriction)."""
    c = r["src_count"]
    svc = r["service"]
    cleartext = svc.startswith("HTTP Management")
    is_mgmt = "Management" in svc
    # VPN / IPSec listeners must accept connections from any remote IP -> orange
    vpn_listener = any(x in svc for x in
                       ("IKE", "SSL VPN", "SSLVPN", "SonicpointN", "NAT-T"))
    if c is None:                       # Any source
        if is_mgmt:
            return "red", "OPEN mgmt — any source"
        if vpn_listener:
            return "orange", "open (VPN listener — expected)"
        return "red", "OPEN — any source"
    if cleartext:
        return "orange", "cleartext HTTP mgmt"
    if c == "?":                        # named object / group, not counted
        return "orange", "restricted (named object)"
    if isinstance(c, int):
        if c <= 2:
            return "green", f"restricted ({c} IP)"
        return "orange", f"restricted ({c} IPs)"
    return "orange", "review"


# ---------------------- differences report ----------------------
def build_differences(configs):
    b = []

    # device summary
    b.append("<h2>Device summary</h2><table><tr><th>Item</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c in configs) + "</tr>")
    rows = [
        ("Firewall name", lambda c: c["fw_name"]),
        ("Licensed to", lambda c: c["lic"]["friendly"] or "—"),
        ("Model", lambda c: c["model"]),
        ("Serial", lambda c: c["serial"]),
        ("Firmware build", lambda c: c["build"]),
        ("Global IPS/IDS", lambda c: onoff(c["ips_global"])),
        ("Global Content Filter", lambda c: onoff(c["cfs_global"])),
        ("# Zones", lambda c: len(c["zones"])),
        ("# VLAN sub-interfaces", lambda c: len(vlans_of(c))),
    ]
    for name, fn in rows:
        vals = [fn(c) for c in configs]
        raw = [str(v) for v in vals]
        cls = " class='diff'" if len(set(raw)) > 1 else ""
        b.append(f"<tr><td>{esc(name)}</td>"
                 + "".join(f"<td{cls}>{v}</td>" for v in vals) + "</tr>")
    b.append("</table><small>Highlighted rows differ between firewalls.</small>")

    # zone security matrix
    b.append("<h2>Per-zone security services</h2>"
             "<small>0 = disabled / no profile. Cells highlighted where the "
             "firewalls differ for that zone.</small>")
    zone_names = []
    for c in configs:
        for z in c["zones"]:
            if z["name"] not in zone_names:
                zone_names.append(z["name"])
    zmap = [{z["name"]: z for z in c["zones"]} for c in configs]
    for field, lbl in [("cfs", "Content Filter"), ("idp", "IPS/IDP"),
                       ("intra", "Intra-zone comm")]:
        b.append(f"<h3 style='font-size:13px;margin:14px 0 4px'>{lbl}</h3>"
                 "<table><tr><th>Zone</th>"
                 + "".join(f"<th>{esc(label(c))}</th>" for c in configs)
                 + "</tr>")
        for zn in zone_names:
            vals = []
            for m in zmap:
                z = m.get(zn)
                vals.append(z[field] if z else "—")
            cls = " class='diff'" if len(set(map(str, vals))) > 1 else ""
            b.append(f"<tr><td>{esc(zn)}</td>"
                     + "".join(f"<td{cls}>{esc(v)}</td>" for v in vals)
                     + "</tr>")
        b.append("</table>")

    # VLAN inventory
    b.append("<h2>VLAN inventory</h2>")
    for c in configs:
        vs = vlans_of(c)
        b.append(f"<div class='card'><h3>{esc(label(c))}</h3>")
        if not vs:
            b.append("<p class='muted'>No VLAN sub-interfaces on this firewall."
                     "</p></div>")
            continue
        b.append("<table><tr><th>VLAN</th><th>Interface</th><th>Name / comment"
                 "</th><th>IP</th></tr>")
        for v in sorted(vs, key=lambda x: int(x["vlan"])):
            cname = esc(v['comment']) or "<span class='muted'>(no name)</span>"
            b.append(f"<tr><td>{esc(v['vlan'])}</td><td>{esc(v['name'])}</td>"
                     f"<td>{cname}</td><td>{esc(v['ip'])}</td></tr>")
        b.append("</table></div>")

    # management posture
    b.append("<h2>Management access posture</h2>"
             "<small>Enabled 'Allow' management rules, by source zone. "
             "'Any' = unrestricted.</small><table><tr><th>Source zone</th>"
             "<th>Service</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c in configs) + "</tr>")
    combos = []
    per = []
    for c in configs:
        seen = {}
        for r in c["mgmt_rules"]:
            if r["enabled"] == "1" and r["action"] == "Allow":
                key = (r["src_zone"], r["service"])
                seen.setdefault(key, set()).add(r["src_desc"])
                if key not in combos:
                    combos.append(key)
        per.append(seen)
    for key in combos:
        vals = []
        for seen in per:
            srcs = seen.get(key)
            vals.append(", ".join(sorted(srcs)) if srcs else "—")
        cls = " class='diff'" if len(set(vals)) > 1 else ""
        b.append(f"<tr><td>{esc(key[0])}</td><td>{esc(key[1])}</td>"
                 + "".join(f"<td{cls}>{esc(v)}</td>" for v in vals) + "</tr>")
    b.append("</table>")

    # VPN authentication & MFA
    b.append("<h2>VPN Authentication &amp; MFA</h2>"
             "<small>Directory (AD/Entra) integration and multi-factor status. "
             "Cells highlighted where the firewalls differ.</small>"
             "<table><tr><th>Item</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c in configs) + "</tr>")
    vrows = [
        ("SSL VPN configured", lambda v: "yes" if v["sslvpn"] else "no"),
        ("L2TP VPN", lambda v: "on" if v["l2tp"] else "off"),
        ("Login auth method", lambda v: v["auth_method"]),
        ("Directory integration", lambda v: v["directory"]),
        ("RADIUS servers", lambda v: ", ".join(v["radius_servers"]) or "—"),
        ("LDAP/AD domains", lambda v: ", ".join(v["ldap_servers"]) or "—"),
        ("Entra / SAML", lambda v: "yes" if v["saml"] else "no"),
        ("DUO detected", lambda v: "yes" if v["duo"] else "no"),
        ("Admin login TOTP", lambda v: "on" if v["admin_totp"] else "off"),
        ("MFA in use", lambda v: v["mfa"]),
    ]
    for name, fn in vrows:
        vals = [fn(c["vpn"]) for c in configs]
        cls = " class='diff'" if len(set(vals)) > 1 else ""
        b.append(f"<tr><td>{esc(name)}</td>"
                 + "".join(f"<td{cls}>{esc(v)}</td>" for v in vals) + "</tr>")
    b.append("</table>")

    # Local user accounts
    b.append("<h2>Local users</h2>"
             "<small>User accounts stored on the firewall itself — enabled "
             "state, last login (only recorded in the export for the admin "
             "account), management (admin) login, VPN access and group "
             "membership. Directory (LDAP/AD/Entra) accounts are not part of "
             "the EXP export.</small>")

    def yn(v, yes="yes", no="no"):
        if v is None:
            return "<span class='muted'>—</span>"
        return (f"<span class='pill green'>{yes}</span>" if v
                else f"<span class='muted'>{no}</span>")

    for c in configs:
        users = c.get("local_users", [])
        b.append(f"<div class='card'><h3>{esc(label(c))}</h3>")
        if not users:
            b.append("<p class='muted'>No local user accounts in this "
                     "export.</p></div>")
            continue
        b.append("<table><tr><th>User</th><th>Status</th><th>Last login</th>"
                 "<th>Admin / mgmt login</th><th>VPN access</th>"
                 "<th>Member of</th></tr>")
        for u in sorted(users, key=lambda x: (not x["builtin"],
                                              x["name"].lower())):
            nm = f"<b>{esc(u['name'])}</b>"
            if u["builtin"]:
                nm += " <span class='pill gray'>built-in</span>"
            elif u["comment"]:
                nm += f"<br><small>{esc(u['comment'])}</small>"
            status = ("<span class='pill green'>enabled</span>" if u["enabled"]
                      else "<span class='pill red'>disabled</span>")
            last = (esc(u["last_login"]) if u["last_login"]
                    else "<span class='muted'>never recorded</span>")
            admin = yn(u["admin"], yes="yes")
            vpn = yn(u["vpn"], yes="yes")
            member = (", ".join(esc(g) for g in u["member_of"])
                      or "<span class='muted'>—</span>")
            b.append(f"<tr><td>{nm}</td><td>{status}</td><td>{last}</td>"
                     f"<td>{admin}</td><td>{vpn}</td><td>{member}</td></tr>")
        b.append("</table></div>")

    # Licenses & VPN license counts
    b.append("<h2>Security &amp; VPN licenses</h2>"
             "<small>VPN license counts (used / max) and security-service "
             "license status. Cells highlighted where firewalls differ.</small>"
             "<table><tr><th>License</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c in configs) + "</tr>")

    def lic_cell(c, code):
        s = c["lic"]["services"].get(code)
        if not s:
            return "—"
        if code in ("VPNSSL", "VPNC"):
            return f"{s['count']} / {s['max']} ({s['status']})"
        return f"{s['status']}" + (f" — exp {s['exp']}" if s["exp"] else "")

    lic_rows = [("SSL VPN (used/max)", "VPNSSL"),
                ("Global VPN Client (used/max)", "VPNC")]
    lic_rows += [(name, code) for code, name in LICENSE_CODES.items()
                 if code not in ("VPNSSL", "VPNC")]
    for name, code in lic_rows:
        vals = [lic_cell(c, code) for c in configs]
        cls = " class='diff'" if len(set(vals)) > 1 else ""
        b.append(f"<tr><td>{esc(name)}</td>"
                 + "".join(f"<td{cls}>{esc(v)}</td>" for v in vals) + "</tr>")
    b.append("</table>")

    # Content filter & Geo-IP comparison
    b.append("<h2>Content filter &amp; Geo-IP</h2><table><tr><th>Item</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c in configs) + "</tr>")
    def cfs_blocked(c):
        return c["cfs_profiles"][0]["blocked"] if c["cfs_profiles"] else []
    crows = [
        ("CFS blocked categories (count)",
         lambda c: str(len(cfs_blocked(c)))),
        ("Geo-IP enforcement", lambda c: "on" if c["geo"]["enforcement"] else "off"),
        ("Geo blocked countries (count)",
         lambda c: str(c["geo"]["blocked_count"])),
        ("Block unknown IPs", lambda c: "on" if c["geo"]["block_unknown"] else "off"),
        ("Botnet filtering", lambda c: "on" if c["geo"]["botnet"] else "off"),
    ]
    for name, fn in crows:
        vals = [fn(c) for c in configs]
        cls = " class='diff'" if len(set(vals)) > 1 else ""
        b.append(f"<tr><td>{esc(name)}</td>"
                 + "".join(f"<td{cls}>{esc(v)}</td>" for v in vals) + "</tr>")
    # which categories differ between firewalls
    if len(configs) > 1:
        sets = [set(cfs_blocked(c)) for c in configs]
        only = []
        allcats = set().union(*sets)
        for cat in sorted(allcats):
            present = [cat in s for s in sets]
            if not all(present):
                only.append(cat + " (" + ", ".join(
                    label(configs[i]) for i, p in enumerate(present) if p)
                    + ")")
        b.append("</table>")
        if only:
            b.append("<p><b>Categories blocked on some but not all firewalls:"
                     "</b><br>" + "<br>".join(esc(x) for x in only) + "</p>")
        else:
            b.append("<p class='muted'>All firewalls block the same content "
                     "filter categories.</p>")
    else:
        b.append("</table>")

    # ---- side-by-side matrices: filters & geo-blocking per firewall ----
    def comparison_matrix(heading, col1, per_fw):
        union = sorted(set().union(*per_fw)) if per_fw else []
        if not union:
            return
        consistent = [it for it in union if all(it in s for s in per_fw)]
        differing = [it for it in union if it not in consistent]
        # differing rows first so the inconsistencies are obvious
        ordered = differing + consistent
        b.append(f"<h3 style='font-size:14px;margin-top:18px'>{esc(heading)} "
                 f"<span class='pill {'green' if not differing else 'orange'}'>"
                 f"{len(differing)} differ</span></h3>"
                 "<table><tr><th>" + esc(col1) + "</th>"
                 + "".join(f"<th>{esc(label(c))}</th>" for c in configs)
                 + "</tr>")
        for it in ordered:
            row_diff = it in differing
            cells = ""
            for s in per_fw:
                sym = ("<span class='sym-green'>&#10004;</span>" if it in s
                       else "<span class='sym-red'>&#10008;</span>")
                cells += (f"<td style='text-align:center;font-size:16px'>"
                          f"{sym}</td>")
            rc = " style='background:#fdf3e3'" if row_diff else ""
            b.append(f"<tr{rc}><td>{esc(it)}</td>{cells}</tr>")
        b.append("</table>")

    b.append("<h2>Filters &amp; geo-blocking — side-by-side</h2>"
             "<small>&#10004; = blocked on that firewall, &#10008; = not "
             "blocked. Rows that differ are listed first and highlighted.</small>")
    comparison_matrix("Content filter categories", "Category",
                      [set(cfs_blocked(c)) for c in configs])
    comparison_matrix("Geo-IP blocked countries", "Country",
                      [set(c["geo"]["blocked_countries"]) for c in configs])

    return _page("SonicWall Configuration Comparison",
                 "Differences across " + str(len(configs))
                 + " firewall exports — content filter, IPS, zones, VLANs, "
                 "management", "".join(b))


def _action_cell(r):
    cls = "pass" if r["action"] == "Allow" else "muted"
    return f"<span class='{cls}'>{esc(r['action'])}</span>"


def _rules_table(rules, cols):
    """cols: list of (header, key-or-callable)."""
    if not rules:
        return "<p class='muted'>None.</p>"
    out = ["<table><tr>" + "".join(f"<th>{esc(h)}</th>" for h, _ in cols)
           + "</tr>"]
    for r in rules:
        cells = []
        for _, fn in cols:
            v = fn(r) if callable(fn) else esc(r.get(fn, ""))
            cells.append(f"<td>{v}</td>")
        # flag unrestricted sources
        rowcls = " class='diff'" if r.get("src_count") is None \
            and r["action"] == "Allow" else ""
        out.append(f"<tr{rowcls}>" + "".join(cells) + "</tr>")
    out.append("</table>")
    return "".join(out)


def _geo_status(g, r):
    """Geo-IP blocking that applies to a WAN-inbound rule -> (color, text)."""
    if not g["enforcement"]:
        return "red", "not enforced"
    if g.get("policy_based"):
        return ("green", "blocked (per-rule)") if r.get("geo_block") \
            else ("orange", "not on this rule")
    return "green", f"{g['blocked_count']} countries"


def _openports_table(rules, geo=None):
    if not rules:
        return "<p class='muted'>No open ports in this category.</p>"
    geo_h = "<th>Geo-IP blocking</th>" if geo else ""
    out = ["<table><tr><th>Service / port</th><th>Zone path</th>"
           "<th>Destination</th><th>Allowed source</th><th>Source IP(s)</th>"
           "<th>IP restriction</th>" + geo_h + "</tr>"]
    # sort worst-first: red, orange, green
    rank = {"red": 0, "orange": 1, "green": 2}
    for r in sorted(rules, key=lambda x: rank.get(compliance(x)[0], 3)):
        color, text = compliance(r)
        geo_td = ""
        if geo:
            gc, gt = _geo_status(geo, r)
            geo_td = f"<td><span class='pill {gc}'>{esc(gt)}</span></td>"
        out.append(
            f"<tr class='r-{color}'><td>{esc(r['service'])}</td>"
            f"<td>{esc(r['src_zone'])} &rarr; {esc(r['dst_zone'])}</td>"
            f"<td>{esc(r['dst_obj'])}</td><td>{esc(r['src_obj'])}</td>"
            f"<td>{esc(r['src_iplist'])}</td>"
            f"<td><span class='pill {color}'>{esc(text)}</span></td>"
            f"{geo_td}</tr>")
    out.append("</table>")
    return "".join(out)


# ---------------------- findings report ----------------------
def build_findings(configs):
    b = []
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    total_fw = len(configs)
    # provenance: which firewalls block each category / country
    cat_blockers, country_blockers = {}, {}
    for c in configs:
        for cat in (c["cfs_profiles"][0]["blocked"] if c["cfs_profiles"]
                    else []):
            cat_blockers.setdefault(cat, []).append(c["fw_name"])
        for ctry in c["geo"]["blocked_countries"]:
            country_blockers.setdefault(ctry, []).append(c["fw_name"])

    def coverage_cell(blockers):
        """(count, colored html) for how many firewalls block an item."""
        n = len(blockers)
        color = "green" if n == total_fw else "orange"
        names = ", ".join(blockers)
        return (f"<td><span class='pill {color}'>{n}/{total_fw}</span></td>"
                f"<td class='muted' style='font-size:11px'>{esc(names)}</td>")

    for cfg in configs:
        checklist, findings, coverage, vlan_list = analyze(cfg)
        b.append(f"<div class='card'><h3>{esc(label(cfg))} "
                 f"<small>({esc(cfg['source'])})</small></h3>")

        # checklist (traffic-light pills)
        pill_color = {"PASS": "green", "FAIL": "red", "REVIEW": "orange"}
        b.append("<table><tr><th>Checklist item</th><th>Status</th>"
                 "<th>Evidence</th></tr>")
        for item, st, ev in checklist:
            b.append(f"<tr><td>{esc(item)}</td><td><span class='pill "
                     f"{pill_color[st]}'>{st}</span></td>"
                     f"<td>{esc(ev)}</td></tr>")
        b.append("</table>")

        # findings
        b.append("<h3 style='margin-top:16px;font-size:14px'>Risk findings</h3>")
        if not findings:
            b.append("<p class='muted'>No risk findings.</p>")
        else:
            findings.sort(key=lambda f: sev_order.get(f["sev"], 9))
            b.append("<table><tr><th>Severity</th><th>Finding</th>"
                     "<th>Detail</th></tr>")
            for f in findings:
                b.append(f"<tr><td><span class='badge {f['sev']}'>{f['sev']}"
                         f"</span></td><td>{esc(f['title'])}</td>"
                         f"<td>{esc(f['detail'])}</td></tr>")
            b.append("</table>")

        # VPN authentication & MFA
        v = cfg["vpn"]
        def yn(x, good_yes=True):
            cls = "pass" if (bool(x) == good_yes) else "fail"
            return f"<span class='{cls}'>{'yes' if x else 'no'}</span>"
        b.append("<h3 style='margin-top:16px;font-size:14px'>VPN "
                 "Authentication &amp; MFA</h3><table>"
                 f"<tr><td>SSL VPN configured</td><td>{yn(v['sslvpn'], False)}"
                 "</td></tr>"
                 f"<tr><td>Login authentication method</td>"
                 f"<td>{esc(v['auth_method'])}</td></tr>"
                 f"<tr><td>Directory (AD / Entra)</td>"
                 f"<td>{esc(v['directory'])}</td></tr>"
                 f"<tr><td>RADIUS servers</td>"
                 f"<td>{esc(', '.join(v['radius_servers']) or '—')}</td></tr>"
                 f"<tr><td>Entra / SAML federation</td><td>{yn(v['saml'])}"
                 "</td></tr>"
                 f"<tr><td>DUO MFA detected</td><td>{yn(v['duo'])}</td></tr>"
                 f"<tr><td>Admin login TOTP</td><td>{yn(v['admin_totp'])}"
                 "</td></tr>"
                 f"<tr><td><b>MFA in use</b></td><td><b>{esc(v['mfa'])}</b>"
                 "</td></tr></table>")

        # VPN user isolation & access — verify: isolated from each other,
        # but able to reach LAN + specific resources
        vuz = RULES.get("vpn_user_zones", ["SSLVPN"])
        zmap = {z["name"]: z for z in cfg["zones"]}
        u2u_on = any(zmap.get(z) and zmap[z]["intra"] == "1" for z in vuz)
        lan_to_v = [r for r in cfg["rules"]
                    if r["enabled"] == "1" and r["action"] == "Allow"
                    and r["src_zone"] == TRUSTED_ZONE and r["dst_zone"] in vuz]
        access = vpn_user_access(cfg)
        b.append("<h3 style='margin-top:16px;font-size:14px'>VPN user "
                 f"isolation &amp; access ({'/'.join(vuz)})</h3><table>"
                 "<tr><td>Isolated from each other (intra-zone comm off)</td>"
                 f"<td>{yn(not u2u_on)}</td></tr>"
                 f"<tr><td>{TRUSTED_ZONE} cannot initiate to VPN users</td>"
                 f"<td>{yn(not lan_to_v)}</td></tr></table>")
        b.append("<p style='margin-top:8px'><b>What VPN users can reach</b> "
                 "<small>(should be LAN + only the specific resources they "
                 "need)</small></p>")
        if not access:
            b.append("<p class='muted'>No explicit VPN-user access rules "
                     "(remote access may be unused, or relies on defaults)."
                     "</p>")
        else:
            b.append("<table><tr><th>To zone</th><th>Destination (resource)</th>"
                     "<th>Service</th><th>From (VPN pool)</th></tr>")
            for r in sorted(access, key=lambda x: (x["dst_zone"], x["dst_obj"])):
                svc = r["service"]
                scls = " class='diff'" if svc == "Any" else ""
                b.append(f"<tr><td>{esc(r['dst_zone'])}</td>"
                         f"<td>{esc(r['dst_obj'])}</td>"
                         f"<td{scls}>{esc(svc)}</td>"
                         f"<td>{esc(r['src_obj'])}</td></tr>")
            b.append("</table><small>Highlighted 'Any' service = VPN users can "
                     "reach that resource on all ports; tighten to the specific "
                     "services if possible.</small>")

        # VPN & security service licenses
        lic = cfg["lic"]
        b.append("<h3 style='margin-top:16px;font-size:14px'>VPN &amp; "
                 "security licenses</h3><table>"
                 f"<tr><td>SSL VPN licenses (used / max)</td>"
                 f"<td><b>{esc(lic['sslvpn'][0] or '?')}</b> / "
                 f"{esc(lic['sslvpn'][1] or '?')}</td></tr>"
                 f"<tr><td>Global VPN Client licenses (used / max)</td>"
                 f"<td><b>{esc(lic['gvc'][0] or '?')}</b> / "
                 f"{esc(lic['gvc'][1] or '?')}</td></tr></table>")
        b.append("<table><tr><th>Security service</th><th>Status</th>"
                 "<th>Expires</th></tr>")
        for code, name in LICENSE_CODES.items():
            if code in ("VPNSSL", "VPNC"):
                continue
            s = lic["services"].get(code)
            if not s:
                continue
            cls = "pass" if s["status"] == "licensed" else "fail"
            b.append(f"<tr><td>{esc(name)}</td>"
                     f"<td class='{cls}'>{esc(s['status'])}</td>"
                     f"<td>{esc(s['exp'] or '—')}</td></tr>")
        b.append("</table>")

        # Trusted network access control — two sections
        b.append(f"<h3 style='margin-top:16px;font-size:14px'>Access INTO "
                 f"trusted {TRUSTED_ZONE} network "
                 "<small>(who can reach the main internal network)</small>"
                 "</h3>")
        b.append(_rules_table(trusted_inbound(cfg), [
            ("From zone", "src_zone"),
            ("Source object", "src_obj"),
            ("Source IP(s)", "src_iplist"),
            ("Destination", "dst_obj"),
            ("Service / port", "service"),
            ("Action", _action_cell),
        ]))
        b.append(f"<h3 style='margin-top:16px;font-size:14px'>Access FROM "
                 f"trusted {TRUSTED_ZONE} network "
                 "<small>(what the main internal network can reach)</small>"
                 "</h3>")
        b.append(_rules_table(trusted_outbound(cfg), [
            ("To zone", "dst_zone"),
            ("Destination", "dst_obj"),
            ("Service / port", "service"),
            ("Action", _action_cell),
        ]))

        # ===== OPEN PORTS & IP RESTRICTIONS (core analysis) =====
        ext = external_open_ports(cfg)
        intern = internal_open_ports(cfg)
        ext_open = sum(1 for r in ext if compliance(r)[0] == "red")
        int_open = sum(1 for r in intern if compliance(r)[0] == "red")
        b.append("<h3 style='margin-top:20px;font-size:15px;color:#0b2540'>"
                 "&#128273; Open ports &amp; IP restrictions</h3>")
        b.append("<p><b>EXTERNAL — open from the Internet (WAN inbound)</b> "
                 f"<span class='pill {'red' if ext_open else 'green'}'>"
                 f"{ext_open} open to ANY</span></p>")
        b.append(_openports_table(ext, geo=cfg["geo"]))
        b.append("<p style='margin-top:12px'><b>INTERNAL — firewall management "
                 "from LAN-side zones</b> "
                 f"<span class='pill {'red' if int_open else 'green'}'>"
                 f"{int_open} open to ANY</span></p>")
        b.append(_openports_table(intern))
        b.append("<p><small>Green = restricted to 1-2 source IPs (compliant); "
                 "orange = restricted but broad, a named group, or cleartext "
                 "HTTP; red = open to any source (non-compliant).</small></p>")

        # Content filter — blocked categories
        b.append("<h3 style='margin-top:16px;font-size:14px'>Content filter — "
                 "blocked categories</h3>")
        if not cfg["cfs_profiles"]:
            b.append("<p class='muted'>No CFS profiles found.</p>")
        for p in cfg["cfs_profiles"]:
            b.append(f"<p><b>{esc(p['name'])}</b> — "
                     f"{len(p['blocked'])} categories blocked"
                     + (f"; Safe Search {esc(p['safe_search'])}" if
                        p['safe_search'] else "")
                     + (f"; HTTPS filtering {esc(p['https_filter'])}" if
                        p['https_filter'] else "")
                     + (f"; forbidden-URL list: {esc(p['forbidden_urls'])}"
                        if p['forbidden_urls'] else "") + "</p>")
            if p["blocked"]:
                b.append("<table><tr><th>#</th><th>Blocked category</th>"
                         "<th>Firewalls</th><th>Also blocked on</th></tr>")
                for n, cat in enumerate(p["blocked"], 1):
                    b.append(f"<tr><td>{n}</td><td>{esc(cat)}</td>"
                             + coverage_cell(cat_blockers.get(cat, []))
                             + "</tr>")
                b.append("</table><small>Orange in 'Firewalls' = not blocked on "
                         "every firewall (inconsistent).</small>")
            else:
                b.append("<p class='fail'>No categories blocked in this "
                         "profile.</p>")

        # Geo-IP blocking — blocked countries
        g = cfg["geo"]
        b.append("<h3 style='margin-top:16px;font-size:14px'>Geo-IP blocking — "
                 f"{g['blocked_count']} countries blocked</h3><table>"
                 f"<tr><td>Geo-IP enforcement</td><td>{yn(g['enforcement'])}"
                 "</td></tr>"
                 f"<tr><td>Block unknown / unclassified IPs</td>"
                 f"<td>{yn(g['block_unknown'])}</td></tr>"
                 f"<tr><td>Botnet filtering</td><td>{yn(g['botnet'])}</td></tr>"
                 "</table>")
        if g["blocked_countries"]:
            b.append("<table><tr><th>#</th><th>Blocked country</th>"
                     "<th>Firewalls</th><th>Also blocked on</th></tr>")
            for n, ctry in enumerate(g["blocked_countries"], 1):
                b.append(f"<tr><td>{n}</td><td>{esc(ctry)}</td>"
                         + coverage_cell(country_blockers.get(ctry, []))
                         + "</tr>")
            b.append("</table>"
                     "<p class='muted'><small>Orange in 'Firewalls' = not "
                     "blocked on every firewall (inconsistent). Decoded from "
                     "the Geo-IP bitmap; spot-check against the firewall UI."
                     "</small></p>")

        # VLAN role coverage
        b.append("<h3 style='margin-top:16px;font-size:14px'>Expected VLAN "
                 "role coverage</h3><table><tr><th>Expected role</th>"
                 "<th>Present?</th><th>Matching VLAN(s)</th></tr>")
        for role, matches in coverage:
            if matches:
                m = ", ".join(f"VLAN {v['vlan']} "
                              f"({v['comment'] or v['name']})" for v in matches)
                b.append(f"<tr><td>{esc(role)}</td><td class='pass'>YES</td>"
                         f"<td>{esc(m)}</td></tr>")
            else:
                b.append(f"<tr><td>{esc(role)}</td><td class='review'>not on "
                         "this firewall</td><td class='muted'>—</td></tr>")
        b.append("</table></div>")

    return _page("SonicWall Security Findings",
                 "Risky / loose rules and audit checklist per firewall",
                 "".join(b))


# ---------------------- compliance report (new page) ----------------------
STATUS_COLOR = {"PASS": "green", "FAIL": "red", "WARN": "orange", "NA": "gray"}


def build_compliance(configs):
    # strictest baseline = union of everything blocked across all firewalls
    union_cats = set()
    union_countries = set()
    for c in configs:
        if c["cfs_profiles"]:
            union_cats |= set(c["cfs_profiles"][0]["blocked"])
        union_countries |= set(c["geo"]["blocked_countries"])

    evals = [(c, evaluate_compliance(c, union_cats, union_countries))
             for c in configs]
    rule_names = [r["rule"] for r in evals[0][1]] if evals else []

    b = []

    # ---- scorecard ----
    b.append("<h2>Compliance scorecard</h2><p>")
    for c, res in evals:
        p = sum(1 for r in res if r["status"] == "PASS")
        f = sum(1 for r in res if r["status"] == "FAIL")
        w = sum(1 for r in res if r["status"] == "WARN")
        verdict = ("<span class='score green'>COMPLIANT</span>" if f == 0
                   else "<span class='score red'>NON-COMPLIANT</span>")
        b.append(f"<span class='score gray'>{esc(label(c))}</span> {verdict}"
                 f"<span class='score green'>{p} pass</span>"
                 f"<span class='score red'>{f} fail</span>"
                 f"<span class='score orange'>{w} warn</span><br>")
    b.append("</p>")

    # ---- matrix: rules x firewalls, colored cells ----
    b.append("<h2>Compliance matrix</h2><table><tr><th>Compliance rule</th>"
             + "".join(f"<th>{esc(label(c))}</th>" for c, _ in evals)
             + "</tr>")
    symbol = {"PASS": "&#10004;", "FAIL": "&#10008;", "WARN": "!",
              "NA": "&ndash;"}
    per = [{r["rule"]: r for r in res} for _, res in evals]
    for rn in rule_names:
        b.append(f"<tr><td>{esc(rn)}</td>")
        for pmap in per:
            r = pmap.get(rn)
            st = r["status"] if r else "NA"
            title = esc(r["detail"]) if r else ""
            b.append(f"<td class='cell' title='{title}'>"
                     f"<span class='sym-{STATUS_COLOR[st]}'>{symbol[st]}"
                     "</span></td>")
        b.append("</tr>")
    b.append("</table><small>"
             "<span class='lg sym-green'>&#10004;</span> pass &nbsp; "
             "<span class='lg sym-red'>&#10008;</span> fail &nbsp; "
             "<span class='lg sym-orange'>!</span> warning &nbsp; "
             "<span class='lg sym-gray'>&ndash;</span> not applicable"
             " &nbsp;(hover a cell for details)</small>")

    # ---- per-firewall detail with evidence ----
    for c, res in evals:
        b.append(f"<div class='card'><h3>{esc(label(c))} "
                 f"<small>({esc(c['fw_name'])})</small></h3>"
                 "<table><tr><th>Rule</th><th>Result</th><th>Details</th></tr>")
        for r in res:
            color = STATUS_COLOR[r["status"]]
            b.append(f"<tr class='r-{color if color != 'gray' else 'green'}'>"
                     f"<td>{esc(r['rule'])}</td>"
                     f"<td><span class='pill {color}'>{r['status']}</span></td>"
                     f"<td>{esc(r['detail'])}</td></tr>")
        b.append("</table>")

        # IP groups used in rules
        b.append("<h3 style='margin-top:16px;font-size:14px'>IP groups "
                 "referenced in access rules</h3>")
        if not c["ip_groups"]:
            b.append("<p class='muted'>No address groups referenced.</p>")
        else:
            b.append("<table><tr><th>Group name</th><th>Member IPs</th>"
                     "<th># IPs</th></tr>")
            for grp in c["ip_groups"]:
                ips = grp["ips"]
                shown = ", ".join(ips) if ips else \
                    "<span class='muted'>(nested/empty — see firewall)</span>"
                b.append(f"<tr><td>{esc(grp['name'])}</td><td>{shown}</td>"
                         f"<td>{len(ips)}</td></tr>")
            b.append("</table>")
        b.append("</div>")

    # ---- consistency exceptions (strictest baseline) ----
    b.append("<h2>Consistency exceptions (strictest firewall is the baseline)"
             "</h2>")
    b.append("<h3 style='font-size:14px'>Content-filter categories not blocked "
             "everywhere</h3>")
    b.append(_consistency_table(configs, union_cats,
                                lambda c: set(c["cfs_profiles"][0]["blocked"])
                                if c["cfs_profiles"] else set()))
    b.append("<h3 style='font-size:14px'>Countries not geo-blocked everywhere"
             "</h3>")
    b.append(_consistency_table(configs, union_countries,
                                lambda c: set(c["geo"]["blocked_countries"])))

    return _page("SonicWall Compliance Report",
                 "Pass / fail against the compliance rules in "
                 + RULES_FILE, "".join(b))


def _consistency_table(configs, union, getter):
    exceptions = []
    for item in sorted(union):
        missing = [label(c) for c in configs if item not in getter(c)]
        if missing:
            exceptions.append((item, missing))
    if not exceptions:
        return "<p class='pass'>Consistent across all firewalls.</p>"
    out = ["<table><tr><th>Blocked item</th><th>MISSING on (non-compliant)</th>"
           "</tr>"]
    for item, missing in exceptions:
        out.append(f"<tr class='r-red'><td>{esc(item)}</td>"
                   f"<td>{esc(', '.join(missing))}</td></tr>")
    out.append("</table>")
    return "".join(out)


# ---------------------- remediation / ticket report ----------------------
PRI_COLOR = {"HIGH": "red", "MEDIUM": "orange", "LOW": "gray"}


def group_mgmt(rules):
    """Collapse management rules by (source zone, service) — SonicWall creates
    one rule per destination interface. Returns sorted summary labels like
    'VPN: SSH Management (8 interfaces)'."""
    counts = {}
    for r in rules:
        k = (r["src_zone"], r["service"])
        counts[k] = counts.get(k, 0) + 1
    out = []
    for (z, s), n in sorted(counts.items()):
        out.append(f"{z}: {s}" + (f" ({n} interfaces)" if n > 1 else ""))
    return out


def rule_label(r):
    """Full, specific identity of one access rule so a tech can find & act on
    exactly it in the SonicWall UI (POLICY > Rules and Policies > Access
    Rules, matching zone pair + service + source/destination)."""
    src = r["src_obj"] or "Any"
    dst = r["dst_obj"] or "Any"
    svc = r["service"] or "Any"
    return (f"{r['src_zone']} -> {r['dst_zone']}  |  service: {svc}  |  "
            f"source: {src}  |  destination: {dst}")


def _is_auto(r):
    """True if the rule was auto-generated by SonicWall (interface mgmt
    checkbox, VPN-SA management, GMS, etc.)."""
    return "auto" in (r.get("comment") or "").lower()


def rules_specific(rules):
    """Sorted, de-duplicated list of specific rule labels; auto-generated
    rules are tagged [auto-created]."""
    out = set()
    for r in rules:
        lbl = rule_label(r)
        if _is_auto(r):
            lbl += "   [auto-created]"
        out.add(lbl)
    return sorted(out)


# Note appended to any DELETE-type step that lists auto-generated rules.
AUTO_NOTE = ("Rules tagged [auto-created] are generated by SonicWall from a "
             "setting — an interface Management checkbox, a VPN policy's "
             "'Management via this SA', or GMS. Turn OFF that setting and the "
             "rule disappears on its own; do NOT hand-delete it.")


def source_change_lines(rules, new_source):
    """List each rule specifically and call out the Source-field change."""
    lines = []
    for r in sorted(rules, key=rule_label):
        tag = "   [auto-created]" if _is_auto(r) else ""
        lines.append(f"  RULE: {r['src_zone']} -> {r['dst_zone']}  |  "
                     f"{r['service']}  |  destination: {r['dst_obj']}{tag}")
        extra = ""
        if r["service"].startswith("HTTP Management"):
            extra = "   (also DISABLE this rule — HTTP is cleartext; HTTPS only)"
        lines.append(f"     >>> CHANGE Source:  {r['src_obj'] or 'Any'}  =>  "
                     f"{new_source}{extra}")
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def strictest_baseline(configs):
    """Union of everything blocked anywhere = the strictest baseline."""
    union_cats, union_countries = set(), set()
    for c in configs:
        if c["cfs_profiles"]:
            union_cats |= set(c["cfs_profiles"][0]["blocked"])
        union_countries |= set(c["geo"]["blocked_countries"])
    return union_cats, union_countries


def remediation_items(cfg, union_cats, union_countries,
                      cat_blockers=None, country_blockers=None,
                      branch_nets=None):
    """Ticket-ready fix list for ONE firewall. Each item:
    {pri, area, action, why, standard, lines} — 'why' is the plain-English
    reason the tech needs, 'standard' is the control/regulation failing, and
    'lines' carry the explicit offending values. cat_blockers/country_blockers
    map each blocked item -> list of firewalls that block it (for provenance)."""
    cat_blockers = cat_blockers or {}
    country_blockers = country_blockers or {}
    branch_nets = branch_nets or {}
    tz = TRUSTED_ZONE
    items = []

    def add(pri, area, action, why, standard, lines=None):
        items.append({"pri": pri, "area": area, "action": action,
                      "why": why, "standard": standard, "lines": lines or []})

    res = evaluate_compliance(cfg, union_cats, union_countries)
    st = {r["rule"]: r for r in res}

    def failed(prefix):
        return any(r["rule"].startswith(prefix) and r["status"] == "FAIL"
                   for r in res)

    mgmt = [r for r in cfg["mgmt_rules"]
            if r["enabled"] == "1" and r["action"] == "Allow"]
    max_mgmt = RULES["management"].get("max_source_ips", 2)
    max_ssh = RULES["ssh"].get("max_source_ips", 2)
    ssh_zones = RULES["ssh"].get("allowed_zones", ["LAN"])
    admin_zones = RULES["management"].get("admin_allowed_zones", ["LAN", "WAN"])

    if failed(f"Content filtering enabled on {tz}"):
        add("HIGH", "Content Filter",
            f"Enable Content Filtering on the {tz} zone (OBJECT > Zones > "
            f"{tz} > enable Content Filtering; verify global CFS is on under "
            "POLICY > Security Services).",
            "The trusted user network can currently reach malware, phishing, "
            "and other malicious web categories unfiltered — the web is the "
            "primary malware-delivery path for staff workstations.",
            "FFIEC Information Security; CIS Control 9 (Email & Web Browser "
            "Protections); PCI DSS v4.0 Req 5 (malware protection).")
    if failed(f"IPS/IDS enabled on {tz}"):
        add("HIGH", "IPS/IDS",
            "Enable Intrusion Prevention globally (POLICY > Security Services "
            f"> Intrusion Prevention > Enable IPS) and confirm the {tz} zone "
            "has the IPS profile applied.",
            "With IPS off, known exploit and attack traffic reaches internal "
            "hosts uninspected — there is no in-line detection or blocking of "
            "network attacks.",
            "PCI DSS v4.0 Req 11.5.1 (IDS/IPS); NIST SP 800-53 SI-4 (System "
            "Monitoring); CIS Control 13 (Network Monitoring & Defense).")
    if failed("SSH management enabled"):
        add("HIGH", "SSH",
            "Enable SSH management on the LAN interface (NETWORK > "
            "Interfaces > X0 > Management: SSH).",
            "SSH is the encrypted CLI admin channel; it must be available so "
            "administration is not done over weaker/unencrypted paths.",
            "PCI DSS v4.0 Req 2.2.7 (encrypted non-console admin access); "
            "NIST SP 800-53 AC-17 (Remote Access).")

    # Admin interface + SSH must come ONLY from the allowed zone(s) — every
    # other zone (VPN, WAN, all VLANs) must be denied. One rule per source
    # zone + service (SonicWall duplicates these across destination interfaces).
    off_zone = [r for r in mgmt if r["src_zone"] not in admin_zones]
    if off_zone:
        def _cmt(r):
            return (r.get("comment") or "").lower()
        vpn_sa = [r for r in off_zone
                  if "via this sa" in _cmt(r) or "vpn enabled management" in _cmt(r)]
        gms_r = [r for r in off_zone if "gms" in _cmt(r)]
        other = [r for r in off_zone if r not in vpn_sa and r not in gms_r]

        lines = ["Do these in order. Most of these rules are auto-created by "
                 "SonicWall, so a few settings changes clear almost all of "
                 "them — you do NOT delete 30+ rules by hand.", ""]
        step_no = 0
        if vpn_sa:
            step_no += 1
            lines += [
                f"Step {step_no}: Turn off management on the VPN tunnel(s) "
                f"(this removes {len(vpn_sa)} of these rules automatically).",
                "  1. Go to NETWORK > IPSec VPN > Rules and Settings.",
                "  2. Edit each VPN policy > Advanced tab.",
                "  3. Under 'Management via this SA', UNcheck HTTP, HTTPS, SSH, "
                "SNMP and SonicPoint. Click OK.",
                "  These auto-created rules will then disappear on their own:"]
            lines += ["    - " + x for x in group_mgmt(vpn_sa)]
            lines.append("")
        if gms_r:
            step_no += 1
            lines += [
                f"Step {step_no}: Disable GMS (see the 'Legacy GMS' task in "
                f"this ticket). That removes these {len(gms_r)} rules "
                "automatically:"]
            lines += ["    - " + x for x in rules_specific(gms_r)]
            lines.append("")
        if other:
            step_no += 1
            lines += [
                f"Step {step_no}: Delete (or set Action = Deny) these "
                f"{len(other)} remaining rule(s) by hand.",
                "  Go to POLICY > Rules and Policies > Access Rules, find each "
                "one by its zone pair + service, and delete it:"]
            lines += ["    - " + x for x in rules_specific(other)]
        add("HIGH", "Management plane isolation",
            f"Only {'/'.join(admin_zones)} may manage this firewall. Right now "
            f"{len(off_zone)} rules let other zones (VPN, WAN, VLANs) reach the "
            "admin interface or SSH. Fix them in the order below:",
            "The firewall's own management plane must be isolated. Any VPN "
            "user or device on a segmented VLAN that can reach the admin GUI "
            "or SSH can attack the firewall itself — a single compromised VPN "
            f"session or VLAN host would defeat all segmentation. Only the "
            f"{'/'.join(admin_zones)} zone may manage the device.",
            "NIST SP 800-53 AC-6 (Least Privilege) & SC-7 (Boundary "
            "Protection); CIS Control 12.6 (dedicated/secure admin access); "
            "PCI DSS v4.0 Req 1.3 & 2.2.7; FFIEC Information Security.",
            lines)

    # Any-source management from the ALLOWED zone (LAN) — including LAN SSH.
    # Off-zone (VPN/WAN/etc.) management is removed by the isolation step above.
    any_mgmt = [r for r in mgmt if r["src_count"] is None
                and r["src_zone"] in admin_zones]
    if any_mgmt:
        jb_obj = RULES["management"].get("admin_source_object", "Mgmt-Jumpbox")
        jb_desc = RULES["management"].get(
            "admin_source_description",
            "the jumpbox that runs the Connect Secure agent")
        az = "/".join(admin_zones)
        lines = [
            f"Step 1: Create the admin source object (once).",
            f"  1. OBJECT > Match Objects > Addresses > Add.",
            f"  2. Name: {jb_obj}   Zone: {admin_zones[0]}   Type: Host.",
            f"  3. IP address: the jumpbox IP — {jb_desc}. Save.",
            f"     (If there are two admin hosts, make an Address GROUP named "
            f"{jb_obj} containing both — max {max_mgmt}.)",
            "",
            f"Step 2: Open each of these {len(any_mgmt)} {az} admin/SSH rules "
            "(POLICY > Rules and Policies > Access Rules) and change ONLY the "
            f"Source field to {jb_obj}, so only the Connect Secure agent on "
            "the jumpbox can reach the firewall. Each rule and its exact change "
            "is listed below:", ""]
        lines += source_change_lines(any_mgmt, jb_obj)
        lines += ["",
                  "(These are auto-added management rules, but here you EDIT "
                  "their Source field rather than delete them — keep management "
                  f"enabled on {admin_zones[0]}, just lock the source to the "
                  "jumpbox. The restriction persists.)"]
        add("HIGH", "Management (incl. SSH) source restriction",
            f"Restrict {az} admin + SSH access to the jumpbox only (the host "
            f"running the Connect Secure agent). Currently these "
            f"{len(any_mgmt)} rules allow 'Any' source:",
            "An 'Any' source exposes the firewall admin interface and SSH to "
            "every host in that zone. Restricting the source to the jumpbox "
            "address object means only the Connect Secure agent can manage the "
            f"firewall. SSH in particular must be limited to at most {max_ssh} "
            "admin IPs.",
            "PCI DSS v4.0 Req 1.3 & 2.2.7; NIST SP 800-53 AC-6 (Least "
            "Privilege) & SC-7; CIS Control 12.",
            lines)
    broad = [r for r in mgmt if r["src_zone"] in admin_zones
             and r["src_count"] is not None
             and (r["src_count"] == "?"
                  or (isinstance(r["src_count"], int)
                      and r["src_count"] > max_mgmt))]
    if broad:
        add("MEDIUM", "Management",
            f"Tighten each of these {len(broad)} {'/'.join(admin_zones)} "
            f"management rules to <= {max_mgmt} source IPs:",
            f"Management access should be limited to at most {max_mgmt} known "
            "admin IPs. Broad source ranges leave more hosts able to attack "
            "the management plane than necessary.",
            "NIST SP 800-53 AC-6 (Least Privilege); CIS Control 12; PCI DSS "
            "v4.0 Req 1.3.",
            rules_specific(broad))

    if cfg["gms_enabled"]:
        add("HIGH", "Legacy GMS",
            "Disable legacy GMS management and manage the firewall via NSM "
            "instead (DEVICE > Settings > Administration / GMS — turn off "
            "'Enable management using GMS'; remove the GMS Addresses object "
            "from any management rules).",
            "GMS has been replaced by NSM across the fleet. A firewall still "
            "configured for GMS (gmsServerEnable=on) has an unused legacy "
            "management channel enabled and is inconsistent with the NSM "
            "standard — that channel should be closed to reduce attack "
            "surface and management drift.",
            "Client management standard (NSM); NIST SP 800-53 CM-6 (Configu"
            "ration Settings) & CM-7 (Least Functionality); CIS Control 4 "
            "(Secure Configuration).")

    vpn_user_zones = RULES.get("vpn_user_zones", ["SSLVPN"])
    zmap = {z["name"]: z for z in cfg["zones"]}
    u2u_bad = [z for z in vpn_user_zones
               if zmap.get(z) and zmap[z]["intra"] == "1"]
    if u2u_bad:
        add("HIGH", "VPN user isolation (user-to-user)",
            "Block VPN-user-to-VPN-user traffic — turn OFF intra-zone "
            f"communication on the {', '.join(u2u_bad)} zone(s):",
            "Every remote VPN user lands in this zone. With intra-zone "
            "communication on, one compromised remote session can scan and "
            "attack every other remote user directly. Turning it off confines "
            "each session to its own path to the servers it needs.",
            "NIST SP 800-53 SC-7 (Boundary Protection) & AC-4 (Information "
            "Flow Enforcement); CIS Control 12; PCI DSS v4.0 Req 1.3.",
            [f"OBJECT > Zones > edit the {z} zone > set 'Allow Interface "
             "Trust' / intra-zone communication to OFF (deny)."
             for z in u2u_bad])

    lan_to_vpn = [r for r in cfg["rules"]
                  if r["enabled"] == "1" and r["action"] == "Allow"
                  and r["src_zone"] == tz and r["dst_zone"] in vpn_user_zones]
    if lan_to_vpn:
        add("HIGH", f"{tz}-to-VPN-user isolation",
            f"Remove (or set to DENY) these {len(lan_to_vpn)} rules that let "
            f"the {tz} initiate connections TO VPN users "
            f"({'/'.join(vpn_user_zones)}):",
            "Remote VPN users reaching LAN servers is expected and stays "
            f"allowed. But the {tz} initiating connections back TO remote user "
            "devices is not needed and only gives an attacker on the LAN a "
            f"path to remote endpoints. Keep {'/'.join(vpn_user_zones)}->{tz}; "
            f"block {tz}->{'/'.join(vpn_user_zones)}.",
            "NIST SP 800-53 SC-7 & AC-4 (Information Flow); CIS Control 12; "
            "PCI DSS v4.0 Req 1.3.",
            rules_specific(lan_to_vpn))

    inbound = untrusted_into_lan(cfg)
    if inbound:
        trusted = "/".join(RULES.get("trusted_zones", [tz]))
        add("HIGH", "Trusted " + tz,
            f"Review and remove/deny each of these {len(inbound)} rules that "
            f"let a NON-trusted zone reach the {tz}. (Trusted zones {trusted} "
            "— including SSL VPN remote users — are allowed and are not "
            "listed.)",
            f"The trusted {tz} holds the institution's core systems. A "
            "non-trusted segment (printers, phones, IoT, cameras, "
            "site-to-site VPN) permitted into it breaks segmentation and lets "
            "a compromised segment pivot into core banking systems. SSL VPN "
            f"users are trusted and keep their {tz} access.",
            "PCI DSS v4.0 Req 1.3 & 1.4 (network segmentation); NIST SP "
            "800-53 SC-7; CIS Control 12; FFIEC Information Security.",
            rules_specific(inbound)
            + (["", AUTO_NOTE] if any(_is_auto(r) for r in inbound) else []))

    # Branch-to-branch (WAN -> LAN) rules must be pinned to the KNOWN branch
    # subnets on BOTH ends: source = other branches' LANs, destination = this
    # branch's own LAN.
    wan_lan_any = wan_lan_any_source(cfg)
    if wan_lan_any:
        others = sorted((name, net) for name, net in branch_nets.items()
                        if name != cfg["fw_name"] and net)
        grp = "Branch-Trusted-Nets"
        my_lan = cfg["lan_subnet"] or "this branch's LAN"
        my_obj = "LAN Primary Subnet"   # built-in object = this branch's LAN
        lines = [
            "These rules carry branch-to-branch VPN traffic but currently "
            "accept ANY source to ANY/WAN-IP destination. We know every "
            "branch's LAN subnet from their configs, so pin BOTH ends:",
            f"  source      = the OTHER branches' LANs",
            f"  destination = THIS branch's LAN ({my_lan})", "",
            "Step 1: Create a Network object for each OTHER branch's LAN "
            "(OBJECT > Match Objects > Addresses > Add; Type: Network):"]
        if others:
            for name, net in others:
                netw, _, mask = net.partition("/")
                try:
                    m = str(ipaddress.IPv4Network(net).netmask)
                except Exception:
                    m = mask
                lines.append(f"    - Name: {name}-LAN   Network: {netw}   "
                             f"Mask: {m}   (= {net})")
        else:
            lines.append("    - (add each remote branch LAN subnet here)")
        lines += [
            "",
            f"Step 2: Create an Address GROUP named '{grp}' and add every Step 1 "
            "object. (This is the SOURCE for all the rules below.)",
            "",
            f"Step 3: Edit each rule below — set BOTH its Source and "
            f"Destination. This branch's LAN is the built-in '{my_obj}' object "
            f"(= {my_lan}):"]
        for r in sorted(wan_lan_any, key=rule_label):
            lines.append(f"  RULE: WAN -> LAN | service: {r['service']}")
            lines.append(f"     >>> Source:       {r['src_obj'] or 'Any'}"
                         f"  =>  {grp}")
            lines.append(f"     >>> Destination:  {r['dst_obj'] or 'Any'}"
                         f"  =>  {my_obj}   (= {my_lan})")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        add("HIGH", "Branch-to-branch VPN (WAN -> LAN)",
            f"Pin these {len(wan_lan_any)} WAN -> LAN rules to the known branch "
            f"subnets — source = other branches' LANs, destination = this "
            f"branch's LAN ({my_lan}). They must never be 'Any':",
            "A WAN -> LAN rule with an 'Any' source (and 'Any'/WAN-IP "
            "destination) lets the entire Internet into the trusted LAN, not "
            "just the sister branches. Because every branch's LAN subnet is "
            "known from its config, both ends can be pinned exactly: only the "
            "sister branches' LANs reach only this branch's LAN.",
            "PCI DSS v4.0 Req 1.2/1.3 (restrict inbound to that required); "
            "NIST SP 800-53 SC-7 (Boundary Protection); CIS Control 12.",
            lines)

    # Remaining external exposure = WAN-inbound services open to any, EXCLUDING
    # what other steps already own: management (isolation step), Ping (ping
    # step) and branch-to-branch WAN->LAN (branch step).
    ext_red = [r for r in external_open_ports(cfg)
               if compliance(r)[0] == "red"
               and "Management" not in r["service"]
               and "Ping" not in r["service"]
               and not (r["dst_zone"] == TRUSTED_ZONE
                        and r["src_count"] is None)]
    if ext_red:
        add("HIGH", "External exposure",
            f"Restrict each of these {len(ext_red)} WAN-inbound services to "
            "known source IPs (currently open to any Internet source):",
            "Services reachable from any Internet source are continuously "
            "scanned and attacked. Restricting to known source IPs removes "
            "the service from broad Internet exposure.",
            "PCI DSS v4.0 Req 1.3 & 1.4; NIST SP 800-53 SC-7 (Boundary "
            "Protection); CIS Control 12.",
            rules_specific(ext_red)
            + (["", AUTO_NOTE] if any(_is_auto(r) for r in ext_red) else []))

    wanping = wan_ping_rules(cfg)
    if wanping:
        auto = all("auto" in (r.get("comment") or "").lower() for r in wanping)
        lines = [
            "DO THIS (one action): NETWORK > Interfaces > edit each WAN "
            "interface > Management tab > UNcheck 'Ping'. Apply.",
            "  Leave 'Ping' ENABLED on the LAN interface — internal ping is "
            "fine and useful for monitoring."]
        if auto:
            lines += [
                "",
                "You do NOT delete rules by hand. The Ping rules below are "
                "auto-created by that checkbox and disappear on their own once "
                "you uncheck it. Just confirm they are gone afterward:"]
        else:
            lines += [
                "",
                "Then delete (or set to DENY) any Ping rule that remains:"]
        lines += ["    - " + x for x in rules_specific(wanping)]
        add("MEDIUM", "Ping / ICMP (WAN)",
            f"Stop the firewall answering ping from the Internet ({len(wanping)}"
            " WAN Ping rule(s) currently respond to any source). Keep internal "
            "(LAN) ping enabled:",
            "Answering ICMP echo from the Internet lets attackers discover and "
            "confirm the firewall's public IPs during reconnaissance. Internal "
            "ping from the LAN is fine; only the Internet-facing ping response "
            "should be turned off.",
            "NIST SP 800-53 SC-7 (Boundary Protection); CIS Control 12; "
            "attack-surface reduction / defense-in-depth.",
            lines)

    r = st.get("SSL VPN configured -> DUO/Entra MFA required")
    if r and r["status"] == "FAIL":
        add("HIGH", "VPN MFA",
            "SSL VPN is enabled but has NO multi-factor authentication. "
            "Choose ONE option:",
            "SSL VPN grants remote access to the internal network. "
            "Password-only remote access is a leading breach cause; MFA stops "
            "stolen credentials from turning into remote network access. If MFA "
            "cannot be added, the safer posture is to turn SSL VPN off rather "
            "than run remote access on single-factor passwords.",
            "FFIEC Authentication guidance (2021); PCI DSS v4.0 Req 8.4.2 & "
            "8.5 (MFA for remote access); NIST SP 800-53 IA-2(1).",
            ["OPTION A  --  ADD MFA   (preferred)",
             "  Require a second factor for every SSL VPN login using DUO or",
             "  Entra ID:",
             "    - DUO:   set up the DUO Authentication Proxy as a RADIUS",
             "             server, then point SSL VPN auth at it",
             "             (DEVICE > Users > Settings > Authentication, add the",
             "             RADIUS server; assign it to the SSL VPN user domain).",
             "    - Entra: configure SAML/SSO to Entra ID and apply it to the",
             "             SSL VPN portal (DEVICE > Users > Settings > SSO/SAML).",
             "",
             "OPTION B  --  DISABLE SSL VPN   (if MFA will NOT be added)",
             "  Turn SSL VPN off until MFA is in place:",
             "    - NETWORK > SSL VPN > Server Settings > uncheck the WAN (and",
             "      any other) zone under 'SSL VPN Server', and disable the",
             "      SSL VPN user portal.",
             "",
             "(Confirm the exact menu path for your SonicOS build.)"])
    r = st.get("VPN authentication integrated with AD/Entra")
    if r and r["status"] == "FAIL":
        add("MEDIUM", "Authentication",
            "Connect user authentication to Active Directory/LDAP or Entra "
            "ID (currently local users only).",
            "Local firewall accounts are not centrally managed, logged, or "
            "disabled at termination. Directory integration gives central "
            "identity, password policy, and immediate deprovisioning.",
            "FFIEC Information Security (access management); NIST SP 800-53 "
            "AC-2 (Account Management); CIS Control 6 (Access Control "
            "Management).")

    def with_provenance(items, blockers):
        out = []
        for it in items:
            who = ", ".join(blockers.get(it, [])) or "peer firewall(s)"
            out.append(f"{it}  [blocked on: {who}]")
        return out

    mine = set(cfg["cfs_profiles"][0]["blocked"]) if cfg["cfs_profiles"] \
        else set()
    missing_cats = sorted(union_cats - mine)
    if missing_cats:
        add("MEDIUM", "Content Filter",
            f"Block these {len(missing_cats)} content-filter categories "
            "(already blocked on other firewalls of this client — the source "
            "firewall is shown in brackets after each):",
            "All of this client's firewalls should enforce the same web "
            "filtering. These categories are blocked on peer firewalls but "
            "not here, leaving a protection gap only at this site.",
            "Client security standardization policy; CIS Control 9; FFIEC "
            "(consistent control baseline across locations).",
            with_provenance(missing_cats, cat_blockers))
    missing_geo = sorted(union_countries
                         - set(cfg["geo"]["blocked_countries"]))
    if missing_geo:
        add("MEDIUM", "Geo-IP",
            f"Add these {len(missing_geo)} countries to the Geo-IP block "
            "list (already blocked on other firewalls of this client — the "
            "source firewall is shown in brackets after each):",
            "Uniform geo-blocking across all sites gives consistent "
            "defense-in-depth against high-risk/sanctioned regions. These "
            "countries are blocked elsewhere but reachable here.",
            "Client security standardization policy; supports OFAC "
            "sanctions posture & FFIEC risk-based controls.",
            with_provenance(missing_geo, country_blockers))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    items.sort(key=lambda x: order[x["pri"]])
    return items


DIV = "-" * 60


def build_remediation(configs):
    union_cats, union_countries = strictest_baseline(configs)
    # provenance: which firewall(s) block each category / country
    cat_blockers, country_blockers = {}, {}
    for c in configs:
        for cat in (c["cfs_profiles"][0]["blocked"] if c["cfs_profiles"]
                    else []):
            cat_blockers.setdefault(cat, []).append(c["fw_name"])
        for ctry in c["geo"]["blocked_countries"]:
            country_blockers.setdefault(ctry, []).append(c["fw_name"])
    branch_nets = {c["fw_name"]: c["lan_subnet"] for c in configs}
    b = ["<p>One ticket per firewall, organized as remediation <b>tasks</b> "
         "(each task may contain numbered <b>Steps</b> to perform, or "
         "<b>Options</b> to choose between). Consistency tasks use the "
         "strictest firewall as the baseline. Use <b>Copy ticket text</b> to "
         "paste a firewall's full ticket into your ticketing system.</p>"]
    for idx, cfg in enumerate(configs):
        items = remediation_items(cfg, union_cats, union_countries,
                                  cat_blockers, country_blockers, branch_nets)
        b.append(
            "<div class='card' style='padding:0;overflow:hidden'>"
            "<div style='background:#0b2540;color:#fff;padding:16px 20px'>"
            f"<div style='font-size:19px;font-weight:700'>{esc(cfg['fw_name'])}"
            "</div>"
            f"<div style='opacity:.75;font-size:12.5px;margin-top:3px'>"
            f"{esc(cfg['model'])} &nbsp;·&nbsp; serial {esc(cfg['serial'])}"
            "</div></div><div style='padding:16px 20px'>")
        if not items:
            b.append("<p class='pass' style='font-size:15px'>&#10004; No "
                     "remediation required — this firewall is compliant.</p>"
                     "</div></div>")
            continue
        counts = {}
        for it in items:
            counts[it["pri"]] = counts.get(it["pri"], 0) + 1
        total = len(items)
        b.append("<p style='margin:0 0 4px'>" + " ".join(
            f"<span class='pill {PRI_COLOR[p]}'>{counts[p]} {p}</span>"
            for p in ("HIGH", "MEDIUM", "LOW") if p in counts)
            + f" &nbsp;<b>{total} tasks</b></p>")

        # ---- plain-text ticket (for Copy) ----
        txt = [DIV,
               f"REMEDIATION TICKET — {cfg['fw_name']} "
               f"({cfg['model']}, serial {cfg['serial']})",
               f"{total} remediation tasks "
               f"({counts.get('HIGH', 0)} HIGH, {counts.get('MEDIUM', 0)} "
               f"MEDIUM)", DIV, ""]
        # ---- task cards (wrapped so they can be downloaded) ----
        pbar = {"HIGH": "#c0392b", "MEDIUM": "#d98324", "LOW": "#6b7a8f"}
        ptint = {"HIGH": "#fbe9e7", "MEDIUM": "#fdf3e3", "LOW": "#eef1f4"}
        mono = "SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"
        b.append(f"<div id='doc{idx}'>")
        for n, it in enumerate(items, 1):
            pri = it["pri"]
            bar, tint = pbar[pri], ptint[pri]
            head = f"TASK {n} of {total}  —  [{pri}]  {it['area']}"
            instr = ""
            if it["lines"]:
                # verbatim (preserve indentation) so screen == copied ticket
                instr = (f"<pre style='margin:2px 0 14px;white-space:pre-wrap;"
                         f"font-family:{mono};font-size:12.5px;line-height:1.65;"
                         "background:#f6f8fa;border:1px solid #e4e8ec;"
                         "border-radius:8px;padding:13px 15px;color:#20303f'>"
                         + esc("\n".join(it["lines"])) + "</pre>")
            b.append(
                "<div style='margin:20px 0 0;border:1px solid #e0e5ea;"
                "border-radius:10px;overflow:hidden'>"
                f"<div style='padding:12px 16px;background:{tint};"
                f"border-left:6px solid {bar}'>"
                "<table style='border:0;background:none;box-shadow:none;"
                "width:100%;margin:0'><tr style='background:none'>"
                "<td style='border:0;padding:0;width:34px;"
                "vertical-align:middle'>"
                f"<span style='display:inline-block;width:30px;height:30px;"
                f"line-height:30px;text-align:center;border-radius:50%;"
                f"background:{bar};color:#fff;font-weight:700;font-size:14px'>"
                f"{n}</span></td>"
                "<td style='border:0;padding:0 10px;vertical-align:middle;"
                f"font-weight:700;font-size:16px;color:#0b2540'>"
                f"{esc(it['area'])}<span style='color:#7a8794;font-weight:400;"
                f"font-size:12px'> &nbsp;· Task {n} of {total}</span></td>"
                "<td style='border:0;padding:0;text-align:right;"
                "vertical-align:middle'>"
                f"<span style='background:{bar};color:#fff;font-weight:700;"
                f"font-size:11px;padding:4px 11px;border-radius:12px'>{pri}"
                "</span></td></tr></table></div>"
                "<div style='padding:15px 18px'>"
                "<div style='font-size:14px;line-height:1.55;margin-bottom:"
                f"10px'><b>What to do:</b> {esc(it['action'])}</div>"
                f"{instr}"
                "<div style='background:#eef5fb;border-left:4px solid #8fb4d8;"
                "padding:9px 13px;border-radius:6px;font-size:13px;"
                f"line-height:1.55;color:#33465a'><b>Why:</b> {esc(it['why'])}"
                "</div>"
                "<div style='margin-top:9px;font-size:11.5px;color:#8a97a4'>"
                f"<b>Standard:</b> {esc(it['standard'])}</div>"
                "</div></div>")

            txt.append(DIV)
            txt.append(head)
            txt.append(DIV)
            txt.append(f"What to do: {it['action']}")
            txt += it["lines"]
            txt.append("")
            txt.append(f"Why: {it['why']}")
            txt.append(f"Standard failing: {it['standard']}")
            txt.append("")

        title = (f"Remediation Ticket — {cfg['fw_name']} "
                 f"({cfg['model']}, serial {cfg['serial']})")
        fname = re.sub(r"[^A-Za-z0-9._-]", "_",
                       f"{cfg['fw_name']}_{cfg['serial']}_remediation")
        b.append(
            "</div>"  # close #doc{idx}
            "<div style='margin-top:16px'>"
            f"<button class='copybtn' onclick=\"copyTicket({idx})\">"
            "&#128203; Copy ticket text</button> "
            f"<button class='copybtn' onclick=\"downloadDoc({idx})\">"
            "&#11015; Download Word (.doc)</button></div>"
            f"<textarea id='tick{idx}' style='display:none'>"
            f"{esc(chr(10).join(txt))}</textarea>"
            f"<span id='title{idx}' style='display:none'>{esc(title)}</span>"
            f"<span id='fname{idx}' style='display:none'>{esc(fname)}</span>"
            "</div></div>")  # close inner content + .card
    b.append("""<script>
function copyTicket(i){var t=document.getElementById('tick'+i);
if(navigator.clipboard&&navigator.clipboard.writeText){
navigator.clipboard.writeText(t.value);}else{
t.style.display='block';t.select();document.execCommand('copy');
t.style.display='none';}}
function downloadDoc(i){
var body=document.getElementById('doc'+i).innerHTML;
var title=document.getElementById('title'+i).textContent;
var fname=document.getElementById('fname'+i).textContent;
var css='<style>body{font-family:Calibri,"Segoe UI",Arial,sans-serif;'
+'font-size:11pt;color:#1c2530;line-height:1.45}'
+'h1{font-size:16pt;color:#0b2540;border-bottom:2px solid #0b2540;'
+'padding-bottom:6px;margin-bottom:14px}'
+'b{color:#0b2540}'
+'pre{font-family:Consolas,"Courier New",monospace;font-size:9.5pt;'
+'white-space:pre-wrap;background:#f6f8fa;border:1px solid #e4e8ec;'
+'padding:10px;line-height:1.5}</style>';
var html='<html xmlns:o="urn:schemas-microsoft-com:office:office" '
+'xmlns:w="urn:schemas-microsoft-com:office:word" '
+'xmlns="http://www.w3.org/TR/REC-html40"><head><meta charset="utf-8">'
+'<title>'+title+'</title>'+css+'</head><body>'
+'<div style="font-size:9pt;letter-spacing:2px;color:#0b5cad;'
+'font-weight:bold">AUDITHAT.COM</div><h1>'+title+'</h1>'+body
+'</body></html>';
var blob=new Blob(['\\ufeff'+html],{type:'application/msword'});
var url=URL.createObjectURL(blob);
var a=document.createElement('a');a.href=url;a.download=fname+'.doc';
document.body.appendChild(a);a.click();document.body.removeChild(a);
setTimeout(function(){URL.revokeObjectURL(url);},1000);}
</script>""")
    return _page("SonicWall Remediation Tickets",
                 "Per-firewall remediation tickets — tasks, steps & options",
                 "".join(b))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def setup_rules():
    """Load compliance_rules.json and apply it to the module globals."""
    global RULES, TRUSTED_ZONE, VLAN_ROLES, NON_CFS_ZONES
    RULES = load_rules()
    TRUSTED_ZONE = RULES.get("trusted_zone", TRUSTED_ZONE)
    if RULES.get("expected_vlan_roles"):
        VLAN_ROLES = RULES["expected_vlan_roles"]
    NON_CFS_ZONES = set(RULES.get("content_filter_exempt_zones",
                                  NON_CFS_ZONES))


def process_paths(paths, decoded_dir=DECODED_DIR, db_path=DB_PATH):
    """Parse + store a list of EXP files. Returns (configs, errors) where
    errors is [(filename, message)] for files that could not be parsed."""
    os.makedirs(decoded_dir, exist_ok=True)
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    init_db(conn)
    configs, errors = [], []
    for path in paths:
        f = os.path.basename(path)
        print(f"Parsing {f} ...")
        try:
            flat = parse_exp_file(path)
            member = exp_member_name(path)
            with open(os.path.join(decoded_dir, member + ".txt"), "w") as out:
                out.write("\n".join(f"{k}={v}" for k, v in flat.items()))
            cfg = extract(flat, member)
        except Exception as e:
            errors.append((f, str(e)))
            print(f"  SKIPPED {f}: {e}")
            continue
        store(conn, cfg)
        configs.append(cfg)
        print(f"  {cfg['fw_name']} · {cfg['model']} {cfg['serial']}  "
              f"| {len(cfg['zones'])} zones, {len(vlans_of(cfg))} VLANs, "
              f"{len(cfg['rules'])} rules")
    conn.close()
    configs.sort(key=lambda c: c["fw_name"].lower())
    return configs, errors


def generate_reports(configs):
    """Render every report type -> {name: html}."""
    return {
        "differences": build_differences(configs),
        "compliance": build_compliance(configs),
        "findings": build_findings(configs),
        "remediation": build_remediation(configs),
    }


def main():
    setup_rules()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    files = [os.path.join(INPUT_DIR, f)
             for f in sorted(os.listdir(INPUT_DIR))
             if os.path.isfile(os.path.join(INPUT_DIR, f))
             and not f.startswith(".")]
    if not files:
        sys.exit(f"No files in ./{INPUT_DIR}/ — add your EXP .zip exports.")

    configs, errors = process_paths(files)
    if not configs:
        sys.exit("No files could be parsed: "
                 + "; ".join(f"{f}: {e}" for f, e in errors))

    for name, doc in generate_reports(configs).items():
        with open(os.path.join(OUTPUT_DIR, name + ".html"), "w") as fh:
            fh.write(doc)

    print(f"\nDone. Reports written to ./{OUTPUT_DIR}/ : "
          "compliance, differences, findings, remediation (.html)")
    print(f"SQLite DB: {DB_PATH}")
    for f, e in errors:
        print(f"  SKIPPED {f}: {e}")


if __name__ == "__main__":
    main()
