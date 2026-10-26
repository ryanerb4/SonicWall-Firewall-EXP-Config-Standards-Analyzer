#!/usr/bin/env python3
"""
make_samples.py — build the fictional sample data set shipped with the repo.

Generates three synthetic SonicOS 7.x EXP exports for an invented community
bank ("Example Community Bank": a head office and two branches) under
samples/exp/, then runs the audit engine over them and writes the resulting
reports to samples/reports/.

Nothing here comes from a real firewall. Firewall names, serial numbers,
object names and addresses are made up; public addresses use the RFC 5737
documentation ranges (203.0.113.0/24, 198.51.100.0/24). The three firewalls
are deliberately configured with a mix of compliant and non-compliant
settings so every report section has something to show:

    HQ-Main           TZ 470  hardened reference config — passes every rule
    Branch-Downtown   TZ 270  open SSH/HTTPS management, RDP forwarded from
                              the Internet, no VPN MFA, expired CFS license
    Branch-Westside   TZ 270  cleartext management open to the Internet, IPS
                              off on LAN, RADIUS-only auth, no NSM, legacy
                              WAN->LAN "Any" rule

Usage (from the repo root):
    python3 samples/make_samples.py                # exports + reports
    python3 samples/make_samples.py --screenshots  # + PNGs via headless Chrome
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXP_DIR = os.path.join(HERE, "exp")
REPORT_DIR = os.path.join(HERE, "reports")
SHOT_DIR = os.path.join(HERE, "screenshots")

TENANT = "Example Community Bank"
BUILD = "7.3.3-7015-R9691"

# ---------------------------------------------------------------------------
# Shared reference data (product-level, not client-specific)
# ---------------------------------------------------------------------------
CATEGORIES = [
    "Violence/Hate/Racism", "Intimate Apparel/Swimsuit", "Nudism",
    "Pornography", "Weapons", "Adult/Mature Content", "Cult/Occult",
    "Drugs/Illegal Drugs", "Illegal Skills/Questionable Skills",
    "Sex Education", "Gambling", "Alcohol/Tobacco",
    "Chat/Instant Messaging (IM)", "Arts/Entertainment", "Business and Economy",
    "Abortion/Advocacy Groups", "Education", "Cultural Institutions",
    "Online Banking", "Online Brokerage and Trading", "Games", "Government",
    "Military", "Political/Advocacy Groups", "Health",
    "Information Technology/Computers", "Hacking/Proxy Avoidance Systems",
    "Search Engines and Portals", "E-Mail", "Web Communications", "Job Search",
    "News and Media", "Personals and Dating", "Usenet News Groups",
    "Kid Friendly", "Religion", "Shopping", "Society and Lifestyle",
    "Sports/Recreation", "Travel", "Vehicles", "Humor/Jokes", "Multimedia",
    "Freeware/Software Downloads", "Pay to Surf Sites",
    "Internet Watch Foundation CAIC", "Social Networking", "Malware", "Radio",
    "Streaming Media", "Phishing and Other Frauds", "Not Rated",
    "Advertisements", "Peer-to-Peer", "Web Hosting", "Dynamic Content",
]

COUNTRIES = [
    "Anonymous Proxy/Private IP", "Satellite Provider", "Unknown",
    "Afghanistan", "Albania", "Algeria", "Argentina", "Australia", "Austria",
    "Belarus", "Belgium", "Brazil", "Bulgaria", "Canada", "China", "Colombia",
    "Cuba", "Czechia", "Denmark", "Egypt", "Finland", "France", "Germany",
    "Greece", "Hong Kong", "Hungary", "India", "Indonesia", "Iran", "Iraq",
    "Ireland", "Israel", "Italy", "Japan", "Kazakhstan", "Kenya",
    "Korea, North", "Korea, South", "Lebanon", "Libya", "Malaysia", "Mexico",
    "Moldova", "Netherlands", "New Zealand", "Nigeria", "Norway", "Pakistan",
    "Philippines", "Poland", "Portugal", "Romania", "Russia", "Saudi Arabia",
    "Serbia", "Singapore", "Somalia", "South Africa", "Spain", "Sudan",
    "Sweden", "Switzerland", "Syria", "Taiwan", "Thailand", "Turkey",
    "Ukraine", "United Arab Emirates", "United Kingdom", "United States",
    "Venezuela", "Vietnam", "Yemen", "Zimbabwe",
]

LIC_SERVICES = [
    ("IDP", "Gateway Anti-Virus, Intrusion Prevention and Application Control"),
    ("CFSP", "Content Filtering Service"),
    ("ADVANCEDDNS", "DNS Filtering"),
    ("SBX", "Capture Advanced Threat Protection"),
    ("UTMAS", "Comprehensive Anti-Spam Service"),
    ("VPNSSL", "SSL VPN"),
    ("VPNC", "Global VPN Client"),
    ("NSMESSENTIAL", "Network Security Manager Essential"),
    ("REPORTANALYTICS", "Analytics"),
    ("HA", "Stateful High Availability"),
]

# (name, type, proto, port1, port2)   type 1 = single service, 2 = group
SERVICES = [
    ("SSH Management", 1, 6, 22, 22), ("HTTPS Management", 1, 6, 443, 443),
    ("HTTP Management", 1, 6, 80, 80), ("Ping", 1, 1, 0, 0),
    ("SNMP", 1, 17, 161, 161), ("SSLVPN", 1, 6, 4433, 4433),
    ("ISAKMP", 1, 17, 500, 500), ("NAT Traversal", 1, 17, 4500, 4500),
    ("HTTPS", 1, 6, 443, 443), ("HTTP", 1, 6, 80, 80),
    ("SMTP", 1, 6, 25, 25), ("RDP", 1, 6, 3389, 3389),
    ("SIP", 1, 17, 5060, 5060), ("RTP", 1, 17, 10000, 20000),
    ("LDAP", 1, 6, 389, 389), ("RADIUS", 1, 17, 1812, 1812),
    ("DNS", 1, 17, 53, 53), ("NTP", 1, 17, 123, 123),
    ("Syslog", 1, 17, 514, 514), ("SMB", 1, 6, 445, 445),
    ("IKE", 2, 0, 0, 0), ("Web Services", 2, 0, 0, 0), ("VoIP", 2, 0, 0, 0),
]
SERVICE_GROUPS = {
    "IKE": ["ISAKMP", "NAT Traversal"],
    "Web Services": ["HTTP", "HTTPS"],
    "VoIP": ["SIP", "RTP"],
}

USER_GROUPS = [            # (name, privilege mask)
    ("Everyone", 0), ("Trusted Users", 1), ("Content Filtering Bypass", 2),
    ("Limited Administrators", 4), ("SonicWALL Administrators", 8),
    ("SonicWALL Read-Only Admins", 16), ("Guest Services", 32),
    ("Guest Administrators", 64), ("SSLVPN Services", 128),
]

# zone: (type, cfs, idp, gav, asp, intra)
def zones(lan_intra=1, sslvpn_intra=0, extra=(), overrides=None):
    base = {
        "LAN": (1, 1, 1, 1, 1, lan_intra), "WAN": (0, 0, 1, 1, 0, 0),
        "DMZ": (2, 1, 1, 1, 0, 0), "VPN": (5, 0, 1, 1, 0, 0),
        "SSLVPN": (8, 0, 1, 0, 0, sslvpn_intra), "MULTICAST": (6, 0, 0, 0, 0, 0),
        "WLAN": (4, 1, 1, 1, 0, 0),
    }
    for z in extra:
        base[z] = (1, 1, 1, 1, 0, 0)
    for z, v in (overrides or {}).items():
        base[z] = v
    return base


def iface(name, zone, ip, mask, comment="", vlan=0, parent=-1, https=0, ssh=0):
    return dict(name=name, zone=zone, ip=ip, mask=mask, comment=comment,
                vlan=vlan, parent=parent, https=https, ssh=ssh)


def host(name, ip):
    return (name, 1, ip, ip)


def net(name, ip, mask):
    return (name, 4, ip, mask)


def group(name):
    return (name, 8, "0.0.0.0", "0.0.0.0")


def rule(src_zone, dst_zone, src, dst, svc, comment="", action=2, enabled=1,
         name=""):
    return dict(src_zone=src_zone, dst_zone=dst_zone, src=src, dst=dst,
                svc=svc, comment=comment, action=action, enabled=enabled,
                name=name)


def nat(name, orig_src, orig_dst, orig_svc, trans_src, trans_dst, trans_svc,
        src_iface, dst_iface, comment=""):
    return dict(name=name, orig_src=orig_src, orig_dst=orig_dst,
                orig_svc=orig_svc, trans_src=trans_src, trans_dst=trans_dst,
                trans_svc=trans_svc, src_iface=src_iface, dst_iface=dst_iface,
                comment=comment)


HQ_BLOCKED_CATS = [
    "Violence/Hate/Racism", "Intimate Apparel/Swimsuit", "Nudism",
    "Pornography", "Weapons", "Adult/Mature Content", "Cult/Occult",
    "Drugs/Illegal Drugs", "Illegal Skills/Questionable Skills",
    "Sex Education", "Gambling", "Alcohol/Tobacco",
    "Hacking/Proxy Avoidance Systems", "Malware", "Phishing and Other Frauds",
    "Peer-to-Peer", "Internet Watch Foundation CAIC", "Personals and Dating",
    "Games", "Freeware/Software Downloads",
]
HQ_BLOCKED_COUNTRIES = [
    "Anonymous Proxy/Private IP", "Satellite Provider", "Unknown",
    "Afghanistan", "Belarus", "China", "Cuba", "Iran", "Iraq", "Korea, North",
    "Libya", "Nigeria", "Pakistan", "Russia", "Somalia", "Sudan", "Syria",
    "Ukraine", "Venezuela", "Yemen", "Zimbabwe",
]


def minus(seq, *drop):
    return [x for x in seq if x not in drop]


# ---------------------------------------------------------------------------
# The three fictional firewalls
# ---------------------------------------------------------------------------
def hq():
    """Head office: the hardened reference. Everything passes."""
    return dict(
        name="HQ-Main", serial="0017C5A00001", model="TZ 470",
        ips="on", cfs="on", gms=("on", "198.51.100.10"),
        zones=zones(lan_intra=1, extra=("VOIP", "PRINTERS", "GUEST", "IOT",
                                        "CCTV", "ATM", "CORE", "FEDLINE")),
        interfaces=[
            iface("X0", "LAN", "10.10.10.1", "255.255.255.0", "Default LAN",
                  https=1, ssh=1),
            iface("X1", "WAN", "203.0.113.2", "255.255.255.248", "ISP fiber",
                  https=1),
            iface("X2", "", "0.0.0.0", "0.0.0.0"),
            iface("X3", "", "0.0.0.0", "0.0.0.0"),
            iface("X0:V10", "LAN", "10.10.1.1", "255.255.255.0",
                  "Mgmt - switches, APs, iDRAC", 10, 0),
            iface("X0:V20", "LAN", "10.10.20.1", "255.255.255.0",
                  "Servers", 20, 0),
            iface("X0:V30", "LAN", "10.10.30.1", "255.255.255.0",
                  "Staff workstations", 30, 0),
            iface("X0:V40", "VOIP", "10.10.40.1", "255.255.255.0",
                  "VoIP phones", 40, 0),
            iface("X0:V50", "PRINTERS", "10.10.50.1", "255.255.255.0",
                  "Printers / MFP", 50, 0),
            iface("X0:V60", "WLAN", "10.10.60.1", "255.255.255.0",
                  "Corporate WiFi", 60, 0),
            iface("X0:V70", "GUEST", "10.10.70.1", "255.255.255.0",
                  "Guest WiFi", 70, 0),
            iface("X0:V80", "IOT", "10.10.80.1", "255.255.255.0",
                  "IoT - HVAC, postage meter", 80, 0),
            iface("X0:V90", "CCTV", "10.10.90.1", "255.255.255.0",
                  "Security cameras / NVR", 90, 0),
            iface("X0:V100", "DMZ", "10.10.100.1", "255.255.255.0",
                  "DMZ - published services", 100, 0),
            iface("X0:V200", "ATM", "10.10.200.1", "255.255.255.240",
                  "ATM network", 200, 0),
            iface("X0:V210", "CORE", "10.10.210.1", "255.255.255.248",
                  "ASI core router", 210, 0),
            iface("X0:V220", "FEDLINE", "10.10.220.1", "255.255.255.248",
                  "FedLine router", 220, 0),
        ],
        addr=[
            host("Mgmt-Jumpbox", "10.10.30.25"),
            host("DUO-Auth-Proxy", "10.10.20.15"),
            host("DC01", "10.10.20.10"),
            host("Web-Server", "10.10.100.25"),
            host("Public-Web-IP", "203.0.113.5"),
            host("RT Datacenter", "198.51.100.10"),
            host("Vendor-Support-IP", "198.51.100.77"),
            host("Core-Banking-Processor", "198.51.100.200"),
            host("NVR", "10.10.90.10"),
            host("PBX", "10.10.40.5"),
            net("Downtown LAN", "10.20.0.0", "255.255.0.0"),
            net("Westside LAN", "10.30.0.0", "255.255.0.0"),
            group("Branch Subnets"),
        ],
        groups={"Branch Subnets": ["Downtown LAN", "Westside LAN"]},
        rules=[
            rule("LAN", "LAN", "Mgmt-Jumpbox", "All X0 Management IP",
                 "SSH Management", "SSH from jumpbox only"),
            rule("LAN", "LAN", "Mgmt-Jumpbox", "All X0 Management IP",
                 "HTTPS Management", "Admin UI from jumpbox only"),
            rule("LAN", "LAN", "", "All X0 Management IP", "Ping",
                 "Auto-added management rule"),
            rule("LAN", "WAN", "", "", "", "Outbound internet"),
            rule("LAN", "VPN", "", "Branch Subnets", "", "To branches"),
            rule("LAN", "DMZ", "", "Web-Server", "Web Services",
                 "Staff to published portal"),
            rule("LAN", "CCTV", "Mgmt-Jumpbox", "NVR", "HTTPS", "NVR admin"),
            rule("LAN", "PRINTERS", "", "", "", "Print from staff"),
            rule("SSLVPN", "LAN", "", "LAN Subnets", "", "Remote users to LAN"),
            rule("WAN", "WAN", "", "WAN Interface IP", "IKE",
                 "Auto-added VPN policy rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "SSLVPN",
                 "Auto-added SSL VPN rule"),
            rule("WAN", "WAN", "RT Datacenter", "WAN Interface IP",
                 "HTTPS Management", "Auto-added management rule (NSM)"),
            rule("WAN", "DMZ", "Vendor-Support-IP", "Public-Web-IP", "HTTPS",
                 "Vendor status portal (restricted)"),
            rule("WLAN", "WAN", "", "", "", "Corp WiFi internet"),
            rule("WLAN", "LAN", "", "", "", "Corp WiFi isolated", action=0),
            rule("GUEST", "WAN", "", "", "Web Services", "Guest internet only"),
            rule("GUEST", "LAN", "", "", "", "Guest isolated", action=0),
            rule("VOIP", "WAN", "", "", "VoIP", "SIP trunk"),
            rule("IOT", "WAN", "", "", "Web Services", "IoT cloud endpoints"),
            rule("IOT", "LAN", "", "", "", "IoT isolated", action=0),
            rule("CCTV", "LAN", "", "", "", "Cameras isolated", action=0),
            rule("PRINTERS", "WAN", "", "", "", "Printers no internet",
                 action=0),
            rule("ATM", "WAN", "", "Core-Banking-Processor", "HTTPS",
                 "ATM to processor only"),
        ],
        nat=[
            nat("Outbound NAT", "LAN Subnets", "", "", "WAN Interface IP",
                "Original", "Original", -1, 1, "Auto-added outbound NAT"),
            nat("Vendor portal forward", "Vendor-Support-IP", "Public-Web-IP",
                "HTTPS", "Original", "Web-Server", "Original", 1, -1,
                "Vendor status portal"),
        ],
        otp={}, users=[
            ("svc-backup", 1, "Backup service account", 0, ""),
            ("oldadmin", 8, "Former IT contractor", 1, ""),
            ("netmon", 16, "Read-only monitoring", 0, ""),
        ],
        membership=[("svc-backup", "Trusted Users"),
                    ("oldadmin", "SonicWALL Administrators")],
        ldap=("dc01.corp.examplebank.local", "DC=corp,DC=examplebank,DC=local"),
        radius=(2, "10.10.20.15"), admin_totp=1,
        sslvpn=("10.10.20.10", "10.10.250.10", "10.10.250.60", 4433),
        lic={}, cats=HQ_BLOCKED_CATS, countries=HQ_BLOCKED_COUNTRIES,
        geo=dict(enf=1, block_all=0, unknown="on", botnet=1, policy=0),
    )


def downtown():
    """Branch with loose management and a vendor RDP forward."""
    return dict(
        name="Branch-Downtown", serial="0017C5B00002", model="TZ 270",
        ips="on", cfs="on", gms=("on", "198.51.100.10"),
        zones=zones(lan_intra=1, sslvpn_intra=1,
                    extra=("VOIP", "PRINTERS", "GUEST", "CCTV", "ATM"),
                    overrides={"GUEST": (4, 0, 1, 1, 0, 0)}),
        interfaces=[
            iface("X0", "LAN", "10.20.10.1", "255.255.255.0", "Default LAN",
                  https=1, ssh=1),
            iface("X1", "WAN", "203.0.113.18", "255.255.255.248", "Cable ISP",
                  https=1),
            iface("X2", "", "0.0.0.0", "0.0.0.0"),
            iface("X0:V30", "LAN", "10.20.30.1", "255.255.255.0",
                  "Teller workstations", 30, 0),
            iface("X0:V40", "VOIP", "10.20.40.1", "255.255.255.0",
                  "Phones", 40, 0),
            iface("X0:V50", "PRINTERS", "10.20.50.1", "255.255.255.0",
                  "Printers", 50, 0),
            iface("X0:V70", "GUEST", "10.20.70.1", "255.255.255.0",
                  "Guest WiFi", 70, 0),
            iface("X0:V90", "CCTV", "10.20.90.1", "255.255.255.0",
                  "Cameras", 90, 0),
            iface("X0:V150", "LAN", "10.20.150.1", "255.255.255.0", "", 150, 0),
            iface("X0:V200", "ATM", "10.20.200.1", "255.255.255.240",
                  "ATM", 200, 0),
        ],
        addr=[
            host("RT-DC-NSM-1", "198.51.100.10"),
            host("RT-DC-NSM-2", "198.51.100.11"),
            group("GMS Addresses"),
            host("Teller-PC-01", "10.20.30.41"),
            host("Mail-Relay", "10.20.10.25"),
            host("Spam-Filter-Cloud", "198.51.100.120"),
            host("Core-Banking-Processor", "198.51.100.200"),
            net("HQ LAN", "10.10.0.0", "255.255.0.0"),
        ],
        groups={"GMS Addresses": ["RT-DC-NSM-1", "RT-DC-NSM-2"]},
        rules=[
            rule("LAN", "LAN", "", "All X0 Management IP", "SSH Management",
                 "Auto-added management rule"),
            rule("LAN", "LAN", "", "All X0 Management IP", "HTTPS Management",
                 "Auto-added management rule"),
            rule("LAN", "LAN", "", "All X0 Management IP", "Ping",
                 "Auto-added management rule"),
            rule("GUEST", "LAN", "", "All X0 Management IP", "HTTPS Management",
                 "Guest AP controller reaches firewall UI"),
            rule("LAN", "WAN", "", "", "", "Outbound internet"),
            rule("LAN", "VPN", "", "HQ LAN", "", "To HQ"),
            rule("VPN", "LAN", "HQ LAN", "LAN Subnets", "", "From HQ"),
            rule("SSLVPN", "LAN", "", "LAN Subnets", "", "Remote users to LAN"),
            rule("LAN", "SSLVPN", "", "", "", "temp - remote support"),
            rule("WAN", "WAN", "", "WAN Interface IP", "IKE",
                 "Auto-added VPN policy rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "SSLVPN",
                 "Auto-added SSL VPN rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "Ping",
                 "Allow ping for ISP monitoring"),
            rule("WAN", "WAN", "GMS Addresses", "WAN Interface IP",
                 "HTTPS Management", "Auto-added management rule (GMS)"),
            rule("WAN", "LAN", "", "WAN Interface IP", "RDP",
                 "Teller PC remote access for vendor"),
            rule("WAN", "LAN", "Spam-Filter-Cloud", "WAN Interface IP", "SMTP",
                 "Inbound mail from spam filter"),
            rule("GUEST", "WAN", "", "", "Web Services", "Guest internet"),
            rule("VOIP", "WAN", "", "", "VoIP", "SIP trunk"),
            rule("CCTV", "WAN", "", "", "", "Camera vendor cloud"),
            rule("ATM", "WAN", "", "Core-Banking-Processor", "HTTPS",
                 "ATM to processor only"),
            rule("LAN", "PRINTERS", "", "", "", "Print from tellers"),
        ],
        nat=[
            nat("Outbound NAT", "LAN Subnets", "", "", "WAN Interface IP",
                "Original", "Original", -1, 1, "Auto-added outbound NAT"),
            nat("RDP to teller PC", "", "WAN Interface IP", "RDP", "Original",
                "Teller-PC-01", "Original", 1, -1, "vendor remote support"),
            nat("Inbound SMTP", "Spam-Filter-Cloud", "WAN Interface IP", "SMTP",
                "Original", "Mail-Relay", "Original", 1, -1,
                "mail from cloud spam filter"),
        ],
        otp={}, users=[
            ("branchadmin", 8, "Branch manager - full admin", 0, ""),
            ("vendor-temp", 128, "Vendor remote support - temporary", 0,
             "LAN Subnets"),
            ("teller-kiosk", 1, "", 0, ""),
        ],
        membership=[("branchadmin", "SonicWALL Administrators"),
                    ("vendor-temp", "SSLVPN Services")],
        ldap=("dc01.corp.examplebank.local", "DC=corp,DC=examplebank,DC=local"),
        radius=(0, ""), admin_totp=0,
        sslvpn=("10.10.20.10", "10.20.250.10", "10.20.250.30", 4433),
        lic={"CFSP": ("expired", "2026-06-30")},
        cats=minus(HQ_BLOCKED_CATS, "Gambling", "Games",
                   "Freeware/Software Downloads"),
        countries=minus(HQ_BLOCKED_COUNTRIES, "Belarus", "Venezuela",
                        "Nigeria"),
        geo=dict(enf=1, block_all=0, unknown="on", botnet=1, policy=0),
    )


def westside():
    """Branch with Internet-facing management and no central management."""
    return dict(
        name="Branch-Westside", serial="0017C5C00003", model="TZ 270",
        ips="on", cfs="on", gms=("off", "0.0.0.0"),
        zones=zones(lan_intra=1, extra=("VOIP", "GUEST", "IOT", "ATM"),
                    overrides={"LAN": (1, 1, 0, 1, 1, 1)}),
        interfaces=[
            iface("X0", "LAN", "10.30.10.1", "255.255.255.0", "Default LAN",
                  https=1, ssh=1),
            iface("X1", "WAN", "198.51.100.34", "255.255.255.248", "DSL ISP",
                  https=1, ssh=1),
            iface("X2", "", "0.0.0.0", "0.0.0.0"),
            iface("X0:V30", "LAN", "10.30.30.1", "255.255.255.0",
                  "Staff PCs", 30, 0),
            iface("X0:V40", "VOIP", "10.30.40.1", "255.255.255.0",
                  "VoIP", 40, 0),
            iface("X0:V70", "GUEST", "10.30.70.1", "255.255.255.0",
                  "Guest wireless", 70, 0),
            iface("X0:V80", "IOT", "10.30.80.1", "255.255.255.0",
                  "HVAC + postage meter", 80, 0),
            iface("X0:V200", "ATM", "10.30.200.1", "255.255.255.240",
                  "ATM", 200, 0),
        ],
        addr=[
            host("IT-Admin-PC", "10.30.30.40"),
            host("IT-Admin-Laptop", "10.30.30.41"),
            host("Branch-Mgr-PC", "10.30.30.42"),
            group("IT Staff"),
            host("Core-Banking-Processor", "198.51.100.200"),
            net("HQ LAN", "10.10.0.0", "255.255.0.0"),
        ],
        groups={"IT Staff": ["IT-Admin-PC", "IT-Admin-Laptop", "Branch-Mgr-PC"]},
        rules=[
            rule("LAN", "LAN", "IT Staff", "All X0 Management IP",
                 "SSH Management", "SSH from IT"),
            rule("LAN", "LAN", "IT Staff", "All X0 Management IP",
                 "HTTPS Management", "Admin UI from IT"),
            rule("LAN", "LAN", "", "All X0 Management IP", "Ping",
                 "Auto-added management rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "HTTP Management",
                 "Auto-added management rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "HTTPS Management",
                 "Auto-added management rule"),
            rule("WAN", "WAN", "", "WAN Interface IP", "IKE",
                 "Auto-added VPN policy rule"),
            rule("LAN", "WAN", "", "", "", "Outbound internet"),
            rule("LAN", "VPN", "", "HQ LAN", "", "To HQ"),
            rule("VPN", "LAN", "HQ LAN", "LAN Subnets", "", "From HQ"),
            rule("WAN", "LAN", "", "LAN Primary Subnet", "",
                 "Branch-to-branch (pre-VPN leftover)"),
            rule("GUEST", "LAN", "", "LAN Subnets", "Web Services",
                 "Guest to intranet page"),
            rule("GUEST", "WAN", "", "", "Web Services", "Guest internet"),
            rule("VOIP", "WAN", "", "", "VoIP", "SIP trunk"),
            rule("IOT", "WAN", "", "", "", "IoT internet"),
            rule("IOT", "LAN", "", "LAN Subnets", "",
                 "HVAC vendor needs access"),
            rule("ATM", "WAN", "", "Core-Banking-Processor", "HTTPS",
                 "ATM to processor only"),
        ],
        nat=[
            nat("Outbound NAT", "LAN Subnets", "", "", "WAN Interface IP",
                "Original", "Original", -1, 1, "Auto-added outbound NAT"),
        ],
        otp={}, users=[("itadmin", 8, "Shared IT admin login", 0, "")],
        membership=[("itadmin", "SonicWALL Administrators")],
        ldap=None, radius=(1, "10.10.20.16"), admin_totp=0,
        sslvpn=("0.0.0.0", "0.0.0.0", "0.0.0.0", 4433),
        lic={"SBX": ("not licensed", ""), "UTMAS": ("expired", "2026-04-01")},
        cats=minus(HQ_BLOCKED_CATS, "Hacking/Proxy Avoidance Systems",
                   "Peer-to-Peer"),
        countries=minus(HQ_BLOCKED_COUNTRIES, "Ukraine", "Pakistan"),
        geo=dict(enf=1, block_all=0, unknown="on", botnet=0, policy=0),
    )


# ---------------------------------------------------------------------------
# Flat key=value builder (mirrors the SonicOS export layout the parser reads)
# ---------------------------------------------------------------------------
class Flat(dict):
    def arr(self, base, values):
        for i, v in enumerate(values):
            self[f"{base}_{i}"] = "" if v is None else str(v)


def build_flat(fw):
    f = Flat()
    f.update({
        "checksumVersion": "1", "buildNum": BUILD, "shortProdName": fw["model"],
        "localeVersionStr": "SonicOS LanguagePack English", "hasHAPort": "0",
        "factoryDefault": "off", "firewallName": fw["name"],
        "serialNumber": fw["serial"], "timeZone": "Eastern Time (US & Canada)",
        "isIDPEnabled": fw["ips"], "cfsEnabled": fw["cfs"],
        "gmsServerEnable": fw["gms"][0], "gmsServerAddr": fw["gms"][1],
        "adminName": "admin", "adminLoginOtpRequire": str(fw["admin_totp"]),
        "adminOtpReq": "0", "sshdPort": "22", "httpsMgmtPort": "443",
        "L2TPServerEnabled": "0",
        "SslvpnsDnsServer1": fw["sslvpn"][0],
        "SslvpnsPPPStartIp": fw["sslvpn"][1],
        "SslvpnsPPPEndIp": fw["sslvpn"][2],
        "sslvpnSvcPort": str(fw["sslvpn"][3]),
        "userRadiusSelect": str(fw["radius"][0]),
    })
    if fw["radius"][1]:
        f["radiusSrvrHost_0"] = fw["radius"][1]
        f["radiusSrvrIsEnabled_0"] = "1"
        f["radiusSrvrPort_0"] = "1812"
    if fw["ldap"]:
        f["ldapServerName"] = fw["ldap"][0]
        f["ldapBaseDN"] = fw["ldap"][1]
        f["ldapServerPort"] = "636"

    # license summary blob
    svcs = []
    for code, label in LIC_SERVICES:
        status, exp = fw["lic"].get(code, ("licensed", "2027-03-15"))
        if code in ("NSMESSENTIAL", "HA"):
            status, exp = ("licensed", "2027-03-15") if code == "NSMESSENTIAL" \
                and fw["gms"][0] == "on" else ("not licensed", "")
        entry = {"serviceCode": code, "securityService": label,
                 "status": status, "expiration": exp, "count": "", "maxCount": ""}
        if code == "VPNSSL":
            entry.update(count="2" if fw["model"] == "TZ 270" else "10",
                         maxCount="50" if fw["model"] == "TZ 270" else "100")
        if code == "VPNC":
            entry.update(count="2", maxCount="2")
        svcs.append(entry)
    f["manualLicSummaryData"] = json.dumps({"data": {
        "friendly-name": fw["name"], "tenant-name": TENANT, "registered": "yes",
        "serial-number": fw["serial"], "securityServices": svcs}})

    # zones
    names = list(fw["zones"])
    vals = [fw["zones"][n] for n in names]
    f.arr("zoneObjId", names)
    f.arr("zoneObjZoneType", [v[0] for v in vals])
    f.arr("zoneObjCflProfile", [v[1] for v in vals])
    f.arr("zoneObjMyIDPProfile", [v[2] for v in vals])
    f.arr("zoneObjGavProfile", [v[3] for v in vals])
    f.arr("zoneObjASProfile", [v[4] for v in vals])
    f.arr("zoneObjIntraZoneCom", [v[5] for v in vals])

    # interfaces
    ifs = fw["interfaces"]
    f.arr("iface_name", [x["name"] for x in ifs])
    f.arr("iface_comment", [x["comment"] for x in ifs])
    f.arr("iface_vlan_tag", [x["vlan"] for x in ifs])
    f.arr("iface_vlan_parent", [x["parent"] for x in ifs])
    f.arr("interface_Zone", [x["zone"] for x in ifs])
    f.arr("iface_static_ip", [x["ip"] for x in ifs])
    f.arr("iface_static_mask", [x["mask"] for x in ifs])
    f.arr("iface_https_mgmt", [x["https"] for x in ifs])
    f.arr("iface_ssh_mgmt", [x["ssh"] for x in ifs])

    # address objects: per-interface IP + subnet objects, defaults, customs
    addr = []
    groups = {"LAN Subnets": [], "WAN Interface IP": [],
              "All X0 Management IP": []}
    for x in ifs:
        if x["ip"] == "0.0.0.0":
            continue
        addr.append(host(f"{x['name']} IP", x["ip"]))
        addr.append(net(f"{x['name']} Subnet", x["ip"], x["mask"]))
        if x["zone"] == "LAN":
            groups["LAN Subnets"].append(f"{x['name']} Subnet")
            groups["All X0 Management IP"].append(f"{x['name']} IP")
        if x["zone"] == "WAN":
            groups["WAN Interface IP"].append(f"{x['name']} IP")
    x0 = ifs[0]
    addr.append(net("LAN Primary Subnet", x0["ip"], x0["mask"]))
    addr += [group(g) for g in groups]
    addr += fw["addr"]
    groups.update(fw["groups"])
    f.arr("addrObjId", [a[0] for a in addr])
    f.arr("addrObjIdDisp", [a[0] for a in addr])
    f.arr("addrObjType", [a[1] for a in addr])
    f.arr("addrObjIp1", [a[2] for a in addr])
    f.arr("addrObjIp2", [a[3] for a in addr])
    members = [(m, g) for g, ms in groups.items() for m in ms]
    f.arr("addro_atomToGrp", [m for m, _ in members])
    f.arr("addro_grpToGrp", [g for _, g in members])

    # services
    f.arr("svcObjId", [s[0] for s in SERVICES])
    f.arr("svcObjType", [s[1] for s in SERVICES])
    f.arr("svcObjIpType", [s[2] for s in SERVICES])
    f.arr("svcObjPort1", [s[3] for s in SERVICES])
    f.arr("svcObjPort2", [s[4] for s in SERVICES])
    smem = [(m, g) for g, ms in SERVICE_GROUPS.items() for m in ms]
    f.arr("so_atomToGrp", [m for m, _ in smem])
    f.arr("so_grpToGrp", [g for _, g in smem])

    # access rules
    rs = fw["rules"]
    f.arr("policyAction", [r["action"] for r in rs])
    f.arr("policyEnabled", [r["enabled"] for r in rs])
    f.arr("policySrcZone", [r["src_zone"] for r in rs])
    f.arr("policyDstZone", [r["dst_zone"] for r in rs])
    f.arr("policySrcNet", [r["src"] for r in rs])
    f.arr("policyDstNet", [r["dst"] for r in rs])
    f.arr("policyDstSvc", [r["svc"] for r in rs])
    f.arr("policyComment", [r["comment"] for r in rs])
    f.arr("policyName", [r["name"] for r in rs])
    f.arr("policyGeoIpBlock", [0 for _ in rs])

    # NAT policies
    ns = fw["nat"]
    f.arr("natPolicyEnabled", [1 for _ in ns])
    for key in ("name", "orig_src", "orig_dst", "orig_svc", "trans_src",
                "trans_dst", "trans_svc", "src_iface", "dst_iface", "comment"):
        camel = "natPolicy" + "".join(w.capitalize() for w in key.split("_"))
        f.arr(camel, [n[key] for n in ns])

    # users & groups
    f.arr("userGroupObjId", [g for g, _ in USER_GROUPS])
    f.arr("userGroupObjPrivMask", [m for _, m in USER_GROUPS])
    f.arr("userGroupOtpReq", [fw["otp"].get(g, 0) for g, _ in USER_GROUPS])
    us = fw["users"]
    f.arr("userObjId", [u[0] for u in us])
    f.arr("userObjPrivMask", [u[1] for u in us])
    f.arr("userObjComment", [u[2] for u in us])
    f.arr("userObjDisabled", [u[3] for u in us])
    f.arr("userObjVpnDestNet", [u[4] for u in us])
    f.arr("usero_atomToGrp", [m for m, _ in fw["membership"]])
    f.arr("usero_grpToGrp", [g for _, g in fw["membership"]])

    # content filter
    f["cfsCategoryStr"] = json.dumps({
        "timestamp": "20261001000000", "count": len(CATEGORIES),
        "language": "eng",
        "entries": [{str(i + 1): c} for i, c in enumerate(CATEGORIES)]})
    blocked = set(fw["cats"])
    f.arr("cfsProfileObjId", ["CFS Default Profile"])
    f.arr("cfsProfileUrlCategoryOpt",
          [",".join("1" if c in blocked else "0" for c in CATEGORIES)])
    f.arr("cfsProfileEnableSafeSearch", [1])
    f.arr("cfsProfileEnableHttpsFlting", [1])
    f.arr("cfsProfileForbiddenUrlsObj", [""])
    f.arr("cfsProfileAllowedUrlsObj", [""])

    # geo-IP: bit position = low byte of countryObjIndex, MSB-first bitmap
    f.arr("countryObjId", COUNTRIES)
    f.arr("countryObjIndex", [0x41230000 | (i + 1) for i in range(len(COUNTRIES))])
    bits = 0
    for i, c in enumerate(COUNTRIES):
        if c in fw["countries"]:
            bits |= 1 << (255 - (i + 1))
    g = fw["geo"]
    f.update({"geoInitBitmap": f"{bits:064X}", "geoEnforcement": str(g["enf"]),
              "geoEnforceBlockAll": str(g["block_all"]),
              "blockUnknownGeo": g["unknown"], "botnetBlock": str(g["botnet"]),
              "geoEnfBasedOnPolicy": str(g["policy"])})
    return f


def write_exp_zip(fw, flat, out_dir):
    body = "&".join(f"{k}={urllib.parse.quote(v, safe='')}"
                    for k, v in flat.items())
    b64 = base64.b64encode(body.encode("latin-1"))
    digest = hashlib.md5(b64).hexdigest()[:8]
    member = f"Default_{fw['serial']}_Oct_26_26_{digest}.exp"
    path = os.path.join(out_dir, f"{fw['name']}.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, b64)
    return path


def build_reports(paths):
    """Run the audit engine over the sample exports -> samples/reports/."""
    os.chdir(ROOT)                      # compliance_rules.json lives here
    sys.path.insert(0, ROOT)
    import sonicwall_compare as engine
    engine.setup_rules()
    with tempfile.TemporaryDirectory() as tmp:
        configs, errors = engine.process_paths(
            paths, decoded_dir=os.path.join(tmp, "decoded"),
            db_path=os.path.join(tmp, "sample.db"))
    if errors or len(configs) != len(paths):
        sys.exit(f"sample exports failed to parse: {errors}")
    os.makedirs(REPORT_DIR, exist_ok=True)
    for name, doc in engine.generate_reports(configs).items():
        with open(os.path.join(REPORT_DIR, name + ".html"), "w") as fh:
            fh.write(doc)
    return configs


def find_chrome():
    for c in (os.environ.get("CHROME"),
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              shutil.which("google-chrome"), shutil.which("chromium"),
              shutil.which("chromium-browser"), shutil.which("chrome")):
        if c and os.path.exists(c):
            return c
    return None


def screenshots(width=1400, max_height=2600):
    """Full-page PNG of each report via headless Chrome (optional step)."""
    chrome = find_chrome()
    if not chrome:
        print("Chrome not found — skipping screenshots (set CHROME=/path)")
        return
    os.makedirs(SHOT_DIR, exist_ok=True)
    base = [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
            "--hide-scrollbars", "--force-device-scale-factor=1"]
    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(os.listdir(REPORT_DIR)):
            if not name.endswith(".html"):
                continue
            src = os.path.join(REPORT_DIR, name)
            probe = os.path.join(tmp, name)
            with open(src) as fh, open(probe, "w") as out:
                out.write(fh.read() + "<script>document.title='H='+"
                          "document.documentElement.scrollHeight</script>")
            dom = subprocess.run(
                base + [f"--window-size={width},900", "--dump-dom",
                        "file://" + probe],
                capture_output=True, text=True).stdout
            h = 1800
            if "<title>H=" in dom:
                h = int(dom.split("<title>H=", 1)[1].split("<", 1)[0])
            h = max(600, min(h + 20, max_height))
            png = os.path.join(SHOT_DIR, name[:-5] + ".png")
            subprocess.run(base + [f"--window-size={width},{h}",
                                   f"--screenshot={png}", "file://" + src],
                           capture_output=True)
            print(f"  {png}  ({width}x{h})")


def main():
    os.makedirs(EXP_DIR, exist_ok=True)
    paths = []
    for fw in (hq(), downtown(), westside()):
        flat = build_flat(fw)
        if fw["name"] != "HQ-Main":          # DUO is detected by name only
            assert not any("duo" in v.lower() for v in flat.values()), fw["name"]
        p = write_exp_zip(fw, flat, EXP_DIR)
        print(f"wrote {p}  ({len(flat)} keys)")
        paths.append(p)
    configs = build_reports(paths)
    print(f"reports written to {REPORT_DIR}/ for "
          + ", ".join(c["fw_name"] for c in configs))
    if "--screenshots" in sys.argv:
        screenshots()


if __name__ == "__main__":
    main()
