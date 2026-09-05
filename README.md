# SonicWall EXP Comparison & Audit

Compares multiple SonicWall EXP config exports (same client) for **content
filtering**, **IPS/IDS**, **VLAN inter-communication**, and **management access
restrictions**, and produces colorized HTML reports.

## Web app (recommended)
```
python3 app.py
```
Opens a local web UI (http://127.0.0.1:8765, or the next free port if that
one is busy — the exact URL is printed):
- **Home** — analysis history, newest first, with search bar and processed
  dates. Click an analysis to reopen its reports; delete removes it.
- **New Analysis wizard** — name the analysis, drag & drop the EXP `.zip`
  files (10+ supported), click Process.
- **Report screen** — Differences shown first; left menu switches to
  Compliance, Findings, and **Remediation tickets**. Each ticket item lists the
  explicit offending rules / missing categories / missing countries, plus a
  plain-English **Why** and the **standard failing** (PCI DSS, NIST 800-53, CIS
  Controls, FFIEC), and a "Copy ticket text" button that copies the full
  per-firewall text (with Why + standard).

Each analysis is stored under `data/analyses/<id>/` (uploads, decoded configs,
SQLite DB, reports). Everything stays local.

## CLI (no web UI)
1. Drop each firewall's EXP download (`.zip`) into `input/`
2. Run:
   ```
   python3 sonicwall_compare.py
   ```
3. Open the reports in `output/`:
   - **compliance.html** — colorized rules **pass/fail** report: scorecard with
     per-firewall COMPLIANT/NON-COMPLIANT verdict, a rules × firewalls
     **compliance matrix** (green/red/orange/gray cells), per-firewall detail
     with evidence, the **IP groups** referenced in rules (name → member IPs),
     and cross-firewall **consistency exceptions**.
   - **differences.html** — what differs between the firewalls.
   - **findings.html** — risky/loose rules, open ports, content filter, geo.
   - **remediation.html** — per-firewall ticket-ready fix lists.

Compliance rules live in **`compliance_rules.json`** — edit it to change the
policy (trusted zone, SSH/management IP limits, required MFA, consistency, etc.)
without touching the code.

Everything runs locally. No data leaves this folder.

## Audit checklist (per firewall)
1. IPS/IDS enabled on LAN (required — global `isIDPEnabled` + LAN zone profile)
2. Content filtering enabled on LAN (required — global + LAN zone CFS profile)
3. SSH management enabled & limited to a single IP
4. External (WAN) management limited to 1–2 IPs
5. Internal management limited to 1–2 IPs
6. VPN authentication via AD/Entra + MFA (DUO)

## Report sections
**findings.html** (per firewall): checklist (traffic-light pills) · risk
findings · **Open ports & IP restrictions** (EXTERNAL from Internet + INTERNAL
firewall management, each row flagged green/orange/red) · VPN Authentication &
MFA · VPN & security licenses · Access INTO / FROM trusted LAN · **Content
filter blocked categories** · **Geo-IP blocked countries** · expected VLAN role
coverage.

**differences.html**: device summary (firewall names) · global flags · per-zone
CFS/IPS/intra-zone matrix · VLAN inventory · management posture · VPN auth ·
Security & VPN license counts · content-filter/Geo-IP comparison.

## Traffic-light coloring (open ports)
- **green** — restricted to 1–2 source IPs (compliant)
- **orange** — restricted but broad / named group / cleartext HTTP / expected
  VPN listener (IKE, SSL VPN)
- **red** — open to any source (non-compliant)

LAN is treated as the **Trusted** network. Firewalls are identified by their
configured name (`firewallName`, e.g. MainBranch / NorthBranch).

## Geo-IP country decode
The blocked-country list is decoded from the `geoInitBitmap` bitmap
(bit position = low byte of each country's `countryObjIndex`, MSB-first).
Validated against the block-unknown flag (Anonymous-Proxy / Other-Country bits
set) and the OFAC/high-risk cluster (China, Iran, N. Korea, Russia, Syria, …).
Spot-check against the firewall UI (Security Services → Geo-IP Filter).

## Files
- `sonicwall_compare.py` — main tool (parse → SQLite → reports)
- `exp_parser.py` — decodes SonicOS 7.x EXP (zip → base64 → `key=value`)
- `inspect_exp.py` — format detector (diagnostic only)
- `data/decoded/*.txt` — human-readable dump of each config
- `data/sonicwall.db` — SQLite of parsed zones / interfaces / mgmt rules

## Tuning
- Expected VLAN roles: `VLAN_ROLES` in `sonicwall_compare.py`
- Zones exempt from the content-filter check: `NON_CFS_ZONES`

## Notes / limitations
- Verified against SonicOS 7.3.3 (TZ 370). Other 7.x builds should work; if a
  future export fails, run `python3 inspect_exp.py` to re-check the format.
- Management "limited to 1–2 IPs" is evaluated from firewall **access rules**
  (`policyDstSvc = *Management`). Host/range/network source objects are resolved
  to exact IP counts; **address _groups_** are treated as "specific" but their
  member count isn't expanded yet — worth spot-checking named groups by hand.
