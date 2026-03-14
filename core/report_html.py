"""
HTML Report Generator
Tạo báo cáo HTML đẹp, tự-chứa (không cần internet) cho từng scan session
"""
import os
import json
import datetime
from typing import List, Optional

from core.scanner import ThreatReport

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "reports"
)
os.makedirs(REPORTS_DIR, exist_ok=True)


VERDICT_BG = {
    "CLEAN":               "#0f2419",
    "POTENTIALLY_UNWANTED": "#2a1f00",
    "SUSPICIOUS":          "#2a1500",
    "MALICIOUS":           "#2a0a0a",
    "CRITICAL_THREAT":     "#1a0a2a",
}
VERDICT_FG = {
    "CLEAN":               "#3fb950",
    "POTENTIALLY_UNWANTED": "#d29922",
    "SUSPICIOUS":          "#f0883e",
    "MALICIOUS":           "#f85149",
    "CRITICAL_THREAT":     "#bc8cff",
}
LEVEL_FG = {
    "CRITICAL": "#f85149",
    "HIGH":     "#f0883e",
    "MEDIUM":   "#d29922",
    "LOW":      "#8b949e",
    "OK":       "#3fb950",
    "INFO":     "#8b949e",
}


def _score_bar(score: int, verdict: str) -> str:
    color = VERDICT_FG.get(verdict, "#8b949e")
    pct = min(score, 100)
    return f"""
    <div class="score-wrap">
      <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:{pct}%;background:{color}"></div>
      </div>
      <span class="score-num" style="color:{color}">{score}/100</span>
    </div>"""


def _badge(text: str, level: str) -> str:
    bg   = LEVEL_FG.get(level, "#8b949e") + "22"
    fg   = LEVEL_FG.get(level, "#8b949e")
    border = LEVEL_FG.get(level, "#8b949e") + "66"
    return (f'<span class="badge" style="background:{bg};color:{fg};'
            f'border:1px solid {border}">{text}</span>')


def _section_row(sec) -> str:
    color = "#f0883e" if sec.get("suspicious") else "#8b949e"
    reasons = "".join(
        f'<div class="reason">⚠ {r}</div>'
        for r in sec.get("reasons", [])
    )
    flags = " ".join(
        f'<span class="flag">{f}</span>' for f in sec.get("flags", [])
    )
    return f"""
    <tr class="{'row-warn' if sec.get('suspicious') else ''}">
      <td><code style="color:{color}">{sec.get('name','?')}</code></td>
      <td class="mono">{sec.get('entropy', 0):.3f}</td>
      <td class="mono">{sec.get('virtual_size', 0):,}</td>
      <td class="mono">{sec.get('raw_size', 0):,}</td>
      <td>{flags}</td>
      <td>{reasons}</td>
    </tr>"""


def _import_row(imp: dict) -> str:
    level = imp.get("level", "INFO")
    color = LEVEL_FG.get(level, "#8b949e")
    return (f'<tr>'
            f'<td>{_badge(level, level)}</td>'
            f'<td><code style="color:{color}">{imp.get("api","")}</code></td>'
            f'<td class="dim">{imp.get("reason","")}</td>'
            f'</tr>')


def _yara_row(m: dict) -> str:
    sev   = m.get("severity", "MEDIUM")
    color = LEVEL_FG.get(sev, "#8b949e")
    fam   = f' &nbsp;<span class="dim">family: {m["family"]}</span>' if m.get("family") else ""
    return (f'<tr>'
            f'<td>{_badge(sev, sev)}</td>'
            f'<td><code style="color:{color}">{m.get("rule","")}</code></td>'
            f'<td class="dim">{m.get("description","")}{fam}</td>'
            f'</tr>')


def _finding_row(f: dict) -> str:
    level = f.get("level", "INFO")
    color = LEVEL_FG.get(level, "#8b949e")
    pts   = f.get("points", 0)
    sign  = "+" if pts > 0 else ""
    return (f'<tr>'
            f'<td>{_badge(level, level)}</td>'
            f'<td style="color:{color};font-weight:500">{sign}{pts}</td>'
            f'<td class="dim">{f.get("description","")}</td>'
            f'</tr>')


def _vt_section(vt: Optional[dict]) -> str:
    if not vt:
        return ""
    if vt.get("error"):
        return f'<div class="card"><h3>VirusTotal</h3><p class="dim">{vt["error"]}</p></div>'

    det_rate = vt.get("detection_rate", 0)
    color    = "#f85149" if det_rate > 20 else ("#f0883e" if det_rate > 5 else "#3fb950")
    mal      = vt.get("malicious", 0)
    total    = vt.get("total_engines", 0)
    names    = vt.get("names", [])

    name_pills = "".join(
        f'<span class="name-pill">{n}</span>' for n in names[:8]
    )
    engines_html = ""
    for e in vt.get("engines", [])[:30]:
        cat = e.get("category", "")
        if cat == "malicious":
            engines_html += (
                f'<div class="eng-row eng-mal">'
                f'<span>{e["engine_name"]}</span>'
                f'<span class="eng-result">{e.get("result","")}</span>'
                f'</div>'
            )

    return f"""
    <div class="card">
      <h3>VirusTotal</h3>
      <div class="vt-stat">
        <span class="vt-big" style="color:{color}">{mal}/{total}</span>
        <span class="vt-label">engines detected&nbsp; — &nbsp;{det_rate}%</span>
        {"<span class='cached-badge'>CACHED</span>" if vt.get("cached") else ""}
      </div>
      {"<div class='name-pills'>"+name_pills+"</div>" if names else ""}
      {"<div class='engines-list'>"+engines_html+"</div>" if engines_html else ""}
      <div class="dim" style="margin-top:8px">
        First seen: {vt.get("first_seen","N/A")} &nbsp;·&nbsp;
        Last scan: {vt.get("last_seen","N/A")} &nbsp;·&nbsp;
        Type: {vt.get("file_type","N/A")}
      </div>
    </div>"""


CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #0d1117; color: #c9d1d9;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 13px; line-height: 1.6;
}
a { color: #58a6ff; text-decoration: none; }
h1 { font-size: 22px; font-weight: 600; color: #e6edf3; }
h2 { font-size: 16px; font-weight: 600; color: #58a6ff; margin-bottom: 12px; }
h3 { font-size: 13px; font-weight: 600; color: #8b949e;
     text-transform: uppercase; letter-spacing: .06em; margin-bottom: 10px; }
code { font-family: "Cascadia Code","Consolas",monospace; font-size: 12px; }
.mono { font-family: "Cascadia Code","Consolas",monospace; }
.dim  { color: #8b949e; }

/* Layout */
.page  { max-width: 1100px; margin: 0 auto; padding: 24px 20px 60px; }
.header { display:flex; align-items:center; justify-content:space-between;
          padding: 20px 24px; background: #161b22; border-radius: 10px;
          border: 1px solid #30363d; margin-bottom: 24px; }
.header-left h1 { margin-bottom: 4px; }
.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 14px; margin-bottom: 24px;
}
.card {
  background: #161b22; border: 1px solid #30363d; border-radius: 10px;
  padding: 18px 20px;
}
.file-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 10px;
  padding: 18px 20px; margin-bottom: 14px;
}
.file-card-header {
  display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 14px; cursor: pointer;
}
.verdict-pill {
  display: inline-block; padding: 3px 12px;
  border-radius: 20px; font-size: 11px; font-weight: 700;
  letter-spacing: .06em;
}
.hash-row  { color: #8b949e; font-size: 11px; margin-bottom: 3px; }
.hash-val  { color: #c9d1d9; font-family: monospace; word-break: break-all; }

/* Score bar */
.score-wrap  { display: flex; align-items: center; gap: 10px; }
.score-bar-bg {
  flex: 1; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden;
}
.score-bar-fill { height: 100%; border-radius: 4px;
  transition: width .4s ease; }
.score-num { font-weight: 700; font-size: 15px; min-width: 48px; text-align: right; }

/* Tables */
table  { width: 100%; border-collapse: collapse; }
thead tr { background: #21262d; }
th  { padding: 8px 10px; text-align: left; color: #8b949e;
      font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
      border-bottom: 1px solid #30363d; }
td  { padding: 7px 10px; border-bottom: 1px solid #21262d;
      vertical-align: top; }
tr:last-child td { border-bottom: none; }
.row-warn { background: #2a1500; }
.reason   { font-size: 11px; color: #f0883e; margin-top: 3px; }
.flag {
  display: inline-block; font-size: 10px; padding: 1px 5px;
  background: #21262d; border-radius: 3px; margin-right: 3px;
  color: #8b949e; font-family: monospace;
}

/* Badges */
.badge {
  display: inline-block; font-size: 10px; font-weight: 700;
  padding: 1px 7px; border-radius: 10px;
  letter-spacing: .04em; white-space: nowrap;
}

/* Strings */
.string-pill {
  display: inline-block; background: #21262d; border: 1px solid #30363d;
  border-radius: 4px; padding: 2px 8px; margin: 2px 3px;
  font-size: 11px; font-family: monospace; color: #d29922;
  word-break: break-all;
}

/* VT */
.vt-stat   { display: flex; align-items: baseline; gap: 12px; margin-bottom: 10px; }
.vt-big    { font-size: 30px; font-weight: 700; }
.vt-label  { color: #8b949e; font-size: 13px; }
.cached-badge {
  background: #21262d; color: #8b949e; font-size: 10px;
  padding: 1px 6px; border-radius: 3px;
}
.name-pills { margin-bottom: 8px; }
.name-pill {
  display: inline-block; background: #f8514922; border: 1px solid #f8514966;
  color: #f85149; font-size: 11px; padding: 2px 8px; border-radius: 10px;
  margin: 2px 3px;
}
.engines-list { max-height: 180px; overflow-y: auto;
  background: #0d1117; border-radius: 6px; padding: 4px 0; }
.eng-row {
  display: flex; justify-content: space-between;
  padding: 3px 10px; font-size: 11px;
}
.eng-mal { background: #2a0a0a; }
.eng-result { color: #f85149; font-family: monospace; }

/* Collapsible */
details > summary { cursor: pointer; list-style: none; }
details > summary::-webkit-details-marker { display: none; }
details[open] > summary { margin-bottom: 14px; }
.chevron { transition: transform .2s; display: inline-block; }
details[open] .chevron { transform: rotate(90deg); }

/* Summary stats */
.stat-num { font-size: 28px; font-weight: 700; color: #e6edf3; }
.stat-label { font-size: 11px; color: #8b949e; text-transform: uppercase;
              letter-spacing: .06em; margin-top: 2px; }

/* Section divider */
.section-title {
  font-size: 11px; font-weight: 700; color: #8b949e;
  text-transform: uppercase; letter-spacing: .08em;
  padding: 6px 0; margin: 18px 0 10px;
  border-bottom: 1px solid #21262d;
}

@media print {
  body { background: #fff; color: #000; }
  .card, .file-card { border: 1px solid #ccc; }
}
"""



def _export_row_html(exp_dict: dict) -> str:
    color = "#f0883e" if exp_dict.get("suspicious") else "#8b949e"
    name = exp_dict.get("name") or f"ord#{exp_dict.get('ordinal',0)}"
    return (f'<tr class="{"row-warn" if exp_dict.get("suspicious") else ""}">'
            f'<td><code style="color:{color}">{name}</code></td>'
            f'<td class="mono dim">{exp_dict.get("ordinal",0)}</td>'
            f'<td class="mono dim">0x{exp_dict.get("address",0):08X}</td>'
            f'<td class="dim">{exp_dict.get("reason","")}</td>'
            f'</tr>')


def _rich_header_html(entries: list) -> str:
    if not entries:
        return ""
    rows = "".join(
        f'<tr><td><code style="color:#58a6ff">{e.get("product","?")}</code></td>'
        f'<td class="dim">{e.get("description","")}</td></tr>'
        for e in entries[:8]
    )
    return f"""
    <div class="section-title">Rich Header (Compiler fingerprint)</div>
    <table>
      <thead><tr><th>Product / Compiler</th><th>Details</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


def _overlay_html(pe) -> str:
    if not pe.has_overlay:
        return ""
    color = "#f85149" if pe.overlay_entropy > 7.0 else "#f0883e"
    enc_note = " &mdash; <strong>ENCRYPTED/PACKED payload</strong>" if pe.overlay_entropy > 7.0 else ""
    return f"""
    <div class="card" style="border-color:{color}44;margin-bottom:12px">
      <h3 style="color:{color}">Overlay Data Detected</h3>
      <div style="display:flex;gap:24px;align-items:center">
        <div><div class="dim">Offset</div>
             <code style="color:{color}">0x{pe.overlay_offset:X}</code></div>
        <div><div class="dim">Size</div>
             <code style="color:{color}">{pe.overlay_size:,} bytes</code></div>
        <div><div class="dim">Entropy</div>
             <code style="color:{color}">{pe.overlay_entropy:.3f}</code>{enc_note}</div>
      </div>
    </div>"""


def _imphash_html(pe) -> str:
    if not pe.imphash:
        return ""
    return f'<div class="hash-row">ImpHash <span class="hash-val">{pe.imphash}</span></div>'


def _checksum_html(pe) -> str:
    if pe.checksum_stored == 0:
        return '<div class="dim" style="font-size:11px">Checksum: 0 (not set)</div>'
    if pe.checksum_valid:
        return (f'<div style="color:#3fb950;font-size:11px">'
                f'Checksum: 0x{pe.checksum_stored:08X} &#10003; valid</div>')
    return (f'<div style="color:#f0883e;font-size:11px">'
            f'Checksum: MISMATCH stored=0x{pe.checksum_stored:08X} '
            f'actual=0x{pe.checksum_actual:08X}</div>')


def generate_report(
    reports: List[ThreatReport],
    vt_results: Optional[dict] = None,
    output_path: Optional[str] = None,
) -> str:
    if output_path is None:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(REPORTS_DIR, f"report_{ts}.html")

    vt = vt_results or {}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total     = len(reports)
    clean     = sum(1 for r in reports if r.verdict == "CLEAN")
    sus       = sum(1 for r in reports if r.verdict == "SUSPICIOUS")
    mal       = sum(1 for r in reports if r.verdict in ("MALICIOUS", "CRITICAL_THREAT"))
    avg_score = int(sum(r.score for r in reports) / total) if total else 0

    overview = f"""
    <div class="summary-grid">
      <div class="card">
        <h3>Files quet</h3>
        <div class="stat-num">{total}</div>
        <div class="stat-label">total files analyzed</div>
      </div>
      <div class="card">
        <h3>Malicious</h3>
        <div class="stat-num" style="color:#f85149">{mal}</div>
        <div class="stat-label">malicious / critical</div>
      </div>
      <div class="card">
        <h3>Suspicious</h3>
        <div class="stat-num" style="color:#f0883e">{sus}</div>
        <div class="stat-label">needs review</div>
      </div>
      <div class="card">
        <h3>Average score</h3>
        <div class="stat-num">{avg_score}/100</div>
        <div class="stat-label">threat score</div>
      </div>
    </div>"""

    file_cards = ""
    for idx, report in enumerate(reports):
        pe   = report.pe_result
        vcol = VERDICT_FG.get(report.verdict, "#8b949e")
        vbg  = VERDICT_BG.get(report.verdict, "#161b22")
        fname = os.path.basename(report.filepath)

        sec_rows = "".join(
            _section_row({
                "name": s.name, "entropy": s.entropy,
                "virtual_size": s.virtual_size, "raw_size": s.raw_size,
                "suspicious": s.is_suspicious, "reasons": s.suspicion_reasons,
                "flags": s.flags,
            }) for s in pe.sections
        ) if pe.sections else "<tr><td colspan='6' class='dim'>N/A</td></tr>"

        imp_rows = "".join(
            _import_row(i) for i in pe.suspicious_imports[:30]
        ) if pe.suspicious_imports else "<tr><td colspan='3' class='dim'>Khong co API dang ngo</td></tr>"

        # Exports table (NEW)
        exp_rows = ""
        if pe.exports:
            exp_rows = "".join(
                _export_row_html({
                    "name": e.name, "ordinal": e.ordinal,
                    "address": e.address, "suspicious": e.is_suspicious,
                    "reason": e.reason,
                }) for e in pe.exports[:30]
            )
        else:
            exp_rows = "<tr><td colspan='4' class='dim'>Khong co exports</td></tr>"

        yara_rows = "".join(
            _yara_row({
                "severity": m.severity, "rule": m.rule_name,
                "description": m.description, "family": m.family,
            }) for m in report.yara_matches
        ) if report.yara_matches else "<tr><td colspan='3' class='dim'>Khong co YARA match</td></tr>"

        find_rows = "".join(
            _finding_row(f) for f in report.findings[:20]
        ) if report.findings else "<tr><td colspan='3' class='dim'>Khong co findings</td></tr>"

        # Strings (including new categories)
        strs_html = ""
        STRING_LABELS = {
            "ips": "IP Addresses", "domains": "Domains",
            "urls": "URLs", "emails": "Emails",
            "registry": "Registry Keys", "irc_commands": "IRC Commands",
            "base64": "Base64 Blobs", "base64_decoded": "Base64 Decoded (Suspicious)",
            "file_paths": "File Paths", "mutexes": "Mutexes (NEW)",
            "c2_indicators": "C2 / RAT Indicators (NEW)",
        }
        for key, vals in pe.suspicious_strings.items():
            if vals and key != "crypto_keys":
                label = STRING_LABELS.get(key, key.upper())
                color = "#f85149" if key in ("c2_indicators","irc_commands","base64_decoded") else "#d29922"
                pills = "".join(f'<span class="string-pill" style="color:{color}">{v[:90]}</span>' for v in vals[:8])
                strs_html += f'<div style="margin-bottom:10px"><div class="section-title">{label}</div>{pills}</div>'

        vt_entry = vt.get(pe.sha256.lower())
        vt_block = _vt_section(vt_entry) if vt_entry else ""

        # Rich Header (NEW)
        rich_html = ""
        if pe.rich_header:
            rich_html = _rich_header_html([
                {"product": e.product, "description": e.description}
                for e in pe.rich_header
            ])

        # PE info
        if pe.is_valid_pe:
            ep_color = "#f85149" if not pe.ep_in_code_section else "#3fb950"
            overlay_block = _overlay_html(pe)
            checksum_block = _checksum_html(pe)
            pe_info = f"""
            {overlay_block}
            <div class="summary-grid" style="margin-bottom:8px">
              <div>
                <div class="dim">Machine</div>
                <div>{pe.machine} ({pe.machine_type})</div>
              </div>
              <div>
                <div class="dim">Compiled</div>
                <div>{pe.timestamp_str}</div>
              </div>
              <div>
                <div class="dim">Compiler</div>
                <div style="color:#58a6ff">{pe.compiler_guess}</div>
              </div>
              <div>
                <div class="dim">Entry point</div>
                <div><code style="color:{ep_color}">0x{pe.entry_point:08X}</code>
                  &nbsp;<span class="dim">in_code={pe.ep_in_code_section}</span></div>
              </div>
              <div>
                <div class="dim">Subsystem</div>
                <div>{pe.subsystem}</div>
              </div>
              <div>
                <div class="dim">ImpHash</div>
                <div><code style="font-size:10px;color:#8b949e">{pe.imphash or 'N/A'}</code></div>
              </div>
              <div>
                <div class="dim">Compiler</div>
                <div>{pe.compiler_guess or 'Unknown'}</div>
              </div>
              <div>
                <div class="dim">Flags</div>
                <div>
                  {'<span class="flag">64-bit</span>' if pe.is_64bit else '<span class="flag">32-bit</span>'}
                  {'<span class="flag">DLL</span>' if pe.is_dll else ''}
                  {'<span class="flag" style="color:#f0883e">TLS</span>' if pe.has_tls else ''}
                  {'<span class="flag" style="color:#f85149">NO_IMPORTS</span>' if pe.no_import_table else ''}
                  {'<span class="flag" style="color:#3fb950">Signed</span>' if pe.has_signature else ''}
                </div>
              </div>
            </div>
            {checksum_block}"""
        else:
            pe_info = f'<div class="dim">Khong phai PE hop le: {pe.error}</div>'

        file_cards += f"""
        <div class="file-card" style="border-color:{vcol}44">
          <details open>
            <summary>
              <div class="file-card-header">
                <div>
                  <span class="chevron">&#9658;</span>
                  &nbsp;<strong style="font-size:14px;color:#e6edf3">{fname}</strong>
                  &nbsp;<span class="dim" style="font-size:11px">{pe.file_size:,} bytes</span>
                </div>
                <div style="display:flex;align-items:center;gap:12px">
                  <div style="width:150px">{_score_bar(report.score, report.verdict)}</div>
                  <span class="verdict-pill" style="background:{vbg};color:{vcol}">{report.verdict}</span>
                </div>
              </div>
            </summary>

            <div style="padding:4px 0 0 16px">
              <div class="section-title">Hashes</div>
              <div class="hash-row">MD5 &nbsp;&nbsp;&nbsp;<span class="hash-val">{pe.md5}</span></div>
              <div class="hash-row">SHA1 &nbsp;&nbsp;<span class="hash-val">{pe.sha1}</span></div>
              <div class="hash-row">SHA256 <span class="hash-val">{pe.sha256}</span></div>
              {_imphash_html(pe)}

              <div class="section-title">PE Header</div>
              {pe_info}

              {rich_html}

              {vt_block}

              <div class="section-title">Sections</div>
              <table>
                <thead><tr>
                  <th>Name</th><th>Entropy</th><th>Virt size</th>
                  <th>Raw size</th><th>Flags</th><th>Issues</th>
                </tr></thead>
                <tbody>{sec_rows}</tbody>
              </table>

              <div class="section-title">Suspicious imports</div>
              <table>
                <thead><tr><th>Level</th><th>API</th><th>Reason</th></tr></thead>
                <tbody>{imp_rows}</tbody>
              </table>

              <div class="section-title">Exports ({len(pe.exports)} total, {len(pe.suspicious_exports)} suspicious)</div>
              <table>
                <thead><tr><th>Name</th><th>Ordinal</th><th>Address</th><th>Notes</th></tr></thead>
                <tbody>{exp_rows}</tbody>
              </table>

              <div class="section-title">YARA matches</div>
              <table>
                <thead><tr><th>Severity</th><th>Rule</th><th>Description</th></tr></thead>
                <tbody>{yara_rows}</tbody>
              </table>

              <div class="section-title">Scoring breakdown</div>
              <table>
                <thead><tr><th>Level</th><th>Points</th><th>Finding</th></tr></thead>
                <tbody>{find_rows}</tbody>
              </table>

              {"<div class='section-title'>Suspicious strings</div>" + strs_html if strs_html else ""}
            </div>
          </details>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EXE Scanner v3 Report &mdash; {now}</title>
  <style>{CSS}</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div class="header-left">
      <h1>EXE Scanner <span style="font-size:13px;color:#8b949e">v3</span></h1>
      <div class="dim">Phan tich malware &amp; botnet &mdash; {now}</div>
    </div>
    <div style="text-align:right">
      <div class="dim" style="font-size:11px">PE Analysis + YARA + VirusTotal</div>
      <div class="dim" style="font-size:11px">{total} file(s) analyzed</div>
    </div>
  </div>

  <h2>Tong quan</h2>
  {overview}

  <h2>Chi tiet tung file</h2>
  {file_cards}

</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path
