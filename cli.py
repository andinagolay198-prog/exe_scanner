"""
EXE Scanner CLI — v3
Thêm: --vt-key, --vt-upload, hiển thị Overlay / ImpHash / Exports / Mutex / B64 decoded
"""
import os
import sys
import argparse
import datetime
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.pe_parser import PEParser
from core.scanner  import ThreatScorer, load_yara_rules, scan_yara
from core.logger   import ScanLogger
from core.report_html import generate_report
from core.virustotal  import VTClient

# ─── ANSI Colors ──────────────────────────────────────────────
R     = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
FG_INFO    = "\033[38;5;245m"
FG_OK      = "\033[38;5;71m"
FG_SECTION = "\033[38;5;75m"
FG_WARN    = "\033[38;5;178m"
FG_HIGH    = "\033[38;5;208m"
FG_CRIT    = "\033[38;5;196m"
FG_PURPLE  = "\033[38;5;135m"

LEVEL_COLOR = {
    "INFO":     FG_INFO,
    "OK":       FG_OK,
    "SECTION":  FG_SECTION + BOLD,
    "WARN":     FG_WARN,
    "HIGH":     FG_HIGH,
    "CRITICAL": FG_CRIT + BOLD,
}
VERDICT_COLOR = {
    "CLEAN":               FG_OK,
    "POTENTIALLY_UNWANTED": FG_WARN,
    "SUSPICIOUS":          FG_HIGH,
    "MALICIOUS":           FG_CRIT,
    "CRITICAL_THREAT":     FG_PURPLE + BOLD,
}


def c(text, color): return color + str(text) + R


def banner():
    print()
    print(c("  ╔══════════════════════════════════════════╗", FG_SECTION))
    print(c("  ║  ", FG_SECTION) + c("EXE Scanner v3 — Malware & Botnet Detector", BOLD + FG_SECTION) + c("  ║", FG_SECTION))
    print(c("  ╚══════════════════════════════════════════╝", FG_SECTION))
    print()


def log(msg, level="INFO"):
    color = LEVEL_COLOR.get(level, FG_INFO)
    prefix = {"SECTION": ">>>", "CRITICAL": "[!!!]", "HIGH": "[!! ]",
               "WARN": "[ ! ]", "OK": "[OK ]", "INFO": "    "}.get(level, "    ")
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{c(ts, DIM)} {c(prefix, color)} {c(msg, color)}")


def scan_file(filepath, parser, scorer, yara_rules, logger, verbose=True,
              vt_client=None, vt_upload=False):
    fname = os.path.basename(filepath)
    log("─" * 62, "SECTION")
    log(f"Bắt đầu quét: {fname}", "SECTION")
    log(f"Path: {filepath}", "INFO")

    pe_result = parser.analyze(filepath)
    logger.new_session(fname[:20].replace(" ", "_"))

    if not pe_result.is_valid_pe:
        log(f"Không phải PE: {pe_result.error}", "WARN")
    else:
        log(f"[PE OK] {pe_result.machine_type} | {pe_result.subsystem}", "OK")
        log(f"Compiled  : {pe_result.timestamp_str}", "INFO")
        log(f"Compiler  : {pe_result.compiler_guess or 'N/A'}", "INFO")
        log(f"MD5       : {pe_result.md5}", "INFO")
        log(f"SHA256    : {pe_result.sha256}", "INFO")
        log(f"ImpHash   : {pe_result.imphash or 'N/A'}", "INFO")
        log(f"EP        : 0x{pe_result.entry_point:08X}  in_code={pe_result.ep_in_code_section}", "INFO")

        if pe_result.has_overlay:
            log(f"Overlay   : {pe_result.overlay_size:,} bytes @ 0x{pe_result.overlay_offset:X} "
                f"(entropy={pe_result.overlay_entropy:.2f})",
                "HIGH" if pe_result.overlay_entropy > 7.0 else "WARN")

        if verbose:
            log("[SECTIONS]", "SECTION")
            for s in pe_result.sections:
                tag = "WARN" if s.is_suspicious else "INFO"
                print(f"       {'⚠' if s.is_suspicious else ' '} "
                      f"{c(s.name, FG_WARN if s.is_suspicious else FG_INFO):<14}"
                      f"  entr={c(f'{s.entropy:.3f}', FG_CRIT if s.entropy>7 else (FG_WARN if s.entropy>6.5 else FG_OK))}"
                      f"  virt={s.virtual_size:<8,}  raw={s.raw_size:,}")
                for r in s.suspicion_reasons:
                    print(f"         {c('=> ' + r, FG_HIGH)}")

            if pe_result.exports:
                log(f"[EXPORTS] {len(pe_result.exports)} function(s)"
                    + (f" — DLL: {pe_result.export_dll_name}" if pe_result.export_dll_name else ""),
                    "SECTION")
                for exp in pe_result.suspicious_exports[:10]:
                    print(f"       {c('[SUSPICIOUS]', FG_HIGH):<22} {c(exp.name, FG_WARN)}  {c(exp.suspicion_reason, DIM)}")

            if pe_result.suspicious_imports:
                log("[SUSPICIOUS IMPORTS]", "SECTION")
                for si in pe_result.suspicious_imports[:20]:
                    lvl = si["level"]
                    col = FG_CRIT if lvl == "CRITICAL" else (FG_HIGH if lvl == "HIGH" else FG_WARN)
                    print(f"       {c('['+lvl+']', col):<22} {c(si['api'], col):<30}  {c(si['reason'], DIM)}")

            strs = pe_result.suspicious_strings
            # Mutex
            if strs.get("mutexes"):
                log("[MUTEXES]", "SECTION")
                for v in strs["mutexes"][:5]:
                    col = FG_CRIT if "[KNOWN_MALWARE]" in v else FG_WARN
                    print(f"       {c(v[:100], col)}")

            # B64 decoded IOCs
            for cat in ("decoded_b64_url", "decoded_b64_ip", "decoded_b64_command", "decoded_b64_path"):
                if strs.get(cat):
                    log(f"[BASE64 DECODED: {cat.upper().replace('DECODED_B64_','')}]", "SECTION")
                    for v in strs[cat][:5]:
                        print(f"       {c(v[:100], FG_CRIT)}")

            # Crypto keys
            if strs.get("crypto_keys"):
                log(f"[CRYPTO KEYS] {len(strs['crypto_keys'])} possible hardcoded key(s)", "SECTION")
                for v in strs["crypto_keys"][:3]:
                    print(f"       {c(v[:64], FG_WARN)}...")

            # Other strings
            for key in ("ips", "urls", "domains", "emails", "irc_commands",
                        "registry", "base64", "file_paths"):
                vals = strs.get(key, [])
                if vals:
                    log(f"[STRINGS: {key.upper()}]", "SECTION")
                    for v in vals[:5]:
                        print(f"       {c(v[:100], FG_WARN)}")

    # YARA
    log("[YARA SCAN]", "SECTION")
    yara_matches = []
    if yara_rules:
        yara_matches = scan_yara(filepath, yara_rules)
        if yara_matches:
            for m in yara_matches:
                col = FG_CRIT if m.severity == "CRITICAL" else (FG_HIGH if m.severity == "HIGH" else FG_WARN)
                print(f"       {c('['+m.severity+']', col):<22} {c(m.rule_name, col)}")
                if m.description and verbose:
                    print(f"         {c(m.description, DIM)}")
                if m.family:
                    print(f"         {c('Family: ' + m.family, FG_WARN)}")
        else:
            log("Không có YARA match", "OK")
    else:
        log("YARA không khả dụng (pip install yara-python)", "WARN")

    # VirusTotal (chạy trước scorer để VT score được tính vào)
    vt_report = None
    if vt_client and pe_result.sha256:
        log("[VIRUSTOTAL]", "SECTION")
        try:
            if vt_upload:
                log(f"Uploading {fname} lên VirusTotal...", "INFO")
                vt_report = vt_client.upload_file(
                    filepath,
                    progress_cb=lambda msg: log(msg, "INFO")
                )
            else:
                log("Tra cứu hash trên VirusTotal...", "INFO")
                vt_report = vt_client.lookup_hash(pe_result.sha256)
            if vt_report.error:
                log(f"VT: {vt_report.error}", "WARN")
            elif vt_report.found:
                det  = vt_report.malicious
                tot  = vt_report.total_engines
                rate = vt_report.detection_rate
                log(f"VT Detection: {det}/{tot} ({rate:.1f}%)",
                    "CRITICAL" if det >= 5 else ("HIGH" if det >= 2 else "WARN"))
                if vt_report.threat_label:
                    print(f"         {c('Threat: ' + vt_report.threat_label, FG_CRIT)}")
                if vt_report.names:
                    print(f"         {c('Names: ' + ', '.join(vt_report.names[:5]), FG_WARN)}")
                if vt_report.first_seen:
                    print(f"         {c('First seen: ' + vt_report.first_seen, DIM)}")
                if vt_report.cached:
                    print(f"         {c('(từ cache)', DIM)}")
            else:
                log("Hash không có trong VT database", "INFO")
        except Exception as e:
            log(f"VT error: {e}", "WARN")

    # Chạy scorer TRƯỚC khi hiển thị packer/disasm/resource
    report = scorer.score(pe_result, yara_matches, vt_report)

    # ─── Packer / Protector ───
    if report.packer_result:
        pr = report.packer_result
        if pr.get('packers'):
            log('[PACKER DETECTED]', 'SECTION')
            for p in pr['packers']:
                col = 'CRITICAL' if p['severity']=='CRITICAL' else 'HIGH'
                print(f"       {c('['+p['severity']+']', FG_CRIT if col=='CRITICAL' else FG_HIGH):<22} {c(p['name'], FG_WARN)} ({p['type']}) @ offset 0x{p['offset']:X}")
        if pr.get('anti_crack') and verbose:
            log(f"[ANTI-ANALYSIS] {len(pr['anti_crack'])} technique(s)", 'SECTION')
            for a in pr['anti_crack'][:8]:
                print(f"       {c(a['desc'], FG_WARN)}")
        if pr.get('license_strings') and verbose:
            log('[LICENSE STRINGS]', 'SECTION')
            for l in pr['license_strings'][:6]:
                print(f"       {c(l['desc'], FG_HIGH)}: {c(l['sample'][:80], DIM)}")

    # ─── Disassembly EP ───
    if report.disasm_result:
        dr = report.disasm_result
        if dr.get('stub_findings'):
            log('[EP DISASM — STUB DETECTED]', 'SECTION')
            for sf in dr['stub_findings']:
                col = FG_CRIT if sf['severity']=='HIGH' else FG_WARN
                print(f"       {c('['+sf['severity']+']', col):<22} {c(sf['name'], col)}")
                print(f"         {c(sf['desc'], DIM)}")
        if dr.get('byte_findings') and verbose:
            log('[SPECIAL BYTES]', 'SECTION')
            for bf in dr['byte_findings'][:6]:
                print(f"       {c('0x'+bf['bytes'], FG_WARN):<20} {c(bf['desc'], FG_WARN)} (x{bf['count']})")
        if verbose and dr.get('ep_text'):
            log('[EP DISASSEMBLY — first 20 insns]', 'SECTION')
            for line in dr['ep_text'][:20]:
                print(f"  {c(line, DIM)}")

    # ─── Resource analysis ───
    if report.resource_result:
        rr = report.resource_result
        if rr.get('embedded_files'):
            log('[EMBEDDED FILES IN RESOURCE]', 'SECTION')
            for emb in rr['embedded_files']:
                col = FG_CRIT if emb['severity']=='CRITICAL' else FG_HIGH
                print(f"       {c('['+emb['severity']+']', col):<22} {c(emb['type'], col)} — {emb['size_kb']:.0f}KB — entropy {emb['entropy']:.2f}")
        elif verbose and rr.get('resources'):
            sus = [r for r in rr['resources'] if r['is_suspicious']]
            if sus:
                log(f"[SUSPICIOUS RESOURCES] {len(sus)}", 'SECTION')
                for res in sus[:5]:
                    print(f"       {c(res['type']+'/'+res['name'], FG_WARN):<25} {res['size_kb']:.0f}KB entropy={res['entropy']:.2f}")
                    for reason in res['suspicion_reasons'][:2]:
                        print(f"         {c('=> '+reason, FG_HIGH)}")

    # ─── Crack Profile ───
    if report.crack_profile and report.crack_profile.get('techniques'):
        cp = report.crack_profile
        log('[CRACK PROFILE]', 'SECTION')
        for profile in cp['profiles']:
            print(f"       {c('[TECHNIQUE]', FG_CRIT)} {c(profile['name'], FG_CRIT)}")
            print(f"         {c(profile['description'], DIM)}")
        print()
        log('[KHUYẾN NGHỊ BẢO VỆ]', 'SECTION')
        for rec in cp['recommendations'][:8]:
            pri = '⚡' if rec['priority']==1 else ('●' if rec['priority']==2 else '○')
            print(f"       {c(pri, FG_OK)} {c(rec['counter'], FG_OK)}")
            print(f"         {c('Chống: '+rec['against'], DIM)}")
        print()

    # Score & Verdict
    vcol = VERDICT_COLOR.get(report.verdict, FG_INFO)
    print()
    print(c(f"  ┌────────────────────────────────────────────┐", vcol))
    print(c(f"  │  SCORE: {report.score:>3}/100   VERDICT: {report.verdict:<24}│", vcol))
    print(c(f"  └────────────────────────────────────────────┘", vcol))
    print()

    if verbose:
        for f in report.findings[:12]:
            col = FG_CRIT if f["level"] == "CRITICAL" else (FG_HIGH if f["level"] == "HIGH" else FG_WARN)
            print(f"       {c('['+f['level']+']', col):<22}  +{f['points']:>2}  {c(f['description'], DIM)}")
        print()

    logger.log_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(prog="cli.py", description="EXE Scanner v3 — CLI mode")
    parser.add_argument("targets", nargs="*", help="File(s) hoặc folder(s) cần quét")
    parser.add_argument("-f", "--file",       help="Quét file cụ thể")
    parser.add_argument("-d", "--dir",        help="Quét toàn bộ folder (đệ quy)")
    parser.add_argument("-o", "--output",     help="Xuất báo cáo HTML sang file chỉ định")
    parser.add_argument("-j", "--json",       help="Xuất summary JSON sang file chỉ định")
    parser.add_argument("-q", "--quiet",      action="store_true", help="Chỉ hiển thị verdict")
    parser.add_argument("--min-score",        type=int, default=0, help="Chỉ in file có score >= N")
    parser.add_argument("--verdict",          help="Lọc theo verdict")
    parser.add_argument("--vt-key",           help="VirusTotal API key (tra hash)")
    parser.add_argument("--vt-upload",        action="store_true",
                        help="Upload file lên VT nếu hash chưa có (cần --vt-key)")
    args = parser.parse_args()

    banner()

    files = []
    EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".pif"}

    def add_path(p):
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for root_, _, fnames in os.walk(p):
                for fn in fnames:
                    if os.path.splitext(fn)[1].lower() in EXTS:
                        files.append(os.path.join(root_, fn))

    for t in args.targets:
        add_path(t)
    if args.file:   add_path(args.file)
    if args.dir:    add_path(args.dir)

    if not files:
        print(c("Không có file nào. Dùng: python cli.py <file.exe>", FG_WARN))
        print(c("  --vt-key <KEY>      Tra cứu VirusTotal", FG_INFO))
        print(c("  --vt-upload         Upload nếu hash chưa có trên VT", FG_INFO))
        sys.exit(1)

    log(f"Tổng số file: {len(files)}", "INFO")

    # YARA
    log("Đang load YARA rules...", "INFO")
    yara_rules = load_yara_rules()
    log("YARA OK" if yara_rules else "YARA không khả dụng", "OK" if yara_rules else "WARN")

    # VT client
    vt_client = None
    if args.vt_key:
        vt_client = VTClient(args.vt_key)
        log("VirusTotal: OK (hash lookup mode)", "OK")
        if args.vt_upload:
            log("VT Upload mode: bật", "WARN")

    pe_parser = PEParser()
    scorer    = ThreatScorer()
    logger    = ScanLogger()
    reports   = []

    for i, fpath in enumerate(files, 1):
        print(c(f"\n[{i}/{len(files)}]", FG_SECTION + BOLD))
        report = scan_file(fpath, pe_parser, scorer, yara_rules, logger,
                           verbose=not args.quiet,
                           vt_client=vt_client,
                           vt_upload=args.vt_upload)
        reports.append(report)

    # Summary
    print()
    print(c("═" * 62, FG_SECTION))
    print(c("  SUMMARY", BOLD))
    print(c("═" * 62, FG_SECTION))
    for verdict in ("CRITICAL_THREAT", "MALICIOUS", "SUSPICIOUS", "POTENTIALLY_UNWANTED", "CLEAN"):
        subset = [r for r in reports if r.verdict == verdict]
        if subset:
            col = VERDICT_COLOR.get(verdict, FG_INFO)
            print(f"  {c(verdict, col):<40} {c(str(len(subset)), BOLD)}")

    print()
    print(f"  Total files : {c(str(len(reports)), BOLD)}")
    high_risk = [r for r in reports if r.verdict in ("MALICIOUS", "CRITICAL_THREAT")]
    if high_risk:
        print(c(f"  High-risk   : {len(high_risk)} file(s) — kiểm tra báo cáo HTML", FG_CRIT + BOLD))
    print()

    filtered = [r for r in reports
                if r.score >= args.min_score
                and (not args.verdict or r.verdict == args.verdict.upper())]
    if filtered:
        print(c("  Files khớp điều kiện lọc:", FG_SECTION))
        for r in sorted(filtered, key=lambda x: x.score, reverse=True):
            col = VERDICT_COLOR.get(r.verdict, FG_INFO)
            print(f"  {c(r.score, col):>3}/100  {c(r.verdict, col):<22}  {c(os.path.basename(r.filepath), DIM)}")
        print()

    # HTML report
    out = args.output
    try:
        path = generate_report(reports, output_path=out)
        log(f"Báo cáo HTML: {path}", "OK")
    except Exception as e:
        log(f"Lỗi tạo report HTML: {e}", "WARN")

    # JSON
    if args.json:
        summary = []
        for r in reports:
            entry = {
                "file":    os.path.basename(r.filepath),
                "score":   r.score,
                "verdict": r.verdict,
                "yara":    [m.rule_name for m in r.yara_matches],
                "md5":     r.pe_result.md5,
                "sha256":  r.pe_result.sha256,
                "imphash": r.pe_result.imphash,
            }
            if r.vt_report and r.vt_report.found:
                entry["vt_detections"] = r.vt_report.malicious
                entry["vt_total"]      = r.vt_report.total_engines
                entry["vt_names"]      = r.vt_report.names
            summary.append(entry)
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            log(f"JSON output: {args.json}", "OK")
        except Exception as e:
            log(f"Lỗi ghi JSON: {e}", "WARN")

    if any(r.verdict in ("MALICIOUS", "CRITICAL_THREAT") for r in reports):
        sys.exit(2)
    if any(r.verdict == "SUSPICIOUS" for r in reports):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
