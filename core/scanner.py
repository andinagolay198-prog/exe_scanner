"""
Threat Scorer + YARA Scanner — v3
Tích hợp VirusTotal vào flow chính
"""
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from core.pe_parser        import PEAnalysisResult
from core.packer_detector  import analyze_packer
from core.disasm_analyzer  import analyze_disasm
from core.resource_analyzer import analyze_resources
from core.crack_profiler   import build_crack_profile

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")


@dataclass
class YaraMatch:
    rule_name: str
    category: str
    severity: str
    description: str
    family: str
    matched_strings: List[str] = field(default_factory=list)


def load_yara_rules() -> Optional[object]:
    if not YARA_AVAILABLE:
        return None
    try:
        yar_files = {}
        for fname in os.listdir(RULES_DIR):
            if fname.endswith(".yar"):
                key = fname.replace(".yar", "").replace("-", "_")
                yar_files[key] = os.path.join(RULES_DIR, fname)
        if not yar_files:
            return None
        return yara.compile(filepaths=yar_files)
    except Exception as e:
        print(f"YARA compile error: {e}")
        return None


def scan_yara(filepath: str, rules) -> List[YaraMatch]:
    if not YARA_AVAILABLE or rules is None:
        return []
    matches = []
    try:
        hits = rules.match(filepath, timeout=30)
        for m in hits:
            meta = m.meta
            matched_str_names = [str(s) for s in m.strings[:10]]
            matches.append(YaraMatch(
                rule_name=m.rule,
                category=meta.get("category", "unknown"),
                severity=meta.get("severity", "MEDIUM"),
                description=meta.get("description", ""),
                family=meta.get("family", ""),
                matched_strings=matched_str_names,
            ))
    except Exception:
        pass
    return matches


VERDICT_THRESHOLDS = {
    "CLEAN":               (0,  14),
    "POTENTIALLY_UNWANTED": (15, 29),
    "SUSPICIOUS":          (30, 59),
    "MALICIOUS":           (60, 84),
    "CRITICAL_THREAT":     (85, 999),
}

VERDICT_COLORS = {
    "CLEAN":               "#27ae60",
    "POTENTIALLY_UNWANTED": "#f39c12",
    "SUSPICIOUS":          "#e67e22",
    "MALICIOUS":           "#e74c3c",
    "CRITICAL_THREAT":     "#8e44ad",
}


@dataclass
class ThreatReport:
    filepath: str
    score: int = 0
    verdict: str = "CLEAN"
    verdict_color: str = "#27ae60"
    findings: List[Dict] = field(default_factory=list)
    yara_matches: List[YaraMatch] = field(default_factory=list)
    pe_result: Optional[PEAnalysisResult] = None
    vt_report: Optional[object] = None
    packer_result: Optional[Dict] = None
    disasm_result: Optional[Dict] = None
    resource_result: Optional[Dict] = None
    crack_profile: Optional[Dict] = None
    summary_lines: List[str] = field(default_factory=list)


class ThreatScorer:
    """Compute threat score từ PE analysis + YARA + VirusTotal."""

    def score(self, pe_result: PEAnalysisResult,
              yara_matches: List[YaraMatch],
              vt_report=None) -> ThreatReport:
        report = ThreatReport(filepath=pe_result.filepath,
                              pe_result=pe_result, vt_report=vt_report)
        total = 0
        findings = []

        def add(pts: int, level: str, desc: str):
            nonlocal total
            total += pts
            findings.append({"points": pts, "level": level, "description": desc})

        # ─── Chạy 4 module phân tích nâng cao ───
        packer_result   = None
        disasm_result   = None
        resource_result = None
        crack_profile   = None

        try:
            import pefile as _pefile
            with open(pe_result.filepath, "rb") as _f:
                _raw = _f.read()
            _pe  = _pefile.PE(data=_raw) if pe_result.is_valid_pe else None
        except Exception:
            _raw = b""
            _pe  = None

        if _raw:
            try:
                packer_result = analyze_packer(_raw, _pe)
            except Exception:
                pass
            try:
                if _pe:
                    disasm_result = analyze_disasm(_raw, _pe, pe_result.is_64bit)
            except Exception:
                pass
            try:
                if _pe:
                    resource_result = analyze_resources(_raw, _pe)
            except Exception:
                pass
            try:
                crack_profile = build_crack_profile(
                    packer_result or {}, disasm_result or {},
                    resource_result or {}, pe_result
                )
            except Exception:
                pass

        report.packer_result   = packer_result
        report.disasm_result   = disasm_result
        report.resource_result = resource_result
        report.crack_profile   = crack_profile

        if not pe_result.is_valid_pe:
            add(5, "INFO", f"Không phải PE hợp lệ: {pe_result.error}")
            report.findings = findings
            report.score = total
            report.verdict, report.verdict_color = self._verdict(total)
            return report

        # ─── VirusTotal scoring (ưu tiên cao nhất) ───
        if vt_report and vt_report.found:
            det = vt_report.malicious
            total_eng = vt_report.total_engines or 1
            rate = vt_report.detection_rate

            if det >= 20:
                add(50, "CRITICAL",
                    f"VirusTotal: {det}/{total_eng} engines detect ({rate:.1f}%) — {vt_report.threat_label or 'Malware'}")
            elif det >= 10:
                add(40, "CRITICAL",
                    f"VirusTotal: {det}/{total_eng} engines detect ({rate:.1f}%) — {vt_report.threat_label or 'Malware'}")
            elif det >= 5:
                add(30, "HIGH",
                    f"VirusTotal: {det}/{total_eng} engines detect ({rate:.1f}%)")
            elif det >= 2:
                add(20, "HIGH",
                    f"VirusTotal: {det}/{total_eng} engines detect ({rate:.1f}%)")
            elif det == 1:
                add(10, "MEDIUM",
                    f"VirusTotal: 1/{total_eng} engine detect — {vt_report.names[0] if vt_report.names else 'unknown'}")
            elif vt_report.suspicious > 0:
                add(8, "MEDIUM",
                    f"VirusTotal: {vt_report.suspicious} engine(s) mark suspicious")

            if vt_report.names:
                findings[-1]["description"] += f" | Names: {', '.join(vt_report.names[:3])}"

        # ─── PE-based scoring ───
        for ind in pe_result.risk_indicators:
            add(ind["points"], ind["level"], ind["description"])

        api_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for si in pe_result.suspicious_imports:
            api_counts[si["level"]] += 1

        if api_counts["CRITICAL"] > 0:
            add(min(api_counts["CRITICAL"] * 12, 36), "CRITICAL",
                f"{api_counts['CRITICAL']} critical suspicious API(s) imported")
        if api_counts["HIGH"] > 0:
            add(min(api_counts["HIGH"] * 7, 28), "HIGH",
                f"{api_counts['HIGH']} high-risk API(s) imported")
        if api_counts["MEDIUM"] > 0:
            add(min(api_counts["MEDIUM"] * 3, 15), "MEDIUM",
                f"{api_counts['MEDIUM']} medium-risk API(s) imported")

        # Entropy
        for sec in pe_result.sections:
            if sec.entropy > 7.2:
                add(18, "HIGH",
                    f"Section '{sec.name}': entropy {sec.entropy:.2f} (>7.2 – encrypted/packed)")
            elif sec.entropy > 6.5:
                add(10, "MEDIUM",
                    f"Section '{sec.name}': entropy {sec.entropy:.2f} (6.5–7.2 – compressed?)")

        # ─── YARA scoring ───
        severity_scores = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
        for m in yara_matches:
            pts = severity_scores.get(m.severity, 10)
            add(pts, m.severity, f"YARA [{m.rule_name}]: {m.description or m.category}")

        # ─── Module scoring ───
        for mod_result in [packer_result, disasm_result, resource_result, crack_profile]:
            if mod_result:
                for ind in mod_result.get("indicators", []):
                    add(ind["points"], ind["level"], ind["description"])

        total = min(total, 100)
        report.score = total
        report.findings = sorted(findings, key=lambda x: x["points"], reverse=True)
        report.yara_matches = yara_matches
        report.verdict, report.verdict_color = self._verdict(total)
        report.summary_lines = self._build_summary(pe_result, yara_matches, vt_report, total)
        return report

    def _verdict(self, score: int):
        for verdict, (lo, hi) in VERDICT_THRESHOLDS.items():
            if lo <= score <= hi:
                return verdict, VERDICT_COLORS[verdict]
        return "CRITICAL_THREAT", VERDICT_COLORS["CRITICAL_THREAT"]

    def _build_summary(self, pe, yara_matches, vt_report, score) -> List[str]:
        lines = []
        if vt_report and vt_report.found and vt_report.malicious > 0:
            lines.append(f"VT: {vt_report.malicious}/{vt_report.total_engines} detections")
        if not pe.ep_in_code_section:
            lines.append("Entry point nằm ngoài .text (packed/dropper)")
        if pe.no_import_table:
            lines.append("Không có Import Table (dynamic resolution)")
        if pe.has_tls:
            lines.append("Có TLS callbacks (code có thể chạy trước EP)")
        if pe.has_overlay:
            lines.append(f"Overlay {pe.overlay_size//1024}KB (entropy {pe.overlay_entropy:.2f})")
        irc = pe.suspicious_strings.get("irc_commands", [])
        if irc:
            lines.append(f"IRC botnet commands: {', '.join(irc[:3])}")
        for m in yara_matches[:5]:
            lines.append(f"YARA: {m.rule_name} [{m.severity}]")
        packed = [s for s in pe.sections if s.entropy > 6.5]
        if packed:
            lines.append(f"{len(packed)} section(s) có entropy cao (packed/encrypted)")
        return lines
