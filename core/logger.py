"""
Logger Module — Ghi log cấu trúc JSON + text dễ đọc
"""
import os
import json
import datetime
import threading
from typing import Optional, Callable

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _fname() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


class ScanLogger:
    """Thread-safe logger with callbacks for live terminal output."""

    def __init__(self, on_message: Optional[Callable[[str, str], None]] = None):
        """
        on_message(text, level): callback for real-time GUI output.
        level: 'INFO' | 'OK' | 'WARN' | 'HIGH' | 'CRITICAL' | 'SECTION'
        """
        self._lock = threading.Lock()
        self._on_message = on_message
        self._session_log: list = []
        self._text_log_path: Optional[str] = None
        self._json_log_path: Optional[str] = None

    # ─── public API ───────────────────────────────────────────────

    def new_session(self, label: str = "scan"):
        ts = _fname()
        base = os.path.join(LOGS_DIR, f"{ts}_{label}")
        self._text_log_path = base + ".txt"
        self._json_log_path = base + ".json"
        self._session_log = []
        self._write_text(f"{'='*70}\n  EXE SCANNER — Session bắt đầu lúc {_ts()}\n{'='*70}\n")

    def info(self, msg: str):      self._log(msg, "INFO")
    def ok(self, msg: str):        self._log(msg, "OK")
    def warn(self, msg: str):      self._log(msg, "WARN")
    def high(self, msg: str):      self._log(msg, "HIGH")
    def critical(self, msg: str):  self._log(msg, "CRITICAL")
    def section(self, msg: str):   self._log(msg, "SECTION")

    def log_report(self, report, include_details: bool = True):
        from core.scanner import ThreatReport
        pe = report.pe_result

        self.section(f"FILE: {os.path.basename(report.filepath)}")
        self.info(f"Path    : {report.filepath}")
        self.info(f"Size    : {pe.file_size:,} bytes")
        self.info(f"MD5     : {pe.md5}")
        self.info(f"SHA256  : {pe.sha256}")

        if pe.is_valid_pe:
            self.info(f"Machine : {pe.machine} ({pe.machine_type})")
            self.info(f"Compiled: {pe.timestamp_str}")
            self.info(f"EP      : 0x{pe.entry_point:08X}  in_code={pe.ep_in_code_section}")
            self.info(f"Subsys  : {pe.subsystem}")

            # Sections
            self.section("  [SECTIONS]")
            for s in pe.sections:
                flag = "SUSPICIOUS" if s.is_suspicious else "ok"
                line = f"  {s.name:<12} virt={s.virtual_size:<8,} raw={s.raw_size:<8,} entropy={s.entropy:.3f}  [{flag}]"
                if s.is_suspicious:
                    self.warn(line)
                    for r in s.suspicion_reasons:
                        self.warn(f"    => {r}")
                else:
                    self.info(line)

            # Imports
            if pe.suspicious_imports:
                self.section("  [SUSPICIOUS IMPORTS]")
                for si in pe.suspicious_imports:
                    msg = f"  [{si['level']:<8}] {si['api']:<35} — {si['reason']}"
                    if si["level"] == "CRITICAL":
                        self.critical(msg)
                    elif si["level"] == "HIGH":
                        self.high(msg)
                    else:
                        self.warn(msg)

            # YARA
            if report.yara_matches:
                self.section("  [YARA MATCHES]")
                for m in report.yara_matches:
                    msg = f"  [{m.severity:<8}] {m.rule_name:<40} {m.description}"
                    if m.severity == "CRITICAL":
                        self.critical(msg)
                    elif m.severity == "HIGH":
                        self.high(msg)
                    else:
                        self.warn(msg)

            # Key strings
            for key, vals in pe.suspicious_strings.items():
                if vals:
                    self.section(f"  [STRINGS:{key.upper()}]")
                    for v in vals[:8]:
                        self.info(f"    {v}")

        # Verdict
        self.section(f"  SCORE: {report.score}/100  |  VERDICT: {report.verdict}")
        for f in report.findings[:10]:
            line = f"  [{f['level']:<8}] +{f['points']:>2} — {f['description']}"
            lvl = f["level"]
            if lvl == "CRITICAL":   self.critical(line)
            elif lvl == "HIGH":     self.high(line)
            elif lvl == "MEDIUM":   self.warn(line)
            else:                   self.info(line)

        # Save JSON
        self._save_json(report)

    def flush(self):
        """Ensure everything is written."""
        pass  # writes are immediate

    # ─── internals ────────────────────────────────────────────────

    def _log(self, msg: str, level: str):
        ts = _ts()
        entry = {"ts": ts, "level": level, "msg": msg}
        with self._lock:
            self._session_log.append(entry)
            line = f"[{ts}] [{level:<8}] {msg}"
            self._write_text(line + "\n")
        if self._on_message:
            self._on_message(msg, level)

    def _write_text(self, text: str):
        if self._text_log_path:
            try:
                with open(self._text_log_path, "a", encoding="utf-8") as f:
                    f.write(text)
            except Exception:
                pass

    def _save_json(self, report):
        if not self._json_log_path:
            return
        try:
            pe = report.pe_result
            data = {
                "timestamp": _ts(),
                "filepath": report.filepath,
                "score": report.score,
                "verdict": report.verdict,
                "hashes": {"md5": pe.md5, "sha1": pe.sha1, "sha256": pe.sha256},
                "pe_info": {
                    "valid": pe.is_valid_pe,
                    "machine": pe.machine_type,
                    "timestamp": pe.timestamp_str,
                    "entry_point": hex(pe.entry_point) if pe.is_valid_pe else "N/A",
                    "ep_in_text": pe.ep_in_code_section,
                    "subsystem": pe.subsystem,
                    "is_64bit": pe.is_64bit,
                    "has_tls": pe.has_tls,
                    "no_imports": pe.no_import_table,
                } if pe.is_valid_pe else {},
                "sections": [
                    {
                        "name": s.name,
                        "entropy": s.entropy,
                        "virtual_size": s.virtual_size,
                        "raw_size": s.raw_size,
                        "suspicious": s.is_suspicious,
                        "reasons": s.suspicion_reasons,
                        "flags": s.flags,
                    }
                    for s in pe.sections
                ],
                "suspicious_imports": pe.suspicious_imports,
                "yara_matches": [
                    {
                        "rule": m.rule_name,
                        "severity": m.severity,
                        "category": m.category,
                        "description": m.description,
                        "family": m.family,
                    }
                    for m in report.yara_matches
                ],
                "strings": {
                    k: v[:20] for k, v in pe.suspicious_strings.items() if v
                },
                "findings": report.findings[:20],
            }
            existing = []
            if os.path.exists(self._json_log_path):
                try:
                    with open(self._json_log_path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    existing = []
            existing.append(data)
            with open(self._json_log_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self._write_text(f"[ERROR] Không lưu được JSON: {e}\n")
