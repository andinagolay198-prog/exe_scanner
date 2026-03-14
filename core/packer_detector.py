"""
Packer / Protector Detector
Phát hiện công cụ cracker dùng để pack/protect/patch binary
"""
import re
import struct
from typing import List, Dict, Tuple

# ─── Packer signatures (byte patterns) ───────────────────────
PACKER_SIGNATURES = [
    # UPX
    {"name": "UPX",         "pattern": b"UPX!",          "type": "packer",    "severity": "HIGH"},
    {"name": "UPX",         "pattern": b"UPX0",          "type": "packer",    "severity": "HIGH"},
    {"name": "UPX",         "pattern": b"UPX1",          "type": "packer",    "severity": "HIGH"},
    # MPRESS
    {"name": "MPRESS",      "pattern": b"MPRESS1",       "type": "packer",    "severity": "HIGH"},
    {"name": "MPRESS",      "pattern": b"MPRESS2",       "type": "packer",    "severity": "HIGH"},
    # Themida / WinLicense
    {"name": "Themida",     "pattern": b"Themida",       "type": "protector", "severity": "CRITICAL"},
    {"name": "WinLicense",  "pattern": b"WinLicense",    "type": "protector", "severity": "CRITICAL"},
    {"name": "Themida",     "pattern": b".themida",      "type": "protector", "severity": "CRITICAL"},
    # VMProtect
    {"name": "VMProtect",   "pattern": b"VMProtect",     "type": "protector", "severity": "CRITICAL"},
    {"name": "VMProtect",   "pattern": b".vmp0",         "type": "protector", "severity": "CRITICAL"},
    {"name": "VMProtect",   "pattern": b".vmp1",         "type": "protector", "severity": "CRITICAL"},
    # ASPack
    {"name": "ASPack",      "pattern": b"ASPack",        "type": "packer",    "severity": "HIGH"},
    {"name": "ASPack",      "pattern": b".aspack",       "type": "packer",    "severity": "HIGH"},
    # PECompact
    {"name": "PECompact",   "pattern": b"PECompact2",    "type": "packer",    "severity": "HIGH"},
    # Nullsoft NSIS
    {"name": "NSIS",        "pattern": b"Nullsoft.NSIS", "type": "installer", "severity": "MEDIUM"},
    # PyInstaller (Python packed)
    {"name": "PyInstaller", "pattern": b"pyiboot01",     "type": "packer",    "severity": "MEDIUM"},
    {"name": "PyInstaller", "pattern": b"PYARMOR",       "type": "packer",    "severity": "MEDIUM"},
    {"name": "PyInstaller", "pattern": b"pyi-windows",   "type": "packer",    "severity": "MEDIUM"},
    # Nuitka
    {"name": "Nuitka",      "pattern": b"__nuitka__",    "type": "packer",    "severity": "MEDIUM"},
    # .NET / Confuser
    {"name": "ConfuserEx",  "pattern": b"ConfuserEx",    "type": "protector", "severity": "HIGH"},
    {"name": ".NET",        "pattern": b"mscoree.dll",   "type": "runtime",   "severity": "LOW"},
    # AutoIt
    {"name": "AutoIt",      "pattern": b"AU3!EA06",      "type": "packer",    "severity": "HIGH"},
    # Go runtime
    {"name": "Go",          "pattern": b"Go build ID",  "type": "runtime",   "severity": "LOW"},
    {"name": "Go",          "pattern": b"runtime.main",  "type": "runtime",   "severity": "LOW"},
    # Rust
    {"name": "Rust",        "pattern": b"rustc/",        "type": "runtime",   "severity": "LOW"},
    # Delphi
    {"name": "Delphi",      "pattern": b"Borland Delphi","type": "runtime",   "severity": "LOW"},
    # Inno Setup
    {"name": "InnoSetup",   "pattern": b"Inno Setup",    "type": "installer", "severity": "LOW"},
    # Enigma Protector
    {"name": "Enigma",      "pattern": b"Enigma Protector","type":"protector", "severity": "CRITICAL"},
    # Obsidium
    {"name": "Obsidium",    "pattern": b"Obsidium",      "type": "protector", "severity": "CRITICAL"},
    # .ndata (NSIS marker)
    {"name": "NSIS",        "pattern": b"\x00.ndata\x00","type": "installer", "severity": "LOW"},
]

# ─── Anti-cracking string patterns ───────────────────────────
ANTI_CRACK_STRINGS = [
    # Debugger detection strings
    (rb"(?i)IsDebuggerPresent",         "API kiểm tra debugger"),
    (rb"(?i)CheckRemoteDebugger",       "API kiểm tra remote debugger"),
    (rb"(?i)NtQueryInformationProcess", "NT API anti-debug"),
    (rb"(?i)OutputDebugString",         "Anti-debug timing trick"),
    (rb"(?i)FindWindow.*[Oo]lly",       "Kiểm tra OllyDbg đang mở"),
    (rb"(?i)FindWindow.*[Xx]64[Dd]bg",  "Kiểm tra x64dbg đang mở"),
    (rb"(?i)FindWindow.*[Ii][Dd][Aa]",  "Kiểm tra IDA Pro đang mở"),
    # VM / Sandbox detection
    (rb"(?i)VBOX|VirtualBox",           "Kiểm tra VirtualBox"),
    (rb"(?i)VMware",                    "Kiểm tra VMware"),
    (rb"(?i)QEMU|qemu",                 "Kiểm tra QEMU"),
    (rb"(?i)Sandboxie",                 "Kiểm tra Sandboxie"),
    (rb"(?i)SbieDll",                   "Sandboxie DLL"),
    (rb"(?i)cuckoo",                    "Kiểm tra Cuckoo sandbox"),
    (rb"(?i)wireshark",                 "Kiểm tra Wireshark"),
    # License/keygen keywords
    (rb"(?i)keygen|key.?gen",           "Từ khóa keygen trong binary"),
    (rb"(?i)crack|cracked|cracking",    "Từ khóa crack trong binary"),
    (rb"(?i)patch(ed)?\.exe",           "Tham chiếu file patch"),
    (rb"(?i)bypass",                    "Từ khóa bypass"),
    (rb"(?i)serial.*number|sn\s*=",     "Serial number hardcoded"),
    (rb"(?i)license.*bypass|bypass.*license", "Bypass license trực tiếp"),
    (rb"(?i)nag.*screen|remove.*nag",   "Xóa nag screen"),
    # Patching / injection keywords
    (rb"(?i)WriteProcessMemory",        "Ghi vào process khác"),
    (rb"(?i)CreateRemoteThread",        "Tạo thread trong process khác"),
    (rb"(?i)code.?cave",                "Code cave injection"),
    (rb"(?i)inject",                    "Injection keyword"),
    (rb"(?i)hook.*api|api.*hook",       "API hooking"),
    # File patching
    (rb"(?i)\.exe.*patch|patch.*\.exe", "Patch file exe"),
    (rb"(?i)backup.*\.exe|\.bak",       "Tạo backup trước khi patch"),
    # Specific cracker tools
    (rb"(?i)x64dbg|x32dbg",            "x64dbg debugger"),
    (rb"(?i)OllyDbg|ollydbg",          "OllyDbg debugger"),
    (rb"(?i)IDA\s*Pro|idat\.exe",       "IDA Pro disassembler"),
    (rb"(?i)Cheat\s*Engine",            "Cheat Engine"),
    (rb"(?i)ReClass",                   "ReClass memory editor"),
]

# ─── License check bypass patterns (assembly-level strings) ──
LICENSE_BYPASS_PATTERNS = [
    (rb"(?i)trial.*expir|expir.*trial",     "Trial expiry bypass"),
    (rb"(?i)days.*left|remaining.*days",    "Days remaining manipulation"),
    (rb"(?i)registered.*version|reg.*ver",  "Registered version flag"),
    (rb"(?i)unregistered|not.*register",    "Unregistered check"),
    (rb"(?i)full.*version|pro.*version",    "Version check"),
    (rb"(?i)activation.*code|activate.*key","Activation code"),
    (rb"(?i)license.*valid|valid.*license", "License validation"),
    (rb"(?i)wrong.*serial|invalid.*serial", "Serial check message"),
    (rb"(?i)thank.*for.*purchas",           "Purchase thank-you message"),
    (rb"(?i)please.*buy|buy.*full",         "Buy prompt"),
]


def scan_packers(raw: bytes) -> List[Dict]:
    """Quét binary tìm packer/protector signatures."""
    found = []
    seen_names = set()

    for sig in PACKER_SIGNATURES:
        if sig["pattern"] in raw:
            name = sig["name"]
            if name not in seen_names:
                seen_names.add(name)
                found.append({
                    "name":     name,
                    "type":     sig["type"],
                    "severity": sig["severity"],
                    "offset":   raw.find(sig["pattern"]),
                })

    return found


def scan_anti_crack_strings(raw: bytes) -> List[Dict]:
    """Tìm strings liên quan đến cracking/bypass."""
    found = []
    for pattern, desc in ANTI_CRACK_STRINGS:
        matches = list(re.finditer(pattern, raw))
        if matches:
            sample = raw[matches[0].start():matches[0].start()+60]
            try:
                sample_str = sample.decode("utf-8", errors="replace").strip()
            except Exception:
                sample_str = repr(sample)
            found.append({
                "pattern":  pattern.decode("utf-8", errors="replace"),
                "desc":     desc,
                "count":    len(matches),
                "sample":   sample_str[:80],
                "offset":   matches[0].start(),
            })
    return found


def scan_license_strings(raw: bytes) -> List[Dict]:
    """Tìm strings liên quan đến license check / bypass."""
    found = []
    for pattern, desc in LICENSE_BYPASS_PATTERNS:
        matches = list(re.finditer(pattern, raw))
        if matches:
            sample = raw[matches[0].start():matches[0].start()+80]
            try:
                sample_str = sample.decode("utf-8", errors="replace").strip()
            except Exception:
                sample_str = ""
            found.append({
                "desc":   desc,
                "count":  len(matches),
                "sample": sample_str[:100],
                "offset": matches[0].start(),
            })
    return found


def analyze_packer(raw: bytes, pe=None) -> Dict:
    """Main entry: phân tích toàn diện packer/protector."""
    result = {
        "packers":          scan_packers(raw),
        "anti_crack":       scan_anti_crack_strings(raw),
        "license_strings":  scan_license_strings(raw),
        "protection_score": 0,
        "protection_level": "NONE",
        "indicators":       [],
    }

    # Tính protection score
    score = 0
    for p in result["packers"]:
        s = p["severity"]
        score += 30 if s == "CRITICAL" else (15 if s == "HIGH" else 5)
    for a in result["anti_crack"]:
        score += 8
    for l in result["license_strings"]:
        score += 5

    result["protection_score"] = min(score, 100)
    if score >= 60:
        result["protection_level"] = "HEAVILY_PROTECTED"
    elif score >= 30:
        result["protection_level"] = "PROTECTED"
    elif score >= 10:
        result["protection_level"] = "LIGHTLY_PROTECTED"
    else:
        result["protection_level"] = "UNPROTECTED"

    # Risk indicators cho scorer
    if result["packers"]:
        names = ", ".join(p["name"] for p in result["packers"])
        sev   = max(result["packers"], key=lambda x: {"CRITICAL":3,"HIGH":2,"MEDIUM":1,"LOW":0}.get(x["severity"],0))["severity"]
        result["indicators"].append({
            "level":       sev,
            "points":      25 if sev == "CRITICAL" else 15,
            "description": f"Packer/Protector phát hiện: {names}",
        })

    if result["anti_crack"]:
        result["indicators"].append({
            "level":       "HIGH",
            "points":      10,
            "description": f"{len(result['anti_crack'])} anti-analysis technique(s) phát hiện",
        })

    if result["license_strings"]:
        result["indicators"].append({
            "level":       "HIGH",
            "points":      12,
            "description": f"{len(result['license_strings'])} license bypass string(s) tìm thấy",
        })

    return result
