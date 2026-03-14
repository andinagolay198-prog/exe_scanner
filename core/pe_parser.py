"""
PE Parser Module — v3 (nâng cấp toàn diện)
Thêm: Overlay, Rich Header, ImpHash, Exports analysis,
      Mutex detection, Base64 decode + re-check, Compiler fingerprint
"""
import os
import re
import math
import base64
import struct
import hashlib
import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    flags: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)


@dataclass
class ImportInfo:
    dll: str
    functions: List[str] = field(default_factory=list)


@dataclass
class ExportInfo:
    name: str
    ordinal: int
    address: int
    is_suspicious: bool = False
    suspicion_reason: str = ""


@dataclass
class RichHeaderEntry:
    comp_id: int
    count: int
    product_name: str = ""
    vs_version: str = ""


@dataclass
class PEAnalysisResult:
    filepath: str
    is_valid_pe: bool = False
    error: str = ""
    machine: str = ""
    machine_type: str = ""
    timestamp: int = 0
    timestamp_str: str = ""
    num_sections: int = 0
    entry_point: int = 0
    image_base: int = 0
    subsystem: str = ""
    is_dll: bool = False
    is_64bit: bool = False
    md5: str = ""
    sha256: str = ""
    sha1: str = ""
    imphash: str = ""
    file_size: int = 0
    sections: List[SectionInfo] = field(default_factory=list)
    ep_in_code_section: bool = True
    imports: List[ImportInfo] = field(default_factory=list)
    suspicious_imports: List[Dict] = field(default_factory=list)
    exports: List[ExportInfo] = field(default_factory=list)
    suspicious_exports: List[ExportInfo] = field(default_factory=list)
    export_dll_name: str = ""
    suspicious_strings: Dict = field(default_factory=dict)
    has_tls: bool = False
    has_debug: bool = False
    has_resources: bool = False
    has_signature: bool = False
    signature_valid: bool = False
    no_import_table: bool = False
    rich_header: List[RichHeaderEntry] = field(default_factory=list)
    compiler_guess: str = ""
    checksum_stored: int = 0
    checksum_actual: int = 0
    checksum_valid: bool = True
    has_overlay: bool = False
    overlay_offset: int = 0
    overlay_size: int = 0
    overlay_entropy: float = 0.0
    risk_indicators: List[Dict] = field(default_factory=list)


SUSPICIOUS_APIS = {
    "CRITICAL": [
        ("VirtualAllocEx",          "Allocate memory in remote process (injection)"),
        ("WriteProcessMemory",       "Write to remote process memory (injection)"),
        ("CreateRemoteThread",       "Create thread in remote process (injection)"),
        ("NtCreateThreadEx",         "NT API: create remote thread (stealthy)"),
        ("RtlCreateUserThread",      "RTL create user thread in remote process"),
        ("QueueUserAPC",             "APC injection technique"),
        ("NtUnmapViewOfSection",     "Process hollowing: unmap legitimate code"),
        ("ZwUnmapViewOfSection",     "Process hollowing: unmap (Zw variant)"),
        ("NtCreateTransaction",      "Transacted Hollowing technique"),
    ],
    "HIGH": [
        ("URLDownloadToFile",        "Download & save file from internet"),
        ("URLDownloadToCacheFile",   "Download file to cache"),
        ("WSAStartup",               "Initialize Winsock (network activity)"),
        ("CryptEncrypt",             "Encrypt data (possible ransomware)"),
        ("BCryptEncrypt",            "Modern encrypt API (ransomware/C2)"),
        ("CryptGenKey",              "Generate encryption key"),
        ("SetWindowsHookEx",         "Hook keyboard/mouse (keylogger)"),
        ("GetAsyncKeyState",         "Read keyboard state (keylogger)"),
        ("RegSetValueEx",            "Write to registry (persistence)"),
        ("CreateService",            "Create Windows service (persistence)"),
        ("NtWriteVirtualMemory",     "Write to virtual memory"),
        ("NtCreateSection",          "Create memory section (injection)"),
    ],
    "MEDIUM": [
        ("IsDebuggerPresent",        "Check if debugged (anti-analysis)"),
        ("CheckRemoteDebuggerPresent", "Check remote debugger (anti-analysis)"),
        ("NtQueryInformationProcess", "Query process info (anti-debug)"),
        ("GetTickCount",             "Timing check (sandbox evasion)"),
        ("QueryPerformanceCounter",  "High-res timing (sandbox evasion)"),
        ("ShellExecute",             "Execute file/URL"),
        ("WinExec",                  "Execute command (legacy)"),
        ("RegCreateKeyEx",           "Create registry key"),
        ("OpenProcess",              "Open handle to another process"),
        ("VirtualProtect",           "Change memory permissions"),
        ("LoadLibraryA",             "Load DLL (dynamic loading)"),
        ("GetProcAddress",           "Resolve API at runtime (evasion)"),
        ("NtDelayExecution",         "Sleep (sandbox bypass)"),
    ],
}

INJECTION_COMBOS = [
    {"name": "Classic Process Injection",
     "apis": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
     "severity": "CRITICAL", "score": 45},
    {"name": "Process Hollowing",
     "apis": {"NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory"},
     "severity": "CRITICAL", "score": 45},
    {"name": "APC Injection",
     "apis": {"VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"},
     "severity": "CRITICAL", "score": 40},
    {"name": "Dynamic API Resolution (Evasion)",
     "apis": {"LoadLibraryA", "GetProcAddress"},
     "severity": "HIGH", "score": 20},
]

SUSPICIOUS_EXPORT_PATTERNS = [
    (r"(?i)^(reflective|inject|shellcode|loader|payload|dropper)", "Tên export đặc trưng loader/injector"),
    (r"(?i)(bypass|evad|hook|patch|exploit)",                       "Tên export gợi ý evasion/exploit"),
]

LEGITIMATE_EXPORTS = {
    "DllMain", "DllRegisterServer", "DllUnregisterServer",
    "DllGetClassObject", "DllCanUnloadNow", "DllInstall",
}

KNOWN_MALWARE_MUTEX = [
    r"(?i)(darkcomet|njrat|cybergate|xtreme|blackshades|bifrost|poison\s*ivy)",
    r"(?i)(asyncrat|quasarrat|nanocore|remcos|netwire|njw0rm)",
    r"(?i)(zeus|citadel|carbanak|spyeye|gozi|dridex|emotet|trickbot)",
    r"(?i)(wannacry|notpetya|ryuk|sodinokibi|revil|lockbit|conti|blackcat)",
    r"(?i)(xmrig|monero|coinhive|cryptojack)",
    r"(?i)^(c2|command.?control|botnet|rat_)",
]

RICH_PRODUCT_NAMES = {
    0x0000: "Unknown/Linker", 0x0001: "Import0",
    0x000F: "Linker600",      0x001E: "Utc12_C",
    0x001F: "Utc12_Cpp",      0x0023: "Linker700",
    0x0028: "Utc13_C",        0x0029: "Utc13_Cpp",
    0x006D: "Utc141_C",       0x006E: "Utc141_Cpp",
    0x00AA: "Masm800",        0x00C9: "Linker800",
    0x00FF: "Utc1400_C",      0x0100: "Utc1400_Cpp",
    0x0101: "Linker900",      0x010F: "Utc1500_C",
    0x0110: "Utc1500_Cpp",    0x0140: "Linker1000",
    0x0166: "Utc1600_C",      0x0167: "Utc1600_Cpp",
    0x0169: "Linker1100",     0x01A0: "Linker1200",
    0x01C3: "Utc1700_C",      0x01C4: "Utc1700_Cpp",
    0x01CC: "Linker1300",     0x0207: "Utc1800_C",
    0x0208: "Utc1800_Cpp",    0x020D: "Linker1400",
    0x0253: "Utc1900_C",      0x0254: "Utc1900_Cpp",
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def get_section_flags(characteristics: int) -> List[str]:
    flags = []
    if characteristics & 0x20:        flags.append("CODE")
    if characteristics & 0x40:        flags.append("INIT_DATA")
    if characteristics & 0x80:        flags.append("UNINIT_DATA")
    if characteristics & 0x20000000:  flags.append("EXECUTE")
    if characteristics & 0x40000000:  flags.append("READ")
    if characteristics & 0x80000000:  flags.append("WRITE")
    return flags


def get_subsystem_name(subsystem: int) -> str:
    names = {1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)",
             5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE",
             10: "EFI Application", 14: "Xbox"}
    return names.get(subsystem, f"Unknown({subsystem})")


def get_machine_name(machine: int) -> Tuple[str, str]:
    machines = {0x014C: ("I386", "x86 32-bit"), 0x8664: ("AMD64", "x64 64-bit"),
                0x01C4: ("ARMNT", "ARM Thumb-2"), 0xAA64: ("ARM64", "ARM 64-bit"),
                0x0200: ("IA64", "Intel Itanium")}
    return machines.get(machine, (f"0x{machine:04X}", "Unknown"))


def compute_hashes(filepath: str) -> Tuple[str, str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _try_decode_base64(s: str) -> Optional[str]:
    try:
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        decoded = base64.b64decode(padded)
        text = decoded.decode("utf-8", errors="strict")
        if len(text) >= 4 and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text):
            return text.strip()
    except Exception:
        pass
    return None


def _classify_decoded_b64(decoded: str) -> Optional[Tuple[str, str]]:
    if re.match(r"https?://", decoded, re.I):
        return ("decoded_b64_url", decoded)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", decoded):
        return ("decoded_b64_ip", decoded)
    if re.match(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", decoded):
        return ("decoded_b64_email", decoded)
    if re.match(r"[A-Za-z]:\\|\\\\", decoded):
        return ("decoded_b64_path", decoded)
    if any(k in decoded.upper() for k in ("EXEC", "CMD", "POWERSHELL", "DOWNLOAD", "UPLOAD")):
        return ("decoded_b64_command", decoded)
    return None


def extract_strings(data: bytes, min_len: int = 5) -> Dict[str, List[str]]:
    ascii_strings = [s.decode("ascii", errors="ignore")
                     for s in re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)]
    unicode_strings = [s.decode("utf-16-le", errors="ignore")
                       for s in re.findall(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}", data)]
    all_str = ascii_strings + unicode_strings

    result: Dict[str, List[str]] = {
        "ips": [], "domains": [], "urls": [], "emails": [],
        "registry": [], "irc_commands": [], "base64": [],
        "file_paths": [], "mutexes": [], "crypto_keys": [],
        "decoded_b64_url": [], "decoded_b64_ip": [],
        "decoded_b64_command": [], "decoded_b64_path": [],
        "decoded_b64_email": [],
    }

    for s in all_str:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
            if s not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                result["ips"].append(s)
        if re.match(r"https?://", s, re.I):
            result["urls"].append(s)
        if re.match(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", s, re.I):
            result["emails"].append(s)
        if any(k in s for k in ("HKEY_", "SOFTWARE\\", "CurrentVersion\\Run",
                                  "SYSTEM\\CurrentControlSet")):
            result["registry"].append(s)
        if any(k in s.upper() for k in ("JOIN #", "PRIVMSG", "!DOWNLOAD",
                                          "!DDOS", "!UPDATE", "!EXEC", "!SCAN")):
            result["irc_commands"].append(s)
        if re.match(r"^(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|cn|xyz|top|onion|bit|pw|cc)", s):
            if len(s) < 80:
                result["domains"].append(s)
        if re.match(r"^[A-Za-z0-9+/]{24,}={0,2}$", s):
            result["base64"].append(s)
            decoded = _try_decode_base64(s)
            if decoded:
                classified = _classify_decoded_b64(decoded)
                if classified:
                    cat, val = classified
                    result[cat].append(f"{s[:20]}... -> {val[:80]}")
        if re.match(r"[A-Za-z]:\\|\\\\|%appdata%|%temp%|%system%", s, re.I):
            result["file_paths"].append(s)

        # Mutex detection
        is_mutex = False
        if re.match(r"^(Global|Local)\\[\w\-\.]{3,}", s):
            is_mutex = True
        elif any(kw in s for kw in ["Global\\", "Local\\", "mutex", "Mutex", "MUTEX"]) and len(s) < 120:
            is_mutex = True
        elif re.match(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$", s):
            is_mutex = True

        if is_mutex:
            is_known_bad = any(re.search(p, s) for p in KNOWN_MALWARE_MUTEX)
            entry = f"[KNOWN_MALWARE] {s}" if is_known_bad else s
            result["mutexes"].append(entry)

        if re.match(r"^[0-9a-fA-F]{32,}$", s) and len(s) in (32, 40, 48, 64, 96, 128):
            result["crypto_keys"].append(s)

    for k in result:
        result[k] = list(dict.fromkeys(result[k]))[:30]

    return result


def parse_rich_header(raw: bytes) -> Tuple[List[RichHeaderEntry], str]:
    entries = []
    compiler_guess = ""
    try:
        rich_pos = raw.find(b"Rich")
        if rich_pos < 0 or rich_pos > 0x200:
            return entries, compiler_guess

        xor_key = struct.unpack_from("<I", raw, rich_pos + 4)[0]
        dans_start = -1
        for i in range(0x40, rich_pos, 4):
            val = struct.unpack_from("<I", raw, i)[0] ^ xor_key
            if val == 0x536e6144:
                dans_start = i
                break

        if dans_start < 0:
            return entries, compiler_guess

        offset = dans_start + 16
        while offset < rich_pos - 4:
            comp_id = struct.unpack_from("<I", raw, offset)[0] ^ xor_key
            count   = struct.unpack_from("<I", raw, offset + 4)[0] ^ xor_key
            offset += 8
            prod_id  = (comp_id >> 16) & 0xFFFF
            vs_id    = comp_id & 0xFFFF
            prod_name = RICH_PRODUCT_NAMES.get(prod_id, f"ProdID=0x{prod_id:04X}")
            entries.append(RichHeaderEntry(comp_id=comp_id, count=count,
                                           product_name=prod_name,
                                           vs_version=f"VS{vs_id}" if vs_id else ""))

        names_str = " ".join(e.product_name for e in entries).lower()
        if "utc1900" in names_str or "utc1800" in names_str:
            compiler_guess = "MSVC 2017/2019"
        elif "utc1700" in names_str or "utc1600" in names_str:
            compiler_guess = "MSVC 2010/2013"
        elif "utc" in names_str:
            compiler_guess = "MSVC (version unknown)"
        elif not entries:
            compiler_guess = "No Rich Header (MinGW/Delphi/Go/Rust?)"
    except Exception:
        pass
    return entries, compiler_guess


def detect_overlay(pe, raw: bytes) -> Tuple[bool, int, int, float]:
    try:
        end_of_pe = 0
        for section in pe.sections:
            sec_end = section.PointerToRawData + section.SizeOfRawData
            if sec_end > end_of_pe:
                end_of_pe = sec_end

        if end_of_pe < len(raw):
            overlay_data = raw[end_of_pe:]
            if len(overlay_data) > 512 and any(b != 0 for b in overlay_data[:256]):
                entr = calculate_entropy(overlay_data)
                return True, end_of_pe, len(overlay_data), round(entr, 3)
    except Exception:
        pass
    return False, 0, 0, 0.0


def compute_imphash(pe) -> str:
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        imphash_list = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace").lower()
            dll = re.sub(r"\.(dll|sys|ocx|exe)$", "", dll)
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode("utf-8", errors="replace").lower()
                    imphash_list.append(f"{dll}.{fname}")
                else:
                    imphash_list.append(f"{dll}.ord{imp.ordinal}")
        if not imphash_list:
            return ""
        imp_str = ",".join(imphash_list)
        return hashlib.md5(imp_str.encode("ascii", errors="replace")).hexdigest()
    except Exception:
        return ""


def analyze_exports(pe) -> Tuple[List[ExportInfo], List[ExportInfo], str]:
    all_exports = []
    suspicious_exports = []
    dll_name = ""
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return all_exports, suspicious_exports, dll_name

        exp_dir = pe.DIRECTORY_ENTRY_EXPORT
        try:
            dll_name = exp_dir.name.decode("utf-8", errors="replace")
        except Exception:
            dll_name = ""

        for sym in exp_dir.symbols:
            name = ""
            if sym.name:
                try:
                    name = sym.name.decode("utf-8", errors="replace")
                except Exception:
                    name = f"ord_{sym.ordinal}"
            else:
                name = f"ord_{sym.ordinal}"

            exp = ExportInfo(name=name, ordinal=sym.ordinal or 0, address=sym.address or 0)

            is_sus = False
            reason = ""
            for pattern, desc in SUSPICIOUS_EXPORT_PATTERNS:
                if re.search(pattern, name):
                    is_sus = True
                    reason = desc
                    break

            system_procs = {"explorer", "svchost", "lsass", "winlogon",
                             "csrss", "services", "spoolsv", "taskhost"}
            if dll_name and any(sp in dll_name.lower() for sp in system_procs):
                is_sus = True
                reason = f"DLL name giống system process: {dll_name}"

            exp.is_suspicious = is_sus
            exp.suspicion_reason = reason
            all_exports.append(exp)
            if is_sus:
                suspicious_exports.append(exp)

        ordinal_only = sum(1 for e in all_exports if e.name.startswith("ord_"))
        if len(all_exports) > 3 and ordinal_only == len(all_exports):
            for exp in all_exports:
                exp.is_suspicious = True
                exp.suspicion_reason = "Tất cả exports chỉ có ordinal — cố tình ẩn tên"
            suspicious_exports = all_exports.copy()

    except Exception:
        pass
    return all_exports, suspicious_exports, dll_name


class PEParser:
    """Full PE file analyser — v3."""

    def analyze(self, filepath: str) -> PEAnalysisResult:
        result = PEAnalysisResult(filepath=filepath)

        if not os.path.isfile(filepath):
            result.error = "File không tồn tại"
            return result

        result.file_size = os.path.getsize(filepath)

        try:
            result.md5, result.sha1, result.sha256 = compute_hashes(filepath)
        except Exception as e:
            result.error = f"Không thể đọc file: {e}"
            return result

        with open(filepath, "rb") as f:
            raw = f.read()

        if len(raw) < 2 or raw[:2] != b"MZ":
            result.error = "Không phải file PE hợp lệ (thiếu magic MZ)"
            return result

        result.rich_header, result.compiler_guess = parse_rich_header(raw)

        if not PEFILE_AVAILABLE:
            result.error = "Thiếu thư viện pefile – chỉ tính hash"
            result.is_valid_pe = True
            result.suspicious_strings = extract_strings(raw)
            return result

        try:
            pe = pefile.PE(data=raw)
        except Exception as e:
            result.error = f"Lỗi parse PE: {e}"
            return result

        result.is_valid_pe = True

        mcode = pe.FILE_HEADER.Machine
        result.machine, result.machine_type = get_machine_name(mcode)
        result.is_64bit = (mcode == 0x8664)
        result.num_sections = pe.FILE_HEADER.NumberOfSections
        result.timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            result.timestamp_str = datetime.datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            result.timestamp_str = "Invalid"

        chars = pe.FILE_HEADER.Characteristics
        result.is_dll = bool(chars & 0x2000)
        result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        result.image_base  = pe.OPTIONAL_HEADER.ImageBase
        result.subsystem   = get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem)

        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        result.has_tls       = dirs[9].VirtualAddress != 0
        result.has_debug     = dirs[6].VirtualAddress != 0
        result.has_resources = dirs[2].VirtualAddress != 0
        result.has_signature = dirs[4].VirtualAddress != 0

        result.imphash = compute_imphash(pe)

        # Checksum
        try:
            result.checksum_stored = pe.OPTIONAL_HEADER.CheckSum
            result.checksum_actual = pe.generate_checksum()
            result.checksum_valid  = (result.checksum_stored == 0 or
                                       result.checksum_stored == result.checksum_actual)
            if not result.checksum_valid and result.checksum_stored != 0:
                result.risk_indicators.append({
                    "level": "MEDIUM", "points": 6,
                    "description": f"PE Checksum mismatch: stored=0x{result.checksum_stored:08X} actual=0x{result.checksum_actual:08X} — file bị chỉnh sửa",
                })
        except Exception:
            result.checksum_stored = getattr(pe.OPTIONAL_HEADER, 'CheckSum', 0)

        # Sections
        ep = result.entry_point
        result.ep_in_code_section = False
        known_bad_names = {".ndata", ".upx0", ".upx1", ".vmp0", ".vmp1",
                           ".themida", ".aspack", ".mpress1", ".mpress2"}

        for s in pe.sections:
            try:
                name = s.Name.decode("utf-8", errors="replace").rstrip("\x00 ").strip()
            except Exception:
                name = "???"

            data  = s.get_data()
            entr  = calculate_entropy(data)
            flags = get_section_flags(s.Characteristics)

            sec = SectionInfo(name=name, virtual_address=s.VirtualAddress,
                              virtual_size=s.Misc_VirtualSize, raw_size=s.SizeOfRawData,
                              entropy=round(entr, 3), characteristics=s.Characteristics, flags=flags)

            if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, 1):
                if name in (".text", "CODE"):
                    result.ep_in_code_section = True

            if entr > 7.2:
                sec.is_suspicious = True
                sec.suspicion_reasons.append(f"Entropy rất cao ({entr:.2f}) – packed/encrypted")
            elif entr > 6.5:
                sec.is_suspicious = True
                sec.suspicion_reasons.append(f"Entropy cao ({entr:.2f}) – có thể packed")

            if name.lower() in known_bad_names:
                sec.is_suspicious = True
                sec.suspicion_reasons.append(f"Tên section '{name}' đặc trưng của packer")

            if s.Misc_VirtualSize > 0 and s.SizeOfRawData == 0:
                sec.is_suspicious = True
                sec.suspicion_reasons.append("VirtualSize > 0 nhưng RawSize = 0 (bất thường)")

            if "WRITE" in flags and "EXECUTE" in flags:
                sec.is_suspicious = True
                sec.suspicion_reasons.append("Section vừa WRITE vừa EXECUTE (W^X violation)")

            result.sections.append(sec)

        if not result.ep_in_code_section:
            result.risk_indicators.append({
                "level": "CRITICAL", "points": 35,
                "description": "Entry point KHÔNG nằm trong section .text — dấu hiệu rõ ràng của packer/dropper",
            })

        # Overlay
        has_ov, ov_off, ov_size, ov_entr = detect_overlay(pe, raw)
        result.has_overlay    = has_ov
        result.overlay_offset = ov_off
        result.overlay_size   = ov_size
        result.overlay_entropy = ov_entr

        if has_ov:
            ov_kb = ov_size / 1024
            if ov_entr > 7.0:
                result.risk_indicators.append({
                    "level": "HIGH", "points": 20,
                    "description": f"Overlay {ov_kb:.1f}KB tại 0x{ov_off:X}: entropy {ov_entr:.2f} — payload mã hóa",
                })
            elif ov_entr > 5.0:
                result.risk_indicators.append({
                    "level": "MEDIUM", "points": 10,
                    "description": f"Overlay {ov_kb:.1f}KB tại 0x{ov_off:X}: entropy {ov_entr:.2f}",
                })
            else:
                result.risk_indicators.append({
                    "level": "LOW", "points": 3,
                    "description": f"Overlay {ov_kb:.1f}KB tại 0x{ov_off:X} (entropy thấp)",
                })

        # Imports
        all_imported_apis: set = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name_imp = entry.dll.decode("utf-8", errors="replace").lower()
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode("utf-8", errors="replace")
                        funcs.append(fname)
                        all_imported_apis.add(fname)
                result.imports.append(ImportInfo(dll=dll_name_imp, functions=funcs))
        else:
            result.no_import_table = True
            result.risk_indicators.append({
                "level": "HIGH", "points": 22,
                "description": "Không có Import Table — có thể dùng dynamic API resolution để bypass detection",
            })

        for level, api_list in SUSPICIOUS_APIS.items():
            for api_name, reason in api_list:
                if api_name in all_imported_apis:
                    result.suspicious_imports.append({"api": api_name, "level": level, "reason": reason})

        for combo in INJECTION_COMBOS:
            if combo["apis"].issubset(all_imported_apis):
                result.risk_indicators.append({
                    "level": combo["severity"], "points": combo["score"],
                    "description": f"API Combo phát hiện: {combo['name']} — {', '.join(sorted(combo['apis']))}",
                })

        # Exports
        result.exports, result.suspicious_exports, result.export_dll_name = analyze_exports(pe)
        if result.suspicious_exports:
            result.risk_indicators.append({
                "level": "MEDIUM",
                "points": 8 * min(len(result.suspicious_exports), 3),
                "description": f"{len(result.suspicious_exports)} suspicious export(s): "
                               f"{', '.join(e.name for e in result.suspicious_exports[:3])}",
            })

        # Strings
        result.suspicious_strings = extract_strings(raw)

        if result.suspicious_strings["irc_commands"]:
            result.risk_indicators.append({
                "level": "CRITICAL", "points": 40,
                "description": f"IRC botnet commands: {result.suspicious_strings['irc_commands'][:3]}",
            })
        if result.suspicious_strings["urls"]:
            result.risk_indicators.append({
                "level": "MEDIUM", "points": 10,
                "description": f"Hardcoded URLs: {len(result.suspicious_strings['urls'])} found",
            })
        if result.suspicious_strings["ips"]:
            result.risk_indicators.append({
                "level": "MEDIUM", "points": 8,
                "description": f"Hardcoded IPs: {result.suspicious_strings['ips'][:5]}",
            })
        if result.suspicious_strings["registry"]:
            result.risk_indicators.append({
                "level": "HIGH", "points": 15,
                "description": "Registry persistence keys found in strings",
            })

        # Mutex
        if result.suspicious_strings["mutexes"]:
            known_bad_mutex = [m for m in result.suspicious_strings["mutexes"]
                               if m.startswith("[KNOWN_MALWARE]")]
            if known_bad_mutex:
                result.risk_indicators.append({
                    "level": "CRITICAL", "points": 35,
                    "description": f"Known malware mutex: {known_bad_mutex[0][:80]}",
                })
            else:
                result.risk_indicators.append({
                    "level": "MEDIUM", "points": 5,
                    "description": f"{len(result.suspicious_strings['mutexes'])} mutex string(s) found",
                })

        # B64 decoded IOCs
        b64_hits = (result.suspicious_strings["decoded_b64_url"] +
                    result.suspicious_strings["decoded_b64_ip"] +
                    result.suspicious_strings["decoded_b64_command"])
        if b64_hits:
            result.risk_indicators.append({
                "level": "HIGH", "points": 15,
                "description": f"Base64 decoded reveals IOCs: {b64_hits[0][:80]}",
            })

        if result.suspicious_strings["crypto_keys"]:
            result.risk_indicators.append({
                "level": "MEDIUM", "points": 8,
                "description": f"{len(result.suspicious_strings['crypto_keys'])} possible hardcoded crypto key(s)",
            })

        # Timestamp
        if result.timestamp == 0:
            result.risk_indicators.append({"level": "MEDIUM", "points": 8,
                                            "description": "Timestamp = 0 — cố tình xóa metadata"})
        elif result.timestamp > int(datetime.datetime.utcnow().timestamp()):
            result.risk_indicators.append({"level": "HIGH", "points": 12,
                                            "description": f"Timestamp trong tương lai: {result.timestamp_str}"})

        if not result.rich_header and result.is_valid_pe:
            result.compiler_guess = "Không có Rich Header — MinGW / Go / Rust / stripped"

        pe.close()
        return result
