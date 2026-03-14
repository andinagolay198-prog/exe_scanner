"""
Resource Analyzer
Phân tích sâu .rsrc section — phát hiện payload nhúng, PE trong PE,
file mã hóa/nén, và các kỹ thuật stegano phổ biến của cracker
"""
import re
import math
import struct
import hashlib
from typing import List, Dict, Optional, Tuple

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ─── Magic bytes phổ biến ─────────────────────────────────────
FILE_MAGIC = {
    b"MZ":                      ("PE/EXE",      "CRITICAL", "Executable nhúng trong resource"),
    b"PK\x03\x04":              ("ZIP",          "HIGH",     "ZIP archive (có thể chứa payload)"),
    b"PK\x05\x06":              ("ZIP empty",    "MEDIUM",   "ZIP archive rỗng"),
    b"\x1f\x8b":                ("GZIP",         "HIGH",     "GZIP compressed data"),
    b"BZh":                     ("BZIP2",        "HIGH",     "BZIP2 compressed data"),
    b"\xfd7zXZ\x00":            ("XZ",           "HIGH",     "XZ compressed data"),
    b"7z\xbc\xaf'\x1c":         ("7ZIP",         "HIGH",     "7-Zip archive"),
    b"Rar!\x1a\x07":            ("RAR",          "HIGH",     "RAR archive"),
    b"\xcf\xfa\xed\xfe":        ("Mach-O 64",    "HIGH",     "macOS executable"),
    b"\xce\xfa\xed\xfe":        ("Mach-O 32",    "HIGH",     "macOS executable 32-bit"),
    b"\x7fELF":                 ("ELF",          "HIGH",     "Linux/Unix executable"),
    b"JFIF":                    ("JPEG",         "LOW",      "JPEG image (có thể steganography)"),
    b"\x89PNG":                 ("PNG",          "LOW",      "PNG image (có thể steganography)"),
    b"GIF8":                    ("GIF",          "LOW",      "GIF image"),
    b"RIFF":                    ("RIFF",         "LOW",      "WAV/AVI container"),
    b"%PDF":                    ("PDF",          "MEDIUM",   "PDF file"),
    b"\xd0\xcf\x11\xe0":        ("OLE",          "MEDIUM",   "OLE/Office document"),
    b"PYARMOR":                 ("PyArmor",      "HIGH",     "PyArmor encrypted Python bytecode"),
    b"\xe3":                    ("PYC",          "MEDIUM",   "Python bytecode"),
    b"\x00\x00\x00\x00\x00\x00\x00\x00": (None, None, None),  # skip zeros
}

# ─── Byte patterns trong resource data ───────────────────────
RESOURCE_PATTERNS = [
    (rb"MZ.{60,200}PE\x00\x00",    "PE header fragment — có thể PE nhúng"),
    (rb"(?i)http[s]?://[^\x00\s]{8,}", "URL trong resource data"),
    (rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}", "IP:Port trong resource"),
    (rb"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "Password trong resource"),
    (rb"(?i)(api.?key|apikey|secret)\s*[=:]\s*\S+", "API key / secret trong resource"),
    (rb"-----BEGIN.{1,30}KEY-----", "PEM private key"),
    (rb"-----BEGIN CERTIFICATE-----", "X.509 certificate"),
    # Command strings
    (rb"(?i)(cmd\.exe|powershell|wscript|cscript)", "Shell command reference"),
    (rb"(?i)(reg\s+add|reg\s+delete|regsvr32)", "Registry command"),
    (rb"(?i)(net\s+user|net\s+localgroup|sc\s+create)", "System command"),
    # DLL names thường inject
    (rb"(?i)(ntdll|kernel32|ws2_32|wininet)\.dll", "System DLL reference trong resource"),
]

# ─── Entropy thresholds ───────────────────────────────────────
ENTROPY_THRESHOLDS = {
    "encrypted":   (7.2, 8.0),
    "compressed":  (6.0, 7.2),
    "normal":      (3.0, 6.0),
    "zeroed":      (0.0, 1.0),
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    e = 0.0
    for f in freq:
        if f:
            p = f / length
            e -= p * math.log2(p)
    return e


def _detect_magic(data: bytes) -> Optional[Tuple[str, str, str]]:
    """Nhận dạng file type từ magic bytes."""
    for magic, info in FILE_MAGIC.items():
        if info[0] is None:
            continue
        if data[:len(magic)] == magic:
            return info  # (type, severity, desc)
    # Check MZ ở bất kỳ offset nào trong 1KB đầu (PE-in-PE)
    for i in range(0, min(1024, len(data)-2), 2):
        if data[i:i+2] == b"MZ":
            pe_sig_offset = struct.unpack_from("<I", data, i+0x3C)[0] if len(data) > i+0x40 else 0
            if pe_sig_offset and pe_sig_offset < 0x200:
                if len(data) > i + pe_sig_offset + 4:
                    if data[i+pe_sig_offset:i+pe_sig_offset+4] == b"PE\x00\x00":
                        return ("PE/EXE (embedded)", "CRITICAL", f"PE nhúng tại offset 0x{i:X}")
    return None


def _scan_patterns(data: bytes) -> List[Dict]:
    """Quét patterns đáng ngờ trong resource data."""
    findings = []
    for pattern, desc in RESOURCE_PATTERNS:
        matches = list(re.finditer(pattern, data[:65536]))  # chỉ scan 64KB đầu
        if matches:
            sample = data[matches[0].start():matches[0].start()+80]
            try:
                sample_str = sample.decode("utf-8", errors="replace")
            except Exception:
                sample_str = sample.hex()[:40]
            findings.append({
                "desc":   desc,
                "count":  len(matches),
                "sample": sample_str.strip()[:100],
                "offset": matches[0].start(),
            })
    return findings


def _analyze_resource_node(res_data: bytes, name: str,
                            res_type: str, size: int) -> Dict:
    """Phân tích một resource entry."""
    entr = _entropy(res_data)
    magic_info = _detect_magic(res_data)
    patterns   = _scan_patterns(res_data)

    # Xác định entropy category
    entr_cat = "normal"
    for cat, (lo, hi) in ENTROPY_THRESHOLDS.items():
        if lo <= entr <= hi:
            entr_cat = cat
            break

    is_suspicious = False
    suspicion_reasons = []

    if entr > 7.2:
        is_suspicious = True
        suspicion_reasons.append(f"Entropy {entr:.2f} — dữ liệu mã hóa/nén")
    if magic_info:
        is_suspicious = True
        suspicion_reasons.append(f"File type: {magic_info[0]} — {magic_info[2]}")
    if patterns:
        is_suspicious = True
        for p in patterns:
            suspicion_reasons.append(p["desc"])
    if size > 1_000_000 and entr > 5.0:
        is_suspicious = True
        suspicion_reasons.append(f"Resource lớn bất thường: {size/1024:.0f}KB")

    md5 = hashlib.md5(res_data[:65536]).hexdigest()

    return {
        "name":       name,
        "type":       res_type,
        "size":       size,
        "size_kb":    round(size / 1024, 1),
        "entropy":    round(entr, 3),
        "entropy_cat": entr_cat,
        "magic":      magic_info[0] if magic_info else None,
        "magic_severity": magic_info[1] if magic_info else None,
        "magic_desc": magic_info[2] if magic_info else None,
        "patterns":   patterns,
        "md5":        md5,
        "is_suspicious": is_suspicious,
        "suspicion_reasons": suspicion_reasons,
    }


# RT_* resource type names
RT_NAMES = {
    1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
    5: "RT_DIALOG", 6: "RT_STRING", 7: "RT_FONTDIR", 8: "RT_FONT",
    9: "RT_ACCELERATOR", 10: "RT_RCDATA", 11: "RT_MESSAGETABLE",
    14: "RT_GROUP_ICON", 16: "RT_VERSION", 23: "RT_HTML", 24: "RT_MANIFEST",
}


def analyze_resources(raw: bytes, pe) -> Dict:
    """
    Main entry: phân tích toàn bộ .rsrc section.
    """
    result = {
        "resources":        [],
        "total_size":       0,
        "suspicious_count": 0,
        "embedded_files":   [],
        "indicators":       [],
        "summary":          "",
    }

    if not PEFILE_AVAILABLE or pe is None:
        return result

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        result["summary"] = "Không có resource directory"
        return result

    try:
        for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            # Tên loại resource
            if res_type.id and res_type.id in RT_NAMES:
                type_name = RT_NAMES[res_type.id]
            elif hasattr(res_type, "name") and res_type.name:
                try:
                    type_name = str(res_type.name)
                except Exception:
                    type_name = f"ID_{res_type.id}"
            else:
                type_name = f"ID_{res_type.id}" if res_type.id else "UNKNOWN"

            if not hasattr(res_type, "directory"):
                continue

            for res_id in res_type.directory.entries:
                if not hasattr(res_id, "directory"):
                    continue
                for res_lang in res_id.directory.entries:
                    try:
                        data_entry = res_lang.data
                        rva  = data_entry.struct.OffsetToData
                        size = data_entry.struct.Size

                        offset = pe.get_offset_from_rva(rva)
                        res_data = raw[offset:offset + min(size, 16*1024*1024)]

                        # Tên resource
                        if hasattr(res_id, "name") and res_id.name:
                            res_name = str(res_id.name)
                        else:
                            res_name = str(res_id.id) if res_id.id else "?"

                        entry = _analyze_resource_node(
                            res_data, res_name, type_name, size
                        )
                        entry["rva"]    = rva
                        entry["offset"] = offset
                        entry["lang"]   = res_lang.id if res_lang.id else 0

                        result["resources"].append(entry)
                        result["total_size"] += size

                        if entry["is_suspicious"]:
                            result["suspicious_count"] += 1

                        if entry["magic"] and entry["magic_severity"] in ("CRITICAL", "HIGH"):
                            result["embedded_files"].append({
                                "type":     entry["magic"],
                                "size_kb":  entry["size_kb"],
                                "entropy":  entry["entropy"],
                                "offset":   entry["offset"],
                                "severity": entry["magic_severity"],
                            })

                    except Exception:
                        continue

    except Exception:
        pass

    # Build indicators
    for emb in result["embedded_files"]:
        result["indicators"].append({
            "level":       emb["severity"],
            "points":      40 if emb["type"] == "PE/EXE" else 20,
            "description": f"Embedded {emb['type']} ({emb['size_kb']:.0f}KB, entropy {emb['entropy']:.2f}) trong resource",
        })

    # Tổng resource size bất thường
    total_kb = result["total_size"] / 1024
    if total_kb > 5000:
        result["indicators"].append({
            "level":   "HIGH",
            "points":  15,
            "description": f"Tổng resource size {total_kb:.0f}KB — bất thường lớn",
        })

    if result["suspicious_count"] > 0:
        result["summary"] = (
            f"{result['suspicious_count']} resource(s) đáng ngờ"
            + (f", {len(result['embedded_files'])} embedded file(s)" if result["embedded_files"] else "")
        )
    else:
        result["summary"] = f"{len(result['resources'])} resource(s), không có gì đáng ngờ"

    return result
