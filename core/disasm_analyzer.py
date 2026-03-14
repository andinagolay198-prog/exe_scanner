"""
Disassembly Analyzer
Phân tích assembly tại Entry Point và các vùng đáng ngờ
Phát hiện: unpacking stubs, license check patterns, anti-debug tricks
"""
import struct
from typing import List, Dict, Optional, Tuple

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ─── Assembly patterns đặc trưng ─────────────────────────────

# Unpacker stub patterns (instruction mnemonics sequences)
UNPACKER_PATTERNS = [
    {
        "name":    "Classic self-modifying / unpack loop",
        "desc":    "Vòng lặp ghi đè code vào vùng nhớ — đặc trưng unpacker",
        "mnemonics": ["mov", "xor", "loop"],  # XOR decrypt loop
        "severity": "HIGH",
    },
    {
        "name":    "Pushad/Popad OEP pattern",
        "desc":    "PUSHAD ở đầu → lưu register → unpack → POPAD → JMP OEP (UPX-style)",
        "mnemonics": ["pushad", "popad"],
        "severity": "HIGH",
    },
    {
        "name":    "VirtualAlloc + memcpy unpack",
        "desc":    "Cấp phát vùng nhớ mới, copy payload vào rồi jump",
        "mnemonics": ["call", "mov", "rep movsb"],
        "severity": "HIGH",
    },
]

# Anti-debug byte patterns trong assembly
ANTIDEBUG_BYTE_PATTERNS = [
    (b"\xCC",              "INT3 breakpoint (có thể là anti-debug trap)"),
    (b"\xCD\x03",          "INT3 software breakpoint"),
    (b"\xEB\xFF\xC0\xC0",  "Junk bytes / anti-disassembly trick"),
    (b"\x0F\x0B",          "UD2 — undefined instruction (crash debugger)"),
    (b"\xF1",              "ICEBP — single-step trap"),
    # RDTSC (timing check)
    (b"\x0F\x31",          "RDTSC — đọc timestamp counter (timing anti-debug)"),
    # CPUID
    (b"\x0F\xA2",          "CPUID — thường dùng để detect VM"),
]

# Syscall patterns thú vị
SYSCALL_PATTERNS = [
    (b"\x0F\x05",          "SYSCALL — direct syscall (bypass API hooks)"),
    (b"\xCD\x2E",          "INT 0x2E — Windows native syscall (cũ)"),
    (b"\x44\x8B\x01",      "Heaven's Gate stub (chuyển từ 32-bit sang 64-bit)"),
]


def _get_ep_data(raw: bytes, pe) -> Tuple[bytes, int]:
    """Lấy bytes tại Entry Point, trả về (data, rva)."""
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_offset = pe.get_offset_from_rva(ep_rva)
        # Lấy 512 bytes đầu tại EP
        ep_data = raw[ep_offset:ep_offset + 512]
        return ep_data, ep_rva
    except Exception:
        return b"", 0


def _disassemble(data: bytes, is_64bit: bool, base_addr: int = 0,
                 max_insns: int = 80) -> List[Dict]:
    """Disassemble bytes, trả về list instruction dicts."""
    if not CAPSTONE_AVAILABLE or not data:
        return []
    try:
        mode = CS_MODE_64 if is_64bit else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = False
        insns = []
        for insn in md.disasm(data, base_addr):
            insns.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
            if len(insns) >= max_insns:
                break
        return insns
    except Exception:
        return []


def _detect_unpacker_stub(insns: List[Dict]) -> List[Dict]:
    """Phát hiện unpacker stub từ instruction sequence."""
    findings = []
    if not insns:
        return findings

    mnemonics = [i["mnemonic"] for i in insns]
    mnem_str  = " ".join(mnemonics)

    # PUSHAD/POPAD pattern (UPX)
    if "pushad" in mnemonics or "pushal" in mnemonics:
        findings.append({
            "name":     "PUSHAD/POPAD unpack stub (UPX-style)",
            "desc":     "PUSHAD tại EP lưu toàn bộ registers trước khi unpack — rất đặc trưng UPX",
            "severity": "HIGH",
        })

    # XOR decrypt loop: có xor + loop/jnz trong 20 insn đầu
    first20 = mnemonics[:20]
    if "xor" in first20 and any(m in first20 for m in ("loop", "jnz", "jne", "dec")):
        findings.append({
            "name":     "XOR decrypt loop tại EP",
            "desc":     "Vòng lặp XOR giải mã payload — phổ biến trong packer đơn giản",
            "severity": "HIGH",
        })

    # Call + pop (thường dùng để lấy địa chỉ hiện tại)
    for i in range(min(10, len(mnemonics)-1)):
        if mnemonics[i] == "call" and mnemonics[i+1] == "pop":
            findings.append({
                "name":     "CALL/POP — position-independent code",
                "desc":     "Kỹ thuật lấy địa chỉ runtime không phụ thuộc base address",
                "severity": "MEDIUM",
            })
            break

    # Nhiều NOP (NOP sled — anti-disassembly hoặc alignment cho hook)
    nop_count = mnemonics.count("nop")
    if nop_count > 8:
        findings.append({
            "name":     f"NOP sled ({nop_count} NOPs)",
            "desc":     "Nhiều NOP liên tiếp — có thể là NOP sled cho exploit hoặc code alignment",
            "severity": "MEDIUM",
        })

    # JMP đến section khác ngay đầu (tail jump to OEP)
    for i, insn in enumerate(insns[:15]):
        if insn["mnemonic"] in ("jmp", "call") and i > 2:
            op = insn["op_str"]
            if op.startswith("0x") or op.startswith("qword"):
                findings.append({
                    "name":     "Early JMP/CALL — chuyển control ra ngoài EP",
                    "desc":     f"Instruction #{i}: {insn['mnemonic']} {op} — có thể là tail jump tới OEP thực",
                    "severity": "MEDIUM",
                })
                break

    return findings


def _scan_byte_patterns(data: bytes) -> List[Dict]:
    """Quét byte patterns đặc biệt trong data."""
    findings = []
    for pattern, desc in ANTIDEBUG_BYTE_PATTERNS:
        count = data.count(pattern)
        if count > 0:
            offset = data.find(pattern)
            findings.append({
                "type":    "anti_debug",
                "bytes":   pattern.hex(),
                "desc":    desc,
                "count":   count,
                "offset":  offset,
                "severity": "HIGH" if count == 1 else "MEDIUM",
            })

    for pattern, desc in SYSCALL_PATTERNS:
        count = data.count(pattern)
        if count > 0:
            offset = data.find(pattern)
            findings.append({
                "type":    "syscall",
                "bytes":   pattern.hex(),
                "desc":    desc,
                "count":   count,
                "offset":  offset,
                "severity": "HIGH",
            })

    return findings


def _analyze_call_targets(insns: List[Dict]) -> List[Dict]:
    """Phân tích call targets — detect suspicious call patterns."""
    findings = []
    calls = [i for i in insns if i["mnemonic"] == "call"]

    # Nhiều call đến địa chỉ tuyệt đối (không phải import) — thường là unpacker
    abs_calls = [c for c in calls if c["op_str"].startswith("0x")]
    if len(abs_calls) > 5:
        findings.append({
            "desc":     f"{len(abs_calls)} call đến địa chỉ tuyệt đối — không qua Import Table",
            "severity": "HIGH",
        })

    return findings


def _format_insns(insns: List[Dict], max_show: int = 40) -> List[str]:
    """Format instructions thành dạng text dễ đọc."""
    lines = []
    for insn in insns[:max_show]:
        lines.append(f"  0x{insn['address']:08X}  {insn['mnemonic']:<10} {insn['op_str']}")
    if len(insns) > max_show:
        lines.append(f"  ... ({len(insns) - max_show} more instructions)")
    return lines


def analyze_disasm(raw: bytes, pe, is_64bit: bool) -> Dict:
    """
    Main entry: phân tích disassembly toàn diện.
    Trả về dict với EP disasm, findings, byte patterns.
    """
    result = {
        "capstone_available": CAPSTONE_AVAILABLE,
        "ep_instructions":    [],
        "ep_text":            [],
        "stub_findings":      [],
        "byte_findings":      [],
        "call_findings":      [],
        "indicators":         [],
        "summary":            "",
    }

    if not PEFILE_AVAILABLE or pe is None:
        return result

    ep_data, ep_rva = _get_ep_data(raw, pe)
    if not ep_data:
        return result

    # Disassemble tại EP
    base = pe.OPTIONAL_HEADER.ImageBase + ep_rva
    if CAPSTONE_AVAILABLE:
        result["ep_instructions"] = _disassemble(ep_data, is_64bit, base)
        result["ep_text"]         = _format_insns(result["ep_instructions"])
        result["stub_findings"]   = _detect_unpacker_stub(result["ep_instructions"])
        result["call_findings"]   = _analyze_call_targets(result["ep_instructions"])

    # Byte pattern scan (không cần capstone)
    result["byte_findings"] = _scan_byte_patterns(ep_data)

    # Scan toàn bộ .text section cho byte patterns
    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00").strip()
            if name in (".text", "CODE"):
                text_data = section.get_data()
                extra = _scan_byte_patterns(text_data)
                for e in extra:
                    e["section"] = name
                    e["offset"] += section.PointerToRawData
                result["byte_findings"].extend(extra)
        except Exception:
            pass

    # Build indicators cho scorer
    for f in result["stub_findings"]:
        pts = 20 if f["severity"] == "HIGH" else 10
        result["indicators"].append({
            "level":       f["severity"],
            "points":      pts,
            "description": f"EP Disasm: {f['name']} — {f['desc']}",
        })

    for f in result["byte_findings"]:
        if f["type"] == "syscall":
            result["indicators"].append({
                "level":       "HIGH",
                "points":      15,
                "description": f"Direct syscall: {f['desc']} (bypass API hooks — x{f['count']})",
            })
        elif f["type"] == "anti_debug" and f["severity"] == "HIGH":
            result["indicators"].append({
                "level":       "MEDIUM",
                "points":      8,
                "description": f"Anti-debug byte: {f['desc']} @ offset 0x{f['offset']:X}",
            })

    # Summary
    if result["stub_findings"]:
        names = [f["name"] for f in result["stub_findings"]]
        result["summary"] = "EP pattern: " + "; ".join(names)
    elif CAPSTONE_AVAILABLE and result["ep_instructions"]:
        first = result["ep_instructions"][0]
        result["summary"] = f"EP bắt đầu: {first['mnemonic']} {first['op_str']}"

    return result
