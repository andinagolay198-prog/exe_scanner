"""
Crack Profiler
Tổng hợp tất cả phân tích → đưa ra "Crack Profile":
- Cracker dùng kỹ thuật gì?
- File này bypass license theo cách nào?
- Bạn cần làm gì để chặn?
"""
from typing import List, Dict, Optional


# ─── Crack technique profiles ────────────────────────────────
CRACK_TECHNIQUES = {
    "LOADER": {
        "name":        "Loader / Dropper",
        "description": "File này là một loader — không crack trực tiếp mà load payload từ resource/disk để bypass",
        "indicators":  ["embedded PE", "rsrc entropy >7.2", "VirtualAlloc", "overlay payload"],
        "counter":     [
            "Server-side activation: loader không giả mạo được server response",
            "Bind license vào machine ID — loader chạy trên máy khác sẽ fail",
            "Kiểm tra integrity của chính mình (self-hash) trước mỗi feature quan trọng",
            "Mã hóa feature code bằng key từ server — loader không có key",
        ],
    },
    "PATCHER": {
        "name":        "Binary Patcher",
        "description": "File này patch trực tiếp binary của bạn — thay đổi JMP/JNZ để bypass license check",
        "indicators":  ["WriteProcessMemory", "VirtualProtect", "patch keyword", "backup .bak"],
        "counter":     [
            "Self-integrity check: app tự hash chính nó, nếu bị patch → từ chối chạy",
            "Đừng dùng 1 điểm kiểm tra license — rải logic check khắp code",
            "Code obfuscation: làm cho patch point khó tìm hơn",
            "Online validation: server biết hash binary hợp lệ là gì",
        ],
    },
    "KEYGEN": {
        "name":        "Key Generator",
        "description": "File generate license key hợp lệ mà không mua — thuật toán keygen đã bị reverse",
        "indicators":  ["keygen", "serial", "activation code", "license generate"],
        "counter":     [
            "HMAC với secret key chỉ bạn có — không thể keygen nếu không có secret",
            "Server-side validation — server verify, không dựa vào thuật toán local",
            "Machine ID binding — key chỉ đúng cho 1 machine cụ thể",
            "Key blacklist — server có thể thu hồi key bất kỳ lúc nào",
        ],
    },
    "HOOK_INJECTOR": {
        "name":        "API Hook Injector",
        "description": "Inject hook vào API để fake kết quả — VD: hook IsLicenseValid() để luôn trả về true",
        "indicators":  ["SetWindowsHookEx", "CreateRemoteThread", "VirtualAllocEx", "hook API"],
        "counter":     [
            "Không tin vào return value của hàm license check đơn giản",
            "Dùng multiple check points: nếu hook 1 chỗ thì chỗ khác vẫn fail",
            "Kernel-mode check (driver) — usermode hook không can thiệp được",
            "Obfuscate tên hàm license check — khó tìm để hook hơn",
        ],
    },
    "MEMORY_PATCHER": {
        "name":        "In-Memory Patcher",
        "description": "Patch binary trong memory lúc runtime — không sửa file, sửa trong RAM",
        "indicators":  ["WriteProcessMemory", "VirtualProtect", "OpenProcess", "code cave"],
        "counter":     [
            "Periodic self-check: hash code sections trong memory định kỳ",
            "Guard pages: đặt page protection để detect ghi vào code region",
            "Anti-debug: nếu có debugger/injection tool → hoạt động sai",
            "Dùng obfuscated code — không có clear function boundary để patch",
        ],
    },
    "UNPACKER": {
        "name":        "Packed/Protected Crack Tool",
        "description": "Bản thân file crack được pack để khó phân tích",
        "indicators":  ["PUSHAD at EP", "XOR decrypt loop", "UPX", "packer signature"],
        "counter":     [
            "Không liên quan trực tiếp đến bảo vệ của bạn",
            "Nhưng nếu crack tool pack được thì binary của bạn cũng nên pack",
            "Dùng VMProtect/Themida cho phần license check critical",
        ],
    },
    "DEBUGGER_TOOL": {
        "name":        "Debugger-Assisted Crack",
        "description": "Cracker dùng debugger để trace và tìm license check point",
        "indicators":  ["anti-debug bypass", "x64dbg", "OllyDbg", "IDA Pro"],
        "counter":     [
            "Anti-debug: detect IsDebuggerPresent, timing check, hardware breakpoints",
            "Obfuscate license logic — không có rõ ràng 1 điểm check",
            "Virtualize critical code (VMProtect) — debugger xem được bytecode VM, không phải logic thật",
            "Rải false checks — mất nhiều thời gian cracker hơn",
        ],
    },
}


def _match_techniques(packer_result: Dict, disasm_result: Dict,
                      resource_result: Dict, pe_result) -> List[str]:
    """Khớp kỹ thuật crack từ các kết quả phân tích."""
    matched = []
    seen = set()

    def add(tech):
        if tech not in seen:
            seen.add(tech)
            matched.append(tech)

    # Từ packer analysis
    if packer_result:
        anti = packer_result.get("anti_crack", [])
        lic  = packer_result.get("license_strings", [])

        anti_descs = " ".join(a["desc"] for a in anti).lower()
        lic_descs  = " ".join(l["desc"] for l in lic).lower()

        if "keygen" in lic_descs or "serial" in lic_descs:
            add("KEYGEN")
        if "patch" in lic_descs or "bypass license" in lic_descs:
            add("PATCHER")
        if "hook" in anti_descs or "inject" in anti_descs:
            add("HOOK_INJECTOR")
        if "debugger" in anti_descs or "x64dbg" in anti_descs or "ollydbg" in anti_descs:
            add("DEBUGGER_TOOL")
        if packer_result.get("packers"):
            add("UNPACKER")

    # Từ disasm
    if disasm_result:
        stubs = disasm_result.get("stub_findings", [])
        stub_names = " ".join(s["name"] for s in stubs).lower()
        byte_descs = " ".join(b["desc"] for b in disasm_result.get("byte_findings", [])).lower()

        if "pushad" in stub_names or "xor" in stub_names:
            add("UNPACKER")
        if "direct syscall" in byte_descs:
            add("HOOK_INJECTOR")
        if "code cave" in stub_names:
            add("MEMORY_PATCHER")

    # Từ resource analysis
    if resource_result:
        embedded = resource_result.get("embedded_files", [])
        if any(e["type"] in ("PE/EXE", "PE/EXE (embedded)") for e in embedded):
            add("LOADER")
        if resource_result.get("total_size", 0) > 5_000_000:
            add("LOADER")

    # Từ PE analysis
    if pe_result and pe_result.is_valid_pe:
        apis = {si["api"] for si in pe_result.suspicious_imports}

        if {"WriteProcessMemory", "VirtualAllocEx"}.issubset(apis):
            add("MEMORY_PATCHER")
            add("HOOK_INJECTOR")
        if {"WriteProcessMemory", "CreateRemoteThread"}.issubset(apis):
            add("HOOK_INJECTOR")
        if {"LoadLibraryA", "GetProcAddress"}.issubset(apis):
            # Dynamic resolution — có thể là loader hoặc unpacker
            if "LOADER" not in seen:
                add("LOADER")

        rsrc_high = [s for s in pe_result.sections
                     if s.name == ".rsrc" and s.entropy > 7.0]
        if rsrc_high:
            add("LOADER")

    return matched


def _build_protection_recommendations(techniques: List[str],
                                       pe_result,
                                       packer_result: Dict,
                                       resource_result: Dict) -> List[Dict]:
    """Xây dựng danh sách khuyến nghị bảo vệ có ưu tiên."""
    recs = []
    seen_recs = set()

    for tech in techniques:
        profile = CRACK_TECHNIQUES.get(tech)
        if not profile:
            continue
        for counter in profile["counter"]:
            if counter not in seen_recs:
                seen_recs.add(counter)
                recs.append({
                    "counter": counter,
                    "against": profile["name"],
                    "priority": 1 if tech in ("LOADER", "KEYGEN") else
                                2 if tech in ("PATCHER", "HOOK_INJECTOR") else 3,
                })

    # Sắp xếp theo priority
    recs.sort(key=lambda x: x["priority"])
    return recs


def build_crack_profile(packer_result: Dict,
                        disasm_result: Dict,
                        resource_result: Dict,
                        pe_result) -> Dict:
    """
    Main entry: xây dựng crack profile đầy đủ.
    """
    techniques = _match_techniques(
        packer_result, disasm_result, resource_result, pe_result
    )

    profiles = []
    for tech in techniques:
        profile = CRACK_TECHNIQUES.get(tech, {})
        profiles.append({
            "id":          tech,
            "name":        profile.get("name", tech),
            "description": profile.get("description", ""),
            "counter":     profile.get("counter", []),
        })

    recommendations = _build_protection_recommendations(
        techniques, pe_result, packer_result, resource_result
    )

    # Risk indicators từ profile
    indicators = []
    if "KEYGEN" in techniques:
        indicators.append({
            "level": "CRITICAL", "points": 30,
            "description": "Crack Profile: Key Generator — thuật toán license đã bị reverse",
        })
    if "LOADER" in techniques:
        indicators.append({
            "level": "HIGH", "points": 20,
            "description": "Crack Profile: Loader/Dropper — payload nhúng sẽ được giải mã lúc runtime",
        })
    if "HOOK_INJECTOR" in techniques:
        indicators.append({
            "level": "HIGH", "points": 18,
            "description": "Crack Profile: API Hook Injector — fake return values của hàm license",
        })
    if "PATCHER" in techniques:
        indicators.append({
            "level": "HIGH", "points": 15,
            "description": "Crack Profile: Binary Patcher — patch file để bypass license check",
        })
    if "MEMORY_PATCHER" in techniques:
        indicators.append({
            "level": "HIGH", "points": 15,
            "description": "Crack Profile: Memory Patcher — patch binary trong RAM lúc runtime",
        })

    return {
        "techniques":        techniques,
        "profiles":          profiles,
        "recommendations":   recommendations,
        "indicators":        indicators,
        "technique_count":   len(techniques),
        "primary_technique": techniques[0] if techniques else "UNKNOWN",
    }
