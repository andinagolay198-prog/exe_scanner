# EXE Scanner — Hướng dẫn cài đặt và sử dụng

## Cài đặt nhanh

```bash
# 1. Tạo virtual environment (khuyến nghị)
python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 2. Cài dependencies
pip install pefile yara-python

# 3. Chạy tool
python main.py
```

---

## Cấu trúc project

```
exe_scanner/
├── main.py                    ← Entry point (chạy file này)
├── requirements.txt
├── core/
│   ├── pe_parser.py           ← Parse toàn bộ PE header, entropy, strings
│   ├── scanner.py             ← YARA scanner + Threat Scorer
│   └── logger.py              ← Ghi log JSON + text
├── rules/
│   ├── botnet_irc.yar         ← IRC botnet (classic, SSL, Mirai)
│   ├── botnet_http.yar        ← HTTP C2 (Zeus, Emotet, TrickBot, DGA)
│   ├── botnet_advanced.yar    ← P2P, DNS tunnel, Tor, steganography
│   └── evasion_persistence.yar← Anti-debug, VM detect, ransomware
└── logs/                      ← Tự tạo — log mỗi phiên quét
    ├── 20240315_143022_scan.txt
    └── 20240315_143022_scan.json
```

---

## Tính năng

### Phân tích tĩnh (Static Analysis)
- Parse đầy đủ PE Header: DOS, COFF, Optional Header, Section Table
- Entropy analysis từng section (phát hiện packed/encrypted)
- Import Table: 40+ suspicious API được phân loại theo mức độ nguy hiểm
- Combo API detection: Process Injection, Process Hollowing, APC Injection
- String extraction: IP, URL, domain, IRC commands, registry keys, mutex
- Hash: MD5, SHA1, SHA256

### YARA Rules (4 file, ~30 rules)
- **IRC Botnet**: classic, SSL, Mirai, keylogger exfil, hidden channels
- **HTTP Botnet**: C2 beaconing, DGA, Zeus, Emotet, TrickBot
- **Advanced**: P2P Kademlia, DNS tunneling, Tor .onion, social media C2
- **Evasion**: Process Hollowing, Reflective DLL, Heaven's Gate, DKOM rootkit
- **Persistence**: Registry, Scheduled Task, COM Hijacking, Service Install
- **Ransomware**: file encryption, shadow copy deletion

### Threat Scoring
- Điểm 0–100 tổng hợp từ mọi indicator
- Verdict: CLEAN / POTENTIALLY_UNWANTED / SUSPICIOUS / MALICIOUS / CRITICAL_THREAT

### GUI & Terminal
- Terminal real-time với màu sắc theo mức độ nguy hiểm
- Bảng kết quả với màu verdict
- Tab Chi tiết: đầy đủ PE info, sections, imports, YARA, strings
- Tab Logs: xem log file trực tiếp trong app

### Logging
- `.txt`: Log text dễ đọc với timestamp
- `.json`: Structured data để phân tích sau hoặc tích hợp vào SIEM

---

## Thêm YARA rules

Tạo file `.yar` mới trong thư mục `rules/`:

```yara
rule My_Custom_Rule {
    meta:
        description = "Mô tả rule"
        severity = "HIGH"   // CRITICAL | HIGH | MEDIUM | LOW
        category = "botnet"
    strings:
        $s1 = "string cần tìm" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $s1
}
```

Tool tự động load tất cả `.yar` files khi khởi động.

---

## Notes

- Không cần internet connection để phân tích tĩnh
- Dynamic analysis (sandbox) cần thêm module riêng — chạy trong VM cô lập
- YARA scan có thể mất 2–10 giây với file lớn
- Log JSON phù hợp để import vào Splunk, Elastic, hoặc bất kỳ SIEM nào
